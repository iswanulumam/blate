//! Tests the procfs reader and scanner against fixture trees, covering states
//! that are hard to produce reliably on a live system.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use blate::classify::EvidenceSource;
use blate::error::Error;
use blate::process::{LineageEnd, Pid, Probe};
use blate::procfs::ProcFs;
use blate::scan::scan;

const KTHREAD_FLAGS: u64 = 0x0020_0000;

/// A temporary procfs tree, removed when dropped.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "proc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn procfs(&self) -> ProcFs {
        ProcFs::at(&self.root)
    }

    fn dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    /// Adds a process with only the `stat` file.
    fn stat_only(&self, pid: u32, comm: &str, ppid: u32, start: u64, flags: u64) {
        fs::create_dir_all(self.dir(pid)).unwrap();
        fs::write(
            self.dir(pid).join("stat"),
            format!(
                "{pid} ({comm}) S {ppid} 1 1 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 2 0 {start} 0 0\n"
            ),
        )
        .unwrap();
    }

    /// Adds a process with every file a live user process has.
    fn full(&self, pid: u32, comm: &str, ppid: u32, start: u64, exe: &str, cmdline: &[u8]) {
        self.stat_only(pid, comm, ppid, start, 0);
        let dir = self.dir(pid);
        fs::write(dir.join("cmdline"), cmdline).unwrap();
        symlink(exe, dir.join("exe")).unwrap();
        fs::write(
            dir.join("status"),
            "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t0\n\
             Seccomp:\t0\nCapEff:\t0000000000000000\n",
        )
        .unwrap();
        fs::write(dir.join("cgroup"), "0::/system.slice/agent.service\n").unwrap();
        fs::create_dir(dir.join("ns")).unwrap();
        symlink("net:[4026531840]", dir.join("ns/net")).unwrap();
        fs::create_dir(dir.join("fd")).unwrap();
        symlink("socket:[111]", dir.join("fd/3")).unwrap();
        symlink("socket:[222]", dir.join("fd/4")).unwrap();
        symlink("/dev/null", dir.join("fd/0")).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn pid(raw: u32) -> Pid {
    Pid::new(raw).unwrap()
}

#[test]
fn inspects_every_field_of_a_process() {
    let fixture = Fixture::new();
    fixture.stat_only(1, "init", 0, 1, 0);
    fixture.full(50, "node", 1, 100, "/usr/bin/node", b"node\0app.js\0");

    let inspection = fixture.procfs().inspect(pid(50)).unwrap();

    let exe = inspection.summary.exe.available().unwrap();
    assert_eq!(exe.path, b"/usr/bin/node");
    let args = &inspection.summary.cmdline.available().unwrap().args;
    assert_eq!(args.len(), 2);
    let status = inspection.summary.status.available().unwrap();
    assert_eq!(status.uid.unwrap().effective, 1000);
    assert_eq!(inspection.sockets, Probe::Available(2));
    assert_eq!(
        inspection.cgroup,
        Probe::Available(Some(b"/system.slice/agent.service".to_vec()))
    );
    assert_eq!(
        inspection.namespaces.net,
        Probe::Available("net:[4026531840]".to_owned())
    );
    assert_eq!(inspection.namespaces.pid, Probe::Missing);
}

#[test]
fn walks_lineage_to_the_root() {
    let fixture = Fixture::new();
    fixture.stat_only(1, "init", 0, 1, 0);
    fixture.stat_only(10, "sshd", 1, 5, 0);
    fixture.stat_only(20, "bash", 10, 9, 0);
    fixture.stat_only(30, "agent", 20, 9, 0);

    let stat = fixture.procfs().read_stat(pid(30)).unwrap();
    let lineage = fixture.procfs().lineage(&stat);

    let pids: Vec<u32> = lineage
        .ancestors
        .iter()
        .map(|a| a.identity.pid.get())
        .collect();
    assert_eq!(pids, [20, 10, 1]);
    assert_eq!(lineage.end, LineageEnd::Root);
}

#[test]
fn lineage_rejects_a_parent_that_started_after_its_child() {
    let fixture = Fixture::new();
    fixture.stat_only(10, "unrelated", 1, 500, 0);
    fixture.stat_only(30, "agent", 10, 100, 0);

    let stat = fixture.procfs().read_stat(pid(30)).unwrap();
    let lineage = fixture.procfs().lineage(&stat);

    assert!(lineage.ancestors.is_empty());
    assert_eq!(lineage.end, LineageEnd::PidReused(pid(10)));
}

#[test]
fn lineage_reports_a_parent_that_has_exited() {
    let fixture = Fixture::new();
    fixture.stat_only(30, "agent", 10, 100, 0);

    let stat = fixture.procfs().read_stat(pid(30)).unwrap();

    assert_eq!(fixture.procfs().lineage(&stat).end, LineageEnd::Gone(10));
}

#[test]
fn lineage_cycles_stop_at_the_depth_limit() {
    let fixture = Fixture::new();
    fixture.stat_only(10, "a", 20, 5, 0);
    fixture.stat_only(20, "b", 10, 5, 0);

    let stat = fixture.procfs().read_stat(pid(10)).unwrap();

    assert_eq!(fixture.procfs().lineage(&stat).end, LineageEnd::DepthLimit);
}

#[test]
fn inspecting_a_missing_process_is_not_found() {
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.procfs().inspect(pid(99)),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn a_stat_for_the_wrong_pid_is_malformed() {
    let fixture = Fixture::new();
    fixture.stat_only(10, "a", 1, 5, 0);
    fs::rename(fixture.dir(10), fixture.dir(11)).unwrap();
    assert!(matches!(
        fixture.procfs().read_stat(pid(11)),
        Err(Error::Malformed { .. })
    ));
}

#[test]
fn a_process_without_optional_files_still_reports_what_is_known() {
    let fixture = Fixture::new();
    fixture.stat_only(10, "zombie", 1, 5, 0);

    let summary = fixture.procfs().summary(pid(10)).unwrap();

    assert_eq!(summary.stat.comm, b"zombie");
    assert_eq!(summary.exe, Probe::Missing);
    assert_eq!(summary.cmdline, Probe::Missing);
}

#[test]
fn long_command_lines_are_truncated_and_flagged() {
    let fixture = Fixture::new();
    fixture.full(10, "big", 1, 5, "/bin/big", &vec![b'a'; 1024 * 1024]);

    let summary = fixture.procfs().summary(pid(10)).unwrap();

    let cmdline = summary.cmdline.available().unwrap();
    assert!(cmdline.truncated);
    assert_eq!(cmdline.args[0].len(), 256 * 1024);
}

#[test]
fn scan_finds_candidates_and_counts_unreadable_entries() {
    let fixture = Fixture::new();
    fixture.full(10, "bash", 1, 5, "/bin/bash", b"bash\0");
    fixture.full(
        20,
        "node",
        1,
        6,
        "/usr/bin/node",
        b"node\0/opt/claude-code/cli.js\0",
    );
    fixture.stat_only(2, "claude", 0, 1, KTHREAD_FLAGS);
    // A process whose stat cannot be parsed must not abort the scan.
    fs::create_dir(fixture.dir(30)).unwrap();
    fs::write(fixture.dir(30).join("stat"), "garbage").unwrap();
    // A directory with no stat behaves like a process that has just exited.
    fs::create_dir(fixture.dir(40)).unwrap();
    // Non-numeric entries are not processes.
    fs::create_dir(fixture.root.join("sys")).unwrap();

    let report = scan(&fixture.procfs()).unwrap();

    let pids: Vec<u32> = report
        .entries
        .iter()
        .map(|e| e.process.stat.identity.pid.get())
        .collect();
    assert_eq!(pids, [2, 10, 20]);
    assert_eq!(report.failed, 1);
    assert_eq!(report.vanished, 1);

    let matched: Vec<_> = report
        .entries
        .iter()
        .filter(|e| !e.classifications.is_empty())
        .collect();
    assert_eq!(matched.len(), 1, "kernel threads must not match");
    let classification = &matched[0].classifications[0];
    assert_eq!(classification.agent, "claude-code");
    assert_eq!(classification.evidence[0].source, EvidenceSource::Script);
}

#[test]
fn scan_fails_when_the_process_list_is_unreadable() {
    let procfs = ProcFs::at(Path::new(env!("CARGO_TARGET_TMPDIR")).join("does-not-exist"));
    assert!(matches!(scan(&procfs), Err(Error::ProcUnavailable { .. })));
}
