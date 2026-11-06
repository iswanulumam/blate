//! Reads process information from a procfs tree.
//!
//! This is the only module that touches `/proc`. The root path is a parameter
//! so that the reader can be tested against fixture trees on any platform.
//!
//! A process can exit, or its PID can be reused, between any two reads. Each
//! read therefore tolerates a vanished process, and [`ProcFs::summary`] and
//! [`ProcFs::inspect`] compare the start time before and after reading, so
//! fields from two different processes are never combined.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::process::{
    Ancestor, CommandLine, ESRCH, Executable, IdSet, Inspection, Lineage, LineageEnd, Namespaces,
    Pid, Probe, ProcStat, ProcStatus, ProcessIdentity, ProcessSummary,
};

/// Bounds memory use, since a process controls the size of its command line.
const MAX_CMDLINE_BYTES: usize = 256 * 1024;
/// Bounds reads of the other files, which the kernel keeps small.
const MAX_FILE_BYTES: usize = 64 * 1024;
/// Stops a lineage walk that a corrupt or malicious view could keep going.
const MAX_LINEAGE_DEPTH: usize = 1024;

/// A procfs tree.
#[derive(Debug, Clone)]
pub struct ProcFs {
    root: PathBuf,
}

impl ProcFs {
    /// Returns the host's `/proc`, or an error if it is not usable.
    pub fn system() -> Result<Self, Error> {
        if !cfg!(target_os = "linux") {
            return Err(Error::UnsupportedPlatform);
        }
        let procfs = Self::at("/proc");
        let path = procfs.root.join("self/stat");
        fs::metadata(&path).map_err(|source| Error::ProcUnavailable { path, source })?;
        Ok(procfs)
    }

    /// Returns a reader for the tree at `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Lists the visible processes in ascending PID order.
    pub fn list_pids(&self) -> Result<Vec<Pid>, Error> {
        let unavailable = |source| Error::ProcUnavailable {
            path: self.root.clone(),
            source,
        };
        let mut pids = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;
            if let Some(pid) = entry.file_name().to_str().and_then(Pid::parse) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        Ok(pids)
    }

    /// Reads and parses `/proc/<pid>/stat`.
    pub fn read_stat(&self, pid: Pid) -> Result<ProcStat, Error> {
        let path = self.path(pid, "stat");
        let (bytes, _) = read_capped(&path, MAX_FILE_BYTES).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound || source.raw_os_error() == Some(ESRCH) {
                Error::NotFound(pid)
            } else if source.kind() == io::ErrorKind::PermissionDenied {
                Error::PermissionDenied(pid)
            } else {
                Error::Io {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let malformed = |reason| Error::Malformed {
            path: path.clone(),
            reason,
        };
        let stat = parse_stat(&bytes).map_err(malformed)?;
        if stat.identity.pid != pid {
            return Err(malformed("PID does not match the requested process"));
        }
        Ok(stat)
    }

    /// Reads what `blate scan` needs for one process.
    pub fn summary(&self, pid: Pid) -> Result<ProcessSummary, Error> {
        let stat = self.read_stat(pid)?;
        let summary = self.read_summary_fields(stat);
        self.confirm_same_process(&summary.stat.identity)?;
        Ok(summary)
    }

    /// Reads everything `blate inspect` reports for one process.
    pub fn inspect(&self, pid: Pid) -> Result<Inspection, Error> {
        let stat = self.read_stat(pid)?;
        let summary = self.read_summary_fields(stat);
        let cgroup = self.read_cgroup(pid);
        let namespaces = self.read_namespaces(pid);
        let sockets = self.count_sockets(pid);
        self.confirm_same_process(&summary.stat.identity)?;
        let lineage = self.lineage(&summary.stat);
        Ok(Inspection {
            summary,
            cgroup,
            namespaces,
            sockets,
            lineage,
        })
    }

    /// Walks parent links from `start` towards the root.
    ///
    /// A real parent cannot have started after its child, so a parent with a
    /// later start time shows that its PID has been reused.
    pub fn lineage(&self, start: &ProcStat) -> Lineage {
        let mut ancestors = Vec::new();
        let mut child_start = start.identity.start_ticks;
        let mut ppid = start.ppid;
        let end = loop {
            if ancestors.len() >= MAX_LINEAGE_DEPTH {
                break LineageEnd::DepthLimit;
            }
            let Some(pid) = Pid::new(ppid) else {
                break LineageEnd::Root;
            };
            let stat = match self.read_stat(pid) {
                Ok(stat) => stat,
                Err(Error::NotFound(_)) => break LineageEnd::Gone(pid.get()),
                Err(Error::PermissionDenied(_)) => break LineageEnd::Denied(pid),
                Err(_) => break LineageEnd::Unreadable(pid),
            };
            if stat.identity.start_ticks > child_start {
                break LineageEnd::PidReused(pid);
            }
            child_start = stat.identity.start_ticks;
            ppid = stat.ppid;
            ancestors.push(Ancestor {
                identity: stat.identity,
                comm: stat.comm,
            });
        };
        Lineage { ancestors, end }
    }

    fn path(&self, pid: Pid, file: &str) -> PathBuf {
        self.root.join(pid.get().to_string()).join(file)
    }

    fn read_summary_fields(&self, stat: ProcStat) -> ProcessSummary {
        let pid = stat.identity.pid;
        ProcessSummary {
            cmdline: self.read_cmdline(pid),
            exe: self.read_exe(pid),
            status: self.read_status(pid),
            stat,
        }
    }

    fn confirm_same_process(&self, identity: &ProcessIdentity) -> Result<(), Error> {
        let pid = identity.pid;
        match self.read_stat(pid) {
            Ok(stat) if stat.identity == *identity => Ok(()),
            Ok(_) | Err(Error::NotFound(_)) => Err(Error::ProcessChanged(pid)),
            Err(other) => Err(other),
        }
    }

    fn read_cmdline(&self, pid: Pid) -> Probe<CommandLine> {
        match read_capped(&self.path(pid, "cmdline"), MAX_CMDLINE_BYTES) {
            Ok((bytes, truncated)) => Probe::Available(parse_cmdline(&bytes, truncated)),
            Err(error) => Probe::from_io_error(&error),
        }
    }

    fn read_exe(&self, pid: Pid) -> Probe<Executable> {
        match fs::read_link(self.path(pid, "exe")) {
            Ok(target) => Probe::Available(parse_exe(target.into_os_string().into_vec())),
            Err(error) => Probe::from_io_error(&error),
        }
    }

    fn read_status(&self, pid: Pid) -> Probe<ProcStatus> {
        match read_capped(&self.path(pid, "status"), MAX_FILE_BYTES) {
            Ok((bytes, _)) => Probe::Available(parse_status(&String::from_utf8_lossy(&bytes))),
            Err(error) => Probe::from_io_error(&error),
        }
    }

    fn read_cgroup(&self, pid: Pid) -> Probe<Option<Vec<u8>>> {
        match read_capped(&self.path(pid, "cgroup"), MAX_FILE_BYTES) {
            Ok((bytes, _)) => Probe::Available(parse_cgroup_v2(&bytes)),
            Err(error) => Probe::from_io_error(&error),
        }
    }

    fn read_namespaces(&self, pid: Pid) -> Namespaces {
        let link = |name: &str| match fs::read_link(self.path(pid, &format!("ns/{name}"))) {
            Ok(target) => Probe::Available(target.to_string_lossy().into_owned()),
            Err(error) => Probe::from_io_error(&error),
        };
        Namespaces {
            pid: link("pid"),
            mnt: link("mnt"),
            net: link("net"),
            user: link("user"),
        }
    }

    fn count_sockets(&self, pid: Pid) -> Probe<usize> {
        let entries = match fs::read_dir(self.path(pid, "fd")) {
            Ok(entries) => entries,
            Err(error) => return Probe::from_io_error(&error),
        };
        let count = entries
            .flatten()
            // A descriptor can close during the walk; it no longer counts.
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .filter(|target| target.as_os_str().as_bytes().starts_with(b"socket:["))
            .count();
        Probe::Available(count)
    }
}

/// Reads at most `limit` bytes and reports whether the file had more.
fn read_capped(path: &Path, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, truncated))
}

/// Parses the contents of `/proc/<pid>/stat`.
///
/// The name field can contain spaces and parentheses, so a process could use
/// its own name to forge later fields. The name therefore ends at the *last*
/// closing parenthesis, and every other field is read after it.
pub fn parse_stat(bytes: &[u8]) -> Result<ProcStat, &'static str> {
    let open = bytes
        .iter()
        .position(|b| *b == b'(')
        .ok_or("missing opening parenthesis")?;
    let close = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or("missing closing parenthesis")?;
    if close < open {
        return Err("parentheses out of order");
    }

    let pid = std::str::from_utf8(&bytes[..open])
        .ok()
        .and_then(|text| Pid::parse(text.trim()))
        .ok_or("invalid PID")?;
    let rest = std::str::from_utf8(&bytes[close + 1..]).map_err(|_| "fields are not text")?;

    // Indexes count from the state field, which proc(5) numbers as field 3.
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
    let field = |index: usize| fields.get(index).copied().ok_or("too few fields");
    let [state] = field(0)?.as_bytes() else {
        return Err("invalid state");
    };

    Ok(ProcStat {
        identity: ProcessIdentity {
            pid,
            start_ticks: field(19)?.parse().map_err(|_| "invalid start time")?,
        },
        comm: bytes[open + 1..close].to_vec(),
        state: *state,
        ppid: field(1)?.parse().map_err(|_| "invalid parent PID")?,
        flags: field(6)?.parse().map_err(|_| "invalid flags")?,
        threads: field(17)?.parse().map_err(|_| "invalid thread count")?,
    })
}

/// Parses the contents of `/proc/<pid>/status`, ignoring unknown lines.
pub fn parse_status(text: &str) -> ProcStatus {
    let mut status = ProcStatus::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "Uid" => status.uid = parse_id_set(value),
            "Gid" => status.gid = parse_id_set(value),
            "NoNewPrivs" => status.no_new_privs = value.parse::<u8>().ok().map(|v| v != 0),
            "Seccomp" => status.seccomp = value.parse().ok(),
            "CapEff" => status.cap_effective = u64::from_str_radix(value, 16).ok(),
            _ => {}
        }
    }
    status
}

fn parse_id_set(value: &str) -> Option<IdSet> {
    let mut ids = value.split_ascii_whitespace().map(str::parse);
    Some(IdSet {
        real: ids.next()?.ok()?,
        effective: ids.next()?.ok()?,
        saved: ids.next()?.ok()?,
        filesystem: ids.next()?.ok()?,
    })
}

/// Parses the contents of `/proc/<pid>/cmdline`.
///
/// Processes that rewrite their title can leave trailing empty arguments,
/// which carry no information and are dropped.
pub fn parse_cmdline(bytes: &[u8], truncated: bool) -> CommandLine {
    let mut args: Vec<Vec<u8>> = bytes.split(|b| *b == 0).map(<[u8]>::to_vec).collect();
    while args.last().is_some_and(Vec::is_empty) {
        args.pop();
    }
    CommandLine { args, truncated }
}

/// Parses the target of `/proc/<pid>/exe`.
fn parse_exe(mut path: Vec<u8>) -> Executable {
    const DELETED: &[u8] = b" (deleted)";
    let deleted = path.ends_with(DELETED);
    if deleted {
        path.truncate(path.len() - DELETED.len());
    }
    Executable { path, deleted }
}

/// Returns the cgroup v2 path from `/proc/<pid>/cgroup`: the `0::` entry.
pub fn parse_cgroup_v2(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"0::"))
        .map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT_TAIL: &str = "S 7 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 3 0 12345 0 0";

    #[test]
    fn parses_plain_stat() {
        let stat = parse_stat(format!("42 (bash) {STAT_TAIL}\n").as_bytes()).unwrap();
        assert_eq!(stat.identity.pid.get(), 42);
        assert_eq!(stat.identity.start_ticks, 12345);
        assert_eq!(stat.comm, b"bash");
        assert_eq!(stat.state, b'S');
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.threads, 3);
        assert!(!stat.is_kernel_thread());
    }

    #[test]
    fn process_name_cannot_forge_stat_fields() {
        // This name tries to pass itself off as the end of the name field and
        // to claim parent PID 1 and start time 1.
        let line = format!("42 (x) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0) {STAT_TAIL}\n");
        let stat = parse_stat(line.as_bytes()).unwrap();
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.identity.start_ticks, 12345);
        assert!(stat.comm.starts_with(b"x) R 1 1"));
    }

    #[test]
    fn keeps_non_utf8_process_names() {
        let mut line = b"42 (\xff\xfe) ".to_vec();
        line.extend_from_slice(STAT_TAIL.as_bytes());
        assert_eq!(parse_stat(&line).unwrap().comm, b"\xff\xfe");
    }

    #[test]
    fn detects_kernel_threads() {
        let line = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0";
        assert!(parse_stat(line.as_bytes()).unwrap().is_kernel_thread());
    }

    #[test]
    fn rejects_malformed_stat() {
        let cases: [&[u8]; 6] = [
            b"",
            b"42 no parens",
            b"42 )x( S 1",
            b"abc (x) S 1",
            b"42 (x) S 1 2 3",
            b"42 (x) LONG 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 1",
        ];
        for bytes in cases {
            assert!(
                parse_stat(bytes).is_err(),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn parses_status_and_ignores_unknown_lines() {
        let status = parse_status(
            "Name:\tx\nUid:\t1000\t1001\t1002\t1003\nGid:\t5\t6\t7\t8\nNoNewPrivs:\t1\n\
             Seccomp:\t2\nCapEff:\t000001ffffffffff\nFuture:\tvalue\n",
        );
        let uid = status.uid.unwrap();
        assert_eq!(
            (uid.real, uid.effective, uid.saved, uid.filesystem),
            (1000, 1001, 1002, 1003)
        );
        assert_eq!(status.gid.unwrap().filesystem, 8);
        assert_eq!(status.no_new_privs, Some(true));
        assert_eq!(status.seccomp, Some(2));
        assert_eq!(status.cap_effective, Some(0x1ff_ffff_ffff));
    }

    #[test]
    fn missing_status_fields_stay_unknown() {
        assert_eq!(parse_status("Uid:\tnot numbers\n"), ProcStatus::default());
    }

    #[test]
    fn splits_cmdline_on_nul_and_drops_padding() {
        let cmdline = parse_cmdline(b"node\0a b\0\0--x\0\0\0", false);
        let expected: [&[u8]; 4] = [b"node", b"a b", b"", b"--x"];
        assert_eq!(cmdline.args, expected);
        assert!(parse_cmdline(b"", false).args.is_empty());
    }

    #[test]
    fn reports_deleted_executables() {
        let exe = parse_exe(b"/tmp/agent (deleted)".to_vec());
        assert_eq!(exe.path, b"/tmp/agent");
        assert!(exe.deleted);
        assert!(!parse_exe(b"/usr/bin/agent".to_vec()).deleted);
    }

    #[test]
    fn finds_the_cgroup_v2_entry_on_hybrid_hosts() {
        assert_eq!(
            parse_cgroup_v2(b"1:name=systemd:/a\n0::/b.slice/c.service\n").unwrap(),
            b"/b.slice/c.service"
        );
        assert_eq!(parse_cgroup_v2(b"3:cpu:/a\n"), None);
    }
}
