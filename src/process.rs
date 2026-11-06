//! Structured process data, independent of how it was collected.
//!
//! Process names, command lines, and paths are kept as raw bytes. Linux does
//! not require them to be UTF-8, and they are controlled by the process being
//! observed. They only become text in [`crate::sanitize`].

use std::fmt;
use std::io;

/// `ESRCH`, returned when reading from a process that has just exited.
pub(crate) const ESRCH: i32 = 3;

/// `PF_KTHREAD` from the `flags` field of `/proc/<pid>/stat`.
const PF_KTHREAD: u64 = 0x0020_0000;

/// A valid process ID: positive and within the range of `pid_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(u32);

impl Pid {
    /// Returns a `Pid`, or `None` if `raw` is outside the valid range.
    pub fn new(raw: u32) -> Option<Self> {
        (raw > 0 && raw <= i32::MAX as u32).then_some(Self(raw))
    }

    /// Parses decimal digits only, rejecting forms such as `+1` and ` 1`.
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok().and_then(Self::new)
    }

    /// Returns the numeric PID.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifies one process across time.
///
/// PIDs are reused, so a PID alone does not identify a process. A PID and its
/// start time together do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    /// The process ID.
    pub pid: Pid,
    /// Start time in clock ticks since boot, from `/proc/<pid>/stat`.
    pub start_ticks: u64,
}

/// The outcome of reading one optional piece of process information.
///
/// Keeping these cases separate stops "not allowed to look" from being
/// reported as "nothing there", which matters in a security tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe<T> {
    /// The value was read.
    Available(T),
    /// The kernel refused access.
    Denied,
    /// The kernel does not expose this for the process, or the process exited.
    Missing,
    /// The read failed for another reason.
    Failed(String),
}

impl<T> Probe<T> {
    /// Classifies a failed read.
    pub fn from_io_error(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Self::Denied,
            io::ErrorKind::NotFound => Self::Missing,
            _ if error.raw_os_error() == Some(ESRCH) => Self::Missing,
            _ => Self::Failed(error.to_string()),
        }
    }

    /// Returns the value if it was read.
    pub fn available(&self) -> Option<&T> {
        match self {
            Self::Available(value) => Some(value),
            _ => None,
        }
    }
}

/// Fields from `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    /// The PID and start time.
    pub identity: ProcessIdentity,
    /// The kernel's process name, at most 15 bytes. Settable by the process.
    pub comm: Vec<u8>,
    /// The single-letter state code.
    pub state: u8,
    /// The parent PID, or 0 if the parent is outside this PID namespace.
    pub ppid: u32,
    /// The kernel's per-process flags.
    pub flags: u64,
    /// The number of threads.
    pub threads: u64,
}

impl ProcStat {
    /// Reports whether this is a kernel thread rather than a user process.
    pub fn is_kernel_thread(&self) -> bool {
        self.flags & PF_KTHREAD != 0
    }

    /// Describes the state code.
    pub fn state_description(&self) -> &'static str {
        match self.state {
            b'R' => "running",
            b'S' => "sleeping",
            b'D' => "uninterruptible sleep",
            b'Z' => "zombie",
            b'T' => "stopped",
            b't' => "tracing stop",
            b'X' | b'x' => "dead",
            b'I' => "idle",
            b'P' => "parked",
            _ => "unknown",
        }
    }
}

/// A command line from `/proc/<pid>/cmdline`. Settable by the process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandLine {
    /// The arguments, starting with `argv[0]`.
    pub args: Vec<Vec<u8>>,
    /// Whether the size limit cut the command line short.
    pub truncated: bool,
}

/// The target of `/proc/<pid>/exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executable {
    /// The path, without the kernel's ` (deleted)` marker.
    pub path: Vec<u8>,
    /// Whether the kernel reports the file as deleted. A real file whose name
    /// ends in ` (deleted)` looks the same.
    pub deleted: bool,
}

/// The four IDs in the `Uid:` or `Gid:` line of `/proc/<pid>/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdSet {
    /// Real ID.
    pub real: u32,
    /// Effective ID.
    pub effective: u32,
    /// Saved ID.
    pub saved: u32,
    /// Filesystem ID.
    pub filesystem: u32,
}

/// Fields from `/proc/<pid>/status`. Each is `None` if the kernel omits it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStatus {
    /// User IDs.
    pub uid: Option<IdSet>,
    /// Group IDs.
    pub gid: Option<IdSet>,
    /// Whether `no_new_privs` is set.
    pub no_new_privs: Option<bool>,
    /// The seccomp mode: 0 disabled, 1 strict, 2 filter.
    pub seccomp: Option<u8>,
    /// The effective capability set.
    pub cap_effective: Option<u64>,
}

/// The namespaces a process belongs to, as `type:[inode]` link targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespaces {
    /// PID namespace.
    pub pid: Probe<String>,
    /// Mount namespace.
    pub mnt: Probe<String>,
    /// Network namespace.
    pub net: Probe<String>,
    /// User namespace.
    pub user: Probe<String>,
}

/// What `blate scan` reads for each process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSummary {
    /// Fields from `stat`.
    pub stat: ProcStat,
    /// The command line.
    pub cmdline: Probe<CommandLine>,
    /// The executable.
    pub exe: Probe<Executable>,
    /// Fields from `status`.
    pub status: Probe<ProcStatus>,
}

/// One process in a [`Lineage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    /// The ancestor's PID and start time.
    pub identity: ProcessIdentity,
    /// The ancestor's name.
    pub comm: Vec<u8>,
}

/// Why a lineage walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageEnd {
    /// Reached a process with no visible parent.
    Root,
    /// The parent exited during the walk.
    Gone(u32),
    /// The PID started after its child, so it cannot be the real parent.
    PidReused(Pid),
    /// The kernel refused access to the parent.
    Denied(Pid),
    /// The parent could not be read for another reason.
    Unreadable(Pid),
    /// The walk reached the depth limit.
    DepthLimit,
}

/// The ancestors of a process, nearest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lineage {
    /// The ancestors that were confirmed.
    pub ancestors: Vec<Ancestor>,
    /// Why the walk stopped.
    pub end: LineageEnd,
}

/// What `blate inspect` reads for a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// The fields shared with `scan`.
    pub summary: ProcessSummary,
    /// The cgroup v2 path, or `None` if the process has no v2 entry.
    pub cgroup: Probe<Option<Vec<u8>>>,
    /// Namespace membership.
    pub namespaces: Namespaces,
    /// The number of open socket file descriptors.
    pub sockets: Probe<usize>,
    /// The ancestors.
    pub lineage: Lineage,
}

/// What a cgroup path suggests about how a process is run.
///
/// This is a hint, not a fact: a process with a delegated cgroup subtree can
/// choose its own cgroup names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadHint {
    /// A container, with the runtime its naming convention suggests.
    Container(&'static str),
    /// A systemd service unit.
    SystemdService(String),
    /// A systemd login session.
    LoginSession(String),
}

/// Derives a [`WorkloadHint`] from a cgroup v2 path.
pub fn workload_hint(cgroup_path: &[u8]) -> Option<WorkloadHint> {
    let text = String::from_utf8_lossy(cgroup_path);
    let components: Vec<&str> = text.split('/').filter(|c| !c.is_empty()).collect();

    let mut previous = "";
    for component in &components {
        let runtime = if component.contains("kubepods") {
            Some("kubernetes")
        } else if component.starts_with("docker-") && component.ends_with(".scope")
            || previous == "docker"
        {
            Some("docker")
        } else if component.starts_with("libpod-") && component.ends_with(".scope") {
            Some("podman")
        } else if component.starts_with("cri-containerd-") && component.ends_with(".scope") {
            Some("containerd")
        } else if component.starts_with("crio-") && component.ends_with(".scope") {
            Some("cri-o")
        } else {
            None
        };
        if let Some(runtime) = runtime {
            return Some(WorkloadHint::Container(runtime));
        }
        previous = component;
    }

    let last = components.last()?;
    if last.ends_with(".service") {
        Some(WorkloadHint::SystemdService((*last).to_owned()))
    } else if last.starts_with("session-") && last.ends_with(".scope") {
        Some(WorkloadHint::LoginSession((*last).to_owned()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_parsing_is_strict() {
        assert_eq!(Pid::parse("42").map(Pid::get), Some(42));
        for bad in ["", "0", "+1", "-1", " 1", "1 ", "0x10", "abc", "2147483648"] {
            assert_eq!(Pid::parse(bad), None, "{bad:?} should be rejected");
        }
    }

    #[test]
    fn probe_separates_denied_from_missing() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        let missing = io::Error::from(io::ErrorKind::NotFound);
        let exited = io::Error::from_raw_os_error(ESRCH);
        let other = io::Error::other("boom");

        assert_eq!(Probe::<u8>::from_io_error(&denied), Probe::Denied);
        assert_eq!(Probe::<u8>::from_io_error(&missing), Probe::Missing);
        assert_eq!(Probe::<u8>::from_io_error(&exited), Probe::Missing);
        assert!(matches!(
            Probe::<u8>::from_io_error(&other),
            Probe::Failed(_)
        ));
    }

    #[test]
    fn workload_hints_follow_cgroup_naming() {
        let cases: [(&[u8], Option<WorkloadHint>); 8] = [
            (
                b"/system.slice/docker-abc123.scope",
                Some(WorkloadHint::Container("docker")),
            ),
            (b"/docker/abc123", Some(WorkloadHint::Container("docker"))),
            (
                b"/machine.slice/libpod-abc.scope",
                Some(WorkloadHint::Container("podman")),
            ),
            (
                b"/kubepods.slice/kubepods-burstable.slice/x",
                Some(WorkloadHint::Container("kubernetes")),
            ),
            (
                b"/system.slice/agent.service",
                Some(WorkloadHint::SystemdService("agent.service".to_owned())),
            ),
            (
                b"/user.slice/user-1000.slice/session-4.scope",
                Some(WorkloadHint::LoginSession("session-4.scope".to_owned())),
            ),
            (b"/", None),
            (b"/some/custom/group", None),
        ];
        for (path, expected) in cases {
            assert_eq!(
                workload_hint(path),
                expected,
                "{}",
                String::from_utf8_lossy(path)
            );
        }
    }
}
