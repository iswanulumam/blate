//! Errors that stop a whole operation.
//!
//! A single unreadable field is not an error: see [`crate::process::Probe`].

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::process::Pid;

/// A failure that prevents Blate from producing a result.
#[derive(Debug)]
pub enum Error {
    /// The host is not Linux, so there is no procfs to read.
    UnsupportedPlatform,
    /// The procfs root could not be read.
    ProcUnavailable {
        /// The path that failed.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// No visible process has this PID.
    NotFound(Pid),
    /// The PID started naming a different process while it was being read.
    ProcessChanged(Pid),
    /// The kernel refused access to the process.
    PermissionDenied(Pid),
    /// A procfs file did not have the documented format.
    Malformed {
        /// The file that failed to parse.
        path: PathBuf,
        /// Why it failed.
        reason: &'static str,
    },
    /// Any other I/O failure while reading a process.
    Io {
        /// The file that failed.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(
                f,
                "process discovery requires Linux procfs; this platform is {}",
                std::env::consts::OS
            ),
            Self::ProcUnavailable { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::NotFound(pid) => write!(
                f,
                "process {pid} not found: it may have exited, belong to another PID namespace, \
                 or be hidden by the /proc hidepid mount option"
            ),
            Self::ProcessChanged(pid) => write!(
                f,
                "process {pid} exited or was replaced while being read; results were discarded"
            ),
            Self::PermissionDenied(pid) => write!(f, "permission denied reading process {pid}"),
            Self::Malformed { path, reason } => {
                write!(f, "unexpected format in {}: {reason}", path.display())
            }
            Self::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProcUnavailable { source, .. } | Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
