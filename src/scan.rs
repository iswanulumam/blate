//! Scans every visible process and classifies each one.

use crate::classify::{Classification, classify};
use crate::error::Error;
use crate::process::{Probe, ProcessSummary};
use crate::procfs::ProcFs;

/// One process that was read successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    /// What was read.
    pub process: ProcessSummary,
    /// The signatures it matched, if any.
    pub classifications: Vec<Classification>,
}

/// The result of a scan, including what it could not see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// The processes that were read, in ascending PID order.
    pub entries: Vec<ScanEntry>,
    /// Processes that exited or were replaced during the scan.
    pub vanished: usize,
    /// Processes the kernel refused to let Blate read at all.
    pub denied: usize,
    /// Processes that could not be read for another reason.
    pub failed: usize,
    /// User processes whose executable path was refused, which removes the
    /// only evidence that does not come from the process itself.
    pub exe_denied: usize,
}

/// Scans `procfs`. Fails only if the process list itself cannot be read.
pub fn scan(procfs: &ProcFs) -> Result<ScanReport, Error> {
    let mut report = ScanReport::default();
    for pid in procfs.list_pids()? {
        match procfs.summary(pid) {
            Ok(process) => {
                if matches!(process.exe, Probe::Denied) {
                    report.exe_denied += 1;
                }
                report.entries.push(ScanEntry {
                    classifications: classify(&process),
                    process,
                });
            }
            Err(Error::NotFound(_) | Error::ProcessChanged(_)) => report.vanished += 1,
            Err(Error::PermissionDenied(_)) => report.denied += 1,
            Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}
