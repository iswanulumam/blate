//! Formats results for the terminal.
//!
//! All data that came from a process goes through [`crate::sanitize`] before
//! it is written.

use std::io::{self, Write};

use crate::classify::{Classification, classify};
use crate::process::{
    IdSet, Inspection, LineageEnd, Probe, ProcStat, ProcessSummary, WorkloadHint, workload_hint,
};
use crate::sanitize::{escape, escape_field, format_args_line, redact_args};
use crate::scan::{ScanEntry, ScanReport};

/// Writes a scan as a table followed by its coverage.
pub fn scan_report(out: &mut dyn Write, report: &ScanReport, all: bool) -> io::Result<()> {
    let candidates = report
        .entries
        .iter()
        .filter(|entry| !entry.classifications.is_empty())
        .count();

    let shown: Vec<&ScanEntry> = report
        .entries
        .iter()
        .filter(|entry| all || !entry.classifications.is_empty())
        .collect();
    if !shown.is_empty() {
        writeln!(
            out,
            "{:<8} {:<8} {:<7} {:<16} {:<13} {:<20} EXECUTABLE",
            "PID", "PPID", "UID", "NAME", "AGENT", "EVIDENCE"
        )?;
    }
    for entry in shown {
        scan_row(out, entry)?;
    }
    if !report.entries.is_empty() && candidates == 0 {
        writeln!(out, "No processes matched a known agent signature.")?;
    }

    writeln!(
        out,
        "\nProcesses read: {}. Potential agents: {candidates}.",
        report.entries.len()
    )?;
    let coverage = [
        (report.vanished, "exited during the scan"),
        (report.denied, "could not be read: permission denied"),
        (report.failed, "could not be read: unexpected error"),
        (
            report.exe_denied,
            "had an unreadable executable path; run with more privileges for stronger evidence",
        ),
    ];
    for (count, description) in coverage {
        if count > 0 {
            writeln!(out, "{count} {description}.")?;
        }
    }
    writeln!(
        out,
        "Matches are heuristic: a match is not proof of an agent, and no match is not proof \
         of absence."
    )
}

fn scan_row(out: &mut dyn Write, entry: &ScanEntry) -> io::Result<()> {
    let process = &entry.process;
    let uid = match &process.status {
        Probe::Available(status) => status
            .uid
            .map_or_else(|| "?".to_owned(), |uid| uid.effective.to_string()),
        _ => "?".to_owned(),
    };
    let agents: Vec<&str> = entry.classifications.iter().map(|c| c.agent).collect();
    let mut sources: Vec<String> = entry
        .classifications
        .iter()
        .flat_map(|c| c.evidence.iter().map(|e| e.source.to_string()))
        .collect();
    sources.dedup();

    writeln!(
        out,
        "{:<8} {:<8} {:<7} {:<16} {:<13} {:<20} {}",
        process.stat.identity.pid,
        process.stat.ppid,
        uid,
        escape_field(&process.stat.comm),
        or_dash(&agents.join(",")),
        or_dash(&sources.join(",")),
        executable_text(process),
    )
}

fn or_dash(text: &str) -> &str {
    if text.is_empty() { "-" } else { text }
}

fn executable_text(process: &ProcessSummary) -> String {
    probe_text(&process.exe, |exe| {
        let path = escape(&exe.path);
        if exe.deleted {
            format!("{path} (deleted)")
        } else {
            path
        }
    })
}

fn probe_text<T>(probe: &Probe<T>, describe: impl FnOnce(&T) -> String) -> String {
    match probe {
        Probe::Available(value) => describe(value),
        Probe::Denied => "(permission denied)".to_owned(),
        Probe::Missing => "(not available)".to_owned(),
        Probe::Failed(message) => format!("(read failed: {})", escape(message.as_bytes())),
    }
}

fn row(out: &mut dyn Write, label: &str, value: &str) -> io::Result<()> {
    writeln!(out, "  {label:<16}{value}")
}

/// Writes the full report for one process.
pub fn inspection(out: &mut dyn Write, inspection: &Inspection) -> io::Result<()> {
    let summary = &inspection.summary;
    let stat = &summary.stat;

    writeln!(out, "Process {}", stat.identity.pid)?;
    row(out, "name", &escape(&stat.comm))?;
    row(
        out,
        "state",
        &format!(
            "{} ({})",
            char::from(stat.state).escape_default(),
            stat.state_description()
        ),
    )?;
    row(out, "parent", &stat.ppid.to_string())?;
    row(
        out,
        "start time",
        &format!("{} ticks after boot", stat.identity.start_ticks),
    )?;
    row(out, "threads", &stat.threads.to_string())?;
    if stat.is_kernel_thread() {
        row(out, "kind", "kernel thread")?;
    }
    row(out, "executable", &executable_text(summary))?;
    row(
        out,
        "command",
        &probe_text(&summary.cmdline, |cmdline| {
            if cmdline.args.is_empty() {
                return "(empty)".to_owned();
            }
            let line = format_args_line(&redact_args(&cmdline.args));
            if cmdline.truncated {
                format!("{line} (truncated)")
            } else {
                line
            }
        }),
    )?;

    writeln!(out, "\nPrivileges")?;
    let status = &summary.status;
    row(out, "uid", &probe_text(status, |s| ids_text(s.uid)))?;
    row(out, "gid", &probe_text(status, |s| ids_text(s.gid)))?;
    row(
        out,
        "capabilities",
        &probe_text(status, |s| {
            s.cap_effective
                .map_or_else(unknown, |caps| format!("{caps:016x} (effective)"))
        }),
    )?;
    row(
        out,
        "no_new_privs",
        &probe_text(status, |s| {
            s.no_new_privs
                .map_or_else(unknown, |set| if set { "yes" } else { "no" }.to_owned())
        }),
    )?;
    row(
        out,
        "seccomp",
        &probe_text(status, |s| match s.seccomp {
            Some(0) => "disabled".to_owned(),
            Some(1) => "strict".to_owned(),
            Some(2) => "filter".to_owned(),
            Some(other) => format!("unknown mode {other}"),
            None => unknown(),
        }),
    )?;

    writeln!(out, "\nExecution context")?;
    row(
        out,
        "cgroup",
        &probe_text(&inspection.cgroup, |path| {
            path.as_deref()
                .map_or_else(|| "(no cgroup v2 entry)".to_owned(), escape)
        }),
    )?;
    if let Some(hint) = inspection
        .cgroup
        .available()
        .and_then(Option::as_deref)
        .and_then(workload_hint)
    {
        row(out, "workload hint", &workload_text(&hint))?;
    }
    let namespaces = &inspection.namespaces;
    for (label, probe) in [
        ("pid namespace", &namespaces.pid),
        ("mnt namespace", &namespaces.mnt),
        ("net namespace", &namespaces.net),
        ("user namespace", &namespaces.user),
    ] {
        row(
            out,
            label,
            &probe_text(probe, |target| escape(target.as_bytes())),
        )?;
    }
    row(
        out,
        "open sockets",
        &probe_text(&inspection.sockets, ToString::to_string),
    )?;

    lineage(out, inspection)?;
    classification(out, &classify(summary))
}

fn unknown() -> String {
    "(not reported)".to_owned()
}

fn ids_text(ids: Option<IdSet>) -> String {
    ids.map_or_else(unknown, |ids| {
        format!(
            "real={} effective={} saved={} fs={}",
            ids.real, ids.effective, ids.saved, ids.filesystem
        )
    })
}

fn workload_text(hint: &WorkloadHint) -> String {
    match hint {
        WorkloadHint::Container(runtime) => format!("container ({runtime} naming)"),
        WorkloadHint::SystemdService(unit) => {
            format!("systemd service {}", escape(unit.as_bytes()))
        }
        WorkloadHint::LoginSession(scope) => {
            format!("login session {}", escape(scope.as_bytes()))
        }
    }
}

fn lineage(out: &mut dyn Write, inspection: &Inspection) -> io::Result<()> {
    let stat: &ProcStat = &inspection.summary.stat;
    writeln!(out, "\nLineage (this process first)")?;
    writeln!(
        out,
        "  {:<8} {}",
        stat.identity.pid,
        escape_field(&stat.comm)
    )?;
    for ancestor in &inspection.lineage.ancestors {
        writeln!(
            out,
            "  {:<8} {}",
            ancestor.identity.pid,
            escape_field(&ancestor.comm)
        )?;
    }
    match inspection.lineage.end {
        LineageEnd::Root => Ok(()),
        LineageEnd::Gone(pid) => writeln!(out, "  incomplete: parent {pid} has exited"),
        LineageEnd::PidReused(pid) => writeln!(
            out,
            "  incomplete: PID {pid} started after its child, so the PID was reused"
        ),
        LineageEnd::Denied(pid) => {
            writeln!(out, "  incomplete: permission denied reading parent {pid}")
        }
        LineageEnd::Unreadable(pid) => writeln!(out, "  incomplete: cannot read parent {pid}"),
        LineageEnd::DepthLimit => writeln!(out, "  incomplete: depth limit reached"),
    }
}

fn classification(out: &mut dyn Write, classifications: &[Classification]) -> io::Result<()> {
    writeln!(out, "\nClassification")?;
    if classifications.is_empty() {
        return writeln!(
            out,
            "  no known agent signature matched (this does not prove it is not an agent)"
        );
    }
    for classification in classifications {
        writeln!(out, "  potential agent: {}", classification.agent)?;
        for evidence in &classification.evidence {
            writeln!(
                out,
                "    {:<8} matched \"{}\"",
                evidence.source, evidence.marker
            )?;
        }
    }
    Ok(())
}
