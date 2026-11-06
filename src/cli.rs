//! Command-line parsing and dispatch.

use std::ffi::OsString;
use std::io::{self, Write};

use crate::error::Error;
use crate::process::Pid;
use crate::procfs::ProcFs;
use crate::sanitize::escape;
use crate::{render, scan};

const EXIT_OK: u8 = 0;
const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE: u8 = 2;

const HELP: &str = "\
Host-level protection and containment for autonomous agents.

Blate is read-only in this release: it never changes the state of the host.

Usage: blate <COMMAND>

Commands:
  scan            List processes that match known agent signatures
  inspect <PID>   Report details of one process

Options:
  -h, --help      Print help
  -V, --version   Print version

Exit codes:
  0  Success
  1  The operation failed
  2  Invalid usage
";

const SCAN_HELP: &str = "\
List processes that match known agent signatures.

Matching is heuristic: a match is not proof of an agent, and no match is not
proof of absence. Command-line arguments are examined but never printed.

Usage: blate scan [OPTIONS]

Options:
  -a, --all    List every process, not only those that match
  -h, --help   Print help
";

const INSPECT_HELP: &str = "\
Report details of one process: identity, privileges, execution context,
lineage, and classification.

Likely secrets in the command line are redacted, but this is best effort.
Treat the output as sensitive.

Usage: blate inspect <PID>

Options:
  -h, --help   Print help
";

/// A parsed command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Print the given help text.
    Help(&'static str),
    /// Print the version.
    Version,
    /// Scan all visible processes.
    Scan {
        /// List every process rather than only the matches.
        all: bool,
    },
    /// Report one process.
    Inspect {
        /// The process to report.
        pid: Pid,
    },
}

/// Parses the arguments that follow the program name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let args: Vec<OsString> = args.into_iter().collect();
    let mut text = Vec::with_capacity(args.len());
    for arg in &args {
        text.push(arg.to_str().ok_or("arguments must be valid UTF-8")?);
    }

    match text.as_slice() {
        ["-h" | "--help" | "help"] => Ok(Command::Help(HELP)),
        ["-V" | "--version"] => Ok(Command::Version),
        ["scan"] => Ok(Command::Scan { all: false }),
        ["scan", "-a" | "--all"] => Ok(Command::Scan { all: true }),
        ["scan", "-h" | "--help"] => Ok(Command::Help(SCAN_HELP)),
        ["inspect", "-h" | "--help"] => Ok(Command::Help(INSPECT_HELP)),
        ["inspect", pid] => Pid::parse(pid)
            .map(|pid| Command::Inspect { pid })
            .ok_or_else(|| format!("invalid PID '{}'", escape(pid.as_bytes()))),
        [] => Err("no command given".to_owned()),
        ["inspect"] => Err("inspect requires a PID".to_owned()),
        [first, ..] => Err(format!(
            "unrecognized arguments starting at '{}'",
            escape(first.as_bytes())
        )),
    }
}

/// Runs the program and returns its exit code.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(message) => {
            let _ = writeln!(err, "error: {message}\n\nRun 'blate --help' for usage.");
            return EXIT_USAGE;
        }
    };
    match execute(command, out) {
        Ok(()) => EXIT_OK,
        Err(Failure::Blate(error)) => {
            let _ = writeln!(err, "error: {error}");
            EXIT_FAILURE
        }
        // The reader went away, as in `blate scan | head`. Nothing is wrong.
        Err(Failure::Output(error)) if error.kind() == io::ErrorKind::BrokenPipe => EXIT_OK,
        Err(Failure::Output(error)) => {
            let _ = writeln!(err, "error: cannot write output: {error}");
            EXIT_FAILURE
        }
    }
}

enum Failure {
    Blate(Error),
    Output(io::Error),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Blate(error)
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Output(error)
    }
}

fn execute(command: Command, out: &mut dyn Write) -> Result<(), Failure> {
    match command {
        Command::Help(text) => out.write_all(text.as_bytes())?,
        Command::Version => writeln!(out, "blate {}", env!("CARGO_PKG_VERSION"))?,
        Command::Scan { all } => {
            let report = scan::scan(&ProcFs::system()?)?;
            render::scan_report(out, &report, all)?;
        }
        Command::Inspect { pid } => {
            let inspection = ProcFs::system()?.inspect(pid)?;
            render::inspection(out, &inspection)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn parses_valid_commands() {
        assert_eq!(parse_strs(&["--help"]), Ok(Command::Help(HELP)));
        assert_eq!(parse_strs(&["-V"]), Ok(Command::Version));
        assert_eq!(parse_strs(&["scan"]), Ok(Command::Scan { all: false }));
        assert_eq!(
            parse_strs(&["scan", "--all"]),
            Ok(Command::Scan { all: true })
        );
        assert_eq!(parse_strs(&["scan", "-h"]), Ok(Command::Help(SCAN_HELP)));
        assert_eq!(
            parse_strs(&["inspect", "7"]),
            Ok(Command::Inspect {
                pid: Pid::new(7).unwrap()
            })
        );
    }

    #[test]
    fn rejects_invalid_usage() {
        let cases: [&[&str]; 6] = [
            &[],
            &["inspect"],
            &["inspect", "abc"],
            &["inspect", "1", "2"],
            &["scan", "--bogus"],
            &["bogus"],
        ];
        for args in cases {
            assert!(parse_strs(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn invalid_arguments_are_escaped_in_errors() {
        let error = parse_strs(&["inspect", "\u{1b}[2J"]).unwrap_err();
        assert!(!error.chars().any(char::is_control), "{error:?}");
    }

    #[test]
    fn a_closed_reader_is_not_a_failure() {
        struct ClosedPipe;
        impl Write for ClosedPipe {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let code = run([OsString::from("--help")], &mut ClosedPipe, &mut Vec::new());
        assert_eq!(code, EXIT_OK);
    }
}
