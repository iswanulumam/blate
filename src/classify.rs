//! Evidence-based identification of potential agent processes.
//!
//! Linux has no concept of an AI agent, so nothing here can prove that a
//! process is one, and a process with no match may still be one. A
//! classification only records which observations matched a known signature.

use std::fmt;

use crate::process::ProcessSummary;

/// What identifies one agent product.
struct Signature {
    agent: &'static str,
    /// Exact file names, compared after removing a script extension.
    names: &'static [&'static str],
    /// Exact path components, such as an install directory.
    path_components: &'static [&'static str],
    /// Exact module names for `python -m`.
    modules: &'static [&'static str],
}

/// A starter set of common agent CLIs, not a complete list.
const SIGNATURES: &[Signature] = &[
    Signature {
        agent: "claude-code",
        names: &["claude"],
        path_components: &["claude-code"],
        modules: &[],
    },
    Signature {
        agent: "codex",
        names: &["codex"],
        path_components: &["codex-cli"],
        modules: &[],
    },
    Signature {
        agent: "gemini-cli",
        names: &["gemini"],
        path_components: &["gemini-cli"],
        modules: &[],
    },
    Signature {
        agent: "aider",
        names: &["aider"],
        path_components: &["aider-chat"],
        modules: &["aider"],
    },
    Signature {
        agent: "goose",
        names: &["goose"],
        path_components: &[],
        modules: &[],
    },
    Signature {
        agent: "opencode",
        names: &["opencode"],
        path_components: &["opencode-ai"],
        modules: &[],
    },
    Signature {
        agent: "cursor-agent",
        names: &["cursor-agent"],
        path_components: &[],
        modules: &[],
    },
];

/// Where an observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    /// The path of `/proc/<pid>/exe`. The kernel reports the link, but anyone
    /// able to create a file chooses its name.
    Executable,
    /// `argv[0]`, which the process sets.
    Argv0,
    /// The kernel's process name, which the process can set.
    ProcessName,
    /// The script given to an interpreter, read from the command line.
    Script,
    /// The module given to `python -m`, read from the command line.
    Module,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Executable => "exe",
            Self::Argv0 => "argv0",
            Self::ProcessName => "comm",
            Self::Script => "script",
            Self::Module => "module",
        })
    }
}

/// One observation that matched a signature.
///
/// The marker comes from Blate's signature table, so printing it cannot
/// disclose anything from the process's command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    /// Where the observation came from.
    pub source: EvidenceSource,
    /// The signature value that matched.
    pub marker: &'static str,
}

/// A process that matched a signature, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The signature's agent name.
    pub agent: &'static str,
    /// The matching observations.
    pub evidence: Vec<Evidence>,
}

/// What an interpreter was asked to run.
enum InterpreterTarget<'a> {
    Script(&'a [u8]),
    Module(&'a [u8]),
}

/// Compares a process against every signature.
pub fn classify(process: &ProcessSummary) -> Vec<Classification> {
    if process.stat.is_kernel_thread() {
        return Vec::new();
    }
    let args = process
        .cmdline
        .available()
        .map_or(&[][..], |cmdline| &cmdline.args);
    let exe = process.exe.available().map(|exe| exe.path.as_slice());
    let argv0 = args.first().map(Vec::as_slice);
    let target = interpreter_target(args);

    SIGNATURES
        .iter()
        .filter_map(|signature| {
            let mut evidence = Vec::new();
            let mut record = |source, marker: Option<&'static str>| {
                if let Some(marker) = marker {
                    evidence.push(Evidence { source, marker });
                }
            };
            record(
                EvidenceSource::Executable,
                exe.and_then(|path| match_path(signature, path)),
            );
            record(
                EvidenceSource::Argv0,
                argv0.and_then(|path| match_path(signature, path)),
            );
            record(
                EvidenceSource::ProcessName,
                signature
                    .names
                    .iter()
                    .copied()
                    .find(|name| name.as_bytes() == process.stat.comm),
            );
            match target {
                Some(InterpreterTarget::Script(script)) => {
                    record(EvidenceSource::Script, match_path(signature, script));
                }
                Some(InterpreterTarget::Module(module)) => record(
                    EvidenceSource::Module,
                    signature
                        .modules
                        .iter()
                        .copied()
                        .find(|name| name.as_bytes() == module),
                ),
                None => {}
            }
            (!evidence.is_empty()).then_some(Classification {
                agent: signature.agent,
                evidence,
            })
        })
        .collect()
}

fn match_path(signature: &Signature, path: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(path);
    let file_name = strip_script_extension(text.rsplit('/').next().unwrap_or(&text));
    signature
        .names
        .iter()
        .copied()
        .find(|name| *name == file_name)
        .or_else(|| {
            signature
                .path_components
                .iter()
                .copied()
                .find(|marker| text.split('/').any(|component| component == *marker))
        })
}

fn strip_script_extension(file_name: &str) -> &str {
    [".js", ".mjs", ".cjs", ".py"]
        .iter()
        .find_map(|extension| file_name.strip_suffix(extension))
        .unwrap_or(file_name)
}

/// Finds the script or module when `args` starts with a known interpreter.
///
/// Arguments are not parsed fully. A flag that takes a separate value, such as
/// `node --require x cli.js`, makes this read the value as the script.
fn interpreter_target(args: &[Vec<u8>]) -> Option<InterpreterTarget<'_>> {
    let (argv0, rest) = args.split_first()?;
    let text = String::from_utf8_lossy(argv0);
    let interpreter = text.rsplit('/').next().unwrap_or(&text);
    let is_python = interpreter.starts_with("python") || interpreter.starts_with("pypy");
    let has_run_subcommand = matches!(interpreter, "bun" | "deno");
    if !is_python && !has_run_subcommand && !matches!(interpreter, "node" | "nodejs") {
        return None;
    }

    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.as_slice() {
            b"-m" if is_python => return rest.next().map(|m| InterpreterTarget::Module(m)),
            // Inline code has no script to examine.
            b"-c" if is_python => return None,
            b"-e" | b"--eval" | b"-p" | b"--print" if !is_python => return None,
            b"run" if has_run_subcommand => {}
            flag if flag.starts_with(b"-") => {}
            script => return Some(InterpreterTarget::Script(script)),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{CommandLine, Executable, Pid, Probe, ProcStat, ProcessIdentity};

    fn process(comm: &str, exe: Option<&str>, args: &[&str]) -> ProcessSummary {
        ProcessSummary {
            stat: ProcStat {
                identity: ProcessIdentity {
                    pid: Pid::new(10).unwrap(),
                    start_ticks: 1,
                },
                comm: comm.as_bytes().to_vec(),
                state: b'S',
                ppid: 1,
                flags: 0,
                threads: 1,
            },
            cmdline: Probe::Available(CommandLine {
                args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
                truncated: false,
            }),
            exe: exe.map_or(Probe::Denied, |path| {
                Probe::Available(Executable {
                    path: path.as_bytes().to_vec(),
                    deleted: false,
                })
            }),
            status: Probe::Missing,
        }
    }

    fn sources(process: &ProcessSummary, agent: &str) -> Vec<EvidenceSource> {
        classify(process)
            .iter()
            .find(|c| c.agent == agent)
            .map(|c| c.evidence.iter().map(|e| e.source).collect())
            .unwrap_or_default()
    }

    #[test]
    fn matches_a_native_binary_on_every_source() {
        let p = process("claude", Some("/usr/local/bin/claude"), &["claude", "-p"]);
        assert_eq!(
            sources(&p, "claude-code"),
            [
                EvidenceSource::Executable,
                EvidenceSource::Argv0,
                EvidenceSource::ProcessName
            ]
        );
    }

    #[test]
    fn matches_a_script_run_by_an_interpreter() {
        let p = process(
            "node",
            Some("/usr/bin/node"),
            &[
                "node",
                "--no-warnings",
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            ],
        );
        assert_eq!(sources(&p, "claude-code"), [EvidenceSource::Script]);
    }

    #[test]
    fn matches_a_python_module() {
        let p = process(
            "python3",
            Some("/usr/bin/python3.12"),
            &["/usr/bin/python3", "-m", "aider"],
        );
        assert_eq!(sources(&p, "aider"), [EvidenceSource::Module]);
    }

    #[test]
    fn matches_a_bun_run_script() {
        let p = process(
            "bun",
            None,
            &["bun", "run", "/opt/opencode-ai/dist/index.js"],
        );
        assert_eq!(sources(&p, "opencode"), [EvidenceSource::Script]);
    }

    #[test]
    fn still_works_when_the_executable_is_unreadable() {
        let p = process("codex", None, &["codex"]);
        assert_eq!(
            sources(&p, "codex"),
            [EvidenceSource::Argv0, EvidenceSource::ProcessName]
        );
    }

    #[test]
    fn does_not_match_on_ordinary_arguments() {
        let cases = [
            process("vim", Some("/usr/bin/vim"), &["vim", "/home/me/claude.py"]),
            process("grep", Some("/usr/bin/grep"), &["grep", "claude", "notes"]),
            process("node", Some("/usr/bin/node"), &["node", "-e", "claude.js"]),
            process("python3", None, &["python3", "-c", "aider"]),
            process("claudette", Some("/bin/claudette"), &["claudette"]),
        ];
        for case in &cases {
            assert_eq!(classify(case), [], "{case:?}");
        }
    }

    #[test]
    fn kernel_threads_are_never_candidates() {
        let mut p = process("claude", None, &[]);
        p.stat.flags = 0x0020_0000;
        assert_eq!(classify(&p), []);
    }
}
