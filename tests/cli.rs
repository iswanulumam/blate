//! Runs the real binary. Tests that need a live procfs are Linux-only.

use std::process::{Command, Output};

fn blate(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_blate"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_lists_the_commands() {
    let output = blate(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("scan"));
    assert!(text.contains("inspect <PID>"));
}

#[test]
fn version_matches_the_manifest() {
    let output = blate(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output).trim(),
        format!("blate {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn invalid_usage_exits_2_and_writes_only_to_stderr() {
    for args in [&[][..], &["bogus"], &["inspect"], &["inspect", "abc"]] {
        let output = blate(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(stderr(&output).starts_with("error: "), "{args:?}");
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn other_platforms_fail_clearly() {
    for args in [&["scan"][..], &["inspect", "1"]] {
        let output = blate(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(stderr(&output).contains("requires Linux"), "{args:?}");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Stdio};
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    /// A child process that is killed and reaped when dropped.
    struct Sleeper(Child);

    impl Sleeper {
        fn spawn_as(argv0: &str) -> Self {
            Self(
                Command::new("sleep")
                    .arg0(argv0)
                    .arg("60")
                    .stdin(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        fn pid(&self) -> String {
            self.0.id().to_string()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Retries until `done` holds, since a new child execs asynchronously.
    fn output_until(args: &[&str], done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = stdout(&blate(args));
            if done(&text) || Instant::now() > deadline {
                return text;
            }
            sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn inspect_reports_a_live_process_and_its_parent() {
        let child = Sleeper::spawn_as("sleep");
        let pid = child.pid();

        // The kernel sets the name and the command line at different points
        // of exec, so wait for the one that is set last.
        let text = output_until(&["inspect", &pid], |t| {
            t.contains("command         sleep 60")
        });

        assert!(text.contains(&format!("Process {pid}")), "{text}");
        assert!(text.contains("command         sleep 60"), "{text}");
        assert!(text.contains("name            sleep"), "{text}");
        assert!(text.contains("no known agent signature"), "{text}");
        // Blate is a sibling of the child, so the test harness is the parent.
        let parent = std::process::id().to_string();
        assert!(
            text.lines()
                .any(|line| { line.split_whitespace().next() == Some(parent.as_str()) }),
            "{text}"
        );
    }

    #[test]
    fn inspect_reads_its_own_process_tree_without_failures() {
        let output = blate(&["inspect", &std::process::id().to_string()]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let text = stdout(&output);
        assert!(text.contains("user namespace  "), "{text}");
        for heading in [
            "Privileges",
            "Execution context",
            "Lineage",
            "Classification",
        ] {
            assert!(text.contains(heading), "{text}");
        }
        assert!(!text.contains("read failed"), "{text}");
    }

    #[test]
    fn scan_identifies_a_process_by_argv0_and_lists_it_with_evidence() {
        let child = Sleeper::spawn_as("claude");
        let pid = child.pid();
        let row_for = |text: &str| {
            text.lines()
                .find(|line| line.split_whitespace().next() == Some(pid.as_str()))
                .map(str::to_owned)
        };

        let text = output_until(&["scan"], |t| row_for(t).is_some());

        let row = row_for(&text).unwrap_or_else(|| panic!("no row for {pid}:\n{text}"));
        assert!(row.contains("claude-code"), "{row}");
        assert!(row.contains("argv0"), "{row}");
        assert!(text.contains("Matches are heuristic"), "{text}");
    }

    #[test]
    fn scan_all_lists_more_than_the_matches() {
        let text = stdout(&blate(&["scan", "--all"]));
        let own = std::process::id().to_string();
        assert!(
            text.lines()
                .any(|line| line.split_whitespace().next() == Some(own.as_str())),
            "{text}"
        );
    }

    #[test]
    fn inspecting_a_process_that_does_not_exist_exits_1() {
        let output = blate(&["inspect", "2147483647"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("not found"));
    }

    #[test]
    fn secrets_in_the_command_line_are_not_printed() {
        let secret = "hunter2-do-not-print";
        // `sleep` rejects unknown flags, so use a shell that ignores its
        // positional arguments. The `read` builtin waits on the open stdin
        // pipe, so the shell keeps its command line and leaves no orphan.
        let mut shell = Command::new("sh");
        shell.args(["-c", "read _", "sh", "--token", secret]);
        let child = Sleeper(shell.stdin(Stdio::piped()).spawn().unwrap());
        let pid = child.pid();

        let text = output_until(&["inspect", &pid], |t| t.contains("--token"));

        assert!(text.contains("--token [REDACTED]"), "{text}");
        assert!(!text.contains(secret), "{text}");
    }
}
