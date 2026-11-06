//! The `blate` command-line entry point.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let code = blate::cli::run(
        std::env::args_os().skip(1),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code)
}
