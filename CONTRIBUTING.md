# Contributing to Blate

Thanks for your interest. Blate is at an early stage, so small, focused changes
are the easiest to review. For anything larger than a small fix, please open an
issue first so the approach can be agreed before you write the code.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

- [rustup](https://rustup.rs/). `rust-toolchain.toml` selects the Rust version
  and installs it automatically.
- Linux, or Docker on another operating system, to run the live procfs tests.

## Local setup

```bash
git clone <repository-url>
cd blate
cargo build
```

On macOS and other non-Linux systems, the project builds and the fixture tests
run, but `scan` and `inspect` exit with an error and the live tests are skipped.
Run the full suite in a Linux container:

```bash
docker run --rm -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/tmp/target \
  rust:1.93.1 cargo test --locked --all-targets --all-features
```

## Quality checks

Run these before opening a pull request. CI runs the same checks.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --all-targets
```

## Branches

`main` is the only long-lived branch. Work on a short-lived branch named for
the kind of change:

| Prefix | Use |
| --- | --- |
| `feat/<description>` | New features |
| `fix/<description>` | Bug fixes |
| `docs/<description>` | Documentation |
| `refactor/<description>` | Internal restructuring |
| `test/<description>` | Test improvements |
| `chore/<description>` | Maintenance |

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/), with one
logical change per commit:

```text
feat(cli): add process inspection command
fix(procfs): handle processes that exit during a read
docs(readme): clarify Linux requirements
```

Do not force-push shared branches or rewrite published history. Never commit
secrets, local environment files, or build output.

## Pull requests

1. Create or reference an issue.
2. Make the smallest meaningful change on a focused branch.
3. Add or update tests, and update any documentation the change affects.
4. Run the quality checks.
5. Open a pull request and fill in the template.
6. Address review feedback.

Pull requests are squash merged after approval, so the title must be a valid
Conventional Commit.

### Definition of done

- The change meets its acceptance criteria, and tests cover the relevant
  behavior, including failure and race cases.
- Formatting, linting, tests, and the build all pass.
- Documentation describes actual behavior, and limitations are written down.
- Security implications have been considered.
- The diff is focused and reviewable.

### What reviewers look for

- **Races:** a process can exit, and its PID can be reused, between any two
  operations.
- **Untrusted input:** process names, command lines, paths, and cgroup names are
  attacker-controlled. They must go through `src/sanitize.rs` before printing.
- **Honest output:** "denied", "missing", and "no match" are different results
  and must not be merged into one. Do not report success without checking it.

## Engineering rules

- **No `unsafe`.** The crate forbids it. A change to that rule needs its own
  issue explaining why it is necessary and what the safety invariants are.
- **Dependencies need a reason.** Blate currently has no runtime dependencies.
  Justify any addition in the pull request, including its transitive
  dependencies, and add `cargo audit` and `cargo deny` to CI with the first one.
- **Read-only until containment is designed.** Do not add anything that changes
  host state without the design described in
  [the architecture document](docs/ARCHITECTURE.md#containment-not-implemented).
- **Keep it simple.** No plugin systems, daemons, or extra crates until a real
  need justifies them.

## Reporting bugs and proposing features

Use the issue templates. **Do not report security vulnerabilities in public
issues;** follow [SECURITY.md](SECURITY.md) instead.

## License

Unless you state otherwise, any contribution you intentionally submit for
inclusion in Blate, as defined in the Apache-2.0 license, is dual licensed as
MIT OR Apache-2.0, without any additional terms or conditions.
