# Blate

Host-level protection and containment for autonomous agents.

> **Status: early and read-only.** Blate can discover and inspect processes on
> Linux. It cannot yet contain, stop, or restrict anything, so **it does not
> currently protect a host.** It has not made a release.

## The problem

AI agents increasingly run on ordinary hosts: as plain processes, systemd
services, or containers, often with a user's credentials and the ability to run
commands. Linux has no concept of an "agent", so it is hard to answer basic
questions about a host. What is running? What can it do? How do you stop all of
it, not just one PID, and how do you know it actually stopped?

Blate aims to answer those questions **without requiring agents to be launched
through a particular sandbox**. The intended loop is to discover, inspect,
contain, verify, and audit. Only the first two exist today, in a basic form.

## Who it is for

Linux administrators, security engineers, and developers who run autonomous
agents on machines they are responsible for.

## What works today

| Capability | Status |
| --- | --- |
| Discover: evidence-based matching against known agent signatures | Basic |
| Inspect: identity, privileges, cgroup, namespaces, socket count, lineage | Basic |
| Contain | Not implemented |
| Verify | Not implemented |
| Audit | Not implemented |

## Supported platforms

| Platform | Status |
| --- | --- |
| Linux | Target platform. Tested in Docker on arm64. |
| macOS | Builds for development only. `scan` and `inspect` exit with an error. |
| Others | Not supported. |

## Build

Blate has no releases yet, so build it from source. You need
[rustup](https://rustup.rs/), which installs the Rust version pinned in
`rust-toolchain.toml`.

```bash
cargo build --release
./target/release/blate --help
```

## Usage

### `blate scan`

Lists processes that match a known agent signature, with the evidence for each
match. `--all` lists every process. Arguments are examined but never printed.

In this example, a `sleep` process was started with `argv[0]` set to `claude`.
The output shows why a match is not proof:

```console
$ blate scan
PID      PPID     UID     NAME             AGENT         EVIDENCE             EXECUTABLE
2092     1        0       sleep            claude-code   argv0                /usr/bin/sleep

Processes read: 3. Potential agents: 1.
Matches are heuristic: a match is not proof of an agent, and no match is not proof of absence.
```

### `blate inspect <pid>`

Reports details of one process:

```console
$ blate inspect 2092
Process 2092
  name            sleep
  state           S (sleeping)
  parent          1
  start time      1914305 ticks after boot
  threads         1
  executable      /usr/bin/sleep
  command         claude 300

Privileges
  uid             real=0 effective=0 saved=0 fs=0
  gid             real=0 effective=0 saved=0 fs=0
  capabilities    00000000a80425fb (effective)
  no_new_privs    no
  seccomp         filter

Execution context
  cgroup          /
  pid namespace   pid:[4026534552]
  mnt namespace   mnt:[4026534524]
  net namespace   net:[4026534554]
  user namespace  user:[4026531837]
  open sockets    0

Lineage (this process first)
  2092     sleep
  1        bash

Classification
  potential agent: claude-code
    argv0 matched "claude"
```

Exit codes: `0` success, `1` the operation failed, `2` invalid usage. A scan that
finds potential agents still exits `0`.

### Permissions

Blate runs without root, but sees less. The executable path, namespaces, and
open sockets of other users' processes then show as `(permission denied)`, and
`scan` reports how many executable paths it could not read.

## Security limitations

- **Classification can be evaded and spoofed.** It matches names that a process
  or its operator can change, and it only knows a small set of agents. No match
  does not mean no agent.
- **Results are snapshots.** Short-lived processes can start and exit between
  scans.
- **Blate trusts `/proc`.** It cannot detect a compromised kernel, and it sees
  only its own PID namespace.
- **`inspect` output can contain secrets.** Redaction of command lines is best
  effort, so treat the output as sensitive.

See [SECURITY.md](SECURITY.md) for the full list of boundaries and how to report a
vulnerability.

## Roadmap

The next goal is to make discovery trustworthy by testing signatures against real
agent installations and attributing processes to whole workloads. Containment
comes after that, once it has a reviewed design for authorization, verification,
and audit. See [docs/ROADMAP.md](docs/ROADMAP.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), which also lists the assumptions
that have not been validated yet.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup,
conventions, and the pull request process. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
