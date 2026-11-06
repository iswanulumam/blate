# Security Policy

## Supported versions

Blate has not made a release. Only the latest commit on `main` is supported.

## Reporting a vulnerability

**Do not report vulnerabilities in public issues.**

Report them through GitHub's private vulnerability reporting, using **Report a
vulnerability** on this repository's **Security** tab.

> **Maintainer note, to resolve before this repository goes public:** private
> reporting has not been enabled, because the repository is not hosted yet.
> Enable it as described in
> [docs/REPOSITORY_SETTINGS.md](docs/REPOSITORY_SETTINGS.md), then delete this
> note. If the option is missing, open a public issue that asks for a private
> contact and contains no details of the vulnerability.

Please include the affected commit, the steps to reproduce, the impact, and the
privileges an attacker would need. No response times are promised yet, because
the project does not have an established maintainer team.

## What Blate does today

Blate is **read-only**. It does not stop, contain, or restrict anything, so
**it does not currently protect a host**. Do not rely on it as a security
control.

## Security boundaries

Blate defends against these:

- **Hostile process data reaching the terminal.** Names, command lines, paths,
  and cgroup names are escaped, so they cannot send terminal control sequences
  or Unicode tricks to the operator.
- **Forged `/proc/<pid>/stat` fields.** A process name containing `)` cannot
  shift the fields after it.
- **PID reuse during a read.** Start times are compared before and after
  reading, and lineage rejects a parent that started after its child.
- **Oversized command lines.** Reads are capped, so a process cannot make Blate
  allocate without limit.
- **Memory-safety bugs in Blate's own code.** `unsafe` is forbidden in the crate.

Blate does **not** defend against these:

- **Evasion of classification.** Matching uses names that an agent or its
  operator can change. Anyone can rename a binary, overwrite `argv`, or use an
  unknown agent. "No match" never means "no agent".
- **False attribution.** A process can imitate an agent's name.
- **A compromised host or kernel.** Blate trusts `/proc`. Root, a kernel rootkit,
  or a bind mount over `/proc` can make it report anything.
- **Processes it cannot see.** Blate sees only its own PID namespace, and the
  `hidepid` mount option can hide processes from it.
- **Changes after the read.** Every result is a snapshot. Short-lived processes
  can start and exit between scans.

## Known limitations

- **Output can contain secrets.** `inspect` prints command lines. Redaction is
  best effort and cannot recognize every secret, such as `-p hunter2` or a
  password inside a prompt. Treat the output as sensitive. `scan` does not print
  arguments.
- **Unprivileged runs see less.** Without privileges, executable paths, namespace
  links, and file descriptors of other users' processes are unavailable. Blate
  reports these as denied.
- **Workload hints can be spoofed.** Cgroup names suggest how a process is run,
  but a process with a delegated cgroup subtree can choose those names.
