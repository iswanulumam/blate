# Architecture

This document separates what exists from what is planned. Only `scan`,
`inspect`, and the modules below are implemented.

## Structure

Blate is one crate with a thin binary on top of a library. The library exists so
that integration tests can call it directly. A multi-crate workspace would add
overhead without a benefit at this size.

| Module | Responsibility |
| --- | --- |
| `cli` | Argument parsing, dispatch, and exit codes |
| `process` | Data types, independent of the data source |
| `procfs` | The only module that reads `/proc` |
| `classify` | Compares processes against agent signatures |
| `scan` | Reads and classifies every process, and counts what it could not read |
| `sanitize` | Escapes untrusted text and redacts likely secrets |
| `render` | Formats results for the terminal |
| `error` | Failures that stop a whole operation |

Data flows in one direction:

```text
/proc -> procfs -> process types -> classify / scan -> render + sanitize -> terminal
```

## Key decisions

### No runtime dependencies

A security tool that may eventually run as root should have a small supply
chain. The command-line grammar is simple enough for slice patterns, so `clap`
would add code without solving a real problem here. JSON output is the most
likely reason to revisit this.

The trade-off is hand-written help text and no shell completions.

### No `unsafe`, so no direct system calls

`unsafe_code` is forbidden. As a result, Blate has no `libc` calls, which leads
to some visible limits:

- Start times are shown as raw clock ticks since boot, because converting them
  needs `sysconf(_SC_CLK_TCK)`.
- Files are reopened by path instead of through a held `/proc/<pid>` directory
  descriptor. The start-time check below covers the resulting race for reads.
- Blate cannot confirm through `statfs` that `/proc` really is procfs.

Containment will probably need to change this rule, and that change should be
made deliberately. Process-directed signals (`pidfd`) cannot be sent safely
without a system call.

### The procfs root is a parameter

`ProcFs::at(path)` reads any directory tree. Tests use it to build states that
are hard to produce on a live system, such as PID reuse and malformed files. The
same tests run on macOS. No trait or mock layer is needed, and the production
binary has no way to change the path.

### Processes are identified by PID and start time

PIDs are reused, so a PID alone does not identify a process. `summary` and
`inspect` read the start time before and after collecting their fields, and
discard the result if it changed or the process vanished. Lineage rejects any
parent that started after its child.

### Process text stays as bytes until display

Linux process names, arguments, and paths are arbitrary bytes that the observed
process controls. They stay as `Vec<u8>` and become text only through
`sanitize`, so output cannot contain terminal escape sequences or Unicode
direction controls.

`/proc/<pid>/stat` is parsed from the *last* `)`, because a process can put `)`
in its own name to try to forge later fields.

### "Unknown" is a result

`Probe<T>` separates *available*, *denied*, *missing*, and *failed*. A scan also
reports what it could not read. A security tool that treats "not allowed to
look" as "nothing there" gives false assurance.

### Classification records evidence and has no score

Linux has no concept of an AI agent. A classification lists which observations
matched a signature, and where each came from, with no numeric confidence.
Blate has no data to calibrate such a number, and it would imply more certainty
than exists.

Only the path of `/proc/<pid>/exe` comes from the kernel, and even then its
filename can be chosen by whoever created the file. `argv` and `comm` are set by
the process itself. Environment variables are deliberately not read, because
they often contain credentials.

## Planned capabilities (not implemented)

### Containment (not implemented)

Terminating one PID is not containment. A design must account for:

- **Supervisors:** systemd or a container runtime can restart what was killed.
- **Descendants:** children can outlive their parent. Cgroup v2 `cgroup.freeze`
  and `cgroup.kill` act on a whole subtree and look like the right primitive.
- **Races:** a PID can be reused between decision and action. `pidfd` addresses
  this for signals.
- **Privilege boundaries:** Blate may not have authority over the target, and
  moving a process between cgroups has its own delegation rules.
- **Authorization:** an operator must be able to see what will happen before it
  happens, and every action must be audited.

The first containment feature must not merge until it has a design for each of
these, and has verification and audit logging (described below).

### Verification (not implemented)

After an action, Blate should re-observe the host and report what actually
changed, including partial failure. For example: frozen, but one descendant
escaped to another cgroup, or killed, but a supervisor restarted it.

### Audit (not implemented)

Security-relevant actions should produce a structured record of who did what, to
which process identity, with what result. It must apply the same redaction rules
as terminal output.

## Differentiation, and what still needs validating

`ps`, `kill`, `systemctl`, and `docker` each see one layer. Blate's intended value
is a single view across those layers, with an act-then-verify loop:

1. Identify a workload by evidence, and show that evidence.
2. Work out the real containment boundary (cgroup, unit, or container), not just
   a PID.
3. Act on that boundary.
4. Verify the result and report partial failure honestly.
5. Leave an audit record.

Today, only part of step 1 exists, which `ps` and `grep` can roughly approximate.
These assumptions are still unproven:

- Evidence from process metadata may not identify real agents reliably enough to
  be useful, especially agents launched through wrappers or as libraries inside a
  general-purpose interpreter.
- The signature table has not been checked against every install method for each
  agent. Native binaries, wrapper scripts, and package managers may look different.
- Cgroup v2 freeze and kill may not be practical without systemd or container
  runtime cooperation, particularly on hosts with cgroup delegation.
- Operators may prefer an existing tool (for example Falco or Tetragon for
  detection, or a sandbox for confinement) if Blate cannot show a clear advantage.
