# Roadmap

This is a statement of intent, not a commitment, and the order may change as
assumptions are tested. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Done

- `blate scan`: evidence-based discovery that reports its own coverage.
- `blate inspect <pid>`: identity, privileges, cgroup, namespaces, socket count,
  lineage, and classification.

## Next: make discovery trustworthy

- Test the signature table against real installations of each agent, and record
  which install methods were checked.
- Attribute processes to a workload: group them by cgroup, systemd unit, and
  container, and identify descendants of a known agent.
- Report network endpoints as well as socket counts, by joining
  `/proc/<pid>/fd` with `/proc/<pid>/net/tcp`.
- Add machine-readable output, deciding whether it justifies a dependency.
- Show wall-clock start times.

## Later: containment design

- Write and review a design for authorization, verification, and audit before any
  code changes host state.
- Prototype freezing a cgroup v2 subtree, with verification and dry-run behavior.
- Decide how to handle the `unsafe` rule for `pidfd` and other system calls.

## Later: broader reach

- Systemd and container runtime integration.
- Network isolation.
- A background daemon, only if continuous monitoring proves that one-shot commands
  are not enough.

## Out of scope

A web dashboard, a distributed control plane, and any required LLM dependency.
