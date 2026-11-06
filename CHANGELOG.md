# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `blate scan`, which lists processes that match known agent signatures and
  reports the evidence and what the scan could not read.
- `blate inspect <pid>`, which reports process identity, privileges, cgroup,
  namespaces, socket count, lineage, and classification.
- Escaping of process-controlled text, and best-effort redaction of secrets in
  command lines.
