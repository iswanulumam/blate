//! Blate: host-level protection and containment for autonomous agents.
//!
//! The current release is read-only. It discovers and inspects processes
//! through Linux procfs and never changes the state of the host. See
//! `docs/ARCHITECTURE.md` for the design and its limits.

pub mod error;
pub mod process;
pub mod procfs;
pub mod sanitize;
