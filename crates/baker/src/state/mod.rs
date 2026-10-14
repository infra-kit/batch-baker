//! JSON state under the OS data directory, guarded by an exclusive file lock.

mod paths;
mod pins;
mod store;

pub use paths::default_state_home;
pub use pins::{openssh_lines, KnownHosts};
pub use store::{instance_key, InstanceRecord, StateStore, TargetRecord};
