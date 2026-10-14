//! Provision a batch VM, upload a directory through `batch-baker-agent`, and run a command.
//!
//! [`Baker`] is the library entry point. The `batch-baker` binary is a thin
//! adapter over [`Baker::run`] and is built only with the `cli` feature.
//!
//! Client code does not spawn local processes. The guest agent applies file
//! deltas and, when `--ttl` is set, deletes the instance through the provider API.

mod api;
mod artifacts;
mod cloud_init;
mod command;
mod error;
mod keys;
mod orchestrate;
mod provider;
mod rotate;
mod ssh;
mod state;
mod target;
mod transfer;
mod ttl;

pub use api::{
    format_summary, Events, InstanceHandle, LogLine, NopEvents, ProvisionSpec, RotationReport,
    RunReport, RunRequest, SshMode, Stream, TransferProgress, TransferStats, UploadSpec,
};
pub use error::{Error, Result};
pub use provider::{ComputeProvider, CreateInstance, InstanceInfo, InstanceStatus, ProviderDefaults};
pub use command::shell_join;
pub use target::Target;

/// Format a [`std::time::SystemTime`] as UTC RFC3339.
pub fn format_system_time(time: std::time::SystemTime) -> String {
    api::system_time_rfc3339(time)
}

use std::path::{Path, PathBuf};

use state::default_state_home;

const EMBEDDED_AGENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/batch-baker-agent"));

enum AgentBytes {
    Embedded,
    #[cfg(test)]
    Override(Vec<u8>),
}

/// State directory plus the embedded guest agent.
pub struct Baker {
    state_home: PathBuf,
    agent: AgentBytes,
}

impl Baker {
    /// Open the default state directory, or `state_home` when `Some`.
    pub fn open(state_home: Option<PathBuf>) -> Result<Self> {
        let state_home = match state_home {
            Some(path) => path,
            None => default_state_home()?,
        };
        Ok(Self {
            state_home,
            agent: AgentBytes::Embedded,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_agent_for_test(state_home: PathBuf, agent: &[u8]) -> Self {
        Self {
            state_home,
            agent: AgentBytes::Override(agent.to_vec()),
        }
    }

    pub(crate) fn state_home(&self) -> &Path {
        &self.state_home
    }

    pub(crate) fn agent_bytes(&self) -> &[u8] {
        match &self.agent {
            AgentBytes::Embedded => EMBEDDED_AGENT,
            #[cfg(test)]
            AgentBytes::Override(bytes) => bytes,
        }
    }
}
