use std::path::PathBuf;

/// Failures returned by the public library API.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("target must be kernel-arch-os-provider, got `{0}`")]
    BadTarget(String),

    #[error(
        "provider `{id}` is not built in; add it in crates/baker/src/provider/mod.rs and a guest-delete arm in the agent"
    )]
    ProviderUnavailable { id: String },

    #[error("{provider} does not support arch `{arch}` and os `{os}`")]
    UnsupportedPlatform {
        provider: String,
        arch: String,
        os: String,
    },

    #[error(
        "host key mismatch for {host}: pinned {pinned}, got {got}. Refusing the key; this may be a MITM attack"
    )]
    Mitm {
        host: String,
        pinned: String,
        got: String,
    },

    #[error("cancelled")]
    Cancelled,

    #[error(
        "agent binary is not embedded. Build it with: cargo zigbuild -p batch-baker-agent --release --target x86_64-unknown-linux-musl"
    )]
    AgentMissing,

    #[error(
        "instance {id} for {target} is missing or not active. Repair the state directory or pass --no-reuse"
    )]
    InstanceUnavailable { target: String, id: String },

    #[error("keys for {target} are inconsistent ({detail}). Repair the state directory or pass --no-reuse")]
    InconsistentKeys { target: String, detail: String },

    #[error("{0}")]
    Message(String),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
