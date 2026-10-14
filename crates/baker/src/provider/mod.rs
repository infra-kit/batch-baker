//! Provider registry.
//!
//! Orchestration depends only on [`ComputeProvider`]. DigitalOcean is the only
//! arm that returns `Ok`. Adding a cloud is a new module plus one match arm in
//! [`open_provider`], and a matching guest-delete arm in `batch-baker-agent`.

mod digitalocean;

use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

pub use digitalocean::DigitalOceanProvider;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ProviderDefaults {
    pub region: String,
    pub size: String,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct CreateInstance {
    pub name: String,
    pub region: String,
    pub size: String,
    pub image: String,
    pub user_data: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InstanceRef {
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceStatus {
    Pending,
    Active,
    Destroyed,
    Missing,
}

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub id: String,
    pub provider: String,
    pub status: InstanceStatus,
    pub public_ipv4: Option<String>,
}

#[derive(Clone)]
pub struct ProviderContext {
    pub token: String,
    pub cancel: CancellationToken,
}

#[async_trait]
pub trait ComputeProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn defaults(&self) -> ProviderDefaults;
    fn default_image(&self, os: &str, arch: &str) -> Result<String>;
    fn ensure_supported(&self, os: &str, arch: &str) -> Result<()>;
    /// JSON config the guest agent reads when `--ttl` is set. Includes the credential.
    fn guest_ttl_config(&self, instance_id: &str, deadline_rfc3339: &str) -> Result<Vec<u8>>;
    async fn create_instance(&self, req: CreateInstance) -> Result<InstanceRef>;
    async fn wait_instance_ready(&self, id: &str, timeout: Duration) -> Result<InstanceInfo>;
    async fn destroy_instance(&self, id: &str) -> Result<()>;
    async fn get_instance(&self, id: &str) -> Result<InstanceInfo>;
}

/// Open the backend named by the target's last field.
pub fn open_provider(id: &str, ctx: ProviderContext) -> Result<Box<dyn ComputeProvider>> {
    match id {
        "digitalocean" => Ok(Box::new(DigitalOceanProvider::new(
            "https://api.digitalocean.com".into(),
            ctx.token,
            ctx.cancel,
        )?)),
        other => Err(Error::ProviderUnavailable {
            id: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_and_gcp_are_not_built_in() {
        for id in ["aws", "gcp", "hetzner"] {
            let err = match open_provider(
                id,
                ProviderContext {
                    token: String::new(),
                    cancel: CancellationToken::new(),
                },
            ) {
                Err(err) => err,
                Ok(_) => panic!("{id} should be unavailable"),
            };
            let message = err.to_string();
            assert!(message.contains(id), "{message}");
            assert!(message.contains("provider/mod.rs"), "{message}");
        }
    }
}
