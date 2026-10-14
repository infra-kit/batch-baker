//! Public types for embedding batch-baker.
//!
//! [`Baker::run`](crate::Baker::run) is the full pipeline. The stepwise methods
//! on [`Baker`](crate::Baker) are the same steps, and each one closes its SSH
//! session before returning.

use std::path::PathBuf;
use std::time::SystemTime;

use tokio_util::sync::CancellationToken;

use crate::target::Target;

/// What one invocation should do. Omitted machine fields are filled from the provider.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub target: Target,
    pub local_dir: PathBuf,
    pub remote_command: Option<String>,
    pub region: Option<String>,
    pub size: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    pub destroy: bool,
    pub ttl: Option<std::time::Duration>,
    pub excludes: Option<PathBuf>,
    pub ssh: SshMode,
    pub reuse: bool,
    pub token: String,
    pub cancel: CancellationToken,
    /// Directory that receives `./<target>/` artifacts. The CLI uses the process cwd.
    pub workdir: PathBuf,
}

impl RunRequest {
    pub fn new(target: Target, local_dir: PathBuf, token: impl Into<String>) -> Self {
        Self {
            target,
            local_dir,
            remote_command: None,
            region: None,
            size: None,
            image: None,
            username: None,
            destroy: false,
            ttl: None,
            excludes: None,
            ssh: SshMode::Safe,
            reuse: true,
            token: token.into(),
            cancel: CancellationToken::new(),
            workdir: PathBuf::from("."),
        }
    }
}

/// Inputs for [`Baker::provision`](crate::Baker::provision).
#[derive(Debug, Clone)]
pub struct ProvisionSpec {
    pub target: Target,
    pub region: Option<String>,
    pub size: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    pub token: String,
    pub reuse: bool,
    pub insecure: bool,
    pub cancel: CancellationToken,
    pub workdir: PathBuf,
}

/// Inputs for [`Baker::upload`](crate::Baker::upload).
#[derive(Debug, Clone)]
pub struct UploadSpec {
    pub local_dir: PathBuf,
    pub excludes: Option<PathBuf>,
    pub cancel: CancellationToken,
}

/// Host-key policy for new SSH sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshMode {
    /// Require the pinned Ed25519 host key.
    Safe,
    /// Accept any host key. The generated ssh config sets `StrictHostKeyChecking no`.
    Insecure,
}

/// A provisioned instance. The token is the caller's provider credential and is not written to disk.
pub struct InstanceHandle {
    pub provider: String,
    pub instance_id: String,
    pub ip: String,
    pub username: String,
    pub target: String,
    pub client_key_fpr: String,
    pub host_key_fpr: String,
    pub keys_rotated: bool,
    pub insecure: bool,
    pub token: String,
    pub workdir: PathBuf,
}

impl std::fmt::Debug for InstanceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceHandle")
            .field("provider", &self.provider)
            .field("instance_id", &self.instance_id)
            .field("ip", &self.ip)
            .field("username", &self.username)
            .field("target", &self.target)
            .field("client_key_fpr", &self.client_key_fpr)
            .field("host_key_fpr", &self.host_key_fpr)
            .field("keys_rotated", &self.keys_rotated)
            .field("insecure", &self.insecure)
            .field("token", &"<redacted>")
            .field("workdir", &self.workdir)
            .finish()
    }
}

/// Outcome of a finished [`Baker::run`](crate::Baker::run).
///
/// A non-zero remote command is `Ok` with [`remote_exit`](Self::remote_exit) set.
/// Provider and SSH failures are `Err`.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub alias: String,
    pub ip: String,
    pub username: String,
    pub private_key: PathBuf,
    pub ssh_config: PathBuf,
    pub known_hosts: PathBuf,
    pub transfer: TransferStats,
    pub rotation: Option<RotationReport>,
    pub remote_exit: Option<i32>,
    pub ttl_until: Option<SystemTime>,
    pub destroyed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    pub files: u64,
    pub bytes_sent: u64,
    pub bytes_reused: u64,
}

#[derive(Debug, Clone)]
pub struct RotationReport {
    pub client_old: String,
    pub client_new: String,
    pub host_old: String,
    pub host_new: String,
}

#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub path: String,
    pub bytes_sent: u64,
    pub bytes_reused: u64,
    pub bytes_sent_total: u64,
    pub bytes_reused_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    /// UTC timestamp in RFC3339 form.
    pub timestamp: String,
    pub stream: Stream,
    pub text: String,
}

/// Callbacks for phase names, log lines, transfer progress, and the final summary.
///
/// Every method has a default empty body. [`NopEvents`] ignores them all.
pub trait Events: Send + Sync {
    fn on_phase(&self, _name: &str) {}
    fn on_log_line(&self, _line: &LogLine) {}
    fn on_transfer_progress(&self, _progress: &TransferProgress) {}
    fn on_ttl_armed(&self, _deadline: SystemTime) {}
    fn on_summary(&self, _report: &RunReport) {}
}

/// Event sink that discards every callback.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopEvents;

impl Events for NopEvents {}

/// Human-readable end-of-run summary.
pub fn format_summary(report: &RunReport) -> String {
    let mut lines = vec![
        format!("Host: {}", report.alias),
        format!("IP: {}", report.ip),
        format!("User: {}", report.username),
        format!("Private key: {}", report.private_key.display()),
        format!("SSH config: {}", report.ssh_config.display()),
        format!("Known hosts: {}", report.known_hosts.display()),
        format!(
            "Transfer: {} files, {} bytes sent, {} bytes reused",
            report.transfer.files, report.transfer.bytes_sent, report.transfer.bytes_reused
        ),
    ];
    if let Some(rotation) = &report.rotation {
        lines.push(format!(
            "Rotation: client {} -> {}, host {} -> {}",
            rotation.client_old, rotation.client_new, rotation.host_old, rotation.host_new
        ));
    }
    if let Some(until) = report.ttl_until {
        lines.push(format!("TTL armed until: {}", system_time_rfc3339(until)));
    }
    if report.destroyed {
        lines.push("Destroyed: yes".into());
    }
    if let Some(code) = report.remote_exit {
        lines.push(format!("Remote exit: {code}"));
    }
    lines.join("\n")
}

pub(crate) fn system_time_rfc3339(time: SystemTime) -> String {
    let offset = time::OffsetDateTime::from(time);
    offset
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

pub(crate) fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}
