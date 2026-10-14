//! Provider delete used by `batch-baker-agent ttl`.
//!
//! DigitalOcean is the only arm. A new provider adds a match here and a
//! guest payload in the baker provider registry.

use std::thread;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TtlConfig {
    pub provider: String,
    pub instance_id: String,
    /// RFC3339 timestamp.
    pub deadline: String,
    /// API origin, for example `https://api.digitalocean.com`.
    pub api: String,
    pub token: String,
}

#[derive(Debug)]
pub enum DestroyError {
    Unsupported { provider: String },
    Message(String),
}

impl std::fmt::Display for DestroyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { provider } => {
                write!(f, "agent cannot delete provider `{provider}`")
            }
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DestroyError {}

#[derive(Debug, Clone)]
pub struct Retry {
    pub attempts: u32,
    pub delay: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 30,
            delay: Duration::from_secs(10),
        }
    }
}

/// Delete only the instance named in `config`. HTTP 404 is success.
pub fn delete_instance(config: &TtlConfig, retry: Retry) -> Result<(), DestroyError> {
    match config.provider.as_str() {
        "digitalocean" => delete_digitalocean(config, retry),
        other => Err(DestroyError::Unsupported {
            provider: other.to_string(),
        }),
    }
}

fn delete_digitalocean(config: &TtlConfig, retry: Retry) -> Result<(), DestroyError> {
    let base = config.api.trim_end_matches('/');
    let url = format!("{base}/v2/droplets/{}", config.instance_id);
    let mut last = String::from("no attempt");
    let attempts = retry.attempts.max(1);
    for attempt in 1..=attempts {
        match ureq::delete(&url)
            .set("Authorization", &format!("Bearer {}", config.token))
            .set("User-Agent", "batch-baker-agent")
            .call()
        {
            Ok(_) => return Ok(()),
            Err(ureq::Error::Status(404, _)) => return Ok(()),
            Err(ureq::Error::Status(code, response)) => {
                let body = response.into_string().unwrap_or_default();
                let body = trim_body(&body);
                last = format!("HTTP {code}: {body}");
            }
            Err(err) => {
                last = err.to_string();
            }
        }
        if attempt < attempts {
            thread::sleep(retry.delay);
        }
    }
    Err(DestroyError::Message(last))
}

fn trim_body(body: &str) -> String {
    let mut trimmed = body.trim().to_string();
    if trimmed.len() > 2048 {
        trimmed.truncate(2048);
    }
    trimmed
}

pub fn deadline_reached(deadline: &str) -> Result<bool, DestroyError> {
    let when = time::OffsetDateTime::parse(deadline, &time::format_description::well_known::Rfc3339)
        .map_err(|err| DestroyError::Message(format!("bad deadline: {err}")))?;
    Ok(time::OffsetDateTime::now_utc() >= when)
}

/// Sleep until `deadline`. A timestamp in the past returns immediately.
pub fn wait_until(deadline: &str) -> Result<(), DestroyError> {
    let when = time::OffsetDateTime::parse(deadline, &time::format_description::well_known::Rfc3339)
        .map_err(|err| DestroyError::Message(format!("bad deadline: {err}")))?;
    loop {
        let now = time::OffsetDateTime::now_utc();
        if now >= when {
            return Ok(());
        }
        let remaining = std::time::Duration::try_from((when - now).unsigned_abs())
            .unwrap_or(Duration::from_secs(30));
        thread::sleep(remaining.min(Duration::from_secs(30)));
    }
}

/// Power the guest off after a successful delete. Not called when delete fails.
#[cfg(target_os = "linux")]
pub fn poweroff() {
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn poweroff() {}
