//! Arm `batch-baker-agent ttl` on the guest.
//!
//! The client writes a root-only config over SSH stdin and starts a systemd
//! unit. The process can then exit. The agent deletes this instance at the deadline.

use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};
use crate::provider::ComputeProvider;
use crate::ssh::SshSession;

const UNIT: &str = "\
[Unit]
Description=batch-baker TTL destroy

[Service]
Type=simple
ExecStart=/usr/local/libexec/batch-baker-agent ttl --config /root/.batch-baker/ttl.json
Restart=no

[Install]
WantedBy=multi-user.target
";

pub fn deadline_from(ttl: Duration) -> (SystemTime, String) {
    let until = SystemTime::now() + ttl;
    (until, crate::api::system_time_rfc3339(until))
}

pub async fn arm(
    session: &mut dyn SshSession,
    provider: &dyn ComputeProvider,
    instance_id: &str,
    deadline_rfc3339: &str,
) -> Result<()> {
    let config = provider.guest_ttl_config(instance_id, deadline_rfc3339)?;
    if !config.windows(7).any(|window| window == b"\"token\"") {
        return Err(Error::msg("guest TTL config is missing a token"));
    }
    let prepared = session
        .exec("sudo mkdir -p /root/.batch-baker /etc/systemd/system")
        .await?;
    status_ok("prepare ttl directories", prepared.status, &prepared.stderr)?;
    let written = session
        .exec_stdin(
            "sudo tee /root/.batch-baker/ttl.json > /dev/null && sudo chmod 0600 /root/.batch-baker/ttl.json",
            &config,
        )
        .await?;
    status_ok("write ttl config", written.status, &written.stderr)?;
    let unit = session
        .exec_stdin(
            "sudo tee /etc/systemd/system/batch-baker-ttl.service > /dev/null",
            UNIT.as_bytes(),
        )
        .await?;
    status_ok("write ttl unit", unit.status, &unit.stderr)?;
    let started = session
        .exec("sudo systemctl daemon-reload && sudo systemctl enable batch-baker-ttl.service && sudo systemctl restart batch-baker-ttl.service")
        .await?;
    status_ok("start ttl unit", started.status, &started.stderr)?;
    Ok(())
}

fn status_ok(step: &str, status: i32, stderr: &str) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::msg(format!("{step} exited {status}: {}", stderr.trim())))
    }
}
