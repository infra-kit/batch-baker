//! First-connection key rotation.
//!
//! Client key C1 is installed and probed before C0 is removed. The host key is
//! rotated only after that. A failure before `sshd` restarts leaves C0 and H0
//! in place. There is no fallback to C0 after it has been removed.

use std::path::Path;

use ssh_key::PublicKey;

use crate::api::RotationReport;
use crate::error::{Error, Result};
use crate::keys::{self, KeyMaterial};
use crate::ssh::{ConnectSpec, SessionFactory, SshSession};
use crate::state::KnownHosts;

pub struct RotationInput<'a> {
    pub state_root: &'a Path,
    pub username: &'a str,
    pub host: &'a str,
    pub host_label: &'a str,
    pub c0: KeyMaterial,
    pub h0_fingerprint: &'a str,
    pub insecure: bool,
}

pub async fn rotate(
    session: &mut dyn SshSession,
    sessions: &dyn SessionFactory,
    input: RotationInput<'_>,
) -> Result<Rotated> {
    let c1 = keys::generate("batch-baker")?;
    keys::store_client(input.state_root, &c1)?;

    let home = format!("/home/{}", input.username);
    let auth = format!("{home}/.ssh/authorized_keys");
    let prep = session
        .exec(&format!("mkdir -p {home}/.ssh && chmod 700 {home}/.ssh"))
        .await?;
    ensure_ok("prepare .ssh", &prep)?;
    let appended = session
        .exec_stdin(
            &format!("tee -a {auth}"),
            format!("{}\n", c1.public_openssh).as_bytes(),
        )
        .await?;
    ensure_ok("install C1", &appended)?;

    let probe = sessions
        .connect(&ConnectSpec {
            host: input.host.to_string(),
            port: 22,
            username: input.username.to_string(),
            client_key: c1.private.clone(),
            insecure: input.insecure,
            pinned_fingerprint: if input.insecure {
                None
            } else {
                Some(input.h0_fingerprint.to_string())
            },
            host_label: input.host_label.to_string(),
        })
        .await;
    if let Err(err) = probe {
        let _ = remove_authorized_line(session, &auth, &c1.public_openssh).await;
        keys::remove_client(input.state_root, &c1.fingerprint)?;
        return Err(Error::msg(format!("C1 probe failed, kept C0: {err}")));
    }
    drop(probe);

    remove_authorized_line(session, &auth, &input.c0.public_openssh).await?;
    keys::remove_client(input.state_root, &input.c0.fingerprint)?;

    let generated = session
        .exec("sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key.new -N '' -q")
        .await?;
    ensure_ok("generate H1", &generated)?;
    let pub_file = session
        .exec("sudo cat /etc/ssh/ssh_host_ed25519_key.new.pub")
        .await?;
    ensure_ok("read H1", &pub_file)?;
    let h1_public_line = pub_file.stdout.trim().to_string();
    let h1_public = PublicKey::from_openssh(&h1_public_line)
        .map_err(|err| Error::msg(format!("parse H1 public key: {err}")))?;
    let h1_fingerprint = keys::fingerprint(&h1_public);

    let sshd = "\
HostKey /etc/ssh/ssh_host_ed25519_key.new
PasswordAuthentication no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
";
    let written = session
        .exec_stdin(
            "sudo tee /etc/ssh/sshd_config.d/99-cloud-mvp.conf > /dev/null",
            sshd.as_bytes(),
        )
        .await?;
    ensure_ok("point sshd at H1", &written)?;

    let mut pins = KnownHosts::load(input.state_root)?;
    pins.remove_fingerprint(input.h0_fingerprint);
    pins.upsert(input.host_label, 22, &h1_fingerprint);
    pins.upsert(input.host, 22, &h1_fingerprint);
    pins.save(input.state_root)?;

    let restarted = session
        .exec("sudo sh -c 'systemctl restart ssh || systemctl restart sshd'")
        .await;
    if let Err(err) = restarted {
        return Err(Error::msg(format!(
            "sshd restart failed before the old session dropped: {err}"
        )));
    }

    let mut h1_session = sessions
        .connect(&ConnectSpec {
            host: input.host.to_string(),
            port: 22,
            username: input.username.to_string(),
            client_key: c1.private.clone(),
            insecure: input.insecure,
            pinned_fingerprint: if input.insecure {
                None
            } else {
                Some(h1_fingerprint.clone())
            },
            host_label: input.host_label.to_string(),
        })
        .await
        .map_err(|err| Error::msg(format!("reconnect with H1/C1 failed: {err}")))?;

    let wiped = h1_session
        .exec("sudo rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub")
        .await?;
    ensure_ok("remove H0", &wiped)?;
    keys::remove_host(input.state_root, input.h0_fingerprint)?;

    let report = RotationReport {
        client_old: input.c0.fingerprint.clone(),
        client_new: c1.fingerprint.clone(),
        host_old: input.h0_fingerprint.to_string(),
        host_new: h1_fingerprint,
    };
    Ok(Rotated {
        client: c1,
        host_public: h1_public_line,
        report,
    })
}

pub struct Rotated {
    pub client: KeyMaterial,
    pub host_public: String,
    pub report: RotationReport,
}

async fn remove_authorized_line(
    session: &mut dyn SshSession,
    path: &str,
    line: &str,
) -> Result<()> {
    let current = session.exec(&format!("cat {path}")).await?;
    ensure_ok("read authorized_keys", &current)?;
    let filtered = current
        .stdout
        .lines()
        .filter(|existing| existing.trim() != line.trim() && !existing.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let body = if filtered.is_empty() {
        String::new()
    } else {
        format!("{filtered}\n")
    };
    let written = session
        .exec_stdin(&format!("tee {path}"), body.as_bytes())
        .await?;
    ensure_ok("rewrite authorized_keys", &written)
}

fn ensure_ok(step: &str, result: &crate::ssh::ExecResult) -> Result<()> {
    if result.status == 0 {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "{step} exited {}: {}",
            result.status,
            result.stderr.trim()
        )))
    }
}
