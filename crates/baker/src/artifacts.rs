//! `./<target>/` files for people who want to SSH in with OpenSSH.

use std::fs;
use std::path::{Path, PathBuf};

use crate::api::SshMode;
use crate::error::{Error, Result};
use crate::keys::{write_public, write_secret};
use crate::state::{openssh_lines, InstanceRecord};

pub struct ArtifactPaths {
    pub dir: PathBuf,
    pub private_key: PathBuf,
    pub ssh_config: PathBuf,
    pub known_hosts: PathBuf,
}

pub fn paths(workdir: &Path, target: &str) -> ArtifactPaths {
    let dir = workdir.join(target);
    ArtifactPaths {
        private_key: dir.join("private_key"),
        ssh_config: dir.join("ssh-config"),
        known_hosts: dir.join("known_hosts"),
        dir,
    }
}

pub fn write_client_and_config(
    workdir: &Path,
    target: &str,
    username: &str,
    ip: &str,
    client_private: &str,
    client_public: &str,
    host_public: &str,
    mode: SshMode,
    record: &InstanceRecord,
) -> Result<ArtifactPaths> {
    let paths = paths(workdir, target);
    fs::create_dir_all(&paths.dir).map_err(|err| Error::io(&paths.dir, err))?;
    write_secret(&paths.private_key, client_private.as_bytes())?;
    write_public(
        &paths.dir.join("private_key.pub"),
        &format!("{}\n", client_public.trim()),
    )?;
    fs::write(&paths.known_hosts, openssh_lines(target, ip, host_public))
        .map_err(|err| Error::io(&paths.known_hosts, err))?;
    let strict = match mode {
        SshMode::Safe => "yes",
        SshMode::Insecure => "no",
    };
    let known_file = if mode == SshMode::Insecure {
        "/dev/null".to_string()
    } else {
        paths.known_hosts.display().to_string()
    };
    let config = format!(
        "\
Host {target}
  HostName {ip}
  User {username}
  Port 22
  HostKeyAlias {target}
  UserKnownHostsFile \"{known_file}\"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking {strict}
  PasswordAuthentication no
  IdentityFile \"{}\"
  IdentitiesOnly yes
  LogLevel FATAL
",
        paths.private_key.display()
    );
    fs::write(&paths.ssh_config, config).map_err(|err| Error::io(&paths.ssh_config, err))?;
    fs::write(
        paths.dir.join("last_instance.json"),
        serde_json::to_vec_pretty(record).map_err(|err| Error::msg(format!("instance json: {err}")))?,
    )
    .map_err(|err| Error::io(paths.dir.join("last_instance.json"), err))?;
    Ok(paths)
}
