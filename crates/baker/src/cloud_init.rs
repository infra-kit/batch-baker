//! Cloud-init document shared by every provider.
//!
//! The host private key is indented inside a YAML literal so the file written
//! on the guest is valid OpenSSH. The provider credential is never placed here;
//! providers store `user_data` and return it from their API.

#[cfg(test)]
use serde::Deserialize;

#[cfg(test)]
use crate::error::{Error, Result};
use crate::keys::KeyMaterial;

pub fn render(username: &str, client: &KeyMaterial, host: &KeyMaterial) -> String {
    let private_key = indent(host.private_openssh.trim_end(), 6);
    format!(
        r#"#cloud-config
users:
  - name: {username}
    shell: /bin/bash
    groups: [sudo]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - {client_pub}

ssh_deletekeys: false
ssh_genkeytypes: []

write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    owner: root:root
    permissions: '0600'
    content: |
{private_key}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    owner: root:root
    permissions: '0644'
    content: {host_pub}
  - path: /etc/ssh/sshd_config.d/99-cloud-mvp.conf
    owner: root:root
    permissions: '0644'
    content: |
      HostKey /etc/ssh/ssh_host_ed25519_key
      PasswordAuthentication no
      KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org
      Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

runcmd:
  - systemctl restart ssh || systemctl restart sshd
"#,
        username = username,
        client_pub = client.public_openssh.trim(),
        host_pub = host.public_openssh.trim(),
        private_key = private_key,
    )
}

fn indent(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct Document {
    users: Vec<User>,
    write_files: Vec<WriteFile>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct User {
    name: String,
    ssh_authorized_keys: Vec<String>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct WriteFile {
    path: String,
    content: String,
}

/// Pull the client public key and host private key back out of a rendered document.
#[cfg(test)]
pub fn parse_embedded_keys(user_data: &str) -> Result<(String, String, String)> {
    let doc: Document = serde_yaml::from_str(user_data)
        .map_err(|err| Error::msg(format!("parse cloud-init: {err}")))?;
    let user = doc
        .users
        .first()
        .ok_or_else(|| Error::msg("cloud-init is missing the user"))?;
    let client = user
        .ssh_authorized_keys
        .first()
        .ok_or_else(|| Error::msg("cloud-init is missing the client public key"))?
        .trim()
        .to_string();
    let host_private = doc
        .write_files
        .iter()
        .find(|file| file.path == "/etc/ssh/ssh_host_ed25519_key")
        .map(|file| file.content.trim().to_string())
        .ok_or_else(|| Error::msg("cloud-init is missing the host private key"))?;
    Ok((user.name.clone(), client, host_private))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PrivateKey;

    #[test]
    fn round_trips_keys_and_disables_password_auth() {
        let client = crate::keys::generate("batch-baker").unwrap();
        let host = crate::keys::generate("host@cloud-mvp").unwrap();
        let doc = render("ubuntu", &client, &host);
        assert!(doc.contains("ssh_deletekeys: false"));
        assert!(doc.contains("ssh_genkeytypes: []"));
        assert!(doc.contains("PasswordAuthentication no"));
        let (_user, pub_line, private_pem) = parse_embedded_keys(&doc).unwrap();
        assert_eq!(pub_line, client.public_openssh);
        let parsed = PrivateKey::from_openssh(&private_pem).unwrap();
        assert_eq!(
            crate::keys::fingerprint(parsed.public_key()),
            host.fingerprint
        );
    }
}
