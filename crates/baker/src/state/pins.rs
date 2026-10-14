use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinEntry {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub algo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct KnownHosts {
    #[serde(default)]
    pub entries: Vec<PinEntry>,
}

impl KnownHosts {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("pins/known_hosts.json");
        match fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => Ok(Self::default()),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|err| Error::msg(format!("parse {}: {err}", path.display()))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(Error::io(path, err)),
        }
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let dir = root.join("pins");
        fs::create_dir_all(&dir).map_err(|err| Error::io(&dir, err))?;
        let path = dir.join("known_hosts.json");
        let body = serde_json::to_vec_pretty(self)
            .map_err(|err| Error::msg(format!("encode pins: {err}")))?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| Error::io(&path, err))?;
        file.write_all(&body).map_err(|err| Error::io(&path, err))
    }

    pub fn upsert(&mut self, host: &str, port: u16, fingerprint: &str) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.host == host && entry.port == port)
        {
            entry.fingerprint = fingerprint.to_string();
            entry.algo = "ssh-ed25519".into();
        } else {
            self.entries.push(PinEntry {
                host: host.to_string(),
                port,
                fingerprint: fingerprint.to_string(),
                algo: "ssh-ed25519".into(),
            });
        }
    }

    pub fn remove_fingerprint(&mut self, fingerprint: &str) {
        self.entries
            .retain(|entry| entry.fingerprint != fingerprint);
    }

    pub fn fingerprint_for(&self, host: &str, port: u16) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.host == host && entry.port == port)
            .map(|entry| entry.fingerprint.as_str())
    }
}

/// OpenSSH `known_hosts` lines for the alias, the address, and `[ip]:22`.
///
/// A port-22 connection to the address looks up the bare IP. The bracket form
/// is not used for the default port.
pub fn openssh_lines(alias: &str, ip: &str, public_openssh: &str) -> String {
    let key = public_openssh.trim();
    format!("{alias} {key}\n{ip} {key}\n[{ip}]:22 {key}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_replaces_fingerprint() {
        let mut hosts = KnownHosts::default();
        hosts.upsert("vm", 22, "SHA256:old");
        hosts.upsert("vm", 22, "SHA256:new");
        assert_eq!(hosts.entries.len(), 1);
        assert_eq!(hosts.fingerprint_for("vm", 22), Some("SHA256:new"));
        hosts.remove_fingerprint("SHA256:new");
        assert!(hosts.entries.is_empty());
    }

    #[test]
    fn openssh_lines_include_the_alias_and_the_address() {
        let text = openssh_lines("vm", "203.0.113.10", "ssh-ed25519 AAAA comment");
        assert_eq!(
            text,
            "\
vm ssh-ed25519 AAAA comment
203.0.113.10 ssh-ed25519 AAAA comment
[203.0.113.10]:22 ssh-ed25519 AAAA comment
"
        );
    }
}
