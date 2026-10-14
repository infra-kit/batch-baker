use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    #[serde(default)]
    pub targets: BTreeMap<String, TargetRecord>,
    #[serde(default)]
    pub instances: BTreeMap<String, InstanceRecord>,
    #[serde(default)]
    pub provider: BTreeMap<String, ProviderRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRecord {
    pub active_instance_id: String,
    pub username: String,
    pub region: String,
    pub size: String,
    pub image: String,
    pub client_key_fpr: String,
    pub host_key_fpr: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_until: Option<String>,
    #[serde(default)]
    pub keys_rotated: bool,
    #[serde(default)]
    pub ttl_armed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub target: String,
    pub ip: String,
    pub status: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destroy_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_region: Option<String>,
}

pub struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn lock(&self) -> Result<StateLock> {
        fs::create_dir_all(&self.root).map_err(|err| Error::io(&self.root, err))?;
        let lock_path = self.root.join("state.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|err| Error::io(&lock_path, err))?;
        file.lock_exclusive()
            .map_err(|err| Error::msg(format!("lock {}: {err}", lock_path.display())))?;
        let state = read_state(&self.root.join("state.json"))?;
        Ok(StateLock {
            _file: file,
            root: self.root.clone(),
            state,
        })
    }
}

pub struct StateLock {
    _file: File,
    root: PathBuf,
    pub state: StateFile,
}

impl StateLock {
    pub fn save(&self) -> Result<()> {
        let path = self.root.join("state.json");
        let body = serde_json::to_vec_pretty(&self.state)
            .map_err(|err| Error::msg(format!("encode state: {err}")))?;
        let tmp = self.root.join("state.json.tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|err| Error::io(&tmp, err))?;
            file.write_all(&body).map_err(|err| Error::io(&tmp, err))?;
        }
        fs::rename(&tmp, &path).map_err(|err| Error::io(&path, err))?;
        Ok(())
    }

    pub fn write_instance_file(&self, provider: &str, id: &str, record: &InstanceRecord) -> Result<()> {
        let dir = self.root.join("instances").join(provider);
        fs::create_dir_all(&dir).map_err(|err| Error::io(&dir, err))?;
        let path = dir.join(format!("{id}.json"));
        let body = serde_json::to_vec_pretty(record)
            .map_err(|err| Error::msg(format!("encode instance: {err}")))?;
        fs::write(&path, body).map_err(|err| Error::io(&path, err))
    }
}

fn read_state(path: &Path) -> Result<StateFile> {
    match File::open(path) {
        Ok(mut file) => {
            let mut buf = String::new();
            file.read_to_string(&mut buf)
                .map_err(|err| Error::io(path, err))?;
            if buf.trim().is_empty() {
                return Ok(StateFile::default());
            }
            serde_json::from_str(&buf).map_err(|err| Error::msg(format!("parse {}: {err}", path.display())))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(StateFile::default()),
        Err(err) => Err(Error::io(path, err)),
    }
}

pub fn instance_key(provider: &str, id: &str) -> String {
    format!("{provider}:{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = std::env::temp_dir().join(format!("bb-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = StateStore::new(&dir);
        {
            let mut lock = store.lock().unwrap();
            lock.state.targets.insert(
                "linux-amd64-ubuntu-digitalocean".into(),
                TargetRecord {
                    active_instance_id: "9".into(),
                    username: "ubuntu".into(),
                    region: "ams3".into(),
                    size: "s-1vcpu-1gb".into(),
                    image: "ubuntu-24-04-x64".into(),
                    client_key_fpr: "SHA256:abc".into(),
                    host_key_fpr: "SHA256:def".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    ttl_until: None,
                    keys_rotated: true,
                    ttl_armed: false,
                },
            );
            lock.save().unwrap();
        }
        let lock = store.lock().unwrap();
        assert!(lock.state.targets["linux-amd64-ubuntu-digitalocean"].keys_rotated);
        let _ = fs::remove_dir_all(&dir);
    }
}
