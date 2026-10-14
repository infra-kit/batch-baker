//! Ed25519 key generation and on-disk blobs.
//!
//! Private key files are created mode `0600` on Unix. Host private keys stay
//! in the state directory until rotation deletes them. They are not written
//! under `./<target>/`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct KeyMaterial {
    pub private_openssh: String,
    pub public_openssh: String,
    pub fingerprint: String,
    pub private: PrivateKey,
}

pub fn generate(comment: &str) -> Result<KeyMaterial> {
    let mut rng = ssh_key::rand_core::OsRng;
    let mut private = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|err| Error::msg(format!("generate ed25519 key: {err}")))?;
    private.set_comment(comment);
    material_from_private(private)
}

pub fn material_from_private(private: PrivateKey) -> Result<KeyMaterial> {
    let private_openssh = private
        .to_openssh(LineEnding::LF)
        .map_err(|err| Error::msg(format!("encode private key: {err}")))?;
    let public_openssh = private
        .public_key()
        .to_openssh()
        .map_err(|err| Error::msg(format!("encode public key: {err}")))?
        .trim()
        .to_string();
    let fingerprint = fingerprint(private.public_key());
    Ok(KeyMaterial {
        private_openssh: private_openssh.to_string(),
        public_openssh,
        fingerprint,
        private,
    })
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn load_private(path: &Path) -> Result<KeyMaterial> {
    let pem = fs::read(path).map_err(|err| Error::io(path, err))?;
    let private = PrivateKey::from_openssh(&pem)
        .map_err(|err| Error::msg(format!("parse {}: {err}", path.display())))?;
    material_from_private(private)
}

pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| Error::io(path, err))?;
    file.write_all(bytes).map_err(|err| Error::io(path, err))?;
    Ok(())
}

pub fn write_public(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
    }
    fs::write(path, text.as_bytes()).map_err(|err| Error::io(path, err))
}

pub fn safe_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn client_private_path(root: &Path, fingerprint: &str) -> PathBuf {
    root.join("blobs/client_keys")
        .join(format!("{}.priv", safe_fingerprint(fingerprint)))
}

pub fn client_public_path(root: &Path, fingerprint: &str) -> PathBuf {
    root.join("blobs/client_keys")
        .join(format!("{}.pub", safe_fingerprint(fingerprint)))
}

pub fn host_private_path(root: &Path, fingerprint: &str) -> PathBuf {
    root.join("blobs/host_keys")
        .join(format!("{}.priv", safe_fingerprint(fingerprint)))
}

pub fn host_public_path(root: &Path, fingerprint: &str) -> PathBuf {
    root.join("blobs/host_keys")
        .join(format!("{}.pub", safe_fingerprint(fingerprint)))
}

pub fn store_client(root: &Path, key: &KeyMaterial) -> Result<()> {
    write_secret(
        &client_private_path(root, &key.fingerprint),
        key.private_openssh.as_bytes(),
    )?;
    write_public(
        &client_public_path(root, &key.fingerprint),
        &format!("{}\n", key.public_openssh),
    )
}

pub fn store_host(root: &Path, key: &KeyMaterial) -> Result<()> {
    write_secret(
        &host_private_path(root, &key.fingerprint),
        key.private_openssh.as_bytes(),
    )?;
    write_public(
        &host_public_path(root, &key.fingerprint),
        &format!("{}\n", key.public_openssh),
    )
}

pub fn remove_client(root: &Path, fingerprint: &str) -> Result<()> {
    remove_if_exists(&client_private_path(root, fingerprint))?;
    remove_if_exists(&client_public_path(root, fingerprint))
}

pub fn remove_host(root: &Path, fingerprint: &str) -> Result<()> {
    remove_if_exists(&host_private_path(root, fingerprint))?;
    remove_if_exists(&host_public_path(root, fingerprint))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::io(path, err)),
    }
}
