//! In-memory guest used by library tests. It speaks the real apply protocol.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use async_trait::async_trait;
use batch_baker_proto::serve_apply;
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::session::{ByteChannel, ConnectSpec, ExecResult, SessionFactory, SshSession};
use crate::cloud_init::parse_embedded_keys;
use crate::error::{Error, Result};
use crate::keys::{self, KeyMaterial};

#[derive(Clone)]
pub struct SharedGuest {
    inner: Arc<Mutex<Guest>>,
    transfer_root: Arc<std::path::PathBuf>,
}

struct Guest {
    user_data: String,
    seeded: bool,
    files: HashMap<String, Vec<u8>>,
    current_host_fpr: String,
    destroyed: bool,
}

impl SharedGuest {
    pub fn new() -> Self {
        let transfer_root = std::env::temp_dir().join(format!(
            "bb-guest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&transfer_root);
        Self {
            inner: Arc::new(Mutex::new(Guest {
                user_data: String::new(),
                seeded: false,
                files: HashMap::new(),
                current_host_fpr: String::new(),
                destroyed: false,
            })),
            transfer_root: Arc::new(transfer_root),
        }
    }

    pub fn set_user_data(&self, user_data: String) {
        self.inner.lock().expect("guest").user_data = user_data;
    }

    pub fn destroyed(&self) -> bool {
        self.inner.lock().expect("guest").destroyed
    }

    pub fn mark_destroyed(&self) {
        self.inner.lock().expect("guest").destroyed = true;
    }
}

pub struct FakeSessions {
    guest: SharedGuest,
}

impl FakeSessions {
    pub fn new(guest: SharedGuest) -> Self {
        Self { guest }
    }
}

#[async_trait]
impl SessionFactory for FakeSessions {
    async fn connect(&self, spec: &ConnectSpec) -> Result<Box<dyn SshSession>> {
        let mut guest = self.guest.inner.lock().expect("guest");
        if !guest.seeded {
            seed(&mut guest)?;
        }
        let client_line = spec
            .client_key
            .public_key()
            .to_openssh()
            .map_err(|err| Error::msg(format!("client public key: {err}")))?;
        let client_line = client_line.trim().to_string();
        let auth_path = format!("/home/{}/.ssh/authorized_keys", spec.username);
        let authorized = String::from_utf8_lossy(guest.files.get(&auth_path).map(Vec::as_slice).unwrap_or(&[])).to_string();
        if !authorized.lines().any(|line| line.trim() == client_line) {
            return Err(Error::msg("public key rejected"));
        }
        if let Some(pinned) = &spec.pinned_fingerprint {
            if pinned != &guest.current_host_fpr {
                return Err(Error::Mitm {
                    host: spec.host_label.clone(),
                    pinned: pinned.clone(),
                    got: guest.current_host_fpr.clone(),
                });
            }
        }
        drop(guest);
        Ok(Box::new(FakeSession {
            guest: self.guest.clone(),
            username: spec.username.clone(),
        }))
    }
}

fn seed(guest: &mut Guest) -> Result<()> {
    let (username, client_pub, host_private) = parse_embedded_keys(&guest.user_data)?;
    let host = PrivateKey::from_openssh(&host_private)
        .map_err(|err| Error::msg(format!("host key in cloud-init: {err}")))?;
    let host_material = keys::material_from_private(host)?;
    guest.current_host_fpr = host_material.fingerprint.clone();
    guest.files.insert(
        format!("/home/{username}/.ssh/authorized_keys"),
        format!("{client_pub}\n").into_bytes(),
    );
    guest.files.insert(
        "/etc/ssh/ssh_host_ed25519_key".into(),
        host_material.private_openssh.into_bytes(),
    );
    guest.files.insert(
        "/etc/ssh/ssh_host_ed25519_key.pub".into(),
        format!("{}\n", host_material.public_openssh).into_bytes(),
    );
    guest.seeded = true;
    Ok(())
}

struct FakeSession {
    guest: SharedGuest,
    username: String,
}

#[async_trait]
impl SshSession for FakeSession {
    async fn exec(&mut self, command: &str) -> Result<ExecResult> {
        self.exec_stdin(command, b"").await
    }

    async fn exec_stdin(&mut self, command: &str, stdin: &[u8]) -> Result<ExecResult> {
        let mut guest = self.guest.inner.lock().expect("guest");
        Ok(interpret(&mut guest, &self.username, command, stdin))
    }

    async fn open_exec(&mut self, command: &str) -> Result<Box<dyn ByteChannel>> {
        let _ = (command, self.username.as_str());
        let dest = self.guest.transfer_root.join("dest");
        let journal = self.guest.transfer_root.join("journal.json");
        std::fs::create_dir_all(&dest).map_err(|err| Error::msg(format!("dest: {err}")))?;
        let (client, server) = std::os::unix::net::UnixStream::pair()
            .map_err(|err| Error::msg(format!("socketpair: {err}")))?;
        thread::spawn(move || {
            let mut server = server;
            let mut read = server.try_clone().expect("clone");
            let _ = serve_apply(
                &mut read,
                &mut server,
                std::path::Path::new(&dest),
                std::path::Path::new(&journal),
            );
        });
        client
            .set_nonblocking(true)
            .map_err(|err| Error::msg(format!("nonblocking: {err}")))?;
        let stream = tokio::net::UnixStream::from_std(client)
            .map_err(|err| Error::msg(format!("tokio unix: {err}")))?;
        Ok(Box::new(UnixChan { stream }))
    }

    async fn exec_streaming(
        &mut self,
        command: &str,
        on_line: &mut (dyn for<'a> FnMut(bool, &'a str) + Send),
    ) -> Result<i32> {
        if command.contains("echo hello") {
            on_line(false, "hello");
            Ok(0)
        } else if command.contains("exit 3") {
            on_line(true, "nope");
            Ok(3)
        } else {
            on_line(false, "ok");
            Ok(0)
        }
    }
}

fn interpret(guest: &mut Guest, username: &str, command: &str, stdin: &[u8]) -> ExecResult {
    let ok = ExecResult {
        status: 0,
        stdout: String::new(),
        stderr: String::new(),
    };
    if command.contains("ssh-keygen") {
        let path = arg(command, "-f").unwrap_or_else(|| "/etc/ssh/ssh_host_ed25519_key.new".into());
        let key = match keys::generate("rotated-host") {
            Ok(key) => key,
            Err(err) => {
                return ExecResult {
                    status: 1,
                    stdout: String::new(),
                    stderr: err.to_string(),
                };
            }
        };
        store_key(guest, &path, &key);
        return ok;
    }
    if command.contains("systemctl restart ssh") {
        if let Some(bytes) = guest.files.get("/etc/ssh/ssh_host_ed25519_key.new.pub").cloned() {
            if let Ok(text) = String::from_utf8(bytes) {
                if let Ok(public) = ssh_key::PublicKey::from_openssh(text.trim()) {
                    guest.current_host_fpr = keys::fingerprint(&public);
                }
            }
        }
        return ok;
    }
    if command.contains("rm -f") {
        for token in command.split_whitespace() {
            if token.starts_with('/') {
                guest.files.remove(token);
            }
        }
        return ok;
    }
    if let Some(path) = tee_path(command) {
        let mut body = stdin.to_vec();
        if command.contains("tee -a") {
            let mut existing = guest.files.get(&path).cloned().unwrap_or_default();
            existing.extend_from_slice(&body);
            body = existing;
        }
        guest.files.insert(path, body);
        return ok;
    }
    if let Some(path) = cat_path(command) {
        let stdout = guest
            .files
            .get(&path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        return ExecResult {
            status: 0,
            stdout,
            stderr: String::new(),
        };
    }
    let _ = username;
    ok
}

fn store_key(guest: &mut Guest, path: &str, key: &KeyMaterial) {
    guest
        .files
        .insert(path.into(), key.private_openssh.as_bytes().to_vec());
    guest.files.insert(
        format!("{path}.pub"),
        format!("{}\n", key.public_openssh).into_bytes(),
    );
}

fn tee_path(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let idx = tokens.iter().position(|token| *token == "tee")?;
    tokens.get(idx + 1).filter(|token| !token.starts_with('-')).map(|s| (*s).to_string())
        .or_else(|| tokens.get(idx + 2).map(|s| (*s).to_string()))
}

fn cat_path(command: &str) -> Option<String> {
    if command.contains("tee") {
        return None;
    }
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let idx = tokens.iter().position(|token| *token == "cat")?;
    tokens.get(idx + 1).map(|s| (*s).to_string())
}

fn arg(command: &str, flag: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let idx = tokens.iter().position(|token| *token == flag)?;
    tokens.get(idx + 1).map(|s| (*s).to_string())
}

struct UnixChan {
    stream: tokio::net::UnixStream,
}

#[async_trait]
impl ByteChannel for UnixChan {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream
            .write_all(data)
            .await
            .map_err(|err| Error::msg(format!("fake send: {err}")))
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 8192];
        let n = self
            .stream
            .read(&mut buf)
            .await
            .map_err(|err| Error::msg(format!("fake recv: {err}")))?;
        if n == 0 {
            Ok(None)
        } else {
            buf.truncate(n);
            Ok(Some(buf))
        }
    }

    async fn close_send(&mut self) -> Result<()> {
        match self.stream.shutdown().await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(err) => Err(Error::msg(format!("fake shutdown: {err}"))),
        }
    }
}
