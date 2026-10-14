//! russh client. Host-key checks go through [`crate::ssh::verifier::accept_host_key`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, AuthResult, Handler};
use russh::ChannelMsg;
use russh::keys::HashAlg;

use super::session::{ByteChannel, ConnectSpec, ExecResult, SessionFactory, SshSession};
use super::verifier::accept_host_key;
use crate::error::{Error, Result};

struct HostKeyHandler {
    insecure: bool,
    pinned: Option<String>,
    host_label: String,
}

#[derive(Debug)]
struct HandlerError(String);

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HandlerError {}

impl From<russh::Error> for HandlerError {
    fn from(err: russh::Error) -> Self {
        Self(err.to_string())
    }
}

impl Handler for HostKeyHandler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let got = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        accept_host_key(
            &self.host_label,
            self.insecure,
            self.pinned.as_deref(),
            &got,
        )
        .map(|()| true)
        .map_err(|err| HandlerError(err.to_string()))
    }
}

pub struct RusshFactory;

#[async_trait]
impl SessionFactory for RusshFactory {
    async fn connect(&self, spec: &ConnectSpec) -> Result<Box<dyn SshSession>> {
        let config = Arc::new(client::Config::default());
        let handler = HostKeyHandler {
            insecure: spec.insecure,
            pinned: spec.pinned_fingerprint.clone(),
            host_label: spec.host_label.clone(),
        };
        let addr = (spec.host.as_str(), spec.port);
        let mut handle = tokio::time::timeout(Duration::from_secs(20), client::connect(config, addr, handler))
            .await
            .map_err(|_| Error::msg(format!("timed out connecting to {}:{}", spec.host, spec.port)))?
            .map_err(|err| Error::msg(format!("ssh connect: {err}")))?;

        let openssh = spec
            .client_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|err| Error::msg(format!("encode client key: {err}")))?;
        let parsed = russh::keys::PrivateKey::from_openssh(openssh.as_bytes())
            .map_err(|err| Error::msg(format!("load client key: {err}")))?;
        let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(parsed), None);
        let auth = handle
            .authenticate_publickey(spec.username.as_str(), key)
            .await
            .map_err(|err| Error::msg(format!("ssh auth: {err}")))?;
        if !matches!(auth, AuthResult::Success) {
            return Err(Error::msg(format!(
                "ssh public-key authentication failed for {}",
                spec.username
            )));
        }
        Ok(Box::new(RusshSession { handle }))
    }
}

struct RusshSession {
    handle: client::Handle<HostKeyHandler>,
}

#[async_trait]
impl SshSession for RusshSession {
    async fn exec(&mut self, command: &str) -> Result<ExecResult> {
        self.exec_stdin(command, b"").await
    }

    async fn exec_stdin(&mut self, command: &str, stdin: &[u8]) -> Result<ExecResult> {
        let mut channel = self.open(command).await?;
        if !stdin.is_empty() {
            channel
                .data(std::io::Cursor::new(stdin.to_vec()))
                .await
                .map_err(|err| Error::msg(format!("ssh stdin: {err}")))?;
        }
        channel
            .eof()
            .await
            .map_err(|err| Error::msg(format!("ssh eof: {err}")))?;
        let (stdout, stderr, status) = read_until_exit(&mut channel).await?;
        Ok(ExecResult {
            status,
            stdout,
            stderr,
        })
    }

    async fn open_exec(&mut self, command: &str) -> Result<Box<dyn ByteChannel>> {
        let channel = self.open(command).await?;
        Ok(Box::new(RusshChan { channel }))
    }

    async fn exec_streaming(
        &mut self,
        command: &str,
        on_line: &mut (dyn for<'a> FnMut(bool, &'a str) + Send),
    ) -> Result<i32> {
        let mut channel = self.open(command).await?;
        channel
            .eof()
            .await
            .map_err(|err| Error::msg(format!("ssh eof: {err}")))?;
        let mut stdout_buf = String::new();
        let mut stderr_buf = String::new();
        let mut status = None;
        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { data } => {
                    stdout_buf.push_str(&String::from_utf8_lossy(&data));
                    emit_lines(&mut stdout_buf, false, on_line);
                }
                ChannelMsg::ExtendedData { data, ext } if ext == 1 => {
                    stderr_buf.push_str(&String::from_utf8_lossy(&data));
                    emit_lines(&mut stderr_buf, true, on_line);
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status as i32),
                ChannelMsg::ExitSignal { .. } => status = Some(128),
                _ => {}
            }
        }
        if !stdout_buf.is_empty() {
            let line = std::mem::take(&mut stdout_buf);
            on_line(false, &line);
        }
        if !stderr_buf.is_empty() {
            let line = std::mem::take(&mut stderr_buf);
            on_line(true, &line);
        }
        Ok(status.unwrap_or(0))
    }
}

fn emit_lines(
    buf: &mut String,
    stderr: bool,
    on_line: &mut (dyn for<'a> FnMut(bool, &'a str) + Send),
) {
    while let Some(idx) = buf.find('\n') {
        let mut line = buf.drain(..=idx).collect::<String>();
        if line.ends_with('\n') {
            line.pop();
        }
        if line.ends_with('\r') {
            line.pop();
        }
        on_line(stderr, &line);
    }
}

impl RusshSession {
    async fn open(&mut self, command: &str) -> Result<russh::Channel<client::Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|err| Error::msg(format!("ssh channel: {err}")))?;
        channel
            .exec(true, command)
            .await
            .map_err(|err| Error::msg(format!("ssh exec: {err}")))?;
        Ok(channel)
    }
}

async fn read_until_exit(
    channel: &mut russh::Channel<client::Msg>,
) -> Result<(String, String, i32)> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext } if ext == 1 => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status as i32),
            ChannelMsg::ExitSignal { .. } => status = Some(128),
            _ => {}
        }
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        status.unwrap_or(0),
    ))
}


struct RusshChan {
    channel: russh::Channel<client::Msg>,
}

#[async_trait]
impl ByteChannel for RusshChan {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.channel
            .data(std::io::Cursor::new(data.to_vec()))
            .await
            .map_err(|err| Error::msg(format!("ssh send: {err}")))
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let Some(msg) = self.channel.wait().await else {
                return Ok(None);
            };
            match msg {
                ChannelMsg::Data { data } => return Ok(Some(data.to_vec())),
                ChannelMsg::Eof | ChannelMsg::Close => return Ok(None),
                _ => {}
            }
        }
    }

    async fn close_send(&mut self) -> Result<()> {
        self.channel
            .eof()
            .await
            .map_err(|err| Error::msg(format!("ssh eof: {err}")))?;
        Ok(())
    }
}

