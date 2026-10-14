use async_trait::async_trait;
use ssh_key::PrivateKey;

use crate::error::Result;

#[derive(Clone)]
pub struct ConnectSpec {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub client_key: PrivateKey,
    pub insecure: bool,
    pub pinned_fingerprint: Option<String>,
    /// Label used in MITM errors. Usually the target alias.
    pub host_label: String,
}

pub struct ExecResult {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait ByteChannel: Send {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Option<Vec<u8>>>;
    async fn close_send(&mut self) -> Result<()>;
}

#[async_trait]
pub trait SshSession: Send {
    async fn exec(&mut self, command: &str) -> Result<ExecResult>;
    async fn exec_stdin(&mut self, command: &str, stdin: &[u8]) -> Result<ExecResult>;
    async fn open_exec(&mut self, command: &str) -> Result<Box<dyn ByteChannel>>;
    async fn exec_streaming(
        &mut self,
        command: &str,
        on_line: &mut (dyn for<'a> FnMut(bool, &'a str) + Send),
    ) -> Result<i32>;
}

#[async_trait]
pub trait SessionFactory: Send + Sync {
    async fn connect(&self, spec: &ConnectSpec) -> Result<Box<dyn SshSession>>;
}
