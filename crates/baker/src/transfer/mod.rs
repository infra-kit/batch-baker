//! Upload a directory by talking to `batch-baker-agent apply`.
//!
//! There is no tar transport. A dropped session resumes after the last file
//! the agent recorded in its journal.

mod excludes;

use std::fs;
use std::path::Path;

use batch_baker_proto::{
    file_hash, op_stats, plan_delta, read_msg, write_msg, AgentMsg, ClientMsg, FileEntry,
};
pub use excludes::{is_excluded, load as load_excludes};

use crate::api::{Events, TransferProgress, TransferStats};
use crate::error::{Error, Result};
use crate::ssh::ByteChannel;
use tokio_util::sync::CancellationToken;

pub fn collect_files(root: &Path, excludes: &globset::GlobSet) -> Result<Vec<(FileEntry, Vec<u8>)>> {
    let mut out = Vec::new();
    walk(root, root, excludes, &mut out)?;
    out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    Ok(out)
}

fn walk(
    root: &Path,
    dir: &Path,
    excludes: &globset::GlobSet,
    out: &mut Vec<(FileEntry, Vec<u8>)>,
) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|err| Error::io(dir, err))?;
    for entry in entries {
        let entry = entry.map_err(|err| Error::io(dir, err))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded(excludes, &relative) {
            continue;
        }
        let meta = entry.metadata().map_err(|err| Error::io(&path, err))?;
        if meta.is_dir() {
            walk(root, &path, excludes, out)?;
            continue;
        }
        if !meta.is_file() || meta.file_type().is_symlink() {
            continue;
        }
        let bytes = fs::read(&path).map_err(|err| Error::io(&path, err))?;
        let mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o777
            }
            #[cfg(not(unix))]
            {
                0o644
            }
        };
        out.push((
            FileEntry {
                path: relative,
                mode,
                len: bytes.len() as u64,
                blake3: file_hash(&bytes),
            },
            bytes,
        ));
    }
    Ok(())
}

pub async fn upload_tree(
    channel: &mut dyn ByteChannel,
    files: Vec<(FileEntry, Vec<u8>)>,
    events: &dyn Events,
    cancel: &CancellationToken,
) -> Result<TransferStats> {
    let mut stats = TransferStats {
        files: files.len() as u64,
        ..TransferStats::default()
    };
    send(channel, &ClientMsg::Hello {
        version: batch_baker_proto::VERSION,
    })
    .await?;
    match recv(channel).await? {
        AgentMsg::Hello { version } if version == batch_baker_proto::VERSION => {}
        AgentMsg::Error { message } => return Err(Error::msg(message)),
        other => return Err(Error::msg(format!("agent hello: {other:?}"))),
    }
    send(
        channel,
        &ClientMsg::Begin {
            files: files.iter().map(|(entry, _)| entry.clone()).collect(),
        },
    )
    .await?;
    let skip = match recv(channel).await? {
        AgentMsg::Plan { skip } => skip,
        AgentMsg::Error { message } => return Err(Error::msg(message)),
        other => return Err(Error::msg(format!("agent plan: {other:?}"))),
    };

    for (entry, bytes) in files {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if skip.iter().any(|path| path == &entry.path) {
            stats.bytes_reused += entry.len;
            events.on_transfer_progress(&TransferProgress {
                path: entry.path.clone(),
                bytes_sent: 0,
                bytes_reused: entry.len,
                bytes_sent_total: stats.bytes_sent,
                bytes_reused_total: stats.bytes_reused,
            });
            continue;
        }
        send(
            channel,
            &ClientMsg::SignaturesPlease {
                path: entry.path.clone(),
            },
        )
        .await?;
        let signatures = match recv(channel).await? {
            AgentMsg::Signatures {
                unchanged, blocks, ..
            } => {
                if unchanged {
                    stats.bytes_reused += entry.len;
                    events.on_transfer_progress(&TransferProgress {
                        path: entry.path.clone(),
                        bytes_sent: 0,
                        bytes_reused: entry.len,
                        bytes_sent_total: stats.bytes_sent,
                        bytes_reused_total: stats.bytes_reused,
                    });
                    continue;
                }
                blocks
            }
            AgentMsg::Error { message } => return Err(Error::msg(format!("{}: {message}", entry.path))),
            other => return Err(Error::msg(format!("agent signatures: {other:?}"))),
        };
        let ops = plan_delta(&bytes, &signatures);
        let (sent, reused) = op_stats(&ops);
        let reused = reused.min(entry.len);
        stats.bytes_sent += sent;
        stats.bytes_reused += reused;
        send(
            channel,
            &ClientMsg::Delta {
                path: entry.path.clone(),
                ops,
            },
        )
        .await?;
        match recv(channel).await? {
            AgentMsg::Applied { .. } => {}
            AgentMsg::Error { message } => {
                return Err(Error::msg(format!("{}: {message}", entry.path)))
            }
            other => return Err(Error::msg(format!("agent applied: {other:?}"))),
        }
        events.on_transfer_progress(&TransferProgress {
            path: entry.path,
            bytes_sent: sent,
            bytes_reused: reused,
            bytes_sent_total: stats.bytes_sent,
            bytes_reused_total: stats.bytes_reused,
        });
    }
    send(channel, &ClientMsg::Finish).await?;
    match recv(channel).await? {
        AgentMsg::Done { .. } => Ok(stats),
        AgentMsg::Error { message } => Err(Error::msg(message)),
        other => Err(Error::msg(format!("agent done: {other:?}"))),
    }
}

async fn send(channel: &mut dyn ByteChannel, msg: &impl serde::Serialize) -> Result<()> {
    let mut buf = Vec::new();
    write_msg(&mut buf, msg).map_err(|err| Error::msg(format!("encode frame: {err}")))?;
    channel.send(&buf).await
}

async fn recv(channel: &mut dyn ByteChannel) -> Result<AgentMsg> {
    let mut buf = Vec::new();
    loop {
        if let Some(msg) = try_pop(&mut buf)? {
            return Ok(msg);
        }
        match channel.recv().await? {
            Some(chunk) => buf.extend_from_slice(&chunk),
            None => {
                return Err(Error::msg("agent closed the transfer channel early"));
            }
        }
    }
}

fn try_pop(buf: &mut Vec<u8>) -> Result<Option<AgentMsg>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let body = buf[4..4 + len].to_vec();
    buf.drain(..4 + len);
    let mut cursor = std::io::Cursor::new({
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    });
    let msg = read_msg(&mut cursor).map_err(|err| Error::msg(format!("decode frame: {err}")))?;
    Ok(Some(msg))
}

pub fn agent_apply_command(username: &str) -> String {
    let home = format!("/home/{username}");
    format!(
        "mkdir -p {home}/.batch-baker && /usr/local/libexec/batch-baker-agent apply --dest {home} --journal {home}/.batch-baker/transfer.json"
    )
}
