//! Frames, checksums, and apply logic for the batch-baker delta transfer.
//!
//! The client and `batch-baker-agent apply` speak length-prefixed [`postcard`]
//! messages. Block matching uses a rolling Adler-32 checksum and a BLAKE3
//! digest. This crate does not open sockets or touch SSH.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Protocol version spoken by [`serve_apply`].
pub const VERSION: u32 = 1;

/// Full-block size. The last block of a file may be shorter and is sent literally.
pub const BLOCK_SIZE: usize = 4096;

const MAX_FRAME: usize = 32 * 1024 * 1024;
const ADLER_MOD: u32 = 65521;

/// A file the client intends to place on the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path using `/` separators. `..` is rejected.
    pub path: String,
    pub mode: u32,
    pub len: u64,
    pub blake3: [u8; 32],
}

/// Signature of one existing block on the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSig {
    pub weak: u32,
    pub strong: [u8; 32],
    pub len: u32,
}

/// One instruction the agent applies to rebuild a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaOp {
    /// Copy the existing block with this index from the old file.
    Reuse { index: u32 },
    /// Append these bytes, which were not found on the guest.
    Literal { data: Vec<u8> },
}

/// Messages the client writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello { version: u32 },
    Begin { files: Vec<FileEntry> },
    SignaturesPlease { path: String },
    Delta { path: String, ops: Vec<DeltaOp> },
    Finish,
}

/// Messages the agent writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMsg {
    Hello { version: u32 },
    Plan { skip: Vec<String> },
    Signatures {
        path: String,
        unchanged: bool,
        blocks: Vec<BlockSig>,
    },
    Applied {
        path: String,
        bytes_written: u64,
        bytes_reused: u64,
    },
    Done {
        bytes_written: u64,
        bytes_reused: u64,
    },
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Protocol(String),
}

impl From<ProtoError> for io::Error {
    fn from(value: ProtoError) -> Self {
        match value {
            ProtoError::Io(err) => err,
            ProtoError::Protocol(message) => io::Error::new(io::ErrorKind::InvalidData, message),
        }
    }
}

/// BLAKE3 of the whole buffer.
pub fn file_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Adler-32-style checksum used as the rolling weak hash. Not the zlib variant:
/// `a` starts at 0 so a window can drop its oldest byte.
pub fn weak_hash(data: &[u8]) -> u32 {
    let (a, b) = weak_parts(data);
    pack(a, b)
}

fn weak_parts(data: &[u8]) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % ADLER_MOD;
        b = (b + a) % ADLER_MOD;
    }
    (a, b)
}

fn pack(a: u32, b: u32) -> u32 {
    (b << 16) | a
}

/// Block signatures for `data`. Every block except possibly the last is [`BLOCK_SIZE`].
pub fn block_sigs(data: &[u8]) -> Vec<BlockSig> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(BLOCK_SIZE)
        .map(|chunk| BlockSig {
            weak: weak_hash(chunk),
            strong: file_hash(chunk),
            len: chunk.len() as u32,
        })
        .collect()
}

/// Build delta ops that reconstruct `new_data` from blocks described by `sigs`.
///
/// `sigs` must be the signature list of the old file, in order. Full blocks are
/// found with a rolling weak hash so an insert in the middle does not resend
/// the tail. A short final block is sent as a literal.
pub fn plan_delta(new_data: &[u8], sigs: &[BlockSig]) -> Vec<DeltaOp> {
    let mut table: HashMap<u32, Vec<(u32, [u8; 32])>> = HashMap::new();
    for (index, sig) in sigs.iter().enumerate() {
        if sig.len as usize == BLOCK_SIZE {
            table
                .entry(sig.weak)
                .or_default()
                .push((index as u32, sig.strong));
        }
    }

    let mut ops = Vec::new();
    let mut literal = Vec::new();
    let flush = |ops: &mut Vec<DeltaOp>, literal: &mut Vec<u8>| {
        for chunk in literal.chunks(BLOCK_SIZE) {
            ops.push(DeltaOp::Literal {
                data: chunk.to_vec(),
            });
        }
        literal.clear();
    };

    let mut index = 0usize;
    while index < new_data.len() {
        if !table.is_empty() {
            if let Some((offset, block_index)) = find_block(&new_data[index..], &table) {
                literal.extend_from_slice(&new_data[index..index + offset]);
                flush(&mut ops, &mut literal);
                ops.push(DeltaOp::Reuse {
                    index: block_index,
                });
                index += offset + BLOCK_SIZE;
                continue;
            }
        }
        literal.extend_from_slice(&new_data[index..]);
        break;
    }
    flush(&mut ops, &mut literal);
    ops
}

/// First full-block match in `data`. The `usize` is the number of leading bytes
/// that did not match and must be sent literally.
fn find_block(data: &[u8], table: &HashMap<u32, Vec<(u32, [u8; 32])>>) -> Option<(usize, u32)> {
    if data.len() < BLOCK_SIZE {
        return None;
    }
    let mut window: VecDeque<u8> = data[..BLOCK_SIZE].iter().copied().collect();
    let (mut a, mut b) = weak_parts(&data[..BLOCK_SIZE]);
    let mut offset = 0usize;
    loop {
        let weak = pack(a, b);
        if let Some(cands) = table.get(&weak) {
            let slice = &data[offset..offset + BLOCK_SIZE];
            let strong = file_hash(slice);
            for (index, sig) in cands {
                if sig == &strong {
                    return Some((offset, *index));
                }
            }
        }
        if offset + BLOCK_SIZE >= data.len() {
            return None;
        }
        let out = window.pop_front().expect("window is full");
        let inn = data[offset + BLOCK_SIZE];
        window.push_back(inn);
        roll(&mut a, &mut b, out, inn);
        offset += 1;
    }
}

fn roll(a: &mut u32, b: &mut u32, out: u8, inn: u8) {
    let n = BLOCK_SIZE as u32;
    let out = u32::from(out);
    let inn = u32::from(inn);
    *a = (*a + ADLER_MOD - (out % ADLER_MOD) + inn) % ADLER_MOD;
    let n_out = (n * (out % ADLER_MOD)) % ADLER_MOD;
    *b = (*b + ADLER_MOD - n_out + *a) % ADLER_MOD;
}

/// Reconstruct a file from `old` and `ops`.
pub fn apply_delta(old: &[u8], ops: &[DeltaOp]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            DeltaOp::Literal { data } => out.extend_from_slice(data),
            DeltaOp::Reuse { index } => {
                let start = *index as usize * BLOCK_SIZE;
                if start >= old.len() {
                    continue;
                }
                let end = (start + BLOCK_SIZE).min(old.len());
                out.extend_from_slice(&old[start..end]);
            }
        }
    }
    out
}

/// Bytes that will cross the network, and bytes copied from the guest.
pub fn op_stats(ops: &[DeltaOp]) -> (u64, u64) {
    let mut written = 0u64;
    let mut reused = 0u64;
    for op in ops {
        match op {
            DeltaOp::Literal { data } => written += data.len() as u64,
            DeltaOp::Reuse { .. } => reused += BLOCK_SIZE as u64,
        }
    }
    (written, reused)
}

/// Write one length-prefixed frame and flush it.
///
/// The agent uses this on stdout. That handle is block-buffered when it is not
/// a terminal, and these frames are not line-oriented, so an unflushed reply
/// never reaches the client.
pub fn write_msg<W: Write>(writer: &mut W, msg: &impl Serialize) -> io::Result<()> {
    let body = postcard::to_allocvec(msg)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 32MiB",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_msg<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 32MiB",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    postcard::from_bytes(&body).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    files: HashMap<String, String>,
}

/// Guest side of `apply`. `root` is the directory that receives files.
/// `journal_path` records completed relative paths so a dropped session can resume.
pub fn serve_apply(reader: &mut impl Read, writer: &mut impl Write, root: &Path, journal_path: &Path) -> Result<(), ProtoError> {
    let hello: ClientMsg = read_msg(reader)?;
    match hello {
        ClientMsg::Hello { version } if version == VERSION => {}
        ClientMsg::Hello { version } => {
            return fail(
                writer,
                format!("unsupported protocol version {version}"),
            );
        }
        other => {
            return fail(writer, format!("expected hello, got {other:?}"));
        }
    }
    write_msg(writer, &AgentMsg::Hello { version: VERSION })?;

    let begin: ClientMsg = read_msg(reader)?;
    let files = match begin {
        ClientMsg::Begin { files } => files,
        other => return fail(writer, format!("expected begin, got {other:?}")),
    };
    let mut by_path: HashMap<String, FileEntry> = HashMap::new();
    for file in files {
        validate_rel(&file.path)?;
        by_path.insert(file.path.clone(), file);
    }

    let mut journal = load_journal(journal_path);
    let mut skip = Vec::new();
    for file in by_path.values() {
        if journal.files.get(&file.path).map(String::as_str) == Some(&hex(&file.blake3))
            && hash_if_exists(&root.join(safe_rel(&file.path)?))?.as_ref() == Some(&file.blake3)
        {
            skip.push(file.path.clone());
        }
    }
    write_msg(writer, &AgentMsg::Plan { skip })?;

    let mut total_written = 0u64;
    let mut total_reused = 0u64;
    loop {
        let msg: ClientMsg = read_msg(reader)?;
        match msg {
            ClientMsg::SignaturesPlease { path } => {
                let Some(entry) = by_path.get(&path) else {
                    return fail(writer, format!("unknown path {path}"));
                };
                let dest = root.join(safe_rel(&path)?);
                let old = read_if_exists(&dest)?;
                let unchanged = !old.is_empty() && file_hash(&old) == entry.blake3
                    || old.is_empty() && entry.len == 0 && dest.is_file();
                let blocks = if unchanged {
                    Vec::new()
                } else {
                    block_sigs(&old)
                };
                write_msg(
                    writer,
                    &AgentMsg::Signatures {
                        path,
                        unchanged,
                        blocks,
                    },
                )?;
            }
            ClientMsg::Delta { path, ops } => {
                let Some(entry) = by_path.get(&path) else {
                    return fail(writer, format!("unknown path {path}"));
                };
                let dest = root.join(safe_rel(&path)?);
                let old = read_if_exists(&dest)?;
                let new_bytes = apply_delta(&old, &ops);
                if file_hash(&new_bytes) != entry.blake3 || new_bytes.len() as u64 != entry.len {
                    return fail(writer, format!("delta for {path} did not match the announced hash"));
                }
                atomic_write(&dest, &new_bytes, entry.mode)?;
                journal.files.insert(path.clone(), hex(&entry.blake3));
                save_journal(journal_path, &journal)?;
                let (bytes_written, mut bytes_reused) = op_stats(&ops);
                if bytes_reused > entry.len {
                    bytes_reused = entry.len;
                }
                total_written += bytes_written;
                total_reused += bytes_reused;
                write_msg(
                    writer,
                    &AgentMsg::Applied {
                        path,
                        bytes_written,
                        bytes_reused,
                    },
                )?;
            }
            ClientMsg::Finish => {
                write_msg(
                    writer,
                    &AgentMsg::Done {
                        bytes_written: total_written,
                        bytes_reused: total_reused,
                    },
                )?;
                return Ok(());
            }
            other => return fail(writer, format!("unexpected client message {other:?}")),
        }
    }
}

fn fail(writer: &mut impl Write, message: String) -> Result<(), ProtoError> {
    let _ = write_msg(writer, &AgentMsg::Error { message: message.clone() });
    Err(ProtoError::Protocol(message))
}

pub fn validate_rel(path: &str) -> Result<(), ProtoError> {
    if path.is_empty() || path.contains('\0') {
        return Err(ProtoError::Protocol(format!("invalid path {path}")));
    }
    let path_ref = Path::new(path);
    if path_ref.is_absolute()
        || path_ref.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ProtoError::Protocol(format!("path escapes the destination: {path}")));
    }
    Ok(())
}

fn safe_rel(path: &str) -> Result<PathBuf, ProtoError> {
    validate_rel(path)?;
    Ok(PathBuf::from(path))
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn load_journal(path: &Path) -> Journal {
    let Ok(bytes) = fs::read(path) else {
        return Journal::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_journal(path: &Path, journal: &Journal) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(journal)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    atomic_write(path, &body, 0o600)?;
    Ok(())
}

fn hash_if_exists(path: &Path) -> io::Result<Option<[u8; 32]>> {
    match read_if_exists(path)? {
        data if path.is_file() => Ok(Some(file_hash(&data))),
        _ => Ok(None),
    }
}

fn read_if_exists(path: &Path) -> io::Result<Vec<u8>> {
    match File::open(path) {
        Ok(mut file) => {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            Ok(buf)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("batch-baker-partial");
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mode = if mode == 0 { 0o644 } else { mode & 0o777 };
            options.mode(mode);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

// serde_json is used for the resume journal. Keep it inside the proto crate so
// the agent does not grow a second parser for this file.
use serde_json;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn write_msg_flushes_a_buffered_writer() {
        struct Watch {
            emitted: Vec<u8>,
            pending: Vec<u8>,
        }
        impl Write for Watch {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.pending.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.emitted.extend_from_slice(&self.pending);
                self.pending.clear();
                Ok(())
            }
        }
        let mut writer = Watch {
            emitted: Vec::new(),
            pending: Vec::new(),
        };
        write_msg(&mut writer, &AgentMsg::Hello { version: VERSION }).unwrap();
        assert!(
            writer.pending.is_empty() && !writer.emitted.is_empty(),
            "a buffered stdout must emit the frame before the next read"
        );
    }

    #[test]
    fn rolling_hash_matches_recompute() {
        let data: Vec<u8> = (0..5000u32).map(|n| (n % 251) as u8).collect();
        let (mut a, mut b) = weak_parts(&data[..BLOCK_SIZE]);
        for offset in 0..(data.len() - BLOCK_SIZE) {
            assert_eq!(pack(a, b), weak_hash(&data[offset..offset + BLOCK_SIZE]));
            if offset + BLOCK_SIZE >= data.len() {
                break;
            }
            roll(
                &mut a,
                &mut b,
                data[offset],
                data[offset + BLOCK_SIZE],
            );
        }
    }

    #[test]
    fn insert_reuses_the_tail() {
        let mut old = vec![7u8; BLOCK_SIZE * 3];
        old.extend_from_slice(b"tail-of-file");
        let sigs = block_sigs(&old);
        let mut new_data = b"inserted-byte".to_vec();
        new_data.extend_from_slice(&old);
        let ops = plan_delta(&new_data, &sigs);
        let rebuilt = apply_delta(&old, &ops);
        assert_eq!(rebuilt, new_data);
        let reused = ops
            .iter()
            .filter(|op| matches!(op, DeltaOp::Reuse { .. }))
            .count();
        assert!(reused >= 3, "expected full blocks to be reused, ops={ops:?}");
    }

    #[test]
    fn identical_file_reuses_every_full_block() {
        let old = vec![4u8; BLOCK_SIZE * 2];
        let sigs = block_sigs(&old);
        let ops = plan_delta(&old, &sigs);
        assert!(ops.iter().all(|op| matches!(op, DeltaOp::Reuse { .. })));
        assert_eq!(apply_delta(&old, &ops), old);
    }

    #[test]
    fn empty_remote_is_all_literals() {
        let new_data = b"brand new file".to_vec();
        let ops = plan_delta(&new_data, &[]);
        assert_eq!(apply_delta(&[], &ops), new_data);
        assert!(ops.iter().all(|op| matches!(op, DeltaOp::Literal { .. })));
    }

    #[test]
    fn rejects_parent_paths() {
        assert!(validate_rel("../etc/passwd").is_err());
        assert!(validate_rel("/etc/passwd").is_err());
        assert!(validate_rel("src/main.rs").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn serve_apply_round_trip_and_resume() {
        let dir = std::env::temp_dir().join(format!("bb-proto-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let root = dir.join("dest");
        let journal = dir.join("journal.json");
        fs::create_dir_all(&root).unwrap();

        let body = vec![9u8; BLOCK_SIZE + 20];
        let entry = FileEntry {
            path: "nested/file.bin".into(),
            mode: 0o644,
            len: body.len() as u64,
            blake3: file_hash(&body),
        };
        transfer(&root, &journal, &[(&entry, &body)]).unwrap();
        let written = fs::read(root.join("nested/file.bin")).unwrap();
        assert_eq!(written, body);

        let stats = transfer(&root, &journal, &[(&entry, &body)]).unwrap();
        assert_eq!(stats.0, 0, "second run should not resend a finished file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn transfer(root: &Path, journal: &Path, files: &[(&FileEntry, &[u8])]) -> io::Result<(u64, u64)> {
        use std::os::unix::net::UnixStream;
        let (mut client, mut server) = UnixStream::pair()?;
        let root = root.to_path_buf();
        let journal = journal.to_path_buf();
        let server_thread = thread::spawn(move || {
            let mut server_read = server.try_clone().unwrap();
            serve_apply(&mut server_read, &mut server, &root, &journal)
        });

        write_msg(&mut client, &ClientMsg::Hello { version: VERSION })?;
        let hello: AgentMsg = read_msg(&mut client)?;
        assert!(matches!(hello, AgentMsg::Hello { version: VERSION }));
        write_msg(
            &mut client,
            &ClientMsg::Begin {
                files: files.iter().map(|(entry, _)| (*entry).clone()).collect(),
            },
        )?;
        let plan: AgentMsg = read_msg(&mut client)?;
        let skip = match plan {
            AgentMsg::Plan { skip } => skip,
            other => panic!("plan: {other:?}"),
        };
        let mut written = 0u64;
        let mut reused = 0u64;
        for (entry, bytes) in files {
            if skip.iter().any(|path| path == &entry.path) {
                reused += entry.len;
                continue;
            }
            write_msg(
                &mut client,
                &ClientMsg::SignaturesPlease {
                    path: entry.path.clone(),
                },
            )?;
            let sigs = match read_msg::<_, AgentMsg>(&mut client)? {
                AgentMsg::Signatures {
                    unchanged, blocks, ..
                } => {
                    if unchanged {
                        reused += entry.len;
                        continue;
                    }
                    blocks
                }
                AgentMsg::Error { message } => {
                    return Err(io::Error::other(message));
                }
                other => panic!("sigs: {other:?}"),
            };
            let ops = plan_delta(bytes, &sigs);
            let (w, r) = op_stats(&ops);
            written += w;
            reused += r.min(entry.len);
            write_msg(
                &mut client,
                &ClientMsg::Delta {
                    path: entry.path.clone(),
                    ops,
                },
            )?;
            match read_msg::<_, AgentMsg>(&mut client)? {
                AgentMsg::Applied { .. } => {}
                AgentMsg::Error { message } => return Err(io::Error::other(message)),
                other => panic!("applied: {other:?}"),
            }
        }
        write_msg(&mut client, &ClientMsg::Finish)?;
        match read_msg::<_, AgentMsg>(&mut client)? {
            AgentMsg::Done { .. } => {}
            other => panic!("done: {other:?}"),
        }
        drop(client);
        server_thread.join().unwrap()?;
        Ok((written, reused))
    }
}
