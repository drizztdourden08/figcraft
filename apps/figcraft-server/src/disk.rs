//! The server's files on disk and reading them back without trusting them: atomic writes (a
//! temporary file beside the target, flushed, then renamed over it), the snapshot format and the
//! append-only log format.
//!
//! - `snapshot.bin`: `FCSN`, a format byte, the generation (u64 LE), a CRC-32 of the rest (u32 LE),
//!   then the session state ([`SessionState`] in the wire encoding).
//! - `log.bin`: `FCLG`, a format byte, the generation of the snapshot it continues, then records:
//!   length (u32 LE), CRC-32 (u32 LE), one [`Journal`] entry in the wire encoding.
//!
//! The format byte is 1 for plain files and 2 for sealed files, whose snapshot holds a
//! [`SealedSessionState`] and whose log [`SealedJournal`] entries (sealed values the server can't
//! read; servers from before sealed files refuse them as a format they don't read).
//!
//! Compaction writes the next generation's snapshot, then an empty log of that generation. A log
//! whose generation isn't the snapshot's is from before a compaction that was cut short: what it
//! holds is in the snapshot already. A log ends at its first damaged record (a write cut short).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use figcraft_collab::message;
use figcraft_collab::{Journal, SealedJournal, SealedSessionState, SessionState};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub const SNAPSHOT: &str = "snapshot.bin";
pub const LOG: &str = "log.bin";
pub const META: &str = "meta.json";
pub const LINKS: &str = "links.json";
pub const LIBRARY: &str = "library.bin";
pub const USAGE: &str = "usage.json";

const SNAP_MAGIC: &[u8; 4] = b"FCSN";
const LOG_MAGIC: &[u8; 4] = b"FCLG";
const FORMAT: u8 = 1;
const SEALED_FORMAT: u8 = 2;
const SNAP_HEADER: usize = 4 + 1 + 8 + 4;
pub const LOG_HEADER: usize = 4 + 1 + 8;
const RECORD_HEADER: usize = 8;

/// Free space on the disk holding `path`, in bytes, where it can be told (Unix).
pub fn free_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        rustix::fs::statvfs(path).ok().map(|s| s.f_bavail.saturating_mul(s.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// `path` with `.tmp` added: where its next version is written first.
pub fn temp_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Replace `path` with `bytes` atomically: a reader sees the old or the new content, never a mix.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_as(path, bytes, false)
}

/// [`write_atomic`] for a secret: on Unix only the owner can read it, from the moment it exists.
pub fn write_atomic_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_as(path, bytes, true)
}

fn write_atomic_as(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    let tmp = temp_of(path);
    {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path.parent());
    Ok(())
}

/// Make a rename in `dir` durable (directories can't be opened for that on Windows).
pub fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(d) = dir
        && let Ok(f) = File::open(d)
    {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Read a file of at most `max` bytes (a longer one is refused without being read).
pub fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = File::open(path).map_err(|e| format!("can't open {}: {e}", name(path)))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len > max {
        return Err(format!("{} is {} bytes, over the {max}-byte cap", name(path), len));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    f.take(max).read_to_end(&mut bytes).map_err(|e| format!("can't read {}: {e}", name(path)))?;
    Ok(bytes)
}

fn name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes)
}

/// A snapshot file's bytes.
pub fn encode_snapshot(generation: u64, state: &SessionState) -> Result<Vec<u8>, String> {
    encode_snapshot_as(generation, FORMAT, state)
}

/// A sealed file's snapshot file's bytes.
pub fn encode_sealed_snapshot(generation: u64, state: &SealedSessionState) -> Result<Vec<u8>, String> {
    encode_snapshot_as(generation, SEALED_FORMAT, state)
}

fn encode_snapshot_as<T: Serialize>(generation: u64, format: u8, state: &T) -> Result<Vec<u8>, String> {
    let body = message::encode(state).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(SNAP_HEADER + body.len());
    out.extend_from_slice(SNAP_MAGIC);
    out.push(format);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&crc(&body).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// A snapshot's format, generation and body, when its header and checksum are right.
fn snapshot_body(bytes: &[u8]) -> Result<(u8, u64, &[u8]), String> {
    if bytes.get(..4) != Some(SNAP_MAGIC.as_slice()) {
        return Err("the snapshot isn't one (wrong header)".into());
    }
    let format = match bytes.get(4) {
        Some(&f) if f == FORMAT || f == SEALED_FORMAT => f,
        _ => return Err("the snapshot is in a format this version doesn't read".into()),
    };
    let (Some(generation), Some(sum), Some(body)) = (u64_at(bytes, 5), u32_at(bytes, 13), bytes.get(SNAP_HEADER..)) else {
        return Err("the snapshot is cut short".into());
    };
    if crc(body) != sum {
        return Err("the snapshot is damaged (checksum mismatch)".into());
    }
    Ok((format, generation, body))
}

/// A snapshot's generation, after checking its header and checksum (no decoding).
pub fn check_snapshot(bytes: &[u8]) -> Result<u64, String> {
    snapshot_body(bytes).map(|(_, g, _)| g)
}

fn decode_snapshot_as<T: DeserializeOwned>(bytes: &[u8], format: u8) -> Result<(u64, T), String> {
    let (found, generation, body) = snapshot_body(bytes)?;
    if found != format {
        return Err(if format == SEALED_FORMAT { "the snapshot isn't a sealed file's" } else { "the snapshot is a sealed file's" }.into());
    }
    let state = message::decode::<T>(body, body.len()).map_err(|e| format!("the snapshot can't be read: {e}"))?;
    Ok((generation, state))
}

/// A snapshot's generation and session state.
pub fn decode_snapshot(bytes: &[u8]) -> Result<(u64, SessionState), String> {
    decode_snapshot_as(bytes, FORMAT)
}

/// A sealed file's snapshot's generation and session state.
pub fn decode_sealed_snapshot(bytes: &[u8]) -> Result<(u64, SealedSessionState), String> {
    decode_snapshot_as(bytes, SEALED_FORMAT)
}

/// An empty log continuing snapshot `generation`.
pub fn log_header(generation: u64) -> Vec<u8> {
    log_header_as(generation, FORMAT)
}

/// An empty log of a sealed file continuing snapshot `generation`.
pub fn sealed_log_header(generation: u64) -> Vec<u8> {
    log_header_as(generation, SEALED_FORMAT)
}

fn log_header_as(generation: u64, format: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(LOG_HEADER);
    out.extend_from_slice(LOG_MAGIC);
    out.push(format);
    out.extend_from_slice(&generation.to_le_bytes());
    out
}

/// One log record (a [`Journal`] or [`SealedJournal`] entry).
pub fn record<T: Serialize>(entry: &T) -> Result<Vec<u8>, String> {
    let body = message::encode(entry).map_err(|e| e.to_string())?;
    let len = u32::try_from(body.len()).map_err(|_| "a journal entry over 4 GiB".to_string())?;
    let mut out = Vec::with_capacity(RECORD_HEADER + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc(&body).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// What a log holds.
#[derive(Debug)]
pub struct LogRead<J = Journal> {
    pub generation: u64,
    pub entries: Vec<J>,
    /// Why it ends before the end of the file (a damaged or cut-short record), if it does.
    pub damaged: Option<String>,
}

/// Read a log: its generation and the entries up to the first damaged record. Only a header that
/// isn't a log's is an error.
pub fn read_log(bytes: &[u8]) -> Result<LogRead, String> {
    read_log_as(bytes, FORMAT)
}

/// [`read_log`] for a sealed file's log.
pub fn read_sealed_log(bytes: &[u8]) -> Result<LogRead<SealedJournal>, String> {
    read_log_as(bytes, SEALED_FORMAT)
}

/// The generation a log (plain or sealed) continues.
pub fn log_generation(bytes: &[u8]) -> Result<u64, String> {
    if bytes.get(..4) != Some(LOG_MAGIC.as_slice()) {
        return Err("the log isn't one (wrong header)".into());
    }
    u64_at(bytes, 5).ok_or_else(|| "the log is cut short".into())
}

fn read_log_as<J: DeserializeOwned>(bytes: &[u8], format: u8) -> Result<LogRead<J>, String> {
    if bytes.get(..4) != Some(LOG_MAGIC.as_slice()) {
        return Err("the log isn't one (wrong header)".into());
    }
    if bytes.get(4) != Some(&format) {
        return Err("the log is in a format this version doesn't read".into());
    }
    let generation = u64_at(bytes, 5).ok_or("the log is cut short")?;
    let mut at = LOG_HEADER;
    let mut entries = Vec::new();
    let mut damaged = None;
    while at < bytes.len() {
        let (Some(len), Some(sum)) = (u32_at(bytes, at), u32_at(bytes, at + 4)) else {
            damaged = Some(format!("a record cut short at byte {at}"));
            break;
        };
        let start = at + RECORD_HEADER;
        let Some(body) = usize::try_from(len).ok().and_then(|n| bytes.get(start..start.checked_add(n)?)) else {
            damaged = Some(format!("a record cut short at byte {at}"));
            break;
        };
        if crc(body) != sum {
            damaged = Some(format!("a damaged record at byte {at}"));
            break;
        }
        match message::decode::<J>(body, body.len()) {
            Ok(e) => entries.push(e),
            Err(e) => {
                damaged = Some(format!("an unreadable record at byte {at} ({e})"));
                break;
            }
        }
        at = start + body.len();
    }
    Ok(LogRead { generation, entries, damaged })
}
