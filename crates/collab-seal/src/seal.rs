//! Sealing and opening values: padding, associated data, XChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use figcraft_collab::{DocProp, Prop};
use figcraft_doc::NodeId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::change::EntryKey;
use crate::keys::{FileKey, Keyring};
use crate::{SealError, random};

/// Largest plaintext [`seal`] takes: padded with its length prefix, it fills 64 MiB.
pub const MAX_PLAINTEXT: usize = (1 << 26) - 4;
/// Epoch (4) and nonce (24) in front of the ciphertext.
const HEADER: usize = 4 + 24;
/// The Poly1305 tag after it.
const TAG: usize = 16;
/// The smallest padded plaintext.
const MIN_PADDED: usize = 64;
/// What the associated data starts with (the format's version).
const AD_PREFIX: &[u8] = b"figcraft sealed v1";

/// Where a sealed value belongs. It is bound into the value (associated data), so a server can't
/// move a value to another node, property, entry, sender or file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    /// Property `prop` of node `id` (a created node's kind is `Prop::Kind`).
    Node { id: NodeId, prop: Prop },
    /// A document-level property.
    Doc { prop: DocProp },
    /// A document-level entry's value.
    Entry(EntryKey),
    /// A named entry's name (sealed next to its [`entry_id`](crate::entry_id)).
    EntryName(EntryKey),
    /// The presence of the session client `client`.
    Presence { client: u32 },
    /// A signal (cursor chat) from session client `client`.
    Signal { client: u32 },
    /// File-level data outside the document: `"name"` (the file name), `"library"` (a team
    /// library archive)…
    Meta { what: String },
}

impl Slot {
    /// The slot as associated-data bytes: a tag byte, then its fields (numbers little-endian,
    /// strings as u32 LE length and UTF-8; property names are their serde names).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), SealError> {
        match self {
            Slot::Node { id, prop } => {
                out.push(1);
                out.extend_from_slice(&id.0.to_le_bytes());
                put_str(out, &serde_name(prop)?);
            }
            Slot::Doc { prop } => {
                out.push(2);
                put_str(out, &serde_name(prop)?);
            }
            Slot::Entry(key) => {
                out.push(3);
                key.encode(out);
            }
            Slot::EntryName(key) => {
                out.push(4);
                key.encode(out);
            }
            Slot::Presence { client } => {
                out.push(5);
                out.extend_from_slice(&client.to_le_bytes());
            }
            Slot::Signal { client } => {
                out.push(6);
                out.extend_from_slice(&client.to_le_bytes());
            }
            Slot::Meta { what } => {
                out.push(7);
                put_str(out, what);
            }
        }
        Ok(())
    }

    /// The subkey this slot's values are sealed with.
    fn subkey(&self, key: &FileKey) -> Result<Zeroizing<[u8; 32]>, SealError> {
        match self {
            Slot::Node { .. } | Slot::Doc { .. } | Slot::Entry(_) | Slot::EntryName(_) => key.value_key(),
            Slot::Presence { .. } | Slot::Signal { .. } => key.presence_key(),
            Slot::Meta { .. } => key.meta_key(),
        }
    }
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The serde name of a unit enum variant (`Prop::Fills` → `fills`).
fn serde_name<T: Serialize>(v: &T) -> Result<String, SealError> {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(SealError::Invalid("property name".into())),
    }
}

/// A sealed value: `epoch (u32 LE) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, XChaCha20-Poly1305 over
/// the padded plaintext (see [`padded_len`]). Its length always says the padded size, so a server
/// can check it and nothing else: [`Sealed::from_bytes`] (and deserializing) accepts only lengths a
/// real sealed value has.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SealedBytes", into = "SealedBytes")]
pub struct Sealed(Vec<u8>);

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealed(epoch {}, {} bytes)", self.epoch(), self.0.len())
    }
}

/// Serde form of [`Sealed`]: bytes, or base64url in JSON.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SealedBytes(#[serde(with = "crate::bin")] Vec<u8>);

impl TryFrom<SealedBytes> for Sealed {
    type Error = SealError;
    fn try_from(b: SealedBytes) -> Result<Sealed, SealError> {
        Sealed::from_bytes(b.0)
    }
}

impl From<Sealed> for SealedBytes {
    fn from(s: Sealed) -> SealedBytes {
        SealedBytes(s.0)
    }
}

impl Sealed {
    /// Check the shape of untrusted bytes (length only: whether they open is [`open`]'s job).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Sealed, SealError> {
        let padded = bytes.len().checked_sub(HEADER + TAG).ok_or(SealError::Malformed("sealed value"))?;
        if !(MIN_PADDED..=MAX_PLAINTEXT + 4).contains(&padded) || padded_len(padded.saturating_sub(4)) != Some(padded) {
            return Err(SealError::Malformed("sealed value"));
        }
        Ok(Sealed(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The epoch of the key it was sealed with.
    pub fn epoch(&self) -> u32 {
        let mut e = [0u8; 4];
        if let Some(b) = self.0.get(..4) {
            e.copy_from_slice(b);
        }
        u32::from_le_bytes(e)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The padded size of an `n`-byte plaintext: its 4-byte length prefix and the plaintext, rounded
/// up to 64 B, 256 B, 1 KiB, then the next power of two (`None` above [`MAX_PLAINTEXT`]).
pub fn padded_len(n: usize) -> Option<usize> {
    if n > MAX_PLAINTEXT {
        return None;
    }
    let framed = n + 4;
    Some(match framed {
        0..=64 => 64,
        65..=256 => 256,
        257..=1024 => 1024,
        _ => framed.next_power_of_two(),
    })
}

/// `u32 LE length ‖ plaintext ‖ zeros`, [`padded_len`] bytes.
fn pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let size = padded_len(plaintext.len()).ok_or(SealError::TooLarge(plaintext.len()))?;
    let len = u32::try_from(plaintext.len()).map_err(|_| SealError::TooLarge(plaintext.len()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(size, 0);
    Ok(out)
}

/// The plaintext inside padded bytes; the padding must be canonical (right size, all zeros).
fn unpad(padded: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut len = [0u8; 4];
    len.copy_from_slice(padded.get(..4).ok_or(SealError::Malformed("padding"))?);
    let len = usize::try_from(u32::from_le_bytes(len)).map_err(|_| SealError::Malformed("padding"))?;
    if padded_len(len) != Some(padded.len()) {
        return Err(SealError::Malformed("padding"));
    }
    let end = len.checked_add(4).ok_or(SealError::Malformed("padding"))?;
    let body = padded.get(4..end).ok_or(SealError::Malformed("padding"))?;
    if padded.get(end..).is_none_or(|rest| rest.iter().any(|&b| b != 0)) {
        return Err(SealError::Malformed("padding"));
    }
    Ok(body.to_vec())
}

/// The associated data: `"figcraft sealed v1" ‖ u32 LE file id length ‖ file id ‖ epoch (u32 LE)
/// ‖ slot` ([`Slot::encode`]).
fn associated_data(file: &str, epoch: u32, slot: &Slot) -> Result<Vec<u8>, SealError> {
    let mut ad = Vec::with_capacity(64 + file.len());
    ad.extend_from_slice(AD_PREFIX);
    put_str(&mut ad, file);
    ad.extend_from_slice(&epoch.to_le_bytes());
    slot.encode(&mut ad)?;
    Ok(ad)
}

/// Seal `plaintext` for `slot` of `file` with `key` (a fresh random nonce every time).
pub fn seal(key: &FileKey, file: &str, slot: &Slot, plaintext: &[u8]) -> Result<Sealed, SealError> {
    let padded = pad(plaintext)?;
    let ad = associated_data(file, key.epoch(), slot)?;
    let subkey = slot.subkey(key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(subkey.as_slice()).map_err(|_| SealError::Key("cipher key"))?;
    let nonce_bytes = random::bytes::<24>()?;
    let nonce = XNonce::from(*nonce_bytes);
    let ct = cipher.encrypt(&nonce, Payload { msg: &padded, aad: &ad }).map_err(|_| SealError::TooLarge(plaintext.len()))?;
    let mut out = Vec::with_capacity(HEADER + ct.len());
    out.extend_from_slice(&key.epoch().to_le_bytes());
    out.extend_from_slice(nonce_bytes.as_slice());
    out.extend_from_slice(&ct);
    Ok(Sealed(out))
}

/// Open a value sealed for `slot` of `file` with whichever key of `keyring` its epoch names.
pub fn open(keyring: &Keyring, file: &str, slot: &Slot, sealed: &Sealed) -> Result<Vec<u8>, SealError> {
    let bytes = sealed.as_bytes();
    if bytes.len() < HEADER + TAG + MIN_PADDED {
        return Err(SealError::Malformed("sealed value"));
    }
    let epoch = sealed.epoch();
    let key = keyring.get(epoch).ok_or(SealError::UnknownEpoch(epoch))?;
    let nonce_bytes: [u8; 24] = bytes.get(4..HEADER).and_then(|b| b.try_into().ok()).ok_or(SealError::Malformed("sealed value"))?;
    let ct = bytes.get(HEADER..).ok_or(SealError::Malformed("sealed value"))?;
    let ad = associated_data(file, epoch, slot)?;
    let subkey = slot.subkey(key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(subkey.as_slice()).map_err(|_| SealError::Key("cipher key"))?;
    let padded = Zeroizing::new(cipher.decrypt(&XNonce::from(nonce_bytes), Payload { msg: ct, aad: &ad }).map_err(|_| SealError::Open)?);
    unpad(&padded)
}
