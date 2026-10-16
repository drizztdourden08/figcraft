//! File keys, their subkeys, keyrings, entry ids and link keys.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{SealError, random};

/// HKDF info labels (`docs/accounts-and-e2e.md` › *Keys*).
pub(crate) const VALUE_LABEL: &[u8] = b"figcraft value";
pub(crate) const ENTRY_LABEL: &[u8] = b"figcraft entry";
pub(crate) const PRESENCE_LABEL: &[u8] = b"figcraft presence";
pub(crate) const META_LABEL: &[u8] = b"figcraft meta";

/// Bytes of [`FileKey::to_bytes`]: epoch (u32 LE) ‖ key (32) ‖ names secret (32).
pub(crate) const FILE_KEY_LEN: usize = 4 + 32 + 32;

/// One epoch of a file's key.
///
/// - `key`: 32 random bytes, new for every epoch. Values, presence and meta are sealed with
///   subkeys derived from it (HKDF-SHA256, no salt, info `"figcraft value"`, `"figcraft presence"`,
///   `"figcraft meta"`), so removing someone and starting a new epoch locks them out of new writes.
/// - `names`: 32 random bytes made once with the file and **carried unchanged into every epoch**.
///   The entry key (HKDF-SHA256, info `"figcraft entry"`) comes from it, so [`entry_id`]s stay the
///   same across epochs: the server keys styles, variables, collections and images by entry id,
///   and a rotation that changed every id would orphan every stored entry (or force rewriting them
///   all). The cost: someone removed from a file can still compute the ids of names they guess;
///   they can't read any value written after their removal.
///
/// Secrets are wiped from memory on drop and never printed by `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileKey {
    epoch: u32,
    key: [u8; 32],
    names: [u8; 32],
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey").field("epoch", &self.epoch).finish_non_exhaustive()
    }
}

impl PartialEq for FileKey {
    /// Constant time in the secret bytes.
    fn eq(&self, other: &FileKey) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.key.iter().chain(&self.names).zip(other.key.iter().chain(&other.names)) {
            diff |= a ^ b;
        }
        self.epoch == other.epoch && diff == 0
    }
}

impl Eq for FileKey {}

impl FileKey {
    /// A new file's first key (epoch 0) with a new names secret.
    pub fn generate() -> Result<FileKey, SealError> {
        Ok(FileKey { epoch: 0, key: *random::bytes::<32>()?, names: *random::bytes::<32>()? })
    }

    /// The next epoch's key: a new random key, the same names secret.
    pub fn rotate(&self) -> Result<FileKey, SealError> {
        let epoch = self.epoch.checked_add(1).ok_or(SealError::Key("epoch counter exhausted"))?;
        Ok(FileKey { epoch, key: *random::bytes::<32>()?, names: self.names })
    }

    /// A key from its parts (test vectors, and keys kept elsewhere).
    pub fn from_parts(epoch: u32, key: [u8; 32], names: [u8; 32]) -> FileKey {
        FileKey { epoch, key, names }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// `epoch (u32 LE) ‖ key (32) ‖ names (32)`: 68 bytes, what links, wrapping and keychains carry.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(FILE_KEY_LEN));
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.names);
        out
    }

    /// Read [`to_bytes`](Self::to_bytes) back.
    pub fn from_bytes(bytes: &[u8]) -> Result<FileKey, SealError> {
        if bytes.len() != FILE_KEY_LEN {
            return Err(SealError::Malformed("file key"));
        }
        let mut epoch = [0u8; 4];
        let mut key = [0u8; 32];
        let mut names = [0u8; 32];
        epoch.copy_from_slice(bytes.get(..4).ok_or(SealError::Malformed("file key"))?);
        key.copy_from_slice(bytes.get(4..36).ok_or(SealError::Malformed("file key"))?);
        names.copy_from_slice(bytes.get(36..68).ok_or(SealError::Malformed("file key"))?);
        let k = FileKey { epoch: u32::from_le_bytes(epoch), key, names };
        key.zeroize();
        names.zeroize();
        Ok(k)
    }

    pub(crate) fn value_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        hkdf(&self.key, VALUE_LABEL)
    }

    pub(crate) fn presence_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        hkdf(&self.key, PRESENCE_LABEL)
    }

    pub(crate) fn meta_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        hkdf(&self.key, META_LABEL)
    }

    pub(crate) fn entry_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        hkdf(&self.names, ENTRY_LABEL)
    }
}

/// HKDF-SHA256 with no salt: 32 bytes of output for `info`.
pub(crate) fn hkdf(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm).expand(info, out.as_mut_slice()).map_err(|_| SealError::Key("HKDF output length"))?;
    Ok(out)
}

/// HMAC-SHA256 of `parts` (concatenated) under `key`.
pub(crate) fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], SealError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| SealError::Key("HMAC key"))?;
    for p in parts {
        mac.update(p);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// The id a sealed file keys a named entry by (a style, collection or variable id, or an image
/// hash): HMAC-SHA256 under the entry key, as 43 characters of unpadded base64url. The same for
/// every epoch of a file (see [`FileKey`]); different between files.
pub fn entry_id(key: &FileKey, name: &str) -> Result<String, SealError> {
    let k = key.entry_key()?;
    Ok(URL_SAFE_NO_PAD.encode(hmac(k.as_slice(), &[name.as_bytes()])?))
}

/// A file's keys by epoch: what someone holding the file can open.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    keys: BTreeMap<u32, FileKey>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring").field("epochs", &self.keys.keys().collect::<Vec<_>>()).finish()
    }
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring::default()
    }

    /// Add (or replace) the key of its epoch.
    pub fn insert(&mut self, key: FileKey) {
        self.keys.insert(key.epoch, key);
    }

    pub fn get(&self, epoch: u32) -> Option<&FileKey> {
        self.keys.get(&epoch)
    }

    /// The newest epoch's key: the one new writes are sealed with.
    pub fn current(&self) -> Option<&FileKey> {
        self.keys.values().next_back()
    }

    pub fn epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.keys.keys().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many epochs it holds.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Add every epoch of `other` (an epoch already here keeps its key).
    pub fn merge(&mut self, other: &Keyring) {
        for (e, k) in &other.keys {
            self.keys.entry(*e).or_insert_with(|| k.clone());
        }
    }
}

impl From<FileKey> for Keyring {
    fn from(key: FileKey) -> Keyring {
        let mut k = Keyring::new();
        k.insert(key);
        k
    }
}

/// A share link's fragment carrying `key`: `k=` then the unpadded base64url of
/// [`FileKey::to_bytes`] (91 characters). Put after `#`, which browsers and the app never send to
/// a server.
pub fn link_fragment(key: &FileKey) -> String {
    format!("k={}", URL_SAFE_NO_PAD.encode(key.to_bytes().as_slice()))
}

/// The file key in a link fragment (with or without the `#`; other `&`-separated parameters are
/// ignored).
pub fn parse_link_fragment(fragment: &str) -> Result<FileKey, SealError> {
    let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
    let value = fragment.split('&').find_map(|p| p.strip_prefix("k=")).ok_or(SealError::Malformed("link key"))?;
    if value.len() > 128 {
        return Err(SealError::Malformed("link key"));
    }
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).map_err(|_| SealError::Malformed("link key"))?);
    FileKey::from_bytes(&bytes)
}

/// Most epochs a link fragment carries ([`ring_fragment`], [`parse_ring_fragment`]).
pub const MAX_LINK_EPOCHS: usize = 1024;

/// A fragment carrying every epoch of `ring`, oldest first: `k=…&k=…` (each as in
/// [`link_fragment`]; the newest is the one new writes are sealed with). A file that never changed
/// epochs has one, the same text as [`link_fragment`]. At most [`MAX_LINK_EPOCHS`] (the newest).
pub fn ring_fragment(ring: &Keyring) -> String {
    let skip = ring.len().saturating_sub(MAX_LINK_EPOCHS);
    ring.keys.values().skip(skip).map(link_fragment).collect::<Vec<_>>().join("&")
}

/// Every key in a link fragment (each `k=…` parameter; with or without the `#`; other parameters
/// are ignored). Fails when there is none, more than [`MAX_LINK_EPOCHS`], or one isn't a key.
pub fn parse_ring_fragment(fragment: &str) -> Result<Keyring, SealError> {
    let fragment = fragment.strip_prefix('#').unwrap_or(fragment);
    let mut ring = Keyring::new();
    for (i, p) in fragment.split('&').filter(|p| p.starts_with("k=")).enumerate() {
        if i >= MAX_LINK_EPOCHS {
            return Err(SealError::Malformed("link key"));
        }
        ring.insert(parse_link_fragment(p)?);
    }
    if ring.is_empty() {
        return Err(SealError::Malformed("link key"));
    }
    Ok(ring)
}
