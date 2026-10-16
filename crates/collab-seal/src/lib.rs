//! Sealed (end-to-end encrypted) files: the cryptography and the data, no I/O.
//!
//! A sealed file keeps its structure visible to the session server (node ids, kinds, the tree,
//! which properties change) and encrypts its contents. See `docs/accounts-and-e2e.md` › *Sealed
//! files* for the design; this crate is its step 6:
//!
//! - [`FileKey`] and [`Keyring`]: a file's key per epoch, and the subkeys derived from it with
//!   HKDF-SHA256 (values, presence, meta) plus the per-file names secret entry ids come from.
//! - [`seal`] and [`open`]: a value bound to its file, epoch and [`Slot`], padded to a size bucket
//!   and encrypted with XChaCha20-Poly1305 ([`Sealed`]).
//! - [`entry_id`]: HMAC-SHA256 of a style, collection, variable or image name, so the server can
//!   key entries without learning their names.
//! - [`SealedChange`], [`seal_change`] and [`open_change`]: a [`figcraft_collab::Change`] with its
//!   values sealed; [`seal_presence`], [`seal_signal`] and their `open_` counterparts.
//! - [`DeviceKeys`]: an install's X25519 key (file keys are wrapped to it with RFC 9180 HPKE,
//!   [`wrap`] / [`unwrap`]) and Ed25519 key ([`DeviceKeys::sign`], [`verify`]).
//! - [`link_fragment`] / [`parse_link_fragment`]: a file key in a share link's `#k=` fragment.
//! - [`RecoveryKey`]: 32 random bytes written as grouped base32 with a checksum, sealing a copy of
//!   someone's keyring.
//!
//! Every parser takes untrusted bytes and fails with a [`SealError`]; nothing here panics.

mod bin;
mod change;
mod device;
mod keys;
mod random;
mod recovery;
mod seal;

#[cfg(test)]
mod tests;

pub use change::{
    EntryKey, SealedChange, SealedEntry, is_container_tag, is_page_tag, kind_tag, node_kind_tag, open_change, open_presence, open_signal,
    seal_change, seal_presence, seal_signal,
};
pub use device::{DeviceKeys, DevicePublic, Wrapped, unwrap, verify, wrap};
pub use keys::{FileKey, Keyring, entry_id, link_fragment, parse_link_fragment};
pub use recovery::RecoveryKey;
pub use seal::{MAX_PLAINTEXT, Sealed, Slot, open, padded_len, seal};

/// Why something couldn't be sealed, opened, decoded or unwrapped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The system's random number generator failed.
    #[error("no randomness available")]
    Random,
    /// A plaintext larger than [`MAX_PLAINTEXT`].
    #[error("value too large to seal ({0} bytes)")]
    TooLarge(usize),
    /// The sealed value's epoch isn't in the keyring.
    #[error("no key for epoch {0}")]
    UnknownEpoch(u32),
    /// Bytes too short or otherwise not in the expected format.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// Decryption failed: wrong key, wrong file or slot, or the bytes were changed.
    #[error("the value doesn't open with this key, file and slot")]
    Open,
    /// The value opened but isn't what its slot or change says it is.
    #[error("invalid sealed value: {0}")]
    Invalid(String),
    /// A key can't be used (e.g. the epoch counter is exhausted).
    #[error("key error: {0}")]
    Key(&'static str),
}
