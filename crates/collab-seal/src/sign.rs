//! Editor signatures on sealed batches, the editors an app trusts, and safety numbers.
//!
//! Everyone who can open a sealed file holds its key, viewers too, so a viewer working with a
//! compromised server could seal changes of its own and have the server pass them on as an
//! editor's. Editors therefore sign each batch with their device's Ed25519 key
//! ([`sign_batch`]: a [`SealedChange::Signature`] at the end of the batch), and apps check the
//! signature and that its device is one of the file's editors' ([`check_batch`] against an
//! [`EditorKeys`] list) before opening the batch.
//!
//! What a check can't settle the same way in every app (a device this app doesn't know as an
//! editor's) ends the session for that app rather than being skipped: two apps with different
//! lists would otherwise come to different documents. See `docs/accounts-and-e2e.md` ›
//! *Editor signatures*.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use figcraft_collab::sealed::{BatchSignature, SealedChange, split_signature};
use sha2::{Digest, Sha256};

use crate::SealError;
use crate::device::{DeviceKeys, DevicePublic};
use crate::seal::put_str;

/// What a batch signature's message starts with (and the format's version).
const BATCH_LABEL: &[u8] = b"figcraft batch v1";
/// What a safety number's hash starts with.
const SAFETY_LABEL: &[u8] = b"figcraft safety number v1";

/// The bytes a batch signature signs: `"figcraft batch v1" ‖ file id (u32 LE length ‖ UTF-8) ‖
/// epoch (u32 LE) ‖ base_seq (u64 LE) ‖ batch_id (u64 LE) ‖ device (32) ‖ the batch's other
/// changes (postcard, as the session messages carry them)`.
pub fn batch_message(
    file: &str,
    epoch: u32,
    base_seq: u64,
    batch_id: u64,
    device: &[u8; 32],
    changes: &[SealedChange],
) -> Result<Vec<u8>, SealError> {
    let body = postcard::to_allocvec(changes).map_err(|e| SealError::Invalid(e.to_string()))?;
    let mut out = Vec::with_capacity(BATCH_LABEL.len() + file.len() + 64 + body.len());
    out.extend_from_slice(BATCH_LABEL);
    put_str(&mut out, file);
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&base_seq.to_le_bytes());
    out.extend_from_slice(&batch_id.to_le_bytes());
    out.extend_from_slice(device);
    out.extend_from_slice(&body);
    Ok(out)
}

/// `device`'s signature of batch `batch_id` of `file` (made on server state `base_seq`, its
/// changes sealed with key epoch `epoch`): the change to append to the batch.
pub fn sign_batch(
    device: &DeviceKeys,
    file: &str,
    epoch: u32,
    base_seq: u64,
    batch_id: u64,
    changes: &[SealedChange],
) -> Result<SealedChange, SealError> {
    let public = device.public()?.signing;
    let message = batch_message(file, epoch, base_seq, batch_id, &public, changes)?;
    let signature = device.sign(&message);
    Ok(SealedChange::Signature(BatchSignature { device: public, epoch, base_seq, signature }))
}

/// How a batch is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signed {
    /// It has no signature.
    Unsigned,
    /// Signed by the device with this Ed25519 public key, and the signature holds.
    By([u8; 32]),
    /// A signature that doesn't hold (changed bytes, another file or batch), or isn't where it
    /// belongs (last, and only one).
    Bad,
}

/// Check the signature at the end of batch `batch_id` of `file` (strict Ed25519 verification).
pub fn verify_batch(file: &str, batch_id: u64, changes: &[SealedChange]) -> Signed {
    let Ok((body, sig)) = split_signature(changes) else { return Signed::Bad };
    let Some(sig) = sig else { return Signed::Unsigned };
    let Ok(message) = batch_message(file, sig.epoch, sig.base_seq, batch_id, &sig.device, body) else { return Signed::Bad };
    let Ok(key) = VerifyingKey::from_bytes(&sig.device) else { return Signed::Bad };
    if key.verify_strict(&message, &Signature::from_bytes(&sig.signature)).is_ok() { Signed::By(sig.device) } else { Signed::Bad }
}

/// The editors of a sealed file an app knows, by device signing key: what [`check_batch`]
/// checks signatures against. Step 9's device registry provides the real list (each editor's
/// registered devices, kept up to date as people and devices come and go); [`AnyEditor`] is the
/// links-mode default (no registry: any intact signature, or none), [`KnownEditors`] a fixed list.
pub trait EditorKeys: Send + Sync {
    /// Whether every batch must be signed by a known editor device (`false`: unsigned batches
    /// are taken, as from apps that have no device key).
    fn required(&self) -> bool;
    /// Whether the device with Ed25519 public key `device` belongs to someone who may edit the
    /// file.
    fn is_editor(&self, device: &[u8; 32]) -> bool;
}

/// No list of editors (a link to a file on a server without accounts: whoever holds an edit link
/// edits). Signatures that are there must hold; unsigned batches are taken.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnyEditor;

impl EditorKeys for AnyEditor {
    fn required(&self) -> bool {
        false
    }

    fn is_editor(&self, _: &[u8; 32]) -> bool {
        true
    }
}

/// A fixed list of editor devices; every batch must be signed by one of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnownEditors {
    devices: BTreeSet<[u8; 32]>,
}

impl KnownEditors {
    /// The editors' devices by their public keys.
    pub fn new<'a>(devices: impl IntoIterator<Item = &'a DevicePublic>) -> KnownEditors {
        KnownEditors { devices: devices.into_iter().map(|d| d.signing).collect() }
    }

    /// Add a device's signing key.
    pub fn insert(&mut self, signing: [u8; 32]) {
        self.devices.insert(signing);
    }
}

impl EditorKeys for KnownEditors {
    fn required(&self) -> bool {
        true
    }

    fn is_editor(&self, device: &[u8; 32]) -> bool {
        self.devices.contains(device)
    }
}

/// Why an app won't take a batch: the session can't go on (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BatchRefused {
    #[error("a change to this encrypted file has a signature that doesn't hold: it was changed on the way, so the session was left")]
    Bad,
    #[error(
        "a change to this encrypted file wasn't signed by an editor: the session was left (someone without the right to edit, or the server, may have made it)"
    )]
    Unsigned,
    #[error("a change to this encrypted file was signed by a device that isn't one of its editors' (yet): the session was left")]
    NotEditor,
}

/// Check a sealed batch's signature against `editors`: the batch's changes without the signature
/// when it may be opened.
pub fn check_batch<'a>(editors: &dyn EditorKeys, file: &str, batch_id: u64, changes: &'a [SealedChange]) -> Result<&'a [SealedChange], BatchRefused> {
    match verify_batch(file, batch_id, changes) {
        Signed::Bad => Err(BatchRefused::Bad),
        Signed::Unsigned if editors.required() => Err(BatchRefused::Unsigned),
        Signed::By(device) if !editors.is_editor(&device) => Err(BatchRefused::NotEditor),
        Signed::Unsigned | Signed::By(_) => Ok(split_signature(changes).map(|(body, _)| body).unwrap_or_default()),
    }
}

/// A short number someone reads out or compares to check another person's device keys (a
/// key-change warning names the person; comparing numbers out of band tells a real new device from
/// one a server slipped in): 12 decimal digits in three groups of four (`1234 5678 9012`), from
/// SHA-256 of `"figcraft safety number v1"` and the devices' public keys (agreement ‖ signing,
/// sorted, duplicates once). The same set of keys gives the same number in any order; any change
/// to the set changes it.
pub fn safety_number(devices: &[DevicePublic]) -> String {
    let mut keys: Vec<[u8; 64]> = devices
        .iter()
        .map(|d| {
            let mut k = [0u8; 64];
            k[..32].copy_from_slice(&d.agreement);
            k[32..].copy_from_slice(&d.signing);
            k
        })
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let mut h = Sha256::new();
    h.update(SAFETY_LABEL);
    h.update(u32::try_from(keys.len()).unwrap_or(u32::MAX).to_le_bytes());
    for k in &keys {
        h.update(k);
    }
    let digest = h.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(digest.get(..8).unwrap_or(&[0; 8]));
    let n = u64::from_le_bytes(first) % 1_000_000_000_000;
    let digits = format!("{n:012}");
    format!("{} {} {}", digits.get(..4).unwrap_or_default(), digits.get(4..8).unwrap_or_default(), digits.get(8..).unwrap_or_default())
}
