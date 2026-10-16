//! Recovery keys: 32 random bytes someone writes down, which seal a copy of their keyring.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keys::hkdf;
use crate::{SealError, random};

const LABEL: &[u8] = b"figcraft recovery";
const AD_PREFIX: &[u8] = b"figcraft recovery v1";
/// Characters per group when written.
const GROUP: usize = 5;
/// Longest input [`RecoveryKey::parse`] looks at.
const MAX_INPUT: usize = 256;

/// A recovery key, written as 55 RFC 4648 base32 characters (A–Z, 2–7) in 11 groups of 5
/// (`ABCDE-FGHIJ-…`): the 32 key bytes then 2 checksum bytes (the start of SHA-256 of the key),
/// so a mistyped key is caught before trying it. Words were considered; a wordlist of our own
/// would need careful design, and base32 is unambiguous to read and type. Reading forgives case,
/// spaces and dashes, and `0`/`1`/`8` typed for `O`/`I`/`B`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl RecoveryKey {
    pub fn generate() -> Result<RecoveryKey, SealError> {
        Ok(RecoveryKey(*random::bytes::<32>()?))
    }

    fn checksum(key: &[u8; 32]) -> [u8; 2] {
        let h = Sha256::digest(key);
        [h.first().copied().unwrap_or(0), h.get(1).copied().unwrap_or(0)]
    }

    /// The key as people write it down: `XXXXX-XXXXX-…` (11 groups).
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(34));
        bytes.extend_from_slice(&self.0);
        bytes.extend_from_slice(&RecoveryKey::checksum(&self.0));
        let text = Zeroizing::new(BASE32_NOPAD.encode(&bytes));
        let mut out = Zeroizing::new(String::with_capacity(text.len() + text.len() / GROUP));
        for (i, c) in text.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Read a written-down key back.
    pub fn parse(text: &str) -> Result<RecoveryKey, SealError> {
        if text.len() > MAX_INPUT {
            return Err(SealError::Malformed("recovery key"));
        }
        let clean: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| match c.to_ascii_uppercase() {
                    '0' => 'O',
                    '1' => 'I',
                    '8' => 'B',
                    c => c,
                })
                .collect(),
        );
        let bytes = Zeroizing::new(BASE32_NOPAD.decode(clean.as_bytes()).map_err(|_| SealError::Malformed("recovery key"))?);
        let key: [u8; 32] = bytes.get(..32).and_then(|b| b.try_into().ok()).ok_or(SealError::Malformed("recovery key"))?;
        let key = RecoveryKey(key);
        if bytes.len() != 34 || bytes.get(32..) != Some(&RecoveryKey::checksum(&key.0)[..]) {
            return Err(SealError::Malformed("recovery key"));
        }
        Ok(key)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, SealError> {
        let k = hkdf(&self.0, LABEL)?;
        XChaCha20Poly1305::new_from_slice(k.as_slice()).map_err(|_| SealError::Key("cipher key"))
    }

    fn ad(context: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(AD_PREFIX.len() + context.len());
        ad.extend_from_slice(AD_PREFIX);
        ad.extend_from_slice(context);
        ad
    }

    /// Seal `plaintext` (e.g. someone's keyring) under this key: `nonce (24) ‖ ciphertext ‖ tag
    /// (16)`, XChaCha20-Poly1305 with key HKDF-SHA256(recovery key, `"figcraft recovery"`) and
    /// associated data `"figcraft recovery v1" ‖ context` (e.g. the account id).
    pub fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let nonce = random::bytes::<24>()?;
        let ct = self
            .cipher()?
            .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad: &RecoveryKey::ad(context) })
            .map_err(|_| SealError::TooLarge(plaintext.len()))?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let nonce: [u8; 24] = sealed.get(..24).and_then(|b| b.try_into().ok()).ok_or(SealError::Malformed("recovery copy"))?;
        let ct = sealed.get(24..).ok_or(SealError::Malformed("recovery copy"))?;
        if ct.len() < 16 {
            return Err(SealError::Malformed("recovery copy"));
        }
        self.cipher()?
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &RecoveryKey::ad(context) })
            .map(Zeroizing::new)
            .map_err(|_| SealError::Open)
    }
}
