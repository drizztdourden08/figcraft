//! Device keys: X25519 for receiving file keys (RFC 9180 HPKE), Ed25519 for signing.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keys::{FILE_KEY_LEN, FileKey};
use crate::{SealError, random};

/// HPKE `info`: what the shared secret is for (and the format's version).
const WRAP_INFO: &[u8] = b"figcraft file key v1";
/// Bytes of [`DeviceKeys::to_secret_bytes`].
const SECRET_LEN: usize = 64;
/// An X25519 public key, an Ed25519 public key.
const KEY_LEN: usize = 32;
/// The wrapped file key's ciphertext: the key and its ChaCha20-Poly1305 tag.
const WRAPPED_CT_LEN: usize = FILE_KEY_LEN + 16;

/// One app install's private keys, kept in the OS keychain ([`to_secret_bytes`](Self::to_secret_bytes)).
/// Wiped from memory on drop; `Debug` prints only the public keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeys {
    /// X25519 private key (HPKE DHKEM(X25519, HKDF-SHA256) recipient key).
    agreement: [u8; 32],
    /// Ed25519 secret key (the 32-byte seed).
    signing: [u8; 32],
}

impl std::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKeys").field("public", &self.public().ok()).finish_non_exhaustive()
    }
}

/// A device's public keys, registered with the server under its owner's identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DevicePublic {
    /// X25519 public key: file keys are wrapped to it.
    #[serde(with = "crate::bin")]
    pub agreement: [u8; 32],
    /// Ed25519 public key: checks the device's signatures.
    #[serde(with = "crate::bin")]
    pub signing: [u8; 32],
}

/// A file key wrapped to one device: RFC 9180 HPKE base mode, DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, ChaCha20-Poly1305, `info` = `"figcraft file key v1"`, associated data = the file
/// id; the plaintext is [`FileKey::to_bytes`] (68 bytes, so the ciphertext is 84).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Wrapped {
    /// The encapsulated (ephemeral X25519 public) key.
    #[serde(with = "crate::bin")]
    pub enc: [u8; 32],
    #[serde(with = "crate::bin")]
    pub ciphertext: Vec<u8>,
}

impl Wrapped {
    /// `enc (32) ‖ ciphertext (84)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Wrapped, SealError> {
        if bytes.len() != KEY_LEN + WRAPPED_CT_LEN {
            return Err(SealError::Malformed("wrapped key"));
        }
        let enc: [u8; 32] = bytes.get(..KEY_LEN).and_then(|b| b.try_into().ok()).ok_or(SealError::Malformed("wrapped key"))?;
        let ciphertext = bytes.get(KEY_LEN..).ok_or(SealError::Malformed("wrapped key"))?.to_vec();
        Ok(Wrapped { enc, ciphertext })
    }
}

type HpkePrivate = <X25519HkdfSha256 as Kem>::PrivateKey;
type HpkePublic = <X25519HkdfSha256 as Kem>::PublicKey;
type HpkeEncapped = <X25519HkdfSha256 as Kem>::EncappedKey;

impl DeviceKeys {
    /// New random keys for this install.
    pub fn generate() -> Result<DeviceKeys, SealError> {
        Ok(DeviceKeys { agreement: *random::bytes::<32>()?, signing: *random::bytes::<32>()? })
    }

    /// `X25519 private key (32) ‖ Ed25519 seed (32)`, for the OS keychain.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_LEN));
        out.extend_from_slice(&self.agreement);
        out.extend_from_slice(&self.signing);
        out
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<DeviceKeys, SealError> {
        if bytes.len() != SECRET_LEN {
            return Err(SealError::Malformed("device keys"));
        }
        let mut keys = DeviceKeys { agreement: [0; 32], signing: [0; 32] };
        keys.agreement.copy_from_slice(bytes.get(..32).ok_or(SealError::Malformed("device keys"))?);
        keys.signing.copy_from_slice(bytes.get(32..).ok_or(SealError::Malformed("device keys"))?);
        Ok(keys)
    }

    fn hpke_private(&self) -> Result<HpkePrivate, SealError> {
        HpkePrivate::from_bytes(&self.agreement).map_err(|_| SealError::Key("X25519 private key"))
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing)
    }

    /// The public keys to register.
    pub fn public(&self) -> Result<DevicePublic, SealError> {
        let agreement: [u8; 32] = X25519HkdfSha256::sk_to_pk(&self.hpke_private()?).to_bytes().into();
        Ok(DevicePublic { agreement, signing: self.signing_key().verifying_key().to_bytes() })
    }

    /// An Ed25519 signature of `message` (64 bytes).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key().sign(message).to_bytes()
    }
}

/// Whether `signature` is `public`'s Ed25519 signature of `message` (strict verification: no
/// malleable or small-order forms).
pub fn verify(public: &DevicePublic, message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&public.signing) else { return false };
    let Ok(sig) = Signature::from_slice(signature) else { return false };
    key.verify_strict(message, &sig).is_ok()
}

/// Wrap `key` (one epoch of `file`'s key) to the device `recipient`.
pub fn wrap(key: &FileKey, file: &str, recipient: &DevicePublic) -> Result<Wrapped, SealError> {
    let pk = HpkePublic::from_bytes(&recipient.agreement).map_err(|_| SealError::Key("X25519 public key"))?;
    let mut rng = random::Seeded::new()?;
    let plaintext = key.to_bytes();
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        WRAP_INFO,
        &plaintext,
        file.as_bytes(),
        &mut rng,
    )
    .map_err(|_| SealError::Key("HPKE encapsulation"))?;
    Ok(Wrapped { enc: enc.to_bytes().into(), ciphertext })
}

/// Unwrap a file key of `file` wrapped to `device`.
pub fn unwrap(device: &DeviceKeys, file: &str, wrapped: &Wrapped) -> Result<FileKey, SealError> {
    if wrapped.ciphertext.len() != WRAPPED_CT_LEN {
        return Err(SealError::Malformed("wrapped key"));
    }
    let enc = HpkeEncapped::from_bytes(&wrapped.enc).map_err(|_| SealError::Malformed("wrapped key"))?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &device.hpke_private()?,
            &enc,
            WRAP_INFO,
            &wrapped.ciphertext,
            file.as_bytes(),
        )
        .map_err(|_| SealError::Open)?,
    );
    FileKey::from_bytes(&plaintext)
}
