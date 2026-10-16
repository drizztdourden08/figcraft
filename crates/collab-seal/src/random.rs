//! Randomness from the operating system (`crypto.getRandomValues` in the browser).

use std::convert::Infallible;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::SealError;

/// `N` random bytes.
pub(crate) fn bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, SealError> {
    let mut out = Zeroizing::new([0u8; N]);
    getrandom::fill(out.as_mut_slice()).map_err(|_| SealError::Random)?;
    Ok(out)
}

/// An infallible CSPRNG for the HPKE crate (which wants one): seeded once from the system (where a
/// failure is reported as [`SealError::Random`]), then HMAC-SHA256 in counter mode over the seed.
pub(crate) struct Seeded {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
    block: Zeroizing<[u8; 32]>,
    used: usize,
}

impl Seeded {
    pub(crate) fn new() -> Result<Seeded, SealError> {
        Ok(Seeded { seed: bytes::<32>()?, counter: 0, block: Zeroizing::new([0; 32]), used: 32 })
    }

    fn refill(&mut self) {
        // HMAC accepts keys of any length, so this never fails; keep the block unchanged-but-used
        // otherwise (unreachable in practice).
        if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(self.seed.as_slice()) {
            mac.update(b"figcraft rng");
            mac.update(&self.counter.to_le_bytes());
            let mut out: [u8; 32] = mac.finalize().into_bytes().into();
            self.block.copy_from_slice(&out);
            out.zeroize();
        }
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }
}

impl hpke::rand_core::TryRng for Seeded {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst.iter_mut() {
            if self.used >= self.block.len() {
                self.refill();
            }
            *byte = self.block.get(self.used).copied().unwrap_or(0);
            self.used += 1;
        }
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for Seeded {}
