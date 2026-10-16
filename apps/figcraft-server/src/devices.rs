//! The devices people register for sealed (end-to-end encrypted) files (`docs/accounts-and-e2e.md`
//! › *Keys*, step 9): each app install's public keys under its person's account
//! (`accounts/devices.json`), and each person's recovery copy (`accounts/recovery.json`: their
//! recovery device's secret sealed with a recovery key the server never sees). Nothing here can
//! open a file: the server keeps public keys and ciphertext only.

use figcraft_collab::message::DeviceInfo;
use figcraft_collab::sealed::DevicePublic;
use figcraft_collab_net::token;
use serde::{Deserialize, Serialize};

use super::{Accounts, State};
use crate::disk;
use crate::store::now;

pub const DEVICES: &str = "devices.json";
pub const RECOVERY: &str = "recovery.json";

/// Most devices one person registers (app installs and their recovery device).
pub const MAX_DEVICES_EACH: usize = 10;
/// Longest device name kept (characters).
const MAX_NAME: usize = 64;
/// Largest recovery copy kept (a device secret sealed: 24 + 64 + 16 bytes; room for more).
const MAX_RECOVERY: usize = 4096;
/// Smallest: a nonce and a tag.
const MIN_RECOVERY: usize = 24 + 16;

/// A registered device (`devices.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRec {
    /// `d` and 16 hex digits.
    pub id: String,
    pub account: String,
    pub name: String,
    pub public: DevicePublic,
    pub created: u64,
    #[serde(default)]
    pub seen: u64,
    /// The device a recovery key stands for.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovery: bool,
}

impl DeviceRec {
    pub fn info(&self) -> DeviceInfo {
        DeviceInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            public: self.public.clone(),
            created: self.created,
            seen: self.seen,
            recovery: self.recovery,
        }
    }
}

/// A person's recovery copy (`recovery.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRec {
    pub account: String,
    pub device: String,
    /// `nonce (24) ‖ ciphertext ‖ tag (16)`, base64url in the file.
    #[serde(with = "figcraft_collab::sealed::bin")]
    pub sealed: Vec<u8>,
    pub created: u64,
}

/// A device name as kept: one line, at most [`MAX_NAME`] characters, "Device" when empty.
fn clean_name(s: &str) -> String {
    let n: String = s.trim().chars().filter(|c| !c.is_control()).take(MAX_NAME).collect();
    if n.trim().is_empty() { "Device".into() } else { n.trim().to_string() }
}

impl Accounts {
    pub(super) fn save_devices(&self, s: &State) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_vec_pretty(&s.devices).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.dir.join(DEVICES), &text).map_err(|e| e.to_string())
    }

    pub(super) fn save_recovery(&self, s: &State) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_vec_pretty(&s.recovery).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.dir.join(RECOVERY), &text).map_err(|e| e.to_string())
    }

    /// Register `public` as a device of `account` (its id; the same keys again: the same id, the
    /// name updated).
    pub fn register_device(&self, account: &str, name: &str, public: &DevicePublic, recovery: bool) -> Result<String, String> {
        let mut s = self.state();
        let t = now();
        let name = clean_name(name);
        if let Some(d) = s.devices.iter_mut().find(|d| d.public == *public) {
            if d.account != account {
                return Err("those device keys are registered to someone else: make new ones".into());
            }
            d.name = name;
            d.seen = t;
            d.recovery = recovery;
            let id = d.id.clone();
            self.save_devices(&s)?;
            return Ok(id);
        }
        let mine = s.devices.iter().filter(|d| d.account == account).count();
        if mine >= MAX_DEVICES_EACH {
            return Err(format!("you have {mine} devices here, the most one person may: revoke one you no longer use first"));
        }
        let id = format!("d{}", token::file_id()?);
        s.devices.push(DeviceRec { id: id.clone(), account: account.to_string(), name, public: public.clone(), created: t, seen: t, recovery });
        self.save_devices(&s)?;
        log::info!("event=device_registered account={account} device={id} recovery={recovery}");
        Ok(id)
    }

    /// `account`'s devices.
    pub fn devices_of(&self, account: &str) -> Vec<DeviceRec> {
        self.state().devices.iter().filter(|d| d.account == account).cloned().collect()
    }

    /// The device with this id.
    pub fn device(&self, id: &str) -> Option<DeviceRec> {
        self.state().devices.iter().find(|d| d.id == id).cloned()
    }

    /// Take device `id` off `account` (and its recovery copy, when it is the recovery device).
    pub fn revoke_device(&self, account: &str, id: &str) -> Result<DeviceRec, String> {
        let mut s = self.state();
        let Some(i) = s.devices.iter().position(|d| d.id == id && d.account == account) else {
            return Err("you have no device with that id here".into());
        };
        let gone = s.devices.remove(i);
        self.save_devices(&s)?;
        let before = s.recovery.len();
        s.recovery.retain(|r| r.device != id);
        if s.recovery.len() != before {
            self.save_recovery(&s)?;
        }
        log::info!("event=device_revoked account={account} device={id}");
        Ok(gone)
    }

    /// Keep `account`'s recovery copy for their recovery device `device` (replacing the last).
    pub fn put_recovery(&self, account: &str, device: &str, sealed: Vec<u8>) -> Result<(), String> {
        if !(MIN_RECOVERY..=MAX_RECOVERY).contains(&sealed.len()) {
            return Err("that isn't a recovery copy".into());
        }
        let mut s = self.state();
        if !s.devices.iter().any(|d| d.id == device && d.account == account && d.recovery) {
            return Err("register the recovery device first".into());
        }
        s.recovery.retain(|r| r.account != account);
        s.recovery.push(RecoveryRec { account: account.to_string(), device: device.to_string(), sealed, created: now() });
        self.save_recovery(&s)?;
        log::info!("event=recovery_kept account={account} device={device}");
        Ok(())
    }

    /// `account`'s recovery copy, if they made one.
    pub fn recovery_of(&self, account: &str) -> Option<RecoveryRec> {
        self.state().recovery.iter().find(|r| r.account == account).cloned()
    }

    /// Forget `account`'s devices and recovery copy (they were taken off the server).
    pub(super) fn forget_devices(&self, s: &mut State, account: &str) -> Result<(), String> {
        let before = (s.devices.len(), s.recovery.len());
        s.devices.retain(|d| d.account != account);
        s.recovery.retain(|r| r.account != account);
        if s.devices.len() != before.0 {
            self.save_devices(s)?;
        }
        if s.recovery.len() != before.1 {
            self.save_recovery(s)?;
        }
        Ok(())
    }
}
