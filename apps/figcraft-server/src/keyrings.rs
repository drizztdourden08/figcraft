//! The keyrings of sealed files on a server with accounts (`docs/accounts-and-e2e.md` › *Keys*,
//! step 9): each sealed file's key, wrapped by the apps to every member device, epoch by epoch,
//! in `files/<id>/keyring.json`. The server only keeps and hands out the wrapped copies; it can't
//! open them. It says which devices still lack a copy ([`AccountReq::PendingKeys`]: the next owner
//! or editor app online wraps for them) and when a file needs a new epoch (someone was taken out
//! or a device revoked: an owner's app starts it).
//!
//! Where everyone is in every file (`[auth] file_access = "everyone"`), a sealed file's key goes
//! to every device of everyone on the server, any of them (all editors) may start a new epoch, and
//! taking someone off the server starts one for every sealed file.
//!
//! `keyring.json`:
//!
//! ```json
//! { "rotate": true,
//!   "epochs": { "0": { "d0123456789abcdef": { "enc": "<base64url>", "ciphertext": "<base64url>" } } } }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use figcraft_auth::{E2eMode, Person};
use figcraft_collab::message::{AccountReply, AccountReq, EditorDevice, KeyWant, KeyWrap, PendingFile, RecoveryCopy, Role};
use figcraft_collab::sealed::Wrapped;
use figcraft_collab_net::hub::{AccountHandled, OpenFile};
use serde::{Deserialize, Serialize};

use super::{Store, read_json_or_default, write_json};
use crate::accounts::devices::DeviceRec;

pub const KEYRING: &str = "keyring.json";

/// Most epochs a file's keyring keeps (a new one is refused beyond it).
pub const MAX_EPOCHS: usize = 1024;
/// Most copies one request carries, and most wanted copies one answer lists.
pub const MAX_WRAPS: usize = 5_000;

const NO_E2E: &str = "this server doesn't keep sealed (end-to-end encrypted) files";
const NOT_IN: &str = "you aren't in this file: ask its owner to invite you";

/// A sealed file's keyring (`keyring.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyringFile {
    /// Someone was taken out, or a device revoked, since the newest epoch began.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rotate: bool,
    /// Epoch → device id → the key of that epoch wrapped to that device.
    pub epochs: BTreeMap<u32, BTreeMap<String, Wrapped>>,
}

impl KeyringFile {
    fn current(&self) -> Option<u32> {
        self.epochs.keys().next_back().copied()
    }
}

impl Store {
    fn keyring_path(&self, file: &str) -> std::path::PathBuf {
        self.dir(file).join(KEYRING)
    }

    /// `file`'s keyring (empty when it has none yet).
    pub fn keyring(&self, file: &str) -> Result<KeyringFile, String> {
        read_json_or_default(&self.keyring_path(file))
    }

    fn save_keyring(&self, file: &str, ring: &KeyringFile) -> Result<(), String> {
        write_json(&self.keyring_path(file), ring).map_err(|e| format!("couldn't save the file's keys: {e}"))
    }

    fn sealed(&self, file: &str) -> bool {
        self.files.get(file).is_some_and(|e| e.meta.sealed)
    }

    /// `account` is out of sealed `file` (taken out, left, or off the server), or lost a device
    /// (`device`): their copies (that device's) go, and the file needs a new epoch.
    pub(crate) fn keys_forget(&mut self, file: &str, account: &str, device: Option<&str>) -> Result<(), String> {
        if !self.sealed(file) {
            return Ok(());
        }
        let mut ring = self.keyring(file)?;
        if ring.epochs.is_empty() {
            return Ok(());
        }
        let theirs: BTreeSet<String> = match device {
            Some(d) => std::iter::once(d.to_string()).collect(),
            None => self.accounts.devices_of(account).into_iter().map(|d| d.id).collect(),
        };
        for wraps in ring.epochs.values_mut() {
            wraps.retain(|d, _| !theirs.contains(d));
        }
        ring.rotate = true;
        self.save_keyring(file, &ring)?;
        log::info!("event=keys_need_rotation file={file}");
        Ok(())
    }

    /// Every member of `file` with their devices (everyone's, where everyone is in every file).
    fn member_devices(&self, file: &str) -> Vec<(Role, DeviceRec)> {
        if self.everyone() {
            return self.accounts.all_devices().into_iter().filter_map(|d| Some((self.role_in(file, &d.account)?, d))).collect();
        }
        let Some(people) = self.people(file) else { return Vec::new() };
        people.members.iter().flat_map(|m| self.accounts.devices_of(&m.account).into_iter().map(move |d| (m.role, d))).collect()
    }

    /// May someone with `role` start a new epoch of a file's key? Owners; where everyone is in
    /// every file, editors too (a file there may have no owner left).
    fn may_rotate(&self, role: Role) -> bool {
        role == Role::Owner || (self.everyone() && role == Role::Editor)
    }

    fn keys_pending(&mut self, who: &Person) -> Vec<PendingFile> {
        let mine: BTreeSet<String> = self.accounts.devices_of(&who.account).into_iter().map(|d| d.id).collect();
        let mut out = Vec::new();
        let mut listed = 0usize;
        for file in self.file_ids() {
            if !self.sealed(&file) {
                continue;
            }
            let Some(role) = self.role_in(&file, &who.account) else { continue };
            let Ok(ring) = self.keyring(&file) else { continue };
            let devices = self.member_devices(&file);
            let may = |d: &DeviceRec| matches!(role, Role::Owner | Role::Editor) || d.account == who.account;
            let mut wanted = Vec::new();
            for (epoch, wraps) in &ring.epochs {
                // Only epochs one of your devices holds: your app may have the key.
                if !wraps.keys().any(|d| mine.contains(d)) {
                    continue;
                }
                for (_, d) in devices.iter().filter(|(_, d)| !wraps.contains_key(&d.id) && may(d)) {
                    wanted.push(KeyWant { epoch: *epoch, device: d.id.clone(), public: d.public.clone() });
                }
            }
            let current = ring.current();
            let owner = self.may_rotate(role);
            let rotate = ring.rotate && owner && current.is_some_and(|c| c < u32::MAX);
            if rotate || (owner && current.is_none()) {
                // A new epoch (or the first copies of a file published before keyrings), for every
                // member device.
                let epoch = current.map_or(0, |c| c.saturating_add(1));
                wanted.extend(devices.iter().map(|(_, d)| KeyWant { epoch, device: d.id.clone(), public: d.public.clone() }));
            }
            if wanted.is_empty() && !rotate {
                continue;
            }
            listed += wanted.len();
            out.push(PendingFile { file, epoch: current, rotate, wanted });
            if listed >= MAX_WRAPS {
                break;
            }
        }
        out
    }

    fn keys_put(&mut self, who: &Person, file: &str, epoch: u32, rotate: bool, wrapped: Vec<(String, Wrapped)>) -> Result<(), String> {
        if !self.sealed(file) {
            return Err("this file isn't sealed: it has no keys".into());
        }
        let role = self.role_of(file, who)?.ok_or(NOT_IN)?;
        if wrapped.len() > MAX_WRAPS {
            return Err(format!("at most {MAX_WRAPS} keys at once"));
        }
        let mut ring = self.keyring(file)?;
        let mine: BTreeSet<String> = self.accounts.devices_of(&who.account).into_iter().map(|d| d.id).collect();
        if rotate {
            if !self.may_rotate(role) {
                return Err("only the file's owners can start a new epoch of its key".into());
            }
            if ring.epochs.contains_key(&epoch) {
                return Err(format!("epoch {epoch} of this file's key exists already (another owner started it): sync again"));
            }
            match ring.current() {
                Some(c) if Some(epoch) != c.checked_add(1) => return Err("a new epoch follows the newest one".into()),
                _ => {}
            }
            if ring.epochs.len() >= MAX_EPOCHS {
                return Err(format!("this file's key has {MAX_EPOCHS} epochs, the most a file keeps"));
            }
            ring.epochs.insert(epoch, BTreeMap::new());
            ring.rotate = false;
            log::info!("event=keys_rotated file={file} epoch={epoch} account={}", who.account);
        } else {
            let Some(wraps) = ring.epochs.get(&epoch) else { return Err(format!("this file's key has no epoch {epoch}")) };
            // Copies come from someone who holds this epoch (one of their devices has it).
            if !wraps.keys().any(|d| mine.contains(d)) {
                return Err("you don't hold that epoch of this file's key".into());
            }
        }
        let editor = matches!(role, Role::Owner | Role::Editor);
        for (device, w) in wrapped {
            if !w.well_formed() {
                return Err("that isn't a wrapped file key".into());
            }
            let d = self.accounts.device(&device).ok_or("no device with that id is registered here")?;
            if self.role_in(file, &d.account).is_none() {
                return Err("that device's person isn't in this file".into());
            }
            if d.account != who.account && !editor {
                return Err("viewers wrap the file's key for their own devices only".into());
            }
            if let Some(wraps) = ring.epochs.get_mut(&epoch) {
                wraps.entry(device).or_insert(w);
            }
        }
        self.save_keyring(file, &ring)
    }

    fn keys_of(&mut self, who: &Person, file: &str) -> Result<AccountReply, String> {
        if self.role_of(file, who)?.is_none() && !who.admin {
            return Err(NOT_IN.into());
        }
        if !self.sealed(file) {
            return Ok(AccountReply::Keyring { sealed: false, epochs: Vec::new(), wrapped: Vec::new() });
        }
        let ring = self.keyring(file)?;
        let mine: BTreeSet<String> = self.accounts.devices_of(&who.account).into_iter().map(|d| d.id).collect();
        let wrapped = ring
            .epochs
            .iter()
            .flat_map(|(e, wraps)| {
                wraps.iter().filter(|(d, _)| mine.contains(*d)).map(|(d, w)| KeyWrap { epoch: *e, device: d.clone(), wrapped: w.clone() })
            })
            .collect();
        Ok(AccountReply::Keyring { sealed: true, epochs: ring.epochs.keys().copied().collect(), wrapped })
    }

    /// `who` revoked their device `device`: its copies go from every sealed file they are in, and
    /// those files need a new epoch.
    fn revoke_device(&mut self, who: &Person, device: &str) -> Result<(), String> {
        self.accounts.revoke_device(&who.account, device)?;
        for file in self.file_ids() {
            if self.role_in(&file, &who.account).is_some() {
                self.keys_forget(&file, &who.account, Some(device))?;
            }
        }
        Ok(())
    }

    /// The owners' and editors' devices of sealed `file` (every member may ask: viewers check
    /// signatures too), and from which batch on its changes must be signed. A file starts
    /// requiring signatures the first time this is asked (only apps that sign ask) once every
    /// owner and editor has registered a device: from the batch after its latest one, so batches
    /// made before by apps that didn't sign stay as they are.
    pub(crate) fn editor_keys(&mut self, who: &Person, file: &str, open: &dyn Fn(&str) -> Option<OpenFile>) -> Result<AccountReply, String> {
        if self.accounts.e2e() == E2eMode::Off {
            return Err(NO_E2E.into());
        }
        if self.role_of(file, who)?.is_none() && !who.admin {
            return Err(NOT_IN.into());
        }
        if !self.sealed(file) {
            return Err("this file isn't end-to-end encrypted: its changes aren't signed".into());
        }
        let people = self.people(file).cloned().unwrap_or_default();
        let editors: Vec<&str> = people.members.iter().filter(|m| matches!(m.role, Role::Owner | Role::Editor)).map(|m| m.account.as_str()).collect();
        let mut list = Vec::new();
        let mut everyone = !editors.is_empty();
        for account in &editors {
            let devices = self.accounts.devices_of(account);
            everyone &= devices.iter().any(|d| !d.recovery);
            list.extend(devices.into_iter().map(|d| EditorDevice { account: d.account, device: d.id, public: d.public, recovery: d.recovery }));
        }
        // Where everyone is in every file, everyone's devices sign (the owners and editors listed
        // must still have a device before signatures are required; a file without any needs one
        // device somewhere).
        if self.everyone() {
            let all: Vec<DeviceRec> = self
                .accounts
                .all_devices()
                .into_iter()
                .filter(|d| !list.iter().any(|e: &EditorDevice| e.device == d.id))
                .filter(|d| self.role_in(file, &d.account).is_some_and(|r| r != Role::Viewer))
                .collect();
            if editors.is_empty() {
                everyone = all.iter().any(|d| !d.recovery);
            }
            list.extend(all.into_iter().map(|d| EditorDevice { account: d.account, device: d.id, public: d.public, recovery: d.recovery }));
        }
        let entry = self.entry(file)?;
        if entry.meta.signed_from.is_none() && everyone {
            let seq = open(file).map_or(entry.meta.seq, |o| o.seq);
            entry.meta.signed_from = Some(seq);
            self.save_meta(file)?;
            log::info!("event=signatures_required file={file} after={seq}");
        }
        let signed_from = self.entry(file)?.meta.signed_from;
        Ok(AccountReply::EditorKeys { signed_from, editors: list })
    }

    /// The devices of `account`, for `who`'s safety number of them: theirs, someone who shares a
    /// file with them, or an admin.
    fn devices_of(&self, who: &Person, account: &str) -> Result<AccountReply, String> {
        let shares = account == who.account
            || who.admin
            || self.file_ids().iter().any(|f| self.role_in(f, &who.account).is_some() && self.role_in(f, account).is_some());
        if !shares {
            return Err("you share no file with them here".into());
        }
        Ok(AccountReply::Devices(self.accounts.devices_of(account).iter().map(DeviceRec::info).collect()))
    }

    /// The device, keyring and recovery requests of an account connection.
    pub(crate) fn key_request(&mut self, who: &Person, req: AccountReq) -> AccountHandled {
        let failed = |reason: String| AccountHandled::from(AccountReply::Failed { reason });
        let done = |r: Result<(), String>| r.map_or_else(failed, |()| AccountReply::Done.into());
        // Any app may ask whether a file has keys (a plain one has none), whatever the server keeps.
        if let AccountReq::Keyring { file } = req {
            return self.keys_of(who, &file).map_or_else(failed, Into::into);
        }
        if self.accounts.e2e() == E2eMode::Off {
            return failed(NO_E2E.into());
        }
        match req {
            AccountReq::RegisterDevice { name, public, recovery } => match self.accounts.register_device(&who.account, &name, &public, recovery) {
                Ok(id) => AccountReply::Device { id }.into(),
                Err(e) => failed(e),
            },
            AccountReq::Devices => AccountReply::Devices(self.accounts.devices_of(&who.account).iter().map(DeviceRec::info).collect()).into(),
            AccountReq::DevicesOf { account } => self.devices_of(who, &account).map_or_else(failed, Into::into),
            AccountReq::RevokeDevice { device } => done(self.revoke_device(who, &device)),
            AccountReq::PutKeys { file, epoch, rotate, wrapped } => done(self.keys_put(who, &file, epoch, rotate, wrapped)),
            AccountReq::PendingKeys => AccountReply::PendingKeys(self.keys_pending(who)).into(),
            AccountReq::PutRecovery { device, sealed } => done(self.accounts.put_recovery(&who.account, &device, sealed)),
            AccountReq::GetRecovery => {
                let copy = self.accounts.recovery_of(&who.account).map(|r| RecoveryCopy { device: r.device, sealed: r.sealed, created: r.created });
                AccountReply::Recovery(copy).into()
            }
            _ => failed("that isn't a request about keys".into()),
        }
    }
}
