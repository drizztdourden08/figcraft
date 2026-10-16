//! Sealed files with accounts (milestone M9, step 9 of `docs/accounts-and-e2e.md`): this app's
//! device keys, the keyrings servers keep of sealed files, and recovery.
//!
//! - **Device keys.** Each install has one [`DeviceKeys`] (X25519 for receiving file keys, Ed25519
//!   for signing), made the first time it is needed. Its secret is kept in the operating system's
//!   keychain when the app installed one ([`KeyState::keychain`]; the desktop app does), else
//!   with the preferences ([`DevicePrefs::secret`]): weaker, since anyone who can read the
//!   preferences file has it (the browser build, `figcraft-cli`, a keychain that refused). The
//!   public keys are registered with each server you use sealed files on
//!   (`AccountReq::RegisterDevice`), which gives the device an id there.
//! - **Keyrings.** A sealed file's key is wrapped (HPKE) to every member device, epoch by epoch,
//!   and the server keeps the copies. Joining a member's link (no `#k=`) asks the server for the
//!   copies wrapped to this device and opens them; with none yet (or not every epoch) the join
//!   waits: "waiting for access" ([`WAITING_FOR_ACCESS`]), and it goes on by itself once an
//!   owner's or editor's app has wrapped the key for this device.
//! - **Syncing keys** (`account.syncKeys`, run after a sealed publish, an invite or a removal, and
//!   in the background every [`KeyState::sync_every`]): the server says which member devices lack
//!   a copy this app may make; it wraps the key for them. When someone was taken out or a device
//!   revoked, an owner's app starts the next epoch ([`FileKey::rotate`]), wraps it for every member
//!   device left, and its sessions seal new writes with it; members' apps pick the new epoch up
//!   at their next sync.
//! - **Recovery.** `account.recoveryKey` makes a recovery device (keys of its own, registered as
//!   one of your devices, so file keys are wrapped to it like to any other) and keeps its secret on
//!   the server sealed with a [`RecoveryKey`] that is shown once and never stored here or there.
//!   `account.recover` on a new device opens the copy, unwraps every file key wrapped to the
//!   recovery device and wraps them for this one. (Approving a new device from an existing one
//!   with a 6-digit comparison is not built yet.)
//!
//! Keys and secrets are never logged, never in a command result (the recovery key once, when it
//! is made: like an owner token) and `Debug` leaves them out.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use figcraft_collab::message::{AccountReply, AccountReq, DeviceInfo, PendingFile};
use figcraft_collab_seal::{DeviceKeys, FileKey, Keyring, RecoveryKey, parse_ring_fragment, ring_fragment, unwrap, wrap};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::accounts::{server_key, server_of};
use crate::cmd::CommandSpec;
use crate::file_keys::link_file;
use crate::live::{Published, SessionId, Share, Status};
use crate::params::{boolean, req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

/// What a join says while no owner or editor has wrapped the file's key for this device.
pub const WAITING_FOR_ACCESS: &str = "Waiting for access: this file is end-to-end encrypted, and its key hasn't been shared with this device yet. It opens by itself once an owner or editor of the file has FigCraft open (or ask them to open it)";

/// Why a session of a sealed file ended when a change came sealed with a newer epoch than its keys
/// (the transport says it; the app fetches the new key and joins again by itself).
pub const NEW_EPOCH: &str = "This file's key changed (someone was taken out of it): getting the new key";

/// What a join says when a change came with a key epoch that the file's keyring doesn't have.
pub const NO_SUCH_EPOCH: &str = "A change in this file is sealed with a key the file doesn't have (someone sent damaged changes): ask its owner";

/// How often keys are synced in the background (`account.syncKeys`).
pub const SYNC_EVERY: Duration = Duration::from_secs(60);

/// Most rotations remembered while they are on their way (see [`KeyState`]).
const MAX_ROTATIONS: usize = 64;

/// The OS keychain, as the app installs it ([`KeyState::keychain`]): where this install's device
/// secret is kept.
pub trait Keychain: Send {
    /// The secret kept, if any.
    fn load(&self) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Keep `secret` (replacing what was kept).
    fn store(&self, secret: &[u8]) -> std::result::Result<(), String>;
}

/// This install registered with a server.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Registered {
    /// The server's address, as [`server_key`] keeps it.
    pub server: String,
    /// The device's id there.
    pub device: String,
    /// The X25519 public key it was registered with (base64url): other keys register again.
    pub public: String,
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered").field("server", &self.server).field("device", &self.device).finish_non_exhaustive()
    }
}

/// What the preferences keep of this install's device (see the module docs).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DevicePrefs {
    /// The name your devices lists show for it (empty: the computer's name).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The device secret (unpadded base64url of its 64 bytes) when no keychain keeps it: a
    /// password, weaker than the keychain.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret: String,
    /// The servers it is registered with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registered: Vec<Registered>,
}

impl std::fmt::Debug for DevicePrefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePrefs").field("name", &self.name).field("registered", &self.registered).finish_non_exhaustive()
    }
}

impl DevicePrefs {
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.secret.is_empty() && self.registered.is_empty()
    }
}

/// Most servers one install is registered with.
const MAX_REGISTERED: usize = 50;

/// Reads the device's preferences: anything that isn't usable is dropped.
pub(crate) fn read<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<DevicePrefs, D::Error> {
    let v = Value::deserialize(d).unwrap_or(Value::Null);
    let mut p: DevicePrefs = serde_json::from_value(v).unwrap_or_default();
    p.name = p.name.chars().filter(|c| !c.is_control()).take(64).collect();
    if p.secret.len() > 128 {
        p.secret.clear();
    }
    p.registered.retain(|r| r.server.len() <= 512 && r.device.len() <= 64 && r.public.len() <= 64 && !r.server.is_empty());
    p.registered.truncate(MAX_REGISTERED);
    Ok(p)
}

/// A join waiting for access (see [`WAITING_FOR_ACCESS`]).
#[derive(Clone, Debug)]
pub(crate) struct Waiting {
    pub session: SessionId,
    /// Joined again only with a newer epoch than this (a session whose key moved on).
    pub after: Option<u32>,
    pub server: String,
    pub file: String,
    pub link: String,
    pub published: Option<Published>,
    pub share: Option<Share>,
}

/// This run's device and key state (the secrets live in [`DeviceKeys`], wiped on drop).
pub struct KeyState {
    /// Where the device secret is kept, when the app has a keychain (the desktop app installs
    /// the OS one; without it the secret is kept with the preferences).
    pub keychain: Option<Box<dyn Keychain>>,
    /// How often keys are synced in the background.
    pub sync_every: Duration,
    device: Option<DeviceKeys>,
    /// Where the device secret is: `"keychain"` or `"preferences"`.
    store: Option<&'static str>,
    pub(crate) waiting: Vec<Waiting>,
    /// New epochs on their way to the server, by server, file and epoch: a sync that runs again
    /// (in the background) makes the same key, not another.
    rotations: Vec<((String, String, u32), FileKey)>,
    /// When the next background sync is due.
    next_sync: Option<web_time::Instant>,
}

impl Default for KeyState {
    fn default() -> Self {
        Self { keychain: None, sync_every: SYNC_EVERY, device: None, store: None, waiting: Vec::new(), rotations: Vec::new(), next_sync: None }
    }
}

impl std::fmt::Debug for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyState").field("keychain", &self.keychain.is_some()).field("store", &self.store).finish_non_exhaustive()
    }
}

/// This computer's name, for a new device's default name.
fn computer_name() -> String {
    let n = ["COMPUTERNAME", "HOSTNAME"].iter().find_map(|k| std::env::var(k).ok()).unwrap_or_default();
    let n: String = n.trim().chars().filter(|c| !c.is_control()).take(48).collect();
    if n.is_empty() { "FigCraft".into() } else { format!("FigCraft on {n}") }
}

fn public_text(keys: &DeviceKeys) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(keys.public().map_err(|e| EngineError::Other(e.to_string()))?.agreement))
}

/// A link with a token (a share link): not a member's.
fn member_free(link: &str) -> bool {
    link.split('#').next().unwrap_or_default().contains("token=")
}

fn other(e: impl std::fmt::Display) -> EngineError {
    EngineError::Other(e.to_string())
}

/// What a join on a server with accounts goes on with.
pub(crate) enum JoinKeys {
    /// The link to join with (a sealed file's with its keys after `#`).
    Link(String),
    /// A sealed file whose key this device doesn't have yet.
    Waiting { server: String, file: String },
}

/// A file's keys as this device can open them.
struct FileRing {
    ring: Keyring,
    /// Every epoch the file has.
    epochs: Vec<u32>,
}

impl FileRing {
    /// This device holds every epoch (an app missing some would skip what others open).
    fn complete(&self) -> bool {
        !self.epochs.is_empty() && self.epochs.iter().all(|e| self.ring.get(*e).is_some())
    }
}

/// What one sync did.
#[derive(Default)]
struct Synced {
    wrapped: usize,
    rotated: Vec<String>,
    refreshed: Vec<String>,
    joined: Vec<String>,
    errors: Vec<String>,
}

impl Session {
    /// This install's device keys: kept, or made now (and kept).
    fn device_keys(&mut self) -> Result<DeviceKeys> {
        if let Some(k) = &self.keys.device {
            return Ok(k.clone());
        }
        let from_prefs = !self.prefs.device.secret.is_empty();
        let kept = if from_prefs {
            let bytes = Zeroizing::new(
                URL_SAFE_NO_PAD.decode(self.prefs.device.secret.as_bytes()).map_err(|_| other("this device's key in the preferences is damaged"))?,
            );
            Some((DeviceKeys::from_secret_bytes(&bytes).map_err(other)?, "preferences"))
        } else {
            match self.keys.keychain.as_ref().map(|k| k.load()) {
                Some(Ok(Some(bytes))) => match DeviceKeys::from_secret_bytes(&bytes) {
                    Ok(k) => Some((k, "keychain")),
                    Err(e) => {
                        log::warn!("devices: the keychain's device key can't be read ({e}); making a new one");
                        None
                    }
                },
                Some(Ok(None)) | None => None,
                Some(Err(e)) => {
                    log::warn!("devices: the keychain can't be read ({e}); keeping this device's key with the preferences");
                    None
                }
            }
        };
        let (keys, store) = match kept {
            Some(k) => k,
            None => {
                let keys = DeviceKeys::generate().map_err(other)?;
                let secret = keys.to_secret_bytes();
                let kept = match self.keys.keychain.as_ref().map(|k| k.store(&secret)) {
                    Some(Ok(())) => true,
                    Some(Err(e)) => {
                        log::warn!("devices: the keychain refused this device's key ({e}); keeping it with the preferences instead");
                        false
                    }
                    None => false,
                };
                if kept {
                    (keys, "keychain")
                } else {
                    self.prefs.device.secret = URL_SAFE_NO_PAD.encode(secret.as_slice());
                    self.live.unsaved = true;
                    (keys, "preferences")
                }
            }
        };
        self.keys.device = Some(keys.clone());
        self.keys.store = Some(store);
        Ok(keys)
    }

    /// This device's public X25519 key (base64url), making the device's keys first if need be.
    pub fn device_keys_public(&mut self) -> Result<String> {
        let keys = self.device_keys()?;
        public_text(&keys)
    }

    /// This device's id on `server`, registering it there first when it isn't (or its keys
    /// changed).
    pub(crate) fn device_id(&mut self, cmd: &str, server: &str) -> Result<String> {
        let keys = self.device_keys()?;
        let public = public_text(&keys)?;
        let server = server_key(server);
        if let Some(r) = self.prefs.device.registered.iter().find(|r| r.server == server && r.public == public) {
            return Ok(r.device.clone());
        }
        let name = if self.prefs.device.name.trim().is_empty() { computer_name() } else { self.prefs.device.name.clone() };
        let req = AccountReq::RegisterDevice { name, public: keys.public().map_err(other)?, recovery: false };
        let id = match self.account_request(cmd, &server, req)? {
            AccountReply::Device { id } => id,
            _ => return Err(other("the server answered something else")),
        };
        self.prefs.device.registered.retain(|r| r.server != server);
        self.prefs.device.registered.insert(0, Registered { server, device: id.clone(), public });
        self.prefs.device.registered.truncate(MAX_REGISTERED);
        self.live.unsaved = true;
        Ok(id)
    }

    /// Keep `ring` as `file`'s keys on `server` (every epoch held: links, names, the next join).
    fn keep_ring(&mut self, server: &str, file: &str, ring: &Keyring) {
        if ring.is_empty() {
            return;
        }
        let mut all = self.kept_ring(server, file).unwrap_or_default();
        all.merge(ring);
        self.keep_file_key(server, file, &format!("#{}", ring_fragment(&all)));
    }

    /// The keys kept here for `file` on `server`.
    fn kept_ring(&self, server: &str, file: &str) -> Option<Keyring> {
        self.file_key(server, file).and_then(|k| parse_ring_fragment(k).ok())
    }

    /// `file`'s keys on `server` as this device opens them (`None`: the file isn't sealed).
    fn file_ring(&mut self, cmd: &str, server: &str, file: &str) -> Result<Option<FileRing>> {
        let (epochs, wrapped) = match self.account_request(cmd, server, AccountReq::Keyring { file: file.to_string() })? {
            AccountReply::Keyring { sealed: false, .. } => return Ok(None),
            AccountReply::Keyring { epochs, wrapped, .. } => (epochs, wrapped),
            _ => return Err(other("the server answered something else")),
        };
        // Registered first (a new device has no copies yet: the next owner or editor online
        // wraps for it).
        let me = self.device_id(cmd, server)?;
        let keys = self.device_keys()?;
        let mut ring = self.kept_ring(server, file).unwrap_or_default();
        for w in wrapped.iter().filter(|w| w.device == me) {
            if ring.get(w.epoch).is_some() {
                continue;
            }
            // A copy that doesn't open (or says another epoch) is skipped.
            match unwrap(&keys, file, &w.wrapped) {
                Ok(k) if k.epoch() == w.epoch => ring.insert(k),
                Ok(_) => log::warn!("devices: a key copy of file {file} is for another epoch than it says"),
                Err(e) => log::warn!("devices: a key copy of file {file} doesn't open on this device ({e})"),
            }
        }
        for ((s, f, _), k) in &self.keys.rotations {
            if *s == server_key(server) && f == file && epochs.contains(&k.epoch()) && ring.get(k.epoch()).is_none() {
                ring.insert(k.clone());
            }
        }
        let fr = FileRing { ring, epochs };
        if fr.complete() {
            self.keep_ring(server, file, &fr.ring);
        }
        Ok(Some(fr))
    }

    /// Where a join of `link` goes on a server with accounts (see the module docs): a member's
    /// link to a sealed file gets the keys this device holds, or waits for them. Anything else
    /// joins as before (with a key kept here for a file of yours).
    pub(crate) fn sealed_join(&mut self, cmd: &str, link: &str) -> Result<JoinKeys> {
        let plain = |s: &Session| Ok(JoinKeys::Link(s.link_with_key(link)));
        let member = !link.contains('#') && !member_free(link);
        let Some((server, file)) = server_of(link).zip(link_file(link).map(str::to_string)) else { return plain(self) };
        if !member || self.signed_in(&server).is_none() {
            return plain(self);
        }
        match self.file_ring(cmd, &server, &file) {
            Ok(None) => Ok(JoinKeys::Link(link.to_string())),
            Ok(Some(fr)) if fr.complete() => Ok(JoinKeys::Link(format!("{link}#{}", ring_fragment(&fr.ring)))),
            Ok(Some(_)) => Ok(JoinKeys::Waiting { server: server_key(&server), file }),
            // A command running in the background waits for the answer.
            Err(EngineError::Waiting) => Err(EngineError::Waiting),
            // A server older than keyrings (or one that can't be asked now): as before.
            Err(e) => {
                log::info!("devices: no keyring for file {file} ({e})");
                plain(self)
            }
        }
    }

    /// A join started waiting for access (session `session`).
    pub(crate) fn wait_for_access(&mut self, w: Waiting) {
        self.keys.waiting.retain(|x| x.session != w.session);
        self.keys.waiting.push(w);
    }

    /// Session `id` ended on a change sealed with a newer epoch than its keys ([`NEW_EPOCH`]):
    /// fetch the file's keys (in the background) and join it again once they are here.
    pub(crate) fn keys_moved_on(&mut self, id: SessionId, target: (String, Option<Published>, Option<Share>)) {
        let (link, published, share) = target;
        let bare = link.split('#').next().unwrap_or_default().to_string();
        let Some((server, file)) = server_of(&bare).zip(link_file(&bare).map(str::to_string)) else { return };
        if self.signed_in(&server).is_none() {
            return;
        }
        let after = self.kept_ring(&server, &file).and_then(|r| r.current().map(FileKey::epoch)).unwrap_or(0);
        let server = server_key(&server);
        self.wait_for_access(Waiting { session: id, after: Some(after), server: server.clone(), file, link: bare, published, share });
        if let Err(e) = self.start_background("account.syncKeys", json!({"server": server})) {
            log::info!("devices: keys not synced with {server}: {e}");
        }
    }

    /// What joining session `id` again needs: its link, and the file's record and sharing.
    pub(crate) fn keys_target(&self, id: SessionId) -> Option<(String, Option<Published>, Option<Share>)> {
        let l = self.live.get(id)?;
        let link = l.info.as_ref().map(|i| i.link.clone()).or(l.published.as_ref().map(|p| p.edit.clone()))?;
        Some((link, l.published.clone(), l.share.clone()))
    }

    /// Session `id` waits for access.
    pub fn waiting_for_access(&self, id: SessionId) -> bool {
        self.keys.waiting.iter().any(|w| w.session == id && self.live.get(id).is_some_and(|l| !l.status.active()))
    }

    /// The live sessions of sealed files on `server`: their ids and file ids.
    fn sealed_sessions(&self, server: &str) -> Vec<(SessionId, String)> {
        let key = server_key(server);
        self.live
            .iter()
            .filter(|l| l.status.active())
            .filter_map(|l| {
                let link = l.info.as_ref().map(|i| i.link.as_str()).or(l.published.as_ref().map(|p| p.edit.as_str()))?;
                // Sealed, joined as a member (a share link's key is the link's own).
                if !crate::file_keys::sealed_link(link) || member_free(link) {
                    return None;
                }
                let s = server_of(link)?;
                (server_key(&s) == key).then(|| Some((l.id, link_file(link)?.to_string()))).flatten()
            })
            .collect()
    }

    /// Hand `ring` to the live sessions of `file` (their next writes are sealed with its newest
    /// epoch).
    fn rekey_sessions(&mut self, server: &str, file: &str, ring: &Keyring) {
        let ids: Vec<SessionId> = self.sealed_sessions(server).into_iter().filter(|(_, f)| f == file).map(|(id, _)| id).collect();
        if ids.is_empty() || ring.is_empty() {
            return;
        }
        let fragment = ring_fragment(ring);
        if let Some(link) = self.live.link() {
            for id in ids {
                if let Err(e) = link.rekey(id, &fragment) {
                    log::warn!("devices: couldn't hand file {file}'s new key to its session: {e}");
                }
            }
        }
    }

    /// The key of `epoch` for a rotation of `file` on `server` that is on its way (made once).
    fn rotation_key(&mut self, server: &str, file: &str, from: &FileKey) -> Result<FileKey> {
        let id = (server_key(server), file.to_string(), from.epoch().saturating_add(1));
        if let Some((_, k)) = self.keys.rotations.iter().find(|(i, _)| *i == id) {
            return Ok(k.clone());
        }
        let k = from.rotate().map_err(other)?;
        self.keys.rotations.push((id, k.clone()));
        if self.keys.rotations.len() > MAX_ROTATIONS {
            self.keys.rotations.remove(0);
        }
        Ok(k)
    }

    /// One file's wanted copies: wrap what this device holds for them, start the next epoch when
    /// it is wanted.
    fn sync_file(&mut self, cmd: &str, server: &str, pf: &PendingFile, out: &mut Synced) -> Result<()> {
        let file = pf.file.as_str();
        let Some(fr) = self.file_ring(cmd, server, file)? else { return Ok(()) };
        let mut ring = fr.ring;
        let wrap_for = |key: &FileKey, epoch: u32| -> Result<Vec<(String, figcraft_collab::sealed::Wrapped)>> {
            pf.wanted.iter().filter(|w| w.epoch == epoch).map(|w| Ok((w.device.clone(), wrap(key, file, &w.public).map_err(other)?))).collect()
        };
        let next = pf.epoch.map(|e| e.saturating_add(1));
        // The first copies of a file published before keyrings (or right after publishing): the
        // key kept here.
        if pf.epoch.is_none() {
            if let Some(key) = ring.current().cloned() {
                let wrapped =
                    pf.wanted.iter().map(|w| Ok((w.device.clone(), wrap(&key, file, &w.public).map_err(other)?))).collect::<Result<Vec<_>>>()?;
                let n = wrapped.len();
                self.account_request(cmd, server, AccountReq::PutKeys { file: file.to_string(), epoch: key.epoch(), rotate: true, wrapped })?;
                out.wrapped += n;
            }
            return Ok(());
        }
        // Copies of epochs that exist.
        let mut epochs: Vec<u32> = pf.wanted.iter().map(|w| w.epoch).filter(|e| Some(*e) != next || !pf.rotate).collect();
        epochs.sort_unstable();
        epochs.dedup();
        for e in epochs {
            let Some(key) = ring.get(e).cloned() else { continue };
            let wrapped = wrap_for(&key, e)?;
            let n = wrapped.len();
            if n > 0 {
                self.account_request(cmd, server, AccountReq::PutKeys { file: file.to_string(), epoch: e, rotate: false, wrapped })?;
                out.wrapped += n;
            }
        }
        // A new epoch: someone was taken out, or a device revoked.
        if pf.rotate
            && let (Some(next), Some(current)) = (next, pf.epoch.and_then(|e| ring.get(e)).cloned())
        {
            let key = self.rotation_key(server, file, &current)?;
            let wrapped = wrap_for(&key, next)?;
            let n = wrapped.len();
            self.account_request(cmd, server, AccountReq::PutKeys { file: file.to_string(), epoch: next, rotate: true, wrapped })?;
            out.wrapped += n;
            ring.insert(key);
            self.keep_ring(server, file, &ring);
            self.rekey_sessions(server, file, &ring);
            out.rotated.push(file.to_string());
        }
        Ok(())
    }

    /// Sync keys on `server` (see the module docs).
    fn sync_server(&mut self, cmd: &str, server: &str) -> Result<Synced> {
        let mut out = Synced::default();
        self.device_id(cmd, server)?;
        let pending = match self.account_request(cmd, server, AccountReq::PendingKeys)? {
            AccountReply::PendingKeys(p) => p,
            _ => return Err(other("the server answered something else")),
        };
        for pf in &pending {
            if let Err(e) = self.sync_file(cmd, server, pf, &mut out) {
                if matches!(e, EngineError::Waiting) {
                    return Err(e);
                }
                out.errors.push(format!("{}: {e}", pf.file));
            }
        }
        // The sessions of sealed files open here: newer epochs others started.
        for (id, file) in self.sealed_sessions(server) {
            match self.file_ring(cmd, server, &file) {
                Ok(Some(fr)) if !fr.ring.is_empty() => {
                    if let Some(link) = self.live.link()
                        && link.rekey(id, &ring_fragment(&fr.ring)).is_ok()
                    {
                        out.refreshed.push(file);
                    }
                }
                Ok(_) => {}
                Err(EngineError::Waiting) => return Err(EngineError::Waiting),
                Err(e) => out.errors.push(format!("{file}: {e}")),
            }
        }
        // Joins waiting for access: on once the keys are here.
        let key = server_key(server);
        let waiting: Vec<Waiting> = self.keys.waiting.iter().filter(|w| w.server == key).cloned().collect();
        for w in waiting {
            let still = self.live.get(w.session).is_some_and(|l| matches!(l.status, Status::Failed { .. }));
            if !still {
                self.keys.waiting.retain(|x| x.session != w.session);
                continue;
            }
            let shown = self.live.get(w.session).and_then(|l| l.tab) == self.ds().ok().map(|d| d.uid);
            match self.file_ring(cmd, server, &w.file) {
                Ok(Some(fr)) if w.after.is_some_and(|a| fr.epochs.last().is_none_or(|e| *e <= a)) => {
                    // The key didn't move on after all: a damaged change, not a new epoch.
                    self.keys.waiting.retain(|x| x.session != w.session);
                    if let Some(l) = self.live.sessions_mut().find(|l| l.id == w.session) {
                        l.status = Status::Failed { reason: NO_SUCH_EPOCH.into() };
                    }
                }
                Ok(Some(fr)) if fr.complete() && shown => {
                    self.keys.waiting.retain(|x| x.session != w.session);
                    // With the keys just fetched (asking again would be a request of its own).
                    let link = format!("{}#{}", w.link, ring_fragment(&fr.ring));
                    match crate::live::start_join(self, "collab.join", &link, w.published.clone(), w.share.clone(), None) {
                        Ok(_) => out.joined.push(w.file.clone()),
                        Err(e) => out.errors.push(format!("{}: {e}", w.file)),
                    }
                }
                Ok(_) => {}
                Err(EngineError::Waiting) => return Err(EngineError::Waiting),
                Err(e) => out.errors.push(format!("{}: {e}", w.file)),
            }
        }
        Ok(out)
    }

    /// Something changed who is in a file on `server` (an invite, a removal): sync its keys now
    /// (what fails is tried again at the next sync).
    pub(crate) fn keys_changed(&mut self, server: &str) {
        if let Err(e) = self.sync_server("account.syncKeys", server) {
            log::info!("devices: keys not synced with {server}: {e}");
        }
    }

    /// A sealed file was published to `server` signed in: wrap its key for your devices (in the
    /// background).
    pub(crate) fn keys_after_publish(&mut self, server: &str) {
        if self.signed_in(server).is_none() {
            return;
        }
        if let Err(e) = self.start_background("account.syncKeys", json!({"server": server_key(server)})) {
            log::info!("devices: keys not synced with {server}: {e}");
        }
    }

    /// Now and then, sync keys in the background with every server you are signed in to (the
    /// engine calls it as it polls the network).
    pub(crate) fn keys_tick(&mut self) {
        if self.prefs.accounts.is_empty() || !self.live.available() || self.waiting_for("account.syncKeys") {
            return;
        }
        let now = web_time::Instant::now();
        match self.keys.next_sync {
            None => self.keys.next_sync = Some(now + self.keys.sync_every),
            Some(t) if now >= t => {
                self.keys.next_sync = Some(now + self.keys.sync_every);
                if let Err(e) = self.start_background("account.syncKeys", json!({"all": true})) {
                    log::info!("devices: keys not synced: {e}");
                }
            }
            Some(_) => {}
        }
    }
}

fn device_json(d: &DeviceInfo, me: &str) -> Value {
    json!({"id": d.id, "name": d.name, "created": d.created, "seen": d.seen, "recovery": d.recovery, "thisDevice": d.id == me})
}

fn devices(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.devices";
    let server = s.account_server(CMD, p)?;
    if let Some(name) = string(p, "name") {
        let name: String = name.trim().chars().filter(|c| !c.is_control()).take(64).collect();
        if s.prefs.device.name != name {
            s.prefs.device.name = name;
            // Registered again under the new name.
            s.prefs.device.registered.clear();
            s.live.unsaved = true;
        }
    }
    let me = s.device_id(CMD, &server)?;
    let list = match s.account_request(CMD, &server, AccountReq::Devices)? {
        AccountReply::Devices(l) => l,
        _ => return Err(other("the server answered something else")),
    };
    Ok(json!({
        "server": server,
        "device": me,
        "keyStore": s.keys.store.unwrap_or("preferences"),
        "devices": list.iter().map(|d| device_json(d, &me)).collect::<Vec<_>>(),
    }))
}

/// The safety number of your devices on a server (`figcraft_collab_seal::safety_number`, step 10):
/// what you read out to someone checking that the devices the server lists for you are yours.
fn safety_number(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.safetyNumber";
    let server = s.account_server(CMD, p)?;
    if string(p, "account").is_some() {
        return Err(bad(CMD, "only your own devices' number for now: the server doesn't list another person's devices yet"));
    }
    s.device_id(CMD, &server)?;
    let list = match s.account_request(CMD, &server, AccountReq::Devices)? {
        AccountReply::Devices(l) => l,
        _ => return Err(other("the server answered something else")),
    };
    let keys: Vec<_> = list.iter().map(|d| d.public.clone()).collect();
    Ok(json!({"server": server, "safetyNumber": figcraft_collab_seal::safety_number(&keys), "devices": list.len()}))
}

fn revoke_device(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.revokeDevice";
    let server = s.account_server(CMD, p)?;
    let device = req_string(CMD, p, "device")?;
    s.account_request(CMD, &server, AccountReq::RevokeDevice { device: device.clone() })?;
    let key = server_key(&server);
    let this = s.prefs.device.registered.iter().any(|r| r.server == key && r.device == device);
    if this {
        s.prefs.device.registered.retain(|r| !(r.server == key && r.device == device));
        s.live.unsaved = true;
    }
    // Your files start a new epoch now where you own them (the others' owners at their next sync).
    let synced = if this { Synced::default() } else { s.sync_server(CMD, &server).unwrap_or_default() };
    Ok(json!({"revoked": device, "thisDevice": this, "rotated": synced.rotated}))
}

/// What a recovery copy is sealed for: the account (a copy can't be moved to another).
fn recovery_context(account: &str) -> Vec<u8> {
    format!("figcraft recovery device|{account}").into_bytes()
}

fn recovery_key(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.recoveryKey";
    let server = s.account_server(CMD, p)?;
    let account =
        s.signed_in(&server).map(|a| a.account.clone()).ok_or_else(|| bad(CMD, "you aren't signed in to this server: `account.signIn` first"))?;
    let replace = boolean(p, "replace").unwrap_or(false);
    let old = match s.account_request(CMD, &server, AccountReq::GetRecovery)? {
        AccountReply::Recovery(c) => c,
        _ => return Err(other("the server answered something else")),
    };
    if let Some(c) = &old
        && !replace
    {
        return Ok(json!({"server": server, "created": false, "device": c.device, "made": c.created}));
    }
    s.device_id(CMD, &server)?;
    let rk = RecoveryKey::generate().map_err(other)?;
    let rdev = DeviceKeys::generate().map_err(other)?;
    let req = AccountReq::RegisterDevice { name: "Recovery key".into(), public: rdev.public().map_err(other)?, recovery: true };
    let device = match s.account_request(CMD, &server, req)? {
        AccountReply::Device { id } => id,
        _ => return Err(other("the server answered something else")),
    };
    let sealed = rk.seal(&recovery_context(&account), &rdev.to_secret_bytes()).map_err(other)?;
    s.account_request(CMD, &server, AccountReq::PutRecovery { device: device.clone(), sealed })?;
    if let Some(c) = old.filter(|c| c.device != device)
        && let Err(e) = s.account_request(CMD, &server, AccountReq::RevokeDevice { device: c.device })
    {
        log::warn!("devices: the old recovery device wasn't revoked: {e}");
    }
    // Every file key this device holds, wrapped for the recovery device too.
    let synced = s.sync_server(CMD, &server).unwrap_or_default();
    Ok(json!({
        "server": server,
        "created": true,
        "device": device,
        // Shown this once: written down by the person, kept nowhere.
        "recoveryKey": rk.to_display().as_str(),
        "wrapped": synced.wrapped,
    }))
}

fn recover(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.recover";
    let server = s.account_server(CMD, p)?;
    let account =
        s.signed_in(&server).map(|a| a.account.clone()).ok_or_else(|| bad(CMD, "you aren't signed in to this server: `account.signIn` first"))?;
    let typed = req_string(CMD, p, "recoveryKey")?;
    let rk = RecoveryKey::parse(&typed)
        .map_err(|_| bad(CMD, "that isn't a recovery key (55 letters and digits in groups of 5): check it and type it again"))?;
    let copy = match s.account_request(CMD, &server, AccountReq::GetRecovery)? {
        AccountReply::Recovery(Some(c)) => c,
        AccountReply::Recovery(None) => return Err(bad(CMD, "no recovery key was made for your account on this server")),
        _ => return Err(other("the server answered something else")),
    };
    let secret = rk
        .open(&recovery_context(&account), &copy.sealed)
        .map_err(|_| bad(CMD, "that recovery key doesn't open your recovery copy on this server"))?;
    let rdev = DeviceKeys::from_secret_bytes(&secret).map_err(other)?;
    let devices = match s.account_request(CMD, &server, AccountReq::Devices)? {
        AccountReply::Devices(l) => l,
        _ => return Err(other("the server answered something else")),
    };
    let registered = devices.iter().find(|d| d.id == copy.device && d.recovery).map(|d| d.public.clone());
    if registered != Some(rdev.public().map_err(other)?) {
        return Err(other(
            "your recovery device is no longer registered here (it was revoked): make a new recovery key from a device that still has access",
        ));
    }
    let me = s.device_id(CMD, &server)?;
    let files = match s.account_request(CMD, &server, AccountReq::Files)? {
        AccountReply::Files(f) => f,
        _ => return Err(other("the server answered something else")),
    };
    let mut recovered = Vec::new();
    for f in files {
        let file = f.info.id;
        let wrapped = match s.account_request(CMD, &server, AccountReq::Keyring { file: file.clone() })? {
            AccountReply::Keyring { sealed: true, wrapped, .. } => wrapped,
            _ => continue,
        };
        let mut ring = Keyring::new();
        for w in wrapped.iter().filter(|w| w.device == copy.device) {
            if let Ok(k) = unwrap(&rdev, &file, &w.wrapped)
                && k.epoch() == w.epoch
            {
                ring.insert(k);
            }
        }
        if ring.is_empty() {
            continue;
        }
        let mut by_epoch: BTreeMap<u32, Vec<(String, figcraft_collab::sealed::Wrapped)>> = BTreeMap::new();
        let public = s.device_keys()?.public().map_err(other)?;
        for e in ring.epochs().collect::<Vec<_>>() {
            if let Some(k) = ring.get(e) {
                by_epoch.entry(e).or_default().push((me.clone(), wrap(k, &file, &public).map_err(other)?));
            }
        }
        for (epoch, wrapped) in by_epoch {
            s.account_request(CMD, &server, AccountReq::PutKeys { file: file.clone(), epoch, rotate: false, wrapped })?;
        }
        s.keep_ring(&server, &file, &ring);
        recovered.push(file);
    }
    Ok(json!({"server": server, "device": me, "recovered": recovered.len(), "files": recovered}))
}

fn sync_keys(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.syncKeys";
    let servers: Vec<String> = if boolean(p, "all").unwrap_or(false) {
        s.prefs.accounts.iter().map(|a| a.server.clone()).collect()
    } else {
        vec![s.account_server(CMD, p)?]
    };
    let mut results = Vec::new();
    for server in servers {
        match s.sync_server(CMD, &server) {
            Ok(r) => results.push(json!({
                "server": server,
                "wrapped": r.wrapped,
                "rotated": r.rotated,
                "refreshed": r.refreshed,
                "joined": r.joined,
                "errors": r.errors,
            })),
            Err(EngineError::Waiting) => return Err(EngineError::Waiting),
            // One server asked for: its error is the command's.
            Err(e) if !boolean(p, "all").unwrap_or(false) => return Err(e),
            Err(e) => results.push(json!({"server": server, "error": e.to_string()})),
        }
    }
    let one = results.len() == 1 && !boolean(p, "all").unwrap_or(false);
    Ok(if one { results.pop().unwrap_or(Value::Null) } else { json!({"servers": results}) })
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "account.devices",
            "Your devices",
            "{server?, name? (this device's name in the list)} → {server, device (this one's id), keyStore: keychain | preferences (where this device's key is kept: preferences is weaker), devices: [{id, name, created, seen, recovery, thisDevice}]}: registers this device for end-to-end encrypted files on a server with accounts, and lists yours",
            false,
            devices
        ),
        spec!(
            "account.safetyNumber",
            "Safety number",
            "{server?} → {server, safetyNumber (12 digits, \"1234 5678 9012\"), devices (how many it covers)}: a short number for the devices registered for you on a server with accounts (recovery device included). Read it out to someone who checks it the same way: a device the server added without you changes it",
            false,
            safety_number
        ),
        spec!(
            "account.revokeDevice",
            "Revoke device",
            "{server?, device} → {revoked, thisDevice, rotated: [file]}: takes a device off your account (a lost laptop): its keys go, and the sealed files you are in get a new key for new writes (yours now, the others when an owner is next online)",
            false,
            revoke_device
        ),
        spec!(
            "account.recoveryKey",
            "Recovery key",
            "{server?, replace? (make a new one; the old one stops working)} → {server, created: true, device, recoveryKey (shown this once: write it down), wrapped} | {server, created: false, device, made}: a recovery key gives a new device access to your end-to-end encrypted files when no other device is at hand",
            false,
            recovery_key
        ),
        spec!(
            "account.recover",
            "Recover access",
            "{server?, recoveryKey} → {server, device, recovered, files: [file]}: on a new device, opens your end-to-end encrypted files with your recovery key",
            false,
            recover
        ),
        spec!(
            "account.syncKeys",
            "Share file keys",
            "{server? | all?} → {server, wrapped, rotated: [file], refreshed: [file], joined: [file], errors} (all: {servers: […]}): gives the keys of end-to-end encrypted files you hold to members' devices that lack them, starts a new key where someone was taken out (owners), and opens files waiting for access. The app does it by itself now and then",
            false,
            sync_keys
        ),
    ]
}

#[cfg(test)]
#[path = "devices_tests.rs"]
mod tests;
