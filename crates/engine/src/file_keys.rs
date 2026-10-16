//! The keys of sealed (end-to-end encrypted) files you published (milestone M9, step 8 of
//! `docs/accounts-and-e2e.md`).
//!
//! The engine never seals or opens a session's messages: the transport does that around the sync
//! client, with the key a sealed file's link carries after `#k=` (`…&token=…#k=<key>`). What the
//! engine keeps is the key of each sealed file published from this app, with the preferences
//! ([`Prefs::file_keys`](crate::Prefs)) by server and file id, so its owner can open it again
//! from a link without the key (a member's link on a server with accounts, `account.files`) and
//! read its name in listings. A key is a password: it is kept on this computer only, never logged,
//! never in a command's result other than the share links it is part of, and `Debug` leaves it out.
//! (Keys kept per device on the server, so other devices and invited members get them, are step 9.)

use figcraft_collab::sealed::{Sealed, parse_sealed_name};
use figcraft_collab_seal::{Keyring, Slot, open, parse_link_fragment, seal};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::Session;
use crate::accounts::{server_key, server_of};
use crate::live::{Shared, SharedLink};

/// Most keys kept: keeping another drops the oldest.
pub const MAX_FILE_KEYS: usize = 1000;

/// What a sealed file's name shows when this app doesn't have its key.
pub const ENCRYPTED_NAME: &str = "Encrypted file";

/// The key of a sealed file (see the module docs). Newest first in the list.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeptKey {
    /// The server's address, as [`server_key`] keeps it.
    pub server: String,
    /// The file's id there.
    pub file: String,
    /// The link fragment that carries the key (`k=…`, without the `#`): a password.
    pub key: String,
}

impl std::fmt::Debug for KeptKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptKey").field("server", &self.server).field("file", &self.file).finish_non_exhaustive()
    }
}

impl KeptKey {
    /// The record made safe to use, or `None` when it can't be one.
    fn clean(self) -> Option<KeptKey> {
        let id = (1..=64).contains(&self.file.len()) && self.file.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let server = !self.server.is_empty() && self.server.len() <= 512 && !self.server.contains(char::is_control);
        (id && server && parse_link_fragment(&self.key).is_ok()).then_some(self)
    }
}

/// Reads the list from the preferences: whatever isn't a usable record is skipped.
pub(crate) fn read<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<KeptKey>, D::Error> {
    let v = Value::deserialize(d).unwrap_or(Value::Null);
    let entries = v.as_array().map(Vec::as_slice).unwrap_or_default();
    let mut out: Vec<KeptKey> = Vec::new();
    for k in entries.iter().take(2 * MAX_FILE_KEYS).filter_map(|e| serde_json::from_value::<KeptKey>(e.clone()).ok()).filter_map(KeptKey::clean) {
        if out.len() < MAX_FILE_KEYS && !out.iter().any(|o| o.server == k.server && o.file == k.file) {
            out.push(k);
        }
    }
    Ok(out)
}

/// The key a link carries after `#` (`k=…`), if it has one.
pub fn link_key(link: &str) -> Option<&str> {
    let (_, fragment) = link.split_once('#')?;
    fragment.split('&').find(|p| p.starts_with("k="))
}

/// A sealed file's link (its key is in it).
pub fn sealed_link(link: &str) -> bool {
    link_key(link).is_some()
}

/// The file id a `figcraft://join?…` (or `ws://…?file=…`) link names.
fn link_file(link: &str) -> Option<&str> {
    let query = link.split('#').next()?.split_once('?')?.1;
    query.split('&').find_map(|p| p.strip_prefix("file="))
}

/// A sealed file's name as listings give it (`sealed:…`), opened with `key` (a link fragment).
fn open_name(key: &str, file: &str, listed: &str) -> Option<String> {
    let sealed = parse_sealed_name(listed)?;
    let ring = Keyring::from(parse_link_fragment(key).ok()?);
    let bytes = open(&ring, file, &Slot::Meta { what: "name".into() }, &sealed).ok()?;
    let name: String = String::from_utf8(bytes).ok()?.trim().chars().filter(|c| !c.is_control()).take(256).collect();
    Some(name)
}

impl Session {
    /// The key kept for `file` on `server` (a link fragment, `k=…`).
    pub(crate) fn file_key(&self, server: &str, file: &str) -> Option<&str> {
        let server = server_key(server);
        self.prefs.file_keys.iter().find(|k| k.server == server && k.file == file).map(|k| k.key.as_str())
    }

    /// Keep the key `link` carries for `file` on `server` (nothing for a link without one).
    pub(crate) fn keep_file_key(&mut self, server: &str, file: &str, link: &str) {
        let Some(key) = link_key(link) else { return };
        let Some(record) = (KeptKey { server: server_key(server), file: file.to_string(), key: key.to_string() }).clean() else { return };
        if self.prefs.file_keys.first() == Some(&record) {
            return;
        }
        self.prefs.file_keys.retain(|k| !(k.server == record.server && k.file == record.file));
        self.prefs.file_keys.insert(0, record);
        self.prefs.file_keys.truncate(MAX_FILE_KEYS);
        // Saved at once, like owner tokens: a crash must not lose a key.
        self.live.unsaved = true;
    }

    /// `link` with the key kept for its file when it has none (a member's link to a sealed file of
    /// yours, `collab.openFile`): what the transport joins with.
    pub(crate) fn link_with_key(&self, link: &str) -> String {
        if link.contains('#') {
            return link.to_string();
        }
        let key = server_of(link).zip(link_file(link)).and_then(|(server, file)| self.file_key(&server, file));
        match key {
            Some(k) => format!("{link}#{k}"),
            None => link.to_string(),
        }
    }

    /// The links others join `file` on `server` with: a sealed file's carry its key, and have no
    /// join codes (a code can't carry the key).
    pub(crate) fn links_with_key(&self, server: &str, file: &str, mut links: Shared) -> Shared {
        let Some(key) = self.file_key(server, file) else { return links };
        let add = |l: &mut SharedLink| {
            if !l.link.contains('#') {
                l.link = format!("{}#{key}", l.link);
            }
            l.code = None;
        };
        add(&mut links.edit);
        links.view.as_mut().map(add);
        links
    }

    /// `name` sealed for `file` on `server` with the key kept for it (`None`: no key kept, the
    /// file isn't a sealed one of yours).
    pub(crate) fn seal_name(&self, server: &str, file: &str, name: &str) -> Option<std::result::Result<Sealed, String>> {
        let key = parse_link_fragment(self.file_key(server, file)?).map_err(|e| e.to_string());
        Some(key.and_then(|k| seal(&k, file, &Slot::Meta { what: "name".into() }, name.as_bytes()).map_err(|e| e.to_string())))
    }

    /// A file's name as a listing gave it, shown: a sealed file's opened with the key kept for it
    /// (or the one `link` carries), else [`ENCRYPTED_NAME`]; and whether the file is sealed.
    pub(crate) fn listed_name(&self, server: &str, file: &str, listed: &str, link: Option<&str>) -> (String, bool) {
        if parse_sealed_name(listed).is_none() {
            return (listed.to_string(), false);
        }
        let keys = link.and_then(link_key).into_iter().chain(self.file_key(server, file));
        let name = keys.into_iter().find_map(|k| open_name(k, file, listed));
        (name.unwrap_or_else(|| ENCRYPTED_NAME.to_string()), true)
    }
}
