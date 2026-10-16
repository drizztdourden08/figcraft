//! The remote servers you use, on top of the files on this computer (milestone M9;
//! `docs/server-accounts.md`).
//!
//! The app always works with local files; the servers in [`Prefs::servers`](crate::Prefs) are
//! available on top of that (the home screen has a section for each). Each is kept by the name you
//! gave it ([`SavedServer`]), in the order you put them. The first one is where join codes typed
//! without a server are asked about, and what `account.*` commands mean without a `server`
//! (`pref.publishServer` follows it).
//!
//! Preferences from before this list name one server, the server for online sharing: it is the
//! list until you change it. The browser build hosted by a server uses that server only (the one
//! the build names, `FIGCRAFT_DEFAULT_SERVER`): its list can't be changed.
//!
//! `account.check` asks a server whether your cached sign-in there still works, and forgets one it
//! no longer takes. No result carries a session token.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::accounts::{SignedIn, server_key};
use crate::cmd::CommandSpec;
use crate::live::{NetReply, SignIn, SignInReply};
use crate::params::{get, req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

/// Most servers kept.
pub const MAX_SERVERS: usize = 20;

/// Longest server name (characters).
const MAX_NAME: usize = 64;

/// A server you use, by the name you gave it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SavedServer {
    pub name: String,
    /// Its address as [`server_key`] keeps it (`wss://host/`), never with a key.
    pub url: String,
}

/// The host a server's address names (`wss://share.example/` is `share.example`).
pub fn host(server: &str) -> &str {
    server.split_once("://").map_or(server, |(_, rest)| rest).trim_end_matches('/')
}

/// The list can be changed here (not in the browser build a server hosts).
pub fn editable() -> bool {
    !cfg!(target_arch = "wasm32")
}

/// A server address as typed, checked: `ws://host:port/` or `wss://host/path/`, without a key.
fn valid_url(cmd: &str, url: &str) -> Result<String> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    let web_socket = lower.starts_with("ws://") || lower.starts_with("wss://");
    let host_part = url.split_once("://").map_or("", |(_, rest)| rest).split('/').next().unwrap_or_default();
    if !web_socket || host_part.is_empty() || url.len() > 500 || url.contains(|c: char| c.is_whitespace() || c.is_control() || c == '?' || c == '#') {
        return Err(bad(cmd, "a server's address is ws://host:port/ or wss://host/path/, without a key (it is saved with your preferences)"));
    }
    Ok(server_key(url))
}

fn clean_name(name: &str, url: &str) -> String {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(MAX_NAME).collect();
    if name.is_empty() { host(url).to_string() } else { name }
}

/// The one server named as `url`, called by its host.
fn named(url: &str) -> Vec<SavedServer> {
    let url = url.trim();
    if url.is_empty() {
        return Vec::new();
    }
    let url = server_key(url);
    vec![SavedServer { name: host(&url).to_string(), url }]
}

impl Session {
    /// The servers you use, in order (see the module docs).
    pub fn servers(&self) -> Vec<SavedServer> {
        if !editable() {
            return named(crate::live::DEFAULT_SERVER);
        }
        match &self.prefs.servers {
            Some(list) => list.clone(),
            None => named(&self.prefs.publish_server),
        }
    }

    /// The first server ([`server_key`]), or empty when there is none.
    pub fn home_server(&self) -> String {
        self.servers().first().map(|s| s.url.clone()).unwrap_or_default()
    }

    /// Keep `list` as the servers; online sharing and join codes follow the first one.
    fn set_servers(&mut self, list: Vec<SavedServer>) {
        self.prefs.publish_server = list.first().map(|s| s.url.clone()).unwrap_or_default();
        self.prefs.servers = Some(list);
        self.live.unsaved = true;
    }

    fn servers_json(&self) -> Value {
        let list: Vec<Value> = self
            .servers()
            .iter()
            .map(|sv| json!({"name": sv.name, "url": sv.url, "signedIn": self.signed_in(&sv.url).map_or(Value::Null, SignedIn::json)}))
            .collect();
        json!({"servers": list, "editable": editable()})
    }
}

fn changing(cmd: &str) -> Result<()> {
    if editable() { Ok(()) } else { Err(bad(cmd, "this version works with the server it is hosted on only")) }
}

fn list(s: &mut Session, _p: &Value) -> Result<Value> {
    Ok(s.servers_json())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "servers.add";
    changing(CMD)?;
    let url = valid_url(CMD, &req_string(CMD, p, "url")?)?;
    let name = clean_name(&string(p, "name").unwrap_or_default(), &url);
    let mut list = s.servers();
    let full = list.len() >= MAX_SERVERS;
    match list.iter_mut().find(|sv| sv.url == url) {
        Some(sv) => sv.name = name,
        None if full => return Err(bad(CMD, format!("at most {MAX_SERVERS} servers are kept: remove one first"))),
        None => list.push(SavedServer { name, url: url.clone() }),
    }
    s.set_servers(list);
    let mut v = s.servers_json();
    v["added"] = json!(url);
    Ok(v)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "servers.remove";
    changing(CMD)?;
    let url = server_key(&req_string(CMD, p, "url")?);
    let mut list = s.servers();
    let before = list.len();
    list.retain(|sv| sv.url != url);
    let removed = list.len() != before;
    s.set_servers(list);
    let mut v = s.servers_json();
    v["removed"] = json!(removed);
    Ok(v)
}

fn move_to(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "servers.move";
    changing(CMD)?;
    let url = server_key(&req_string(CMD, p, "url")?);
    let to = get(p, "to").and_then(Value::as_u64).ok_or_else(|| bad(CMD, "`to` is the position to move it to (0: first)"))?;
    let mut list = s.servers();
    let from = list.iter().position(|sv| sv.url == url).ok_or_else(|| bad(CMD, "that server isn't in the list"))?;
    let item = list.remove(from);
    let to = usize::try_from(to).unwrap_or(usize::MAX).min(list.len());
    list.insert(to, item);
    s.set_servers(list);
    Ok(s.servers_json())
}

fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let server = s.account_server("account.check", p)?;
    let Some(me) = s.signed_in(&server).cloned() else {
        return Ok(json!({"server": server, "signedIn": false, "reason": "you aren't signed in to this server"}));
    };
    let reply = match s.net(crate::live::NetRequest::SignIn { server: server.clone(), req: SignIn::Session { token: me.session.clone() } })?.0 {
        NetReply::SignIn(r) => r,
        _ => return Err(EngineError::Other("the link answered something else".into())),
    };
    match reply {
        Ok(SignInReply::SignedIn(fresh)) => {
            let account = s.keep_sign_in(&server, fresh);
            Ok(json!({"server": server, "signedIn": true, "account": account}))
        }
        Ok(SignInReply::Refused { reason }) => {
            let reason = format!("your sign-in to this server ended ({reason}): sign in again");
            s.forget_sign_in(&server, &reason);
            Ok(json!({"server": server, "signedIn": false, "reason": reason}))
        }
        Ok(_) => Ok(json!({"server": server, "signedIn": false, "reason": "the server didn't sign you in", "offline": false})),
        // Not reachable now: the sign-in stays for when it is.
        Err(why) => Ok(json!({"server": server, "signedIn": false, "offline": true, "reason": why})),
    }
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "servers.list",
            "Servers",
            "{} → {servers: [{name, url, signedIn: {server, account, name, email, admin, expires} | null}], editable}: the remote servers you use, in order (the home screen has a section for each; the first is where join codes are asked)",
            false,
            list
        ),
        spec!(
            "servers.add",
            "Add server",
            "{url (ws://host:port/ or wss://host/path/, no key), name? (default: its host)} → servers.list's answer with {added}: at the end of the list (renamed when it is there already)",
            false,
            add
        ),
        spec!(
            "servers.remove",
            "Remove server",
            "{url} → servers.list's answer with {removed}: forgets the server (sign-ins to it stay)",
            false,
            remove
        ),
        spec!(
            "servers.move",
            "Move server",
            "{url, to (0: first)} → servers.list's answer: puts the server at another place in the list",
            false,
            move_to
        ),
        spec!(
            "account.check",
            "Check sign-in",
            "{server? (default: the first server)} → {server, signedIn: true, account} | {server, signedIn: false, reason, offline?}: asks the server whether your sign-in there still works; one it no longer takes is forgotten (offline: it couldn't be reached and the sign-in stays)",
            false,
            check
        ),
    ]
}

#[cfg(test)]
#[path = "servers_tests.rs"]
mod tests;
