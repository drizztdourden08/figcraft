//! Signing in to servers with accounts, and the people in your files there (milestone M9;
//! `docs/accounts-and-e2e.md`).
//!
//! A server with accounts lets people in by who they are. `account.signIn` signs in through one of
//! the server's identity providers: in the browser (the provider's page opens; the app waits for
//! it to come back), with a code typed on another device (`account.signInPoll` asks whether it
//! was entered: what scripts and agents use), or with a token. The server hands back a session
//! token, kept with the preferences ([`Prefs::accounts`](crate::Prefs)) on this computer only,
//! like the owner tokens of your online files: no command result or summary carries it, and
//! `Debug` leaves it out. Joining or publishing a file on that server then signs in first.
//!
//! On such a server a file has members with a role (owner, editor, viewer):
//! `collab.members`, `collab.invite`, `collab.setRole` and `collab.removeMember` manage them for
//! the file in front; `account.files` lists yours.

use figcraft_collab::message::{AccountReply, AccountReq, Invited, Member, MyFile, Role};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cmd::CommandSpec;
use crate::live::{Flow, Me, NetReply, NetRequest, ServerInfo, SignIn, SignInReply};
use crate::params::{req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

/// Most servers you stay signed in to.
pub const MAX_ACCOUNTS: usize = 50;

/// You, signed in to a server (see the module docs).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignedIn {
    /// The server's address (`wss://host/`), as [`server_key`] keeps it.
    pub server: String,
    pub account: String,
    pub name: String,
    pub email: Option<String>,
    pub admin: bool,
    /// The session token: a password. Never logged or put in a command's result.
    pub session: String,
    /// When the sign-in ends unless used (seconds since 1970).
    pub expires: u64,
}

impl std::fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn").field("server", &self.server).field("account", &self.account).field("name", &self.name).finish_non_exhaustive()
    }
}

impl SignedIn {
    fn json(&self) -> Value {
        json!({"server": self.server, "account": self.account, "name": self.name, "email": self.email, "admin": self.admin, "expires": self.expires})
    }
}

/// A sign-in waiting for the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pending {
    /// The provider's page is open in the browser.
    Browser { server: String, url: String },
    /// A code to type on another device.
    Device { server: String, provider: String, handle: String, user_code: String, verification_uri: String, interval: u32 },
}

/// What the app knows of signing in (this run).
#[derive(Clone, Debug, Default)]
pub struct Accounts {
    pub pending: Option<Pending>,
    /// The last sign-in's outcome, for the UI: who, or why not.
    pub last: Option<std::result::Result<String, String>>,
}

/// How a server's address is kept and compared: trimmed, without a query, lowercase scheme and
/// host, ending with `/`; `ws(s)://` assumed.
pub fn server_key(server: &str) -> String {
    let s = server.trim();
    let s = s.split('?').next().unwrap_or_default();
    let (scheme, rest) = s.split_once("://").unwrap_or(("wss", s));
    let (host, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    let path = if path.ends_with('/') { path.to_string() } else { format!("{path}/") };
    format!("{}://{}{path}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase())
}

/// The server a `figcraft://join?…` link names (`server=…`, or `host=…` for `ws://host/`).
pub fn server_of(link: &str) -> Option<String> {
    let query = link.split_once('?')?.1;
    let get = |k: &str| query.split('&').filter_map(|p| p.split_once('=')).find(|(key, _)| *key == k).map(|(_, v)| v.to_string());
    match (get("server"), get("host")) {
        (Some(s), _) => Some(s.replace("%3A", ":").replace("%2F", "/").replace("%3a", ":").replace("%2f", "/")),
        (None, Some(h)) => Some(format!("ws://{h}/")),
        _ => None,
    }
}

impl Session {
    /// The server a command means: its `server`, else the one in Preferences.
    fn account_server(&self, cmd: &str, p: &Value) -> Result<String> {
        let s = string(p, "server").unwrap_or_else(|| self.prefs.publish_server.clone());
        let s = if s.trim().is_empty() { crate::live::DEFAULT_SERVER.to_string() } else { s };
        if s.trim().is_empty() {
            return Err(bad(cmd, "no server: give `server` (wss://host/) or set one in Preferences"));
        }
        Ok(server_key(&s))
    }

    /// Your sign-in to `server`, if any.
    pub fn signed_in(&self, server: &str) -> Option<&SignedIn> {
        let key = server_key(server);
        self.prefs.accounts.iter().find(|a| a.server == key)
    }

    /// Tell the link where you are signed in (before it joins or publishes).
    pub(crate) fn share_sign_ins(&mut self) {
        let list: Vec<(String, String)> = self.prefs.accounts.iter().map(|a| (a.server.clone(), a.session.clone())).collect();
        if let Some(link) = self.live.link() {
            link.sign_ins(list);
        }
    }

    /// Keep a sign-in (replacing the one to the same server).
    fn keep_sign_in(&mut self, server: &str, me: Me) -> Value {
        let key = server_key(server);
        let session = match (me.session.is_empty(), self.signed_in(&key)) {
            (true, Some(old)) => old.session.clone(),
            _ => me.session.clone(),
        };
        let s = SignedIn { server: key.clone(), account: me.account, name: me.name, email: me.email, admin: me.admin, session, expires: me.expires };
        let json = s.json();
        self.prefs.accounts.retain(|a| a.server != key);
        self.prefs.accounts.insert(0, s);
        self.prefs.accounts.truncate(MAX_ACCOUNTS);
        self.accounts.pending = None;
        self.accounts.last = Some(Ok(json["name"].as_str().unwrap_or_default().to_string()));
        self.live.unsaved = true;
        self.share_sign_ins();
        json
    }

    /// A browser sign-in came back (see [`crate::live::Event::SignIn`]).
    pub(crate) fn account_signed_in(&mut self, server: &str, reply: std::result::Result<SignInReply, String>) {
        let waiting = matches!(&self.accounts.pending, Some(Pending::Browser { server: s, .. }) if *s == server_key(server));
        if !waiting {
            return;
        }
        self.accounts.pending = None;
        match reply {
            Ok(SignInReply::SignedIn(me)) => {
                self.keep_sign_in(server, me);
            }
            Ok(SignInReply::Refused { reason }) | Err(reason) => self.accounts.last = Some(Err(reason)),
            Ok(_) => self.accounts.last = Some(Err("the server didn't sign you in".into())),
        }
    }

    fn server_info(&mut self, server: &str) -> Result<ServerInfo> {
        match self.net(NetRequest::Info { server: server.to_string() })?.0 {
            NetReply::Info(r) => r.map_err(EngineError::Other),
            _ => Err(EngineError::Other("the link answered something else".into())),
        }
    }

    fn sign_in_step(&mut self, server: &str, req: SignIn) -> Result<SignInReply> {
        match self.net(NetRequest::SignIn { server: server.to_string(), req })?.0 {
            NetReply::SignIn(r) => r.map_err(EngineError::Other),
            _ => Err(EngineError::Other("the link answered something else".into())),
        }
    }

    /// One request on your account at `server`.
    fn account_request(&mut self, cmd: &str, server: &str, req: AccountReq) -> Result<AccountReply> {
        let Some(me) = self.signed_in(server) else {
            return Err(bad(cmd, "you aren't signed in to this server: `account.signIn` first"));
        };
        let session = me.session.clone();
        let reply = match self.net(NetRequest::Account { server: server.to_string(), session, req })?.0 {
            NetReply::Account(r) => r.map_err(EngineError::Other)?,
            _ => return Err(EngineError::Other("the link answered something else".into())),
        };
        match reply {
            AccountReply::Failed { reason } => Err(EngineError::Other(reason)),
            r => Ok(r),
        }
    }

    /// The file in front, on a server with accounts: its server and id.
    fn account_file(&self, cmd: &str) -> Result<(String, String)> {
        let live = self.live();
        let published = live.published.as_ref().ok_or_else(|| bad(cmd, "the file in front isn't on a server (publish it first)"))?;
        let server = if live.server.trim().is_empty() { server_of(&published.edit).unwrap_or_default() } else { live.server.clone() };
        if server.is_empty() {
            return Err(bad(cmd, "the file in front isn't on a server (publish it first)"));
        }
        Ok((server_key(&server), published.file.clone()))
    }
}

fn info_json(info: &ServerInfo) -> Value {
    let providers: Vec<Value> = info
        .providers
        .iter()
        .map(|p| {
            let flows: Vec<&str> = p
                .flows
                .iter()
                .map(|f| match f {
                    Flow::Browser { .. } => "browser",
                    Flow::Device => "device",
                    Flow::Token { .. } => "token",
                })
                .collect();
            json!({"id": p.id, "label": p.label, "flows": flows})
        })
        .collect();
    json!({"auth": info.auth.id(), "accounts": info.auth.accounts(), "links": info.auth.links(), "providers": providers, "e2e": info.e2e.id()})
}

fn info(s: &mut Session, p: &Value) -> Result<Value> {
    let server = s.account_server("account.info", p)?;
    let info = s.server_info(&server)?;
    let mut v = info_json(&info);
    v["server"] = json!(server);
    v["signedIn"] = s.signed_in(&server).map_or(Value::Null, SignedIn::json);
    Ok(v)
}

fn sign_in(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.signIn";
    let server = s.account_server(CMD, p)?;
    let info = s.server_info(&server)?;
    if !info.auth.accounts() {
        return Err(bad(CMD, "this server has no accounts: join its files with links or codes"));
    }
    let provider = match string(p, "provider") {
        Some(id) => info.providers.iter().find(|x| x.id == id).ok_or_else(|| bad(CMD, format!("this server has no sign-in called {id:?}")))?,
        None => info.providers.first().ok_or_else(|| bad(CMD, "this server has no sign-in providers"))?,
    };
    let has = |want: &str| {
        provider
            .flows
            .iter()
            .any(|f| matches!((f, want), (Flow::Browser { .. }, "browser") | (Flow::Device, "device") | (Flow::Token { .. }, "token")))
    };
    let token = string(p, "token");
    let flow = match (string(p, "flow"), &token) {
        (Some(f), _) => f,
        (None, Some(_)) => "token".into(),
        (None, None) if has("browser") => "browser".into(),
        (None, None) if has("device") => "device".into(),
        (None, None) => "token".into(),
    };
    if !has(&flow) {
        return Err(bad(CMD, format!("{} doesn't offer `{flow}` sign-in here", provider.label)));
    }
    let provider_id = provider.id.clone();
    match flow.as_str() {
        "token" => {
            let token = token.ok_or_else(|| bad(CMD, "give `token`"))?;
            match s.sign_in_step(&server, SignIn::Token { provider: provider_id, token })? {
                SignInReply::SignedIn(me) => Ok(json!({"status": "signedIn", "account": s.keep_sign_in(&server, me)})),
                SignInReply::Refused { reason } => Err(EngineError::Other(reason)),
                _ => Err(EngineError::Other("the server didn't sign you in".into())),
            }
        }
        "device" => match s.sign_in_step(&server, SignIn::DeviceStart { provider: provider_id.clone() })? {
            SignInReply::Device(code) => {
                let pending = Pending::Device {
                    server: server.clone(),
                    provider: provider_id,
                    handle: code.handle,
                    user_code: code.user_code.clone(),
                    verification_uri: code.verification_uri.clone(),
                    interval: code.interval,
                };
                s.accounts.pending = Some(pending);
                s.request_ui("account.code", json!({"userCode": code.user_code, "verificationUri": code.verification_uri}));
                Ok(
                    json!({"status": "enterCode", "userCode": code.user_code, "verificationUri": code.verification_uri, "interval": code.interval, "expiresIn": code.expires_in}),
                )
            }
            SignInReply::Refused { reason } => Err(EngineError::Other(reason)),
            _ => Err(EngineError::Other("the server didn't start a device sign-in".into())),
        },
        "browser" => {
            let Some(page) = provider.flows.iter().find(|f| matches!(f, Flow::Browser { .. })).cloned() else {
                return Err(bad(CMD, "no sign-in page"));
            };
            let link = s.live.link().ok_or_else(|| EngineError::Other(crate::live::NO_ACCOUNTS.into()))?;
            let url = link.browser_sign_in(&server, &provider_id, &page).map_err(EngineError::Other)?;
            s.accounts.pending = Some(Pending::Browser { server: server.clone(), url: url.clone() });
            s.request_ui("open.url", json!({"url": url}));
            Ok(json!({"status": "waitingForBrowser", "url": url}))
        }
        other => Err(bad(CMD, format!("`flow` is browser, device or token, not {other:?}"))),
    }
}

fn sign_in_poll(s: &mut Session, _p: &Value) -> Result<Value> {
    const CMD: &str = "account.signInPoll";
    match s.accounts.pending.clone() {
        None => Ok(json!({"status": "idle", "last": last_json(s)})),
        Some(Pending::Browser { url, .. }) => Ok(json!({"status": "waitingForBrowser", "url": url})),
        Some(Pending::Device { server, provider, handle, user_code, verification_uri, interval }) => {
            match s.sign_in_step(&server, SignIn::DevicePoll { provider, handle })? {
                SignInReply::SignedIn(me) => Ok(json!({"status": "signedIn", "account": s.keep_sign_in(&server, me)})),
                SignInReply::Pending => {
                    Ok(json!({"status": "enterCode", "userCode": user_code, "verificationUri": verification_uri, "interval": interval}))
                }
                SignInReply::Refused { reason } => {
                    s.accounts.pending = None;
                    s.accounts.last = Some(Err(reason.clone()));
                    Err(EngineError::Other(reason))
                }
                _ => Err(bad(CMD, "the server answered something else")),
            }
        }
    }
}

fn last_json(s: &Session) -> Value {
    match &s.accounts.last {
        Some(Ok(name)) => json!({"signedInAs": name}),
        Some(Err(why)) => json!({"error": why}),
        None => Value::Null,
    }
}

fn cancel(s: &mut Session, _p: &Value) -> Result<Value> {
    let was = s.accounts.pending.take().is_some();
    Ok(json!({"cancelled": was}))
}

fn sign_out(s: &mut Session, p: &Value) -> Result<Value> {
    let server = s.account_server("account.signOut", p)?;
    let Some(me) = s.signed_in(&server).cloned() else { return Ok(json!({"signedOut": false, "server": server})) };
    // Forgotten here first; the server is told when it can be reached (its session ends anyway).
    s.prefs.accounts.retain(|a| a.server != me.server);
    s.live.unsaved = true;
    s.share_sign_ins();
    let told = s.sign_in_step(&server, SignIn::SignOut { token: me.session }).is_ok();
    Ok(json!({"signedOut": true, "server": server, "serverTold": told}))
}

fn status(s: &mut Session, _p: &Value) -> Result<Value> {
    let accounts: Vec<Value> = s.prefs.accounts.iter().map(SignedIn::json).collect();
    let pending = match &s.accounts.pending {
        None => Value::Null,
        Some(Pending::Browser { server, url }) => json!({"server": server, "flow": "browser", "url": url}),
        Some(Pending::Device { server, user_code, verification_uri, .. }) => {
            json!({"server": server, "flow": "device", "userCode": user_code, "verificationUri": verification_uri})
        }
    };
    Ok(json!({"accounts": accounts, "pending": pending, "last": last_json(s)}))
}

fn role_id(r: Role) -> &'static str {
    r.id()
}

/// One of your files on `server`: a sealed file's name opened with its key kept here, else
/// "Encrypted file" (`sealed: true` either way).
fn my_file_json(s: &Session, server: &str, f: &MyFile) -> Value {
    let (name, sealed) = s.listed_name(server, &f.info.id, &f.info.name, None);
    json!({"file": f.info.id, "name": name, "sealed": sealed, "role": role_id(f.role), "people": f.info.people, "updated": f.info.updated})
}

fn files(s: &mut Session, p: &Value) -> Result<Value> {
    let server = s.account_server("account.files", p)?;
    match s.account_request("account.files", &server, AccountReq::Files)? {
        AccountReply::Files(list) => Ok(json!({"server": server, "files": list.iter().map(|f| my_file_json(s, &server, f)).collect::<Vec<_>>()})),
        _ => Err(EngineError::Other("the server answered something else".into())),
    }
}

fn member_json(m: &Member) -> Value {
    json!({"account": m.account, "name": m.name, "email": m.email, "role": role_id(m.role)})
}

fn invited_json(i: &Invited) -> Value {
    json!({"email": i.email, "role": role_id(i.role)})
}

fn members(s: &mut Session, _p: &Value) -> Result<Value> {
    const CMD: &str = "collab.members";
    let (server, file) = s.account_file(CMD)?;
    match s.account_request(CMD, &server, AccountReq::Members { file: file.clone() })? {
        AccountReply::Members { members, invited } => Ok(json!({
            "server": server,
            "file": file,
            "members": members.iter().map(member_json).collect::<Vec<_>>(),
            "invited": invited.iter().map(invited_json).collect::<Vec<_>>(),
        })),
        _ => Err(EngineError::Other("the server answered something else".into())),
    }
}

fn role(cmd: &str, p: &Value) -> Result<Role> {
    let r = string(p, "role").unwrap_or_else(|| "editor".into());
    Role::parse(&r).ok_or_else(|| bad(cmd, "`role` is owner, editor or viewer"))
}

fn invite(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "collab.invite";
    let (server, file) = s.account_file(CMD)?;
    let email = req_string(CMD, p, "email")?;
    let role = role(CMD, p)?;
    s.account_request(CMD, &server, AccountReq::Invite { file, email: email.clone(), role })?;
    Ok(json!({"invited": email, "role": role.id()}))
}

fn set_role(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "collab.setRole";
    let (server, file) = s.account_file(CMD)?;
    let account = req_string(CMD, p, "account")?;
    let role = role(CMD, p)?;
    s.account_request(CMD, &server, AccountReq::SetRole { file, account: account.clone(), role })?;
    Ok(json!({"account": account, "role": role.id()}))
}

fn remove_member(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "collab.removeMember";
    let (server, file) = s.account_file(CMD)?;
    let req = match (string(p, "account"), string(p, "email")) {
        (Some(account), _) => AccountReq::RemoveMember { file, account },
        (None, Some(email)) => AccountReq::Uninvite { file, email },
        (None, None) => return Err(bad(CMD, "give `account` (a member) or `email` (an invite)")),
    };
    s.account_request(CMD, &server, req)?;
    Ok(json!({"removed": true}))
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "account.info",
            "Server accounts",
            "{server? (default: the server in Preferences)} → {server, auth: links | accounts | accounts+links, accounts, links, providers: [{id, label, flows: [browser | device | token]}], e2e: off | optional | required, signedIn: {server, account, name, email, admin, expires} | null}: what the server accepts",
            false,
            info
        ),
        spec!(
            "account.signIn",
            "Sign in to server",
            "{server?, provider? (an id from `account.info`; default the first), flow? (browser | device | token; default browser when offered), token? (the token flow)} → {status: signedIn, account} (token), {status: enterCode, userCode, verificationUri, interval, expiresIn} (device: type the code there, then `account.signInPoll`), or {status: waitingForBrowser, url} (the provider's page opens in the browser; `account.status` tells when it came back). The session token is kept on this computer only and never returned",
            false,
            sign_in
        ),
        spec!(
            "account.signInPoll",
            "Check sign-in",
            "{} → {status: signedIn, account} | {status: enterCode, userCode, verificationUri, interval} | {status: waitingForBrowser, url} | {status: idle, last}: asks the server whether the device code was entered",
            false,
            sign_in_poll
        ),
        spec!("account.cancelSignIn", "Cancel sign-in", "{} → {cancelled}: stops waiting for a sign-in", false, cancel),
        spec!(
            "account.signOut",
            "Sign out of server",
            "{server?} → {signedOut, server, serverTold}: forgets the sign-in here and ends the session on the server",
            false,
            sign_out
        ),
        spec!(
            "account.status",
            "Sign-ins",
            "{} → {accounts: [{server, account, name, email, admin, expires}], pending: {server, flow, url | userCode, verificationUri} | null, last: {signedInAs} | {error} | null}",
            false,
            status
        ),
        spec!(
            "account.files",
            "Your files on server",
            "{server?} → {server, files: [{file, name, sealed (end-to-end encrypted: its name opened with the key kept on this computer, else \"Encrypted file\"), role: owner | editor | viewer, people, updated}]}: the files you're in on a server with accounts (join one with `collab.join {link: \"figcraft://join?server=…&file=…\"}`)",
            false,
            files
        ),
        spec!(
            "collab.members",
            "People in file",
            "{} → {server, file, members: [{account, name, email, role}], invited: [{email, role}]}: who is in the file in front (on a server with accounts)",
            false,
            members
        ),
        spec!(
            "collab.invite",
            "Invite to file",
            "{email, role? (owner | editor | viewer; default editor)} → {invited, role}: lets someone into the file in front by email (owners): at once if they signed in to the server before, else when they first do",
            false,
            invite
        ),
        spec!(
            "collab.setRole",
            "Change role",
            "{account, role} → {account, role}: owners change a member's role (a file keeps at least one owner)",
            false,
            set_role
        ),
        spec!(
            "collab.removeMember",
            "Remove from file",
            "{account | email} → {removed}: owners take a member out of the file in front (they are disconnected at once) or take an invite back",
            false,
            remove_member
        ),
    ]
}
