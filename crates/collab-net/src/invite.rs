//! Invite links and server addresses.
//!
//! An invite (or share) link names a session's endpoint, its file and a token:
//! `figcraft://join?host=<host:port>&file=<id>&token=<secret>` for a plain `ws://` endpoint at `/`
//! (what the desktop app hosts), `figcraft://join?server=<ws(s)://host[:port][/path]>&file=…&token=…`
//! for any endpoint (a `figcraft-server` behind a TLS reverse proxy, under a path), or the same
//! session as a WebSocket URL `ws(s)://host[:port][/path]?file=<id>&token=<secret>`.
//!
//! The token never travels in the WebSocket request (a proxy's logs would keep it): the client
//! connects to the endpoint and sends the token in its `Hello`. A server address for managing
//! files carries the server's key the same way (`ws://host:port/?key=<key>`). Errors never echo a
//! link or an address.
//!
//! A join by code names the server to ask and the code:
//! `figcraft://join?server=<ws(s)://…>&code=<code>` ([`Invite::parse_join`]); the server says which
//! file and token the code stands for.
//!
//! A sealed (end-to-end encrypted) file's link carries its key after `#`: `…&token=…#k=<key>`
//! (and a member's link on a server with accounts `…&file=…#k=<key>`). The fragment never leaves
//! the app: it isn't in the WebSocket request ([`Invite::endpoint`]), in a hello or in any error,
//! and `Debug` doesn't print the key ([`FileKey`]). A file whose key changed epochs (someone was
//! taken out of it) carries every epoch the app holds: `#k=<oldest>&…&k=<newest>` (the newest
//! seals new writes; see [`Keys`]).

use std::sync::{Arc, PoisonError, RwLock};

use figcraft_collab_seal::{FileKey, Keyring, MAX_LINK_EPOCHS, parse_ring_fragment, ring_fragment};

/// A sealed file's keys for a session: every epoch the app holds. Shared by every copy of the
/// invite it came with, so a newer epoch added while the session runs ([`Keys::add`]: the app
/// learned it from the file's keyring) is what the next writes are sealed with. `Debug` prints the
/// epochs only.
#[derive(Clone, Default)]
pub struct Keys(Arc<RwLock<Keyring>>);

impl Keys {
    pub fn new(ring: Keyring) -> Keys {
        Keys(Arc::new(RwLock::new(ring)))
    }

    /// Every epoch held now.
    pub fn ring(&self) -> Keyring {
        self.0.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The newest epoch's key: what new writes are sealed with.
    pub fn current(&self) -> Option<FileKey> {
        self.0.read().unwrap_or_else(PoisonError::into_inner).current().cloned()
    }

    /// Add the epochs of `ring` (for every copy of the invite).
    pub fn add(&self, ring: &Keyring) {
        self.0.write().unwrap_or_else(PoisonError::into_inner).merge(ring);
    }
}

impl From<FileKey> for Keys {
    fn from(key: FileKey) -> Keys {
        Keys::new(Keyring::from(key))
    }
}

impl PartialEq for Keys {
    fn eq(&self, other: &Keys) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.ring() == other.ring()
    }
}

impl Eq for Keys {}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys({:?})", self.ring())
    }
}

/// Where a session or a server listens: `ws://host:port/path` or `wss://…` (TLS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// `host:port` (an IP address, `[v6]:port`, or a host name).
    pub host: String,
    /// The path it answers on: `/`, or a reverse proxy's prefix (`/figcraft/`).
    pub path: String,
    /// `wss://`: TLS (a reverse proxy in front of the server).
    pub secure: bool,
}

/// What an invite link names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub server: Endpoint,
    /// The shared file's id.
    pub file: String,
    /// The link's secret.
    pub token: String,
    /// A sealed file's keys, from the link's `#k=…` (`None`: the file isn't sealed, or the link
    /// doesn't say).
    pub key: Option<Keys>,
}

/// Longest link accepted, before its fragment (anything longer isn't one of ours).
const MAX_LINK: usize = 2048;
/// Longest fragment: [`MAX_LINK_EPOCHS`] keys of 91 characters with their `&k=`.
const MAX_FRAGMENT: usize = MAX_LINK_EPOCHS * 96;

const NOT: &str = "that's not a live session invite: expected figcraft://join?host=…&file=…&token=… or ws://host:port/?file=…&token=…";

impl Endpoint {
    /// A plain `ws://host/` endpoint.
    pub fn plain(host: impl Into<String>) -> Self {
        Self { host: host.into(), path: "/".into(), secure: false }
    }

    /// `ws://` at `/`: an invite can name it as `host=…`.
    fn is_plain(&self) -> bool {
        !self.secure && self.path == "/"
    }

    /// The WebSocket URL to connect to (no secrets in it).
    pub fn url(&self) -> String {
        format!("{}://{}{}", if self.secure { "wss" } else { "ws" }, self.host, self.path)
    }

    /// How the address is shown: `host:port` for a plain endpoint, else its URL.
    pub fn display(&self) -> String {
        if self.is_plain() { self.host.clone() } else { self.url() }
    }

    /// The host is this machine (a loopback address or `localhost`).
    pub fn loopback(&self) -> bool {
        match self.host.parse::<std::net::SocketAddr>() {
            Ok(a) => a.ip().is_loopback(),
            Err(_) => self.host.rsplit_once(':').is_some_and(|(name, _)| name.eq_ignore_ascii_case("localhost")),
        }
    }

    /// Read `ws(s)://host[:port][/path][?query]` (a missing port is the scheme's: 80 or 443): the
    /// endpoint and the query's decoded pairs. Errors say what's wrong without echoing `url`.
    pub fn parse(url: &str) -> Result<(Endpoint, Vec<(String, String)>), String> {
        const BAD: &str = "that's not a server address: expected ws://host:port/ or wss://host/";
        let url = clean(url);
        if url.len() > MAX_LINK {
            return Err(BAD.into());
        }
        let (scheme, rest) = url.split_once("://").ok_or(BAD)?;
        let secure = if scheme.eq_ignore_ascii_case("ws") {
            false
        } else if scheme.eq_ignore_ascii_case("wss") {
            true
        } else {
            return Err(BAD.into());
        };
        let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, path) = match before_query.find('/') {
            Some(i) => before_query.split_at(i),
            None => (before_query, "/"),
        };
        let host = with_port(authority, if secure { 443 } else { 80 });
        if !valid_host(&host) {
            return Err("the address's host isn't a host name or IP address with a port (like 192.168.1.20:47900)".into());
        }
        if !valid_path(path) {
            return Err("the address's path has characters a server path can't have".into());
        }
        let mut path = path.to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        Ok((Endpoint { host, path, secure }, pairs(query)?))
    }
}

impl Invite {
    /// An invite for a plain `ws://host/` endpoint.
    pub fn new(host: impl Into<String>, file: impl Into<String>, token: impl Into<String>) -> Self {
        Self { server: Endpoint::plain(host), file: file.into(), token: token.into(), key: None }
    }

    /// The same invite with a sealed file's key (its links end with `#k=…`).
    pub fn with_key(mut self, key: Option<FileKey>) -> Self {
        self.key = key.map(Keys::from);
        self
    }

    /// `#k=…` for a sealed file (every epoch held), else nothing.
    fn fragment(&self) -> String {
        self.key.as_ref().map(|k| k.ring()).filter(|r| !r.is_empty()).map(|r| format!("#{}", ring_fragment(&r))).unwrap_or_default()
    }

    /// The `figcraft://join?…` link (without `&token=…` for a member's link: [`member`](Self::member);
    /// with `#k=…` for a sealed file).
    pub fn link(&self) -> String {
        let token = if self.member() { String::new() } else { format!("&token={}", self.token) };
        let key = self.fragment();
        if self.server.is_plain() {
            format!("figcraft://join?host={}&file={}{token}{key}", self.server.host, self.file)
        } else {
            format!("figcraft://join?server={}&file={}{token}{key}", self.server.url(), self.file)
        }
    }

    /// The same session as a WebSocket URL (with `#k=…` for a sealed file: never sent).
    pub fn url(&self) -> String {
        let token = if self.member() { String::new() } else { format!("&token={}", self.token) };
        format!("{}?file={}{token}{}", self.server.url(), self.file, self.fragment())
    }

    /// A link without a secret: on a server with accounts, members join by who they are.
    pub fn member(&self) -> bool {
        self.token.is_empty()
    }

    /// What the client connects to (no secrets in it).
    pub fn endpoint(&self) -> String {
        self.server.url()
    }

    /// The host is this machine.
    pub fn loopback(&self) -> bool {
        self.server.loopback()
    }

    /// Read an invite link (any form; surrounding spaces, quotes or angle brackets are fine).
    pub fn parse(link: &str) -> Result<Invite, String> {
        match Self::parse_join(link)? {
            (invite, None) => Ok(invite),
            (_, Some(_)) => Err("that names a join code, not a file: join with it first".into()),
        }
    }

    /// Read what a join starts from: an invite link, or a server with a join code to ask it about
    /// (then the invite names only the server, until the server says what the code opens).
    pub fn parse_join(link: &str) -> Result<(Invite, Option<String>), String> {
        let link = clean(link);
        let (before, fragment) = link.split_once('#').unwrap_or((link, ""));
        if before.len() > MAX_LINK || fragment.len() > MAX_FRAGMENT {
            return Err(NOT.into());
        }
        // A sealed file's keys, after `#` (other fragments are ignored).
        let (link, key) = match link.split_once('#') {
            Some((link, fragment)) if fragment.split('&').any(|p| p.starts_with("k=")) => {
                let ring = parse_ring_fragment(fragment).map_err(|_| "the invite link's key (after #k=) isn't one: copy the whole link again")?;
                (link, Some(Keys::new(ring)))
            }
            Some((link, _)) => (link, None),
            None => (link, None),
        };
        let (scheme, rest) = link.split_once("://").ok_or(NOT)?;
        let (server, query) = if scheme.eq_ignore_ascii_case("figcraft") {
            let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
            if !path.trim_end_matches('/').eq_ignore_ascii_case("join") {
                return Err(NOT.into());
            }
            let query = pairs(query).map_err(|_| NOT)?;
            let get = |k: &str| query.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
            let server = match (get("server"), get("host")) {
                (Some(url), _) => Endpoint::parse(&url).map(|(e, _)| e).map_err(|_| "the invite link's server isn't a ws:// or wss:// address")?,
                (None, Some(host)) if valid_host(&host) => Endpoint::plain(host),
                _ => return Err("the invite link's host isn't an address with a port (like 192.168.1.20:47900)".into()),
            };
            (server, query)
        } else if scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss") {
            Endpoint::parse(link).map_err(|e| if e.contains("host") { e } else { NOT.into() })?
        } else {
            return Err(NOT.into());
        };
        let get = |k: &str| query.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        if let Some(code) = get("code") {
            let code = figcraft_collab::code::normalize(&code).ok().filter(|c| c.len() == figcraft_collab::code::ONLINE_LEN);
            let code = code.ok_or("the link's join code isn't one")?;
            return Ok((Invite { server, file: String::new(), token: String::new(), key }, Some(code)));
        }
        let file = get("file").filter(|f| valid_id(f, 1, 64)).ok_or("the invite link has no valid file id")?;
        // No token: a member's link on a server with accounts (who you are lets you in).
        let token = match get("token") {
            None => String::new(),
            Some(t) if valid_id(&t, 16, 128) => t,
            Some(_) => return Err("the invite link has no valid token".into()),
        };
        Ok((Invite { server, file, token, key }, None))
    }
}

/// Without surrounding spaces, quotes or angle brackets.
fn clean(s: &str) -> &str {
    s.trim().trim_matches(|c| matches!(c, '<' | '>' | '"' | '\''))
}

/// A %-escaped query value, decoded (`+` is a space).
pub(crate) fn decode(v: &str) -> Option<String> {
    percent_decode(&v.replace('+', " "))
}

/// A query's `key=value` pairs, decoded.
fn pairs(query: &str) -> Result<Vec<(String, String)>, String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((k.to_string(), percent_decode(v).ok_or("a broken %-escape")?))
        })
        .collect()
}

/// `authority` with `default` as its port when it has none.
fn with_port(authority: &str, default: u16) -> String {
    let has_port = match authority.rsplit_once(':') {
        // `[v6]` alone has colons inside the brackets only.
        Some((h, p)) => !(h.starts_with('[') && !h.ends_with(']')) && !p.contains(']'),
        None => false,
    };
    if has_port { authority.to_string() } else { format!("{authority}:{default}") }
}

/// Ids and tokens are URL-safe base64 / hex characters.
pub(crate) fn valid_id(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `ip:port`, `[v6]:port` or `name:port` with a non-zero port.
fn valid_host(s: &str) -> bool {
    if s.parse::<std::net::SocketAddr>().is_ok_and(|a| a.port() != 0) {
        return true;
    }
    let Some((name, port)) = s.rsplit_once(':') else { return false };
    port.parse::<u16>().is_ok_and(|p| p != 0)
        && (1..=253).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !name.starts_with(['-', '.'])
}

/// A path of unreserved characters and slashes, starting with `/`.
fn valid_path(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 256 && p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~'))
}

/// `%XX` escapes decoded (UTF-8); `None` for broken escapes.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(if b == b'+' { b' ' } else { b });
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}
