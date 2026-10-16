//! Signing in to a server with accounts (`docs/accounts-and-e2e.md`): the app's side of the flows
//! a server's providers offer. One implementation per flow serves every provider, because the
//! server does the talking to the provider:
//!
//! - **browser**: the provider's page opens in the system browser with a PKCE challenge (S256), a
//!   `state` and a loopback redirect (`http://127.0.0.1:<port>/`); the code that comes back goes
//!   to the server, which exchanges it.
//! - **device**: the server asks the provider for a code to type on another device; the app shows
//!   it and asks the server until the person has entered it.
//! - **token**: a token the person pasted goes to the server, which asks the provider.
//!
//! What the person must see on the way ([`Step`]) is handed to a callback (the app opens the page
//! or shows the code); the result is the server's [`Me`] with its session token.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use base64::Engine as _;
use figcraft_auth::{DeviceCode, Flow, Me, ProviderInfo, SignIn, SignInReply};
use sha2::{Digest, Sha256};

use crate::invite::Endpoint;
use crate::limits::NetLimits;
use crate::manage;

/// How long a sign-in waits for the person (the browser page, or the code on another device).
pub const WAIT: Duration = Duration::from_secs(300);

/// What the person must see during a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Open this page in the browser.
    OpenUrl(String),
    /// Enter this code at this address on another device.
    Code(DeviceCode),
}

/// Which flow to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// The provider's page in the browser (the default when the provider offers it).
    Browser,
    /// A code typed on another device.
    Device,
    /// A token the person has.
    Token(String),
}

/// The provider `id` among `providers` (or the first one).
pub fn pick<'a>(providers: &'a [ProviderInfo], id: Option<&str>) -> Result<&'a ProviderInfo, String> {
    match id.map(str::trim).filter(|i| !i.is_empty()) {
        Some(id) => providers.iter().find(|p| p.id == id).ok_or_else(|| {
            let known: Vec<&str> = providers.iter().map(|p| p.id.as_str()).collect();
            format!("this server has no sign-in called {id:?} (it has: {})", known.join(", "))
        }),
        None => providers.first().ok_or_else(|| "this server has no sign-in providers".to_string()),
    }
}

/// The flow to use with `provider`: as asked, else the browser when offered, else a device code,
/// else a token.
pub fn choose(provider: &ProviderInfo, asked: Option<Via>) -> Result<Via, String> {
    let has_browser = provider.flows.iter().any(|f| matches!(f, Flow::Browser { .. }));
    let has_device = provider.flows.contains(&Flow::Device);
    let has_token = provider.flows.iter().any(|f| matches!(f, Flow::Token { .. }));
    match asked {
        Some(Via::Browser) if has_browser => Ok(Via::Browser),
        Some(Via::Device) if has_device => Ok(Via::Device),
        Some(Via::Token(t)) if has_token => Ok(Via::Token(t)),
        Some(_) => Err(format!("{} doesn't offer that way of signing in here", provider.label)),
        None if has_browser => Ok(Via::Browser),
        None if has_device => Ok(Via::Device),
        None if has_token => Err(format!("{} signs in with a token: paste it", provider.label)),
        None => Err(format!("{} can't be used to sign in right now (try again in a moment)", provider.label)),
    }
}

/// Sign in to the server at `server` with `provider` (an id from its `Info`; the first when
/// `None`) by `via` (see [`choose`]); `step` shows the person what they must do.
pub fn sign_in(
    server: &Endpoint,
    provider: Option<&str>,
    via: Option<Via>,
    step: &dyn Fn(Step),
    limits: &NetLimits,
    timeout: Duration,
) -> Result<Me, String> {
    let info = manage::info(server, limits, timeout)?;
    if !info.auth.accounts() {
        return Err(format!("{} has no accounts: join its files with links or codes", server.display()));
    }
    let p = pick(&info.providers, provider)?;
    let signed = |r: SignInReply| match r {
        SignInReply::SignedIn(me) => Ok(me),
        SignInReply::Refused { reason } => Err(reason),
        _ => Err("the server didn't sign you in".to_string()),
    };
    match choose(p, via)? {
        Via::Token(token) => signed(manage::sign_in(server, SignIn::Token { provider: p.id.clone(), token }, limits, timeout)?),
        Via::Device => {
            let code = match manage::sign_in(server, SignIn::DeviceStart { provider: p.id.clone() }, limits, timeout)? {
                SignInReply::Device(c) => c,
                SignInReply::Refused { reason } => return Err(reason),
                _ => return Err("the server didn't start a device sign-in".into()),
            };
            step(Step::Code(code.clone()));
            let until = Instant::now() + Duration::from_secs(u64::from(code.expires_in)).min(WAIT);
            let pause = Duration::from_secs(u64::from(code.interval.clamp(1, 60)));
            loop {
                std::thread::sleep(pause);
                let poll = SignIn::DevicePoll { provider: p.id.clone(), handle: code.handle.clone() };
                match manage::sign_in(server, poll, limits, timeout)? {
                    SignInReply::Pending if Instant::now() < until => {}
                    SignInReply::Pending => return Err("the code wasn't entered in time: start again".into()),
                    other => return signed(other),
                }
            }
        }
        Via::Browser => {
            let Some(Flow::Browser { authorize_url, client_id, scopes, params }) = p.flows.iter().find(|f| matches!(f, Flow::Browser { .. })) else {
                return Err("no sign-in page".into());
            };
            let listener =
                TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).map_err(|e| format!("can't wait for the sign-in page: {e}"))?;
            let redirect = format!("http://127.0.0.1:{}/", listener.local_addr().map_err(|e| e.to_string())?.port());
            let pkce = Pkce::new()?;
            step(Step::OpenUrl(pkce.authorize_url(authorize_url, client_id, scopes, params, &redirect)));
            let code = wait_for_code(&listener, &pkce.state, Instant::now() + WAIT)?;
            let req = SignIn::Code { provider: p.id.clone(), code, verifier: pkce.verifier.clone(), redirect_uri: redirect };
            signed(manage::sign_in(server, req, limits, timeout)?)
        }
    }
}

/// A PKCE verifier and the `state` of one browser sign-in.
pub struct Pkce {
    pub verifier: String,
    pub state: String,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| format!("no secure random numbers: {e}"))?;
    Ok(b)
}

/// `s` as a URL query value.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Pkce {
    pub fn new() -> Result<Pkce, String> {
        Ok(Pkce { verifier: b64(&random(32)?), state: b64(&random(16)?) })
    }

    /// The S256 challenge.
    pub fn challenge(&self) -> String {
        b64(&Sha256::digest(self.verifier.as_bytes()))
    }

    /// The provider's page with everything it needs.
    pub fn authorize_url(&self, page: &str, client_id: &str, scopes: &[String], params: &[(String, String)], redirect: &str) -> String {
        let mut q = vec![
            ("response_type".to_string(), "code".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("redirect_uri".to_string(), redirect.to_string()),
            ("scope".to_string(), scopes.join(" ")),
            ("code_challenge".to_string(), self.challenge()),
            ("code_challenge_method".to_string(), "S256".to_string()),
            ("state".to_string(), self.state.clone()),
        ];
        q.extend(params.iter().filter(|(k, _)| !q.iter().any(|(have, _)| have == k)).cloned().collect::<Vec<_>>());
        let query: Vec<String> = q.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
        format!("{page}{}{}", if page.contains('?') { '&' } else { '?' }, query.join("&"))
    }
}

/// What the browser was sent back with: the code, or why not.
pub fn callback(request_line: &str, state: &str) -> Option<Result<String, String>> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let get = |k: &str| query.split('&').filter_map(|p| p.split_once('=')).find(|(key, _)| *key == k).map(|(_, v)| crate::invite::decode(v));
    if get("state").flatten().as_deref() != Some(state) {
        // Not our redirect (a favicon, a stale tab): keep waiting.
        return None;
    }
    if let Some(err) = get("error").flatten() {
        let more = get("error_description").flatten().map(|d| format!(": {d}")).unwrap_or_default();
        return Some(Err(format!("the sign-in was stopped ({err}{more})")));
    }
    get("code").flatten().filter(|c| !c.is_empty() && c.len() <= 4096).map(Ok)
}

const DONE: &str = "<!doctype html><meta charset=utf-8><title>FigCraft</title><body style=\"font-family:system-ui;margin:3em\"><h2>Signed in</h2><p>You can close this tab and go back to FigCraft.</p>";
const STOPPED: &str = "<!doctype html><meta charset=utf-8><title>FigCraft</title><body style=\"font-family:system-ui;margin:3em\"><h2>Sign-in stopped</h2><p>Go back to FigCraft to try again.</p>";

fn respond(mut s: TcpStream, body: &str) {
    let _ =
        write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// Wait on `listener` for the browser to come back with `state`, until `deadline`.
pub fn wait_for_code(listener: &TcpListener, state: &str, deadline: Instant) -> Result<String, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut s, peer)) if peer.ip().is_loopback() => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                // The request line may come in pieces: read until it is whole (or 8 KiB).
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                while !buf.contains(&b'\n') && buf.len() < 8192 {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                    }
                }
                let text = String::from_utf8_lossy(&buf);
                let line = text.lines().next().unwrap_or_default();
                match callback(line, state) {
                    Some(Ok(code)) => {
                        respond(s, DONE);
                        return Ok(code);
                    }
                    Some(Err(why)) => {
                        respond(s, STOPPED);
                        return Err(why);
                    }
                    None => respond(s, STOPPED),
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("the sign-in page couldn't reach the app: {e}")),
        }
    }
    Err("the sign-in wasn't finished in time: start again".into())
}
