//! The parts of a browser sign-in that don't need a socket, for the desktop app (its loopback
//! page, `signin.rs`) and the browser build (its redirect, `web.rs`) alike: the PKCE verifier and
//! `state`, the provider's page with everything it needs, and reading what the page was sent back
//! with.
//!
//! The browser build signs in by sending the whole tab to the provider ([`Flow::Redirect`]): the
//! provider sends it back to the page's own address (one the server lists, matched exactly) with
//! `?code=…&state=…`. What the tab needs to finish then (the server, the provider, the verifier,
//! the `state` and the address used) is kept for the tab's session as a [`Redirect`] while it is
//! away.

use base64::Engine as _;
use figcraft_auth::Flow;
use sha2::{Digest, Sha256};

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

/// Query parameter `k` of `query` (without the `?`), decoded.
fn param(query: &str, k: &str) -> Option<String> {
    query.split('&').filter_map(|p| p.split_once('=')).find(|(key, _)| *key == k).and_then(|(_, v)| crate::invite::decode(v))
}

/// What a sign-in page sent back in `query` (without the `?`) for the sign-in with `state`: the
/// code, or why not. `None` when it isn't the answer to that sign-in (another `state`, or no
/// code).
pub fn answer(query: &str, state: &str) -> Option<Result<String, String>> {
    if param(query, "state").as_deref() != Some(state) {
        return None;
    }
    if let Some(err) = param(query, "error") {
        let more = param(query, "error_description").map(|d| format!(": {d}")).unwrap_or_default();
        return Some(Err(format!("the sign-in was stopped ({err}{more})")));
    }
    param(query, "code").filter(|c| !c.is_empty() && c.len() <= 4096).map(Ok)
}

/// The parameters a provider sends back to the page (they are taken off its address once read).
const SENT_BACK: [&str; 9] = ["code", "state", "scope", "authuser", "hd", "prompt", "iss", "error", "error_description"];

/// `query` (without the `?`) with what a sign-in page sent back taken out; the page's own flags
/// (`webgl`) stay.
pub fn without_answer(query: &str) -> String {
    let kept: Vec<&str> = query.split('&').filter(|p| !p.is_empty() && !SENT_BACK.contains(&p.split_once('=').map_or(*p, |(k, _)| k))).collect();
    kept.join("&")
}

/// The address of `flow`'s list the page at `page` (its origin and path, without query or
/// fragment) comes back to: exactly the same, as the server compares them.
pub fn redirect_for<'a>(flow: &'a Flow, page: &str) -> Result<&'a str, String> {
    let Flow::Redirect { redirect_uris, .. } = flow else { return Err("that isn't a sign-in for pages".into()) };
    redirect_uris
        .iter()
        .map(String::as_str)
        .find(|u| *u == page)
        .ok_or_else(|| format!("this page ({page}) isn't one the server lets sign-ins come back to: its operator lists them in `web_redirect_uris`"))
}

/// A redirect sign-in on its way: what the tab needs once the provider sends it back.
#[derive(Clone, PartialEq, Eq)]
pub struct Redirect {
    pub server: String,
    pub provider: String,
    pub state: String,
    pub verifier: String,
    pub redirect_uri: String,
}

impl std::fmt::Debug for Redirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redirect").field("server", &self.server).field("provider", &self.provider).finish_non_exhaustive()
    }
}

impl Redirect {
    /// Start one with `flow` (a [`Flow::Redirect`]) of `provider` on `server`, from the page at
    /// `page`: it, and the provider's page to send the tab to.
    pub fn start(server: &str, provider: &str, flow: &Flow, page: &str) -> Result<(Redirect, String), String> {
        let Flow::Redirect { authorize_url, client_id, scopes, params, .. } = flow else { return Err("that isn't a sign-in for pages".into()) };
        let redirect_uri = redirect_for(flow, page)?.to_string();
        let pkce = Pkce::new()?;
        let url = pkce.authorize_url(authorize_url, client_id, scopes, params, &redirect_uri);
        let r = Redirect { server: server.to_string(), provider: provider.to_string(), state: pkce.state, verifier: pkce.verifier, redirect_uri };
        Ok((r, url))
    }

    /// As kept while the tab is away (a query string).
    pub fn to_text(&self) -> String {
        let fields = [
            ("server", &self.server),
            ("provider", &self.provider),
            ("state", &self.state),
            ("verifier", &self.verifier),
            ("redirect", &self.redirect_uri),
        ];
        fields.iter().map(|(k, v)| format!("{k}={}", encode(v))).collect::<Vec<_>>().join("&")
    }

    /// From [`to_text`](Self::to_text).
    pub fn from_text(text: &str) -> Option<Redirect> {
        let get = |k: &str| param(text, k).filter(|v| !v.is_empty());
        Some(Redirect {
            server: get("server")?,
            provider: get("provider")?,
            state: get("state")?,
            verifier: get("verifier")?,
            redirect_uri: get("redirect")?,
        })
    }

    /// What the page was loaded with (`query`, without the `?`) for this sign-in: the code, or why
    /// not; `None` when it isn't its answer.
    pub fn answer(&self, query: &str) -> Option<Result<String, String>> {
        answer(query, &self.state)
    }
}

/// A redirect sign-in that came back with its code: what finishes it on the server
/// (`account.signIn` with `flow: "code"`).
#[derive(Clone, PartialEq, Eq)]
pub struct Back {
    pub server: String,
    pub provider: String,
    pub code: String,
    pub verifier: String,
    pub redirect_uri: String,
}

impl std::fmt::Debug for Back {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Back").field("server", &self.server).field("provider", &self.provider).finish_non_exhaustive()
    }
}

/// The page was loaded with `query` (without the `?`) while `kept` (what [`Redirect::to_text`]
/// kept, if anything) was on its way: the sign-in to finish, why it stopped, or `None` (not a
/// page a sign-in came back to).
pub fn came_back(query: &str, kept: Option<&str>) -> Option<Result<Back, String>> {
    let sent_back = param(query, "state").is_some() && (param(query, "code").is_some() || param(query, "error").is_some());
    if !sent_back {
        return None;
    }
    let Some(r) = kept.and_then(Redirect::from_text) else {
        return Some(Err("this sign-in was started in another tab or has expired: sign in again".into()));
    };
    match r.answer(query) {
        Some(Ok(code)) => Some(Ok(Back { server: r.server, provider: r.provider, code, verifier: r.verifier, redirect_uri: r.redirect_uri })),
        Some(Err(why)) => Some(Err(why)),
        None => Some(Err("this sign-in doesn't match the one this tab started: sign in again".into())),
    }
}
