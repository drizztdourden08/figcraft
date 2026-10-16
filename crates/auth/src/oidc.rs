//! The `oidc` provider: any OpenID Connect issuer (Google, Microsoft Entra ID, GitLab, Keycloak,
//! Authentik, Auth0, Okta, Zitadel…). The server does the exchanges; apps open the sign-in page.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::config::ProviderConfig;
use crate::jwt::{self, Expect, Jwks};
use crate::provider::{AuthError, DeviceStart, Fetch, FetchError, Identity, IdentityProvider};
use crate::wire::{Flow, ProviderInfo};

/// How long a discovery document and a key set are kept before being fetched again.
const KEEP: Duration = Duration::from_secs(3600);

/// A token signed with a key not in the cached set refetches the set at most this often.
const REFETCH: Duration = Duration::from_secs(60);

/// What a preset fills in.
pub struct Preset {
    pub name: &'static str,
    pub issuer: &'static str,
    pub label: &'static str,
}

/// Issuers known by name. Others are configured with `issuer`.
pub const PRESETS: &[Preset] = &[
    Preset { name: "google", issuer: "https://accounts.google.com", label: "Google" },
    Preset { name: "gitlab", issuer: "https://gitlab.com", label: "GitLab" },
];

/// The parts of a discovery document used here.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

struct Cache {
    discovery: Option<(Discovery, Instant)>,
    keys: Option<(Jwks, Instant)>,
    /// When the keys were last fetched again for an unknown key id.
    refetched: Option<Instant>,
}

/// An OpenID Connect issuer.
pub struct Oidc {
    id: String,
    label: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    params: Vec<(String, String)>,
    browser: bool,
    device: bool,
    fetch: Arc<dyn Fetch>,
    cache: Mutex<Cache>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn unavailable(e: FetchError) -> AuthError {
    AuthError::Unavailable(e.to_string())
}

impl Oidc {
    /// From `[[auth.provider]]` with `kind = "oidc"`.
    pub fn new(cfg: &ProviderConfig, fetch: Arc<dyn Fetch>) -> Result<Oidc, String> {
        let preset = match cfg.preset.trim() {
            "" => None,
            name => Some(PRESETS.iter().find(|p| p.name == name).ok_or_else(|| {
                let known: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
                format!("provider {:?}: unknown preset {name:?} (known: {})", cfg.id, known.join(", "))
            })?),
        };
        let issuer = match (cfg.issuer.trim(), preset) {
            ("", Some(p)) => p.issuer.to_string(),
            ("", None) => return Err(format!("provider {:?}: set `issuer` (or a `preset`)", cfg.id)),
            (i, _) => i.trim_end_matches('/').to_string(),
        };
        if !issuer.starts_with("https://") && !issuer.starts_with("http://127.0.0.1") && !issuer.starts_with("http://localhost") {
            return Err(format!("provider {:?}: `issuer` must be an https:// address", cfg.id));
        }
        if cfg.client_id.trim().is_empty() {
            return Err(format!("provider {:?}: set `client_id` (from the issuer's app registration)", cfg.id));
        }
        let client_secret = match (cfg.client_secret.trim(), cfg.client_secret_file.trim()) {
            (s, "") => s.to_string(),
            ("", f) => {
                std::fs::read_to_string(f).map_err(|e| format!("provider {:?}: can't read `client_secret_file` {f}: {e}", cfg.id))?.trim().to_string()
            }
            _ => return Err(format!("provider {:?}: set `client_secret` or `client_secret_file`, not both", cfg.id)),
        };
        let flows: Vec<String> =
            if cfg.flows.is_empty() { vec!["browser".into()] } else { cfg.flows.iter().map(|f| f.trim().to_ascii_lowercase()).collect() };
        if let Some(bad) = flows.iter().find(|f| *f != "browser" && *f != "device") {
            return Err(format!("provider {:?}: unknown flow {bad:?} (\"browser\", \"device\")", cfg.id));
        }
        let scopes = if cfg.scopes.is_empty() { vec!["openid".into(), "email".into(), "profile".into()] } else { cfg.scopes.clone() };
        if !scopes.iter().any(|s| s == "openid") {
            return Err(format!("provider {:?}: `scopes` must include \"openid\"", cfg.id));
        }
        let label = match cfg.label.trim() {
            "" => preset.map_or_else(|| cfg.id.clone(), |p| p.label.to_string()),
            l => l.to_string(),
        };
        Ok(Oidc {
            id: cfg.id.clone(),
            label,
            issuer,
            client_id: cfg.client_id.trim().to_string(),
            client_secret,
            scopes,
            params: cfg.params.clone(),
            browser: flows.iter().any(|f| f == "browser"),
            device: flows.iter().any(|f| f == "device"),
            fetch,
            cache: Mutex::new(Cache { discovery: None, keys: None, refetched: None }),
        })
    }

    /// The issuer's discovery document (cached).
    pub fn discovery(&self) -> Result<Discovery, AuthError> {
        if let Some((d, at)) = &self.cache.lock().unwrap_or_else(PoisonError::into_inner).discovery
            && at.elapsed() < KEEP
        {
            return Ok(d.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let body = self.fetch.get(&url).map_err(unavailable)?;
        let d: Discovery = serde_json::from_slice(&body).map_err(|_| AuthError::Unavailable(format!("{url} isn't a discovery document")))?;
        if d.issuer.trim_end_matches('/') != self.issuer {
            return Err(AuthError::Unavailable(format!("{url} names another issuer ({})", d.issuer)));
        }
        self.cache.lock().unwrap_or_else(PoisonError::into_inner).discovery = Some((d.clone(), Instant::now()));
        Ok(d)
    }

    fn keys(&self, d: &Discovery, refresh: bool) -> Result<Jwks, AuthError> {
        {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            let fresh = cache.keys.as_ref().is_some_and(|(_, at)| at.elapsed() < KEEP);
            let refetched_lately = cache.refetched.is_some_and(|at| at.elapsed() < REFETCH);
            if let Some((k, _)) = &cache.keys
                && (fresh && !refresh || refresh && refetched_lately)
            {
                return Ok(k.clone());
            }
        }
        let body = self.fetch.get(&d.jwks_uri).map_err(unavailable)?;
        let k: Jwks = serde_json::from_slice(&body).map_err(|_| AuthError::Unavailable("the issuer's keys couldn't be read".into()))?;
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.keys = Some((k.clone(), Instant::now()));
        if refresh {
            cache.refetched = Some(Instant::now());
        }
        Ok(k)
    }

    /// Who an ID token from this issuer says it is (signature, issuer, audience, times).
    pub fn check_id_token(&self, token: &str) -> Result<Identity, AuthError> {
        let d = self.discovery()?;
        let parsed = jwt::parse(token)?;
        let mut keys = self.keys(&d, false)?;
        if jwt::key_for(&keys, &parsed).is_none() {
            // A new key (issuers rotate them): fetch the set again, at most once a minute.
            keys = self.keys(&d, true)?;
        }
        let key = jwt::key_for(&keys, &parsed)
            .ok_or_else(|| AuthError::Refused("the sign-in couldn't be checked: it was signed with an unknown key".into()))?;
        jwt::verify_signature(&parsed, key)?;
        jwt::check_claims(&parsed.claims, &Expect { issuer: &d.issuer, audience: &self.client_id, now: now() })?;
        Ok(identity(&self.id, &parsed.claims))
    }

    fn with_secret<'a>(&'a self, form: &mut Vec<(&'a str, &'a str)>) {
        form.push(("client_id", &self.client_id));
        if !self.client_secret.is_empty() {
            form.push(("client_secret", &self.client_secret));
        }
    }
}

/// The identity in a checked token's claims.
fn identity(provider: &str, claims: &Value) -> Identity {
    let s = |k: &str| claims[k].as_str().map(str::trim).filter(|v| !v.is_empty()).map(String::from);
    let verified = match &claims["email_verified"] {
        Value::Bool(b) => *b,
        // Some issuers send it as a string.
        Value::String(v) => v == "true",
        _ => false,
    };
    Identity {
        provider: provider.to_string(),
        subject: s("sub").unwrap_or_default(),
        email: s("email").map(|e| e.to_ascii_lowercase()),
        email_verified: verified,
        name: s("name").or_else(|| s("preferred_username")),
    }
}

/// An error answer from a token endpoint: its `error` code.
fn oauth_error(e: &FetchError) -> Option<String> {
    match e {
        FetchError::Status { body, .. } => serde_json::from_slice::<Value>(body).ok()?["error"].as_str().map(String::from),
        FetchError::Network(_) => None,
    }
}

impl IdentityProvider for Oidc {
    fn info(&self) -> ProviderInfo {
        let mut flows = Vec::new();
        if self.browser {
            // Without the discovery document the page isn't known: the flow is left out until the
            // issuer answers (apps ask again).
            match self.discovery() {
                Ok(d) => flows.push(Flow::Browser {
                    authorize_url: d.authorization_endpoint,
                    client_id: self.client_id.clone(),
                    scopes: self.scopes.clone(),
                    params: self.params.clone(),
                }),
                Err(e) => log::warn!("provider {}: {e}", self.id),
            }
        }
        if self.device {
            flows.push(Flow::Device);
        }
        ProviderInfo { id: self.id.clone(), label: self.label.clone(), flows }
    }

    fn exchange_code(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<Identity, AuthError> {
        if !self.browser {
            return Err(AuthError::Unsupported);
        }
        let d = self.discovery()?;
        let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri), ("code_verifier", verifier)];
        self.with_secret(&mut form);
        let body = self.fetch.post_form(&d.token_endpoint, &form).map_err(|e| match oauth_error(&e) {
            Some(code) => AuthError::Refused(format!("the sign-in was refused ({code}): try again")),
            None => unavailable(e),
        })?;
        let answer: Value = serde_json::from_slice(&body).map_err(|_| AuthError::Unavailable("the issuer's answer couldn't be read".into()))?;
        let id_token =
            answer["id_token"].as_str().ok_or_else(|| AuthError::Unavailable("the issuer sent no ID token (is \"openid\" in the scopes?)".into()))?;
        self.check_id_token(id_token)
    }

    fn start_device(&self) -> Result<DeviceStart, AuthError> {
        if !self.device {
            return Err(AuthError::Unsupported);
        }
        let d = self.discovery()?;
        let endpoint = d.device_authorization_endpoint.ok_or_else(|| AuthError::Unavailable(format!("{} has no device sign-in", self.label)))?;
        let scope = self.scopes.join(" ");
        let mut form = vec![("scope", scope.as_str())];
        self.with_secret(&mut form);
        let body = self.fetch.post_form(&endpoint, &form).map_err(unavailable)?;
        let a: Value = serde_json::from_slice(&body).map_err(|_| AuthError::Unavailable("the device code couldn't be read".into()))?;
        let s = |k: &str| a[k].as_str().map(String::from);
        let (Some(device_code), Some(user_code)) = (s("device_code"), s("user_code")) else {
            return Err(AuthError::Unavailable("the issuer sent no device code".into()));
        };
        // RFC 8628 says verification_uri; Google says verification_url.
        let verification_uri = s("verification_uri_complete").or_else(|| s("verification_uri")).or_else(|| s("verification_url")).unwrap_or_default();
        let num = |k: &str, d: u64| u32::try_from(a[k].as_u64().unwrap_or(d)).unwrap_or(u32::MAX);
        Ok(DeviceStart { device_code, user_code, verification_uri, interval: num("interval", 5).clamp(1, 60), expires_in: num("expires_in", 600) })
    }

    fn poll_device(&self, device_code: &str) -> Result<Identity, AuthError> {
        if !self.device {
            return Err(AuthError::Unsupported);
        }
        let d = self.discovery()?;
        let mut form = vec![("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", device_code)];
        self.with_secret(&mut form);
        match self.fetch.post_form(&d.token_endpoint, &form) {
            Ok(body) => {
                let answer: Value =
                    serde_json::from_slice(&body).map_err(|_| AuthError::Unavailable("the issuer's answer couldn't be read".into()))?;
                let id_token = answer["id_token"].as_str().ok_or_else(|| AuthError::Unavailable("the issuer sent no ID token".into()))?;
                self.check_id_token(id_token)
            }
            Err(e) => match oauth_error(&e).as_deref() {
                Some("authorization_pending" | "slow_down") => Err(AuthError::Pending),
                Some("expired_token") => Err(AuthError::Refused("the code expired: start again".into())),
                Some("access_denied") => Err(AuthError::Refused("the sign-in was declined".into())),
                Some(other) => Err(AuthError::Refused(format!("the sign-in was refused ({other})"))),
                None => Err(unavailable(e)),
            },
        }
    }

    fn verify_token(&self, token: &str) -> Result<Identity, AuthError> {
        // An ID token the app got some other way (an agent signed in elsewhere).
        self.check_id_token(token)
    }
}
