//! The `[auth]` and `[e2e]` settings of `server.toml` (see `docs/accounts-and-e2e.md`). Unknown keys
//! are errors, like the rest of the server's settings.

use serde::Deserialize;

use crate::policy::Policy;
use crate::wire::{AuthMode, E2eMode};

/// `[auth]`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// `"links"` (default), `"accounts"` or `"accounts+links"`.
    pub mode: String,
    /// Emails that manage the server (like the server key).
    pub admins: Vec<String>,
    /// Who may sign in (both empty: anyone a provider vouches for).
    pub allow_emails: Vec<String>,
    pub allow_domains: Vec<String>,
    /// A sign-in lasts this many days without being used.
    pub session_days: f64,
    /// `[[auth.provider]]`.
    pub provider: Vec<ProviderConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Links.id().into(),
            admins: Vec::new(),
            allow_emails: Vec::new(),
            allow_domains: Vec::new(),
            session_days: 30.0,
            provider: Vec::new(),
        }
    }
}

/// `[[auth.provider]]`: one identity provider. Which keys apply depends on `kind`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderConfig {
    /// What apps show and send back (letters, digits, `-` and `_`).
    pub id: String,
    /// `"oidc"`, `"external"`, or a kind registered by the server build.
    pub kind: String,
    /// What people see (default: from the preset, else the id).
    pub label: String,
    /// `oidc`: fills `issuer`, `scopes` and the label (`"google"`, `"microsoft"`, `"gitlab"`).
    pub preset: String,
    /// `oidc`: the issuer (`https://accounts.google.com`); its discovery document is
    /// `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    /// `oidc`: the client secret, or (better) a file holding it.
    pub client_secret: String,
    pub client_secret_file: String,
    /// `oidc`: scopes asked for (default `openid email profile`).
    pub scopes: Vec<String>,
    /// `oidc`: extra parameters for the sign-in page (`[["prompt", "select_account"]]`).
    pub params: Vec<(String, String)>,
    /// `oidc`: the flows offered (default: `browser`, and `device` when the issuer has a device
    /// endpoint).
    pub flows: Vec<String>,
    /// `external`: where the server POSTs `{"token": …}` to learn who it is.
    pub verify_url: String,
}

/// `[e2e]`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct E2eConfig {
    /// `"off"` (default), `"optional"` or `"required"`.
    pub mode: String,
}

impl Default for E2eConfig {
    fn default() -> Self {
        Self { mode: E2eMode::Off.id().into() }
    }
}

impl E2eConfig {
    pub fn mode(&self) -> Result<E2eMode, String> {
        E2eMode::parse(&self.mode).ok_or_else(|| format!("`e2e.mode` must be \"off\", \"optional\" or \"required\", not {:?}", self.mode))
    }
}

/// Most providers one server configures.
pub const MAX_PROVIDERS: usize = 32;

impl AuthConfig {
    pub fn mode(&self) -> Result<AuthMode, String> {
        AuthMode::parse(&self.mode).ok_or_else(|| format!("`auth.mode` must be \"links\", \"accounts\" or \"accounts+links\", not {:?}", self.mode))
    }

    pub fn policy(&self) -> Policy {
        Policy::new(&self.admins, &self.allow_emails, &self.allow_domains)
    }

    /// Seconds a session lasts unused.
    pub fn session_secs(&self) -> u64 {
        // `check` keeps the days finite and in range.
        (self.session_days.clamp(0.0, 3650.0) * 86_400.0).round() as u64
    }

    /// Check what doesn't depend on a provider's kind (each kind checks its own keys when built).
    pub fn check(&self) -> Result<(), String> {
        let mode = self.mode()?;
        if !self.session_days.is_finite() || !(0.01..=3650.0).contains(&self.session_days) {
            return Err("`auth.session_days` must be from 0.01 to 3650".into());
        }
        if self.provider.len() > MAX_PROVIDERS {
            return Err(format!("at most {MAX_PROVIDERS} `[[auth.provider]]`"));
        }
        if mode.accounts() && self.provider.is_empty() {
            return Err(format!("`auth.mode = \"{}\"` needs at least one `[[auth.provider]]` to sign in with", mode.id()));
        }
        let mut seen = Vec::new();
        for p in &self.provider {
            if !valid_id(&p.id) {
                return Err(format!("provider id {:?}: use 1–32 letters, digits, `-` or `_`", p.id));
            }
            if seen.contains(&p.id) {
                return Err(format!("two providers are called {:?}", p.id));
            }
            seen.push(p.id.clone());
            if p.kind.trim().is_empty() {
                return Err(format!("provider {:?} needs a `kind` (\"oidc\", \"external\"…)", p.id));
            }
        }
        for e in self.admins.iter().chain(&self.allow_emails) {
            if !e.contains('@') || e.chars().any(char::is_whitespace) {
                return Err(format!("{e:?} isn't an email address"));
            }
        }
        Ok(())
    }
}

/// A provider id: 1–32 ASCII letters, digits, `-` or `_`.
pub fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
