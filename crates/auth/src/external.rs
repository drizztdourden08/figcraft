//! The `external` provider: the server asks a verifier the operator runs who a token is. The
//! contract (also `examples/auth-verifier/`):
//!
//! ```text
//! POST <verify_url>   Content-Type: application/json
//! {"provider": "<id>", "token": "<what the person pasted>"}
//!
//! 200 {"subject": "stable id", "email": "a@b.c"?, "email_verified": true?, "name": "Ann"?}
//! 401 or 403 {"error": "why, shown to the person"}?   anything else: the verifier is unavailable
//! ```

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::ProviderConfig;
use crate::provider::{AuthError, Fetch, FetchError, Identity, IdentityProvider};
use crate::wire::{Flow, ProviderInfo};

/// Longest token sent on (bytes).
const MAX_TOKEN: usize = 8 << 10;

pub struct External {
    id: String,
    label: String,
    verify_url: String,
    /// An email counts as verified when the answer doesn't say (`trust_email`).
    trust_email: bool,
    fetch: Arc<dyn Fetch>,
}

impl External {
    /// From `[[auth.provider]]` with `kind = "external"`.
    pub fn new(cfg: &ProviderConfig, fetch: Arc<dyn Fetch>) -> Result<External, String> {
        let url = cfg.verify_url.trim();
        let local = url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost") || url.starts_with("http://[::1]");
        if !url.starts_with("https://") && !local {
            return Err(format!("provider {:?}: `verify_url` must be https:// (or http:// on this machine)", cfg.id));
        }
        let label = if cfg.label.trim().is_empty() { cfg.id.clone() } else { cfg.label.trim().to_string() };
        Ok(External { id: cfg.id.clone(), label, verify_url: url.to_string(), trust_email: cfg.trust_email, fetch })
    }
}

impl IdentityProvider for External {
    fn info(&self) -> ProviderInfo {
        ProviderInfo { id: self.id.clone(), label: self.label.clone(), flows: vec![Flow::Token { label: self.label.clone() }] }
    }

    fn verify_token(&self, token: &str) -> Result<Identity, AuthError> {
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_TOKEN {
            return Err(AuthError::Refused("that token isn't valid".into()));
        }
        let body = serde_json::to_vec(&json!({"provider": self.id, "token": token})).map_err(|e| AuthError::Unavailable(e.to_string()))?;
        let answer = match self.fetch.post_json(&self.verify_url, &body) {
            Ok(a) => a,
            Err(FetchError::Status { status: 401 | 403, body }) => {
                let why =
                    serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["error"].as_str().map(|s| s.chars().take(200).collect::<String>()));
                return Err(AuthError::Refused(why.unwrap_or_else(|| "that token isn't valid".into())));
            }
            Err(e) => return Err(AuthError::Unavailable(e.to_string())),
        };
        let v: Value = serde_json::from_slice(&answer).map_err(|_| AuthError::Unavailable("the verifier's answer couldn't be read".into()))?;
        let s = |k: &str| v[k].as_str().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        let subject = s("subject").ok_or_else(|| AuthError::Unavailable("the verifier didn't say who it is (no \"subject\")".into()))?;
        Ok(Identity {
            provider: self.id.clone(),
            subject,
            email: s("email").map(|e| e.to_ascii_lowercase()),
            email_verified: match &v["email_verified"] {
                Value::Bool(b) => *b,
                Value::Null => self.trust_email,
                _ => false,
            },
            name: crate::oidc::person_name(&s),
            picture: s("picture").filter(|u| u.len() <= 2048),
        })
    }
}
