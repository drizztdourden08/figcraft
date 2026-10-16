//! Building providers from `[[auth.provider]]`: the built-in kinds, and kinds a server build adds
//! ([`Registry::register`]). [`Registry::check`] builds one without the network, so a settings
//! check finds what would stop the server starting.

use std::sync::Arc;

use crate::config::ProviderConfig;
use crate::provider::{Fetch, FetchError, IdentityProvider};

/// Makes a provider from its settings. It must not use the network while building (the issuer is
/// first contacted when it is used): [`Registry::check`] builds with a [`Fetch`] that refuses
/// every request.
pub type Factory = fn(&ProviderConfig, Arc<dyn Fetch>) -> Result<Box<dyn IdentityProvider>, String>;

/// Provider kinds by name.
pub struct Registry {
    kinds: Vec<(String, Factory)>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    /// `oidc` and `external`.
    pub fn builtin() -> Registry {
        let oidc: Factory = |c, f| Ok(Box::new(crate::oidc::Oidc::new(c, f)?));
        let external: Factory = |c, f| Ok(Box::new(crate::external::External::new(c, f)?));
        Registry { kinds: vec![("oidc".into(), oidc), ("external".into(), external)] }
    }

    /// Add (or replace) a kind.
    pub fn register(&mut self, kind: &str, factory: Factory) {
        let kind = kind.trim().to_ascii_lowercase();
        self.kinds.retain(|(k, _)| *k != kind);
        self.kinds.push((kind, factory));
    }

    /// The kinds known.
    pub fn kinds(&self) -> Vec<&str> {
        self.kinds.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Build the provider `cfg` describes.
    pub fn build(&self, cfg: &ProviderConfig, fetch: Arc<dyn Fetch>) -> Result<Box<dyn IdentityProvider>, String> {
        let kind = cfg.kind.trim().to_ascii_lowercase();
        let (_, factory) = self
            .kinds
            .iter()
            .find(|(k, _)| *k == kind)
            .ok_or_else(|| format!("provider {:?}: unknown kind {:?} (known: {})", cfg.id, cfg.kind, self.kinds().join(", ")))?;
        factory(cfg, fetch)
    }

    /// Check `cfg` the way [`build`](Self::build) would (its kind, and the keys that kind reads,
    /// including that a `client_secret_file` can be read), without the network.
    pub fn check(&self, cfg: &ProviderConfig) -> Result<(), String> {
        self.build(cfg, Arc::new(Offline)).map(drop)
    }
}

/// A [`Fetch`] that refuses every request (building a provider must not fetch).
struct Offline;

impl Offline {
    fn refuse(url: &str) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Network(format!("{url}: no network while checking the settings")))
    }
}

impl Fetch for Offline {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        Self::refuse(url)
    }

    fn post_form(&self, url: &str, _form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError> {
        Self::refuse(url)
    }

    fn post_json(&self, url: &str, _body: &[u8]) -> Result<Vec<u8>, FetchError> {
        Self::refuse(url)
    }
}
