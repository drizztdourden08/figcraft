//! Building providers from `[[auth.provider]]`: the built-in kinds, and kinds a server build adds
//! ([`Registry::register`]).

use std::sync::Arc;

use crate::config::ProviderConfig;
use crate::provider::{Fetch, IdentityProvider};

/// Makes a provider from its settings.
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
}
