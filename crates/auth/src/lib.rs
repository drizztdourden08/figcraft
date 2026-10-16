//! Accounts for `figcraft-server` (design: `docs/accounts-and-e2e.md`).
//!
//! A server can let people in by who they are instead of only by share links. *Who they are* comes
//! from an [`IdentityProvider`]: built-in kinds speak standards (OpenID Connect, the OAuth device
//! flow) or ask a verifier the operator runs, and anyone can add their own. The server talks to the
//! providers; apps only open the provider's sign-in page and hand the server what comes back
//! ([`SignIn`]), then use the server's own session token ([`Me::session`]).
//!
//! - [`wire`]: what apps and servers say about signing in (also part of `figcraft-collab`'s
//!   messages): [`ServerInfo`], [`SignIn`], [`SignInReply`].
//! - [`provider`]: [`Identity`], the [`IdentityProvider`] trait, and [`Fetch`] (the HTTPS a
//!   provider needs, supplied by the server so this crate opens no sockets).
//! - [`policy`]: who may sign in once a provider vouched for them, and who is an admin.
//! - [`config`]: the `[auth]` and `[e2e]` settings of `server.toml`.
//! - With the `providers` feature: [`oidc`] (any OpenID Connect issuer; Google and GitLab are
//!   presets), [`external`] (a verifier the operator runs) and the [`registry`] that builds them
//!   from `[[auth.provider]]` and takes kinds of your own.
//! - [`Gate`]: what a host asks before a connection's first message: what it accepts and who this
//!   is. [`Links`] is today's behaviour (no accounts).

pub mod config;
#[cfg(feature = "providers")]
pub mod external;
#[cfg(feature = "providers")]
pub mod jwt;
#[cfg(feature = "providers")]
pub mod oidc;
pub mod policy;
pub mod provider;
#[cfg(feature = "providers")]
pub mod registry;
pub mod wire;

pub use config::{AuthConfig, E2eConfig, FileAccess, ProviderConfig};
pub use policy::Policy;
pub use provider::{AuthError, DeviceStart, Fetch, FetchError, Identity, IdentityProvider, loopback_redirect};
pub use wire::{AuthMode, DeviceCode, E2eMode, Flow, Me, ProviderInfo, ServerAbout, ServerInfo, SignIn, SignInReply};

/// Someone a connection was signed in as: what a host's backend admits by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    /// The server's id for them (stable across sign-ins).
    pub account: String,
    pub name: String,
    pub email: Option<String>,
    /// May manage the server (like the server key).
    pub admin: bool,
}

/// Where a sign-in step came from: what a host needs to hold back password guessing and to take
/// passwords only over a private channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The client's address (behind the trusted proxy: the one it forwarded).
    pub ip: std::net::IpAddr,
    /// The connection came from this machine, or through the trusted reverse proxy (which
    /// terminates TLS): a password sent on it wasn't on the network in the clear. The server
    /// itself speaks plain `ws://`, so any other connection is in the clear.
    pub private: bool,
}

impl Origin {
    /// A step from this machine (tests, the command line).
    pub fn local() -> Origin {
        Origin { ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), private: true }
    }
}

/// What a host asks before a connection's first message (`Hello`, `Manage`…): what it accepts,
/// and who a sign-in is. Called from the connection's own thread (providers are slow), never the
/// hub's.
pub trait Gate: Send + Sync {
    /// What this host accepts (the answer to `Info`: only the flows older apps read, see
    /// [`ServerInfo::for_older_apps`]).
    fn info(&self) -> ServerInfo;

    /// A sign-in step: the reply, and the person when it signed the connection in.
    fn sign_in(&self, req: SignIn) -> (SignInReply, Option<Person>);

    /// What this host says about itself (the answer to `About`): its name and everything it
    /// accepts.
    fn about(&self) -> ServerAbout {
        ServerAbout { name: String::new(), info: self.info(), version: String::new() }
    }

    /// [`sign_in`](Self::sign_in), knowing where the step came from (hosts that take passwords
    /// need it).
    fn sign_in_from(&self, req: SignIn, _from: Origin) -> (SignInReply, Option<Person>) {
        self.sign_in(req)
    }
}

/// Today's behaviour: share links only, nobody signs in, nothing sealed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Links;

impl Gate for Links {
    fn info(&self) -> ServerInfo {
        ServerInfo::default()
    }

    fn sign_in(&self, _req: SignIn) -> (SignInReply, Option<Person>) {
        (SignInReply::Refused { reason: "this server has no accounts: join with a share link or a code".into() }, None)
    }
}

#[cfg(test)]
#[cfg(feature = "providers")]
mod providers_tests;
#[cfg(test)]
mod tests;
