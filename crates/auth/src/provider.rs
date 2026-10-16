//! Identity providers: who a sign-in is.

use crate::wire::ProviderInfo;

/// Who someone is, as a provider says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The configured provider's id.
    pub provider: String,
    /// The provider's stable id for the person (OpenID Connect's `sub`).
    pub subject: String,
    pub email: Option<String>,
    /// The provider checked the email belongs to them (allow-lists use only verified emails).
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Why a sign-in didn't work.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The provider doesn't do this (a flow it wasn't configured for).
    #[error("this sign-in method isn't available here")]
    Unsupported,
    /// The provider said no, or what came back doesn't check out (shown to the person).
    #[error("{0}")]
    Refused(String),
    /// The provider couldn't be reached or answered nonsense (try again later).
    #[error("the sign-in service couldn't be reached: {0}")]
    Unavailable(String),
    /// A device sign-in still waits for the person.
    #[error("waiting for the code to be entered")]
    Pending,
}

/// A device sign-in started by a provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStart {
    /// The provider's secret for polling (kept by the server, never sent to the app).
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u32,
    pub expires_in: u32,
}

/// `uri` is a page on this machine (`http://127.0.0.1:<port>/`, `http://localhost:<port>/` or
/// `http://[::1]:<port>/`): where the desktop app waits for a browser sign-in.
pub fn loopback_redirect(uri: &str) -> bool {
    ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"].iter().any(|p| uri.starts_with(p))
}

/// Says who a sign-in is. The server builds one per `[[auth.provider]]`; implement it to add a kind
/// of your own. Methods a provider doesn't support keep their default ([`AuthError::Unsupported`]).
/// Called from connection threads: they may block on the network.
pub trait IdentityProvider: Send + Sync {
    /// Its id, label and the flows apps may use.
    fn info(&self) -> ProviderInfo;

    /// `redirect_uri` is a page on the web this provider lets sign-ins come back to (exactly as
    /// listed: `web_redirect_uris`). The desktop app's loopback page ([`loopback_redirect`]) is
    /// always let through by the server.
    fn web_redirect(&self, _redirect_uri: &str) -> bool {
        false
    }

    /// The `code` its sign-in page sent to `redirect_uri`, with the PKCE `verifier`.
    fn exchange_code(&self, _code: &str, _verifier: &str, _redirect_uri: &str) -> Result<Identity, AuthError> {
        Err(AuthError::Unsupported)
    }

    /// Start a device sign-in.
    fn start_device(&self) -> Result<DeviceStart, AuthError> {
        Err(AuthError::Unsupported)
    }

    /// Poll a device sign-in: [`AuthError::Pending`] until the person entered the code.
    fn poll_device(&self, _device_code: &str) -> Result<Identity, AuthError> {
        Err(AuthError::Unsupported)
    }

    /// A token it issued (the `token` flow).
    fn verify_token(&self, _token: &str) -> Result<Identity, AuthError> {
        Err(AuthError::Unsupported)
    }

    /// A username and password (the `password` flow: the server's own accounts, or a directory
    /// such as LDAP a kind of your own asks). Wrong ones are [`AuthError::Refused`]; the server
    /// counts them against the username and the address (and locks both out for a while). Never
    /// log the password.
    fn verify_password(&self, _username: &str, _password: &str) -> Result<Identity, AuthError> {
        Err(AuthError::Unsupported)
    }

    /// Make an account with this username and password (the `signUp` flow, when the provider lets
    /// people sign up), then who it is. `email` isn't verified.
    fn sign_up(&self, _username: &str, _password: &str, _email: Option<&str>, _name: &str) -> Result<Identity, AuthError> {
        Err(AuthError::Unsupported)
    }
}

/// The HTTPS requests providers make, supplied by the server (this crate opens no sockets).
/// Answers are the response body of a 2xx; anything else is an error carrying the status and body.
pub trait Fetch: Send + Sync {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError>;
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, FetchError>;
}

/// A request that didn't get a 2xx.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The server answered with this status and body.
    #[error("HTTP {status}")]
    Status { status: u16, body: Vec<u8> },
    /// No answer (network, TLS, timeout).
    #[error("{0}")]
    Network(String),
}
