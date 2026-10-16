//! What apps and servers say about signing in. These travel inside `figcraft-collab`'s messages
//! (postcard, then JSON for agents), so new fields go at the end of new variants only.

use serde::{Deserialize, Serialize};

/// Who may get into a server's files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthMode {
    /// Share links and join codes only (no accounts): every server before accounts.
    #[default]
    Links,
    /// Signing in is required, and people have a role per file.
    Accounts,
    /// Both: links keep working, and a file can demand signing in.
    AccountsAndLinks,
}

impl AuthMode {
    /// `"links"`, `"accounts"` or `"accounts+links"` (as in `server.toml`).
    pub fn id(self) -> &'static str {
        match self {
            AuthMode::Links => "links",
            AuthMode::Accounts => "accounts",
            AuthMode::AccountsAndLinks => "accounts+links",
        }
    }

    /// From [`id`](Self::id) (any case, surrounding spaces ignored).
    pub fn parse(s: &str) -> Option<AuthMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "links" => Some(AuthMode::Links),
            "accounts" => Some(AuthMode::Accounts),
            "accounts+links" | "links+accounts" => Some(AuthMode::AccountsAndLinks),
            _ => None,
        }
    }

    /// People sign in on this server.
    pub fn accounts(self) -> bool {
        self != AuthMode::Links
    }

    /// Share links (and join codes) let people in.
    pub fn links(self) -> bool {
        self != AuthMode::Accounts
    }
}

/// Whether a server's files are end-to-end encrypted ("sealed").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum E2eMode {
    /// Nothing sealed: every server before sealing.
    #[default]
    Off,
    /// Owners choose per file.
    Optional,
    /// Every file published is sealed.
    Required,
}

impl E2eMode {
    /// `"off"`, `"optional"` or `"required"`.
    pub fn id(self) -> &'static str {
        match self {
            E2eMode::Off => "off",
            E2eMode::Optional => "optional",
            E2eMode::Required => "required",
        }
    }

    /// From [`id`](Self::id) (any case, surrounding spaces ignored).
    pub fn parse(s: &str) -> Option<E2eMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(E2eMode::Off),
            "optional" => Some(E2eMode::Optional),
            "required" => Some(E2eMode::Required),
            _ => None,
        }
    }
}

/// How an app gets something to sign in with, for one provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Flow {
    /// Open `authorize_url` in the browser with these parameters, a PKCE challenge (S256), a
    /// `state` and a loopback `redirect_uri` (`http://127.0.0.1:<port>/`), then send the `code`
    /// that comes back ([`SignIn::Code`]).
    Browser { authorize_url: String, client_id: String, scopes: Vec<String>, params: Vec<(String, String)> },
    /// Ask the server for a code to enter on another device ([`SignIn::DeviceStart`]), then poll.
    Device,
    /// Paste a token the provider issues ([`SignIn::Token`]); `label` names it ("Company token").
    Token { label: String },
}

/// A provider a server accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// What apps send back ([`SignIn::Code::provider`] …).
    pub id: String,
    /// What people see ("Google", "Company sign-in").
    pub label: String,
    pub flows: Vec<Flow>,
}

/// What a server accepts: the answer to `Info`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub auth: AuthMode,
    pub providers: Vec<ProviderInfo>,
    pub e2e: E2eMode,
}

/// A sign-in step (before a connection's first message).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignIn {
    /// A session token the server gave earlier ([`Me::session`]).
    Session { token: String },
    /// What the provider's page sent back to the loopback redirect, with the PKCE verifier and the
    /// exact `redirect_uri` used.
    Code { provider: String, code: String, verifier: String, redirect_uri: String },
    /// Start a device sign-in: the server answers [`SignInReply::Device`].
    DeviceStart { provider: String },
    /// Has the person entered the code yet? ([`SignInReply::Pending`] until they have.)
    DevicePoll { provider: String, handle: String },
    /// A token the provider issued (the `token` flow).
    Token { provider: String, token: String },
    /// End this session token (signing out on this device).
    SignOut { token: String },
}

/// Someone signed in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    /// The server's id for them.
    pub account: String,
    pub name: String,
    pub email: Option<String>,
    pub admin: bool,
    /// A new session token (empty when signing in with one): keep it in the keychain and sign in
    /// with it next time ([`SignIn::Session`]).
    pub session: String,
    /// When the session ends unless it is used (seconds since 1970).
    pub expires: u64,
}

/// A device sign-in started: show `user_code` and `verification_uri`, poll every `interval` s.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub user_code: String,
    pub verification_uri: String,
    /// What [`SignIn::DevicePoll`] sends back (the server's handle, not the provider's secret).
    pub handle: String,
    pub interval: u32,
    /// Seconds until the code stops working.
    pub expires_in: u32,
}

/// The answer to a [`SignIn`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignInReply {
    SignedIn(Me),
    Device(DeviceCode),
    /// The device code wasn't entered yet: poll again.
    Pending,
    SignedOut,
    /// Why not (shown to the person; never echoes a secret).
    Refused {
        reason: String,
    },
}
