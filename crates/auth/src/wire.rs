//! What apps and servers say about signing in. These travel inside `figcraft-collab`'s messages
//! (postcard, then JSON for agents), so new fields go at the end of new variants only.

use serde::{Deserialize, Serialize};

/// Who may get into a server's files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthMode {
    /// Share links and join codes only (no accounts): every server before accounts. Apps call
    /// such a server **open** (`mode = "open"` in `server.toml` is the same).
    #[default]
    Links,
    /// Signing in is required, and people have a role per file.
    Accounts,
    /// Both: members sign in, and share links and join codes keep working (a file that demands
    /// signing in even with a link isn't built yet).
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

    /// From [`id`](Self::id) (any case, surrounding spaces ignored; `"open"` is `"links"`).
    pub fn parse(s: &str) -> Option<AuthMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "links" | "open" => Some(AuthMode::Links),
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
    // Appended for basic (username and password) accounts. Apps from before them can't read these:
    // a server lists them only in [`ServerAbout`], never in the answer to `Info`.
    /// Type a username and password ([`SignIn::Password`]); `label` names the sign-in ("Server
    /// account"). Apps send a password only over TLS (`wss://`) or to this machine.
    Password { label: String },
    /// People may make their own account here ([`SignIn::SignUp`]).
    SignUp,
    // Appended for the browser build a server hosts (apps from before it can't read this: a
    // server lists it only in the answer to `AboutAll` (figcraft-collab's message), never in `Info` or
    // `About`).
    /// [`Flow::Browser`] for a page: send the person (in the same tab) to `authorize_url` with a
    /// PKCE challenge (S256), a `state` and a `redirect_uri` that is exactly one of
    /// `redirect_uris` (the page's own address), then send the `code` the page is loaded with
    /// back ([`SignIn::Code`] with that `redirect_uri`). `client_id` may differ from the
    /// browser flow's (providers want a separate client for web redirects).
    Redirect { authorize_url: String, client_id: String, scopes: Vec<String>, params: Vec<(String, String)>, redirect_uris: Vec<String> },
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

/// What a server accepts: the answer to `Info`. A server of share links only
/// ([`AuthMode::Links`]) is an **open** server: nobody signs in, a link or a join code is the
/// access.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub auth: AuthMode,
    pub providers: Vec<ProviderInfo>,
    pub e2e: E2eMode,
}

impl ServerInfo {
    /// Only the flows apps from before basic accounts can read ([`Flow::Browser`], [`Flow::Device`],
    /// [`Flow::Token`]): what a server answers `Info` with. A provider left with no flow is still
    /// listed (older apps say it can't be used from them).
    pub fn for_older_apps(mut self) -> ServerInfo {
        for p in &mut self.providers {
            p.flows.retain(|f| matches!(f, Flow::Browser { .. } | Flow::Device | Flow::Token { .. }));
        }
        self
    }

    /// Everything but [`Flow::Redirect`]: what a server answers `About` with (apps that read
    /// [`Flow::Password`] and [`Flow::SignUp`] but not that one).
    pub fn without_redirects(mut self) -> ServerInfo {
        for p in &mut self.providers {
            p.flows.retain(|f| !matches!(f, Flow::Redirect { .. }));
        }
        self
    }

    /// How people get in, in one word for the app: `"open"` (no sign-in: share links and join
    /// codes), `"basic"` (usernames and passwords), `"sso"` (an identity provider: Google,
    /// Keycloak…), or `"basic+sso"` (both).
    pub fn access(&self) -> &'static str {
        if !self.auth.accounts() {
            return "open";
        }
        let basic = self.providers.iter().any(|p| p.flows.iter().any(|f| matches!(f, Flow::Password { .. })));
        let sso = self.providers.iter().any(|p| p.flows.iter().any(|f| !matches!(f, Flow::Password { .. } | Flow::SignUp)));
        match (basic, sso) {
            (true, true) => "basic+sso",
            (true, false) => "basic",
            _ => "sso",
        }
    }
}

/// What a server says about itself: the answer to `About` (servers from before it refuse the
/// question: ask `Info` then). New fields go in a new message, never here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAbout {
    /// The name its operator gave it (`name` in `server.toml`; empty: none). Apps show the name
    /// people gave the server first, then this, then its address.
    pub name: String,
    /// What it accepts, with every flow (also [`Flow::Password`] and [`Flow::SignUp`]).
    pub info: ServerInfo,
    /// Its version.
    pub version: String,
}

/// A sign-in step (before a connection's first message). `Debug` leaves the secrets out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignIn {
    /// A session token the server gave earlier ([`Me::session`]).
    Session { token: String },
    /// What the provider's page sent back to the redirect (the loopback one, or a page's listed in
    /// [`Flow::Redirect`]), with the PKCE verifier and the exact `redirect_uri` used.
    Code { provider: String, code: String, verifier: String, redirect_uri: String },
    /// Start a device sign-in: the server answers [`SignInReply::Device`].
    DeviceStart { provider: String },
    /// Has the person entered the code yet? ([`SignInReply::Pending`] until they have.)
    DevicePoll { provider: String, handle: String },
    /// A token the provider issued (the `token` flow).
    Token { provider: String, token: String },
    /// End this session token (signing out on this device).
    SignOut { token: String },
    // Appended for basic accounts (servers from before them can't read these).
    /// A username and password (the [`Flow::Password`] flow). Never logged.
    Password { provider: String, username: String, password: String },
    /// Make an account with this username and password and sign in with it (the [`Flow::SignUp`]
    /// flow, on a server that lets people sign up). An email given here isn't verified: the
    /// allow-lists don't count it.
    SignUp { provider: String, username: String, password: String, email: Option<String>, name: String },
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignIn::Session { .. } => f.write_str("Session { .. }"),
            SignIn::Code { provider, redirect_uri, .. } => {
                f.debug_struct("Code").field("provider", provider).field("redirect_uri", redirect_uri).finish_non_exhaustive()
            }
            SignIn::DeviceStart { provider } => f.debug_struct("DeviceStart").field("provider", provider).finish(),
            SignIn::DevicePoll { provider, .. } => f.debug_struct("DevicePoll").field("provider", provider).finish_non_exhaustive(),
            SignIn::Token { provider, .. } => f.debug_struct("Token").field("provider", provider).finish_non_exhaustive(),
            SignIn::SignOut { .. } => f.write_str("SignOut { .. }"),
            SignIn::Password { provider, username, .. } => {
                f.debug_struct("Password").field("provider", provider).field("username", username).finish_non_exhaustive()
            }
            SignIn::SignUp { provider, username, .. } => {
                f.debug_struct("SignUp").field("provider", provider).field("username", username).finish_non_exhaustive()
            }
        }
    }
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
