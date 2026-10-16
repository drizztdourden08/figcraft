//! People who sign in (`[auth]`, `docs/accounts-and-e2e.md`): the providers built from the
//! settings, who has signed in (`accounts/people.json`) and their sessions
//! (`accounts/sessions.json`, tokens kept only as hashes). This is the server's [`Gate`]: sign-in
//! steps run in the connection's own thread, so a slow provider holds up only that connection.
//!
//! The store looks people up here too (who an invited email belongs to); everything sits behind
//! one lock, held only for in-memory work and the small atomic writes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use figcraft_auth::registry::Registry;
use figcraft_auth::{
    AuthConfig, AuthError, AuthMode, DeviceCode, E2eMode, Fetch, Gate, Identity, IdentityProvider, Me, Person, Policy, ServerInfo, SignIn,
    SignInReply,
};
use figcraft_collab_net::token;
use serde::{Deserialize, Serialize};

use crate::disk;
use crate::store::{hash, now};

pub const DIR: &str = "accounts";
const PEOPLE: &str = "people.json";
const SESSIONS: &str = "sessions.json";

/// Most people one server keeps, and sessions per person (the oldest go first).
const MAX_PEOPLE: usize = 100_000;
const MAX_SESSIONS_EACH: usize = 20;
/// Device sign-ins waiting at once.
const MAX_DEVICE: usize = 1_000;
/// A session's expiry is written again only when it moved this much (seconds).
const TOUCH: u64 = 86_400;

/// Someone who signed in (`people.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// The server's id for them.
    pub id: String,
    pub provider: String,
    pub subject: String,
    /// Verified only (lowercase).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub name: String,
    pub created: u64,
    #[serde(default)]
    pub seen: u64,
}

/// A session (`sessions.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Session {
    /// SHA-256 of the token, hex.
    hash: String,
    account: String,
    created: u64,
    expires: u64,
}

/// A device sign-in waiting for the person.
struct Device {
    provider: String,
    device_code: String,
    expires: u64,
}

struct State {
    people: Vec<Account>,
    sessions: Vec<Session>,
    device: HashMap<String, Device>,
}

/// The accounts side of a server.
pub struct Accounts {
    mode: AuthMode,
    e2e: E2eMode,
    policy: Policy,
    session_secs: u64,
    /// By their configured id.
    providers: Vec<(String, Box<dyn IdentityProvider>)>,
    dir: PathBuf,
    state: Mutex<State>,
}

fn read<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{} is damaged: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("can't read {}: {e}", path.display())),
    }
}

impl Accounts {
    /// Build the providers and load who has signed in from `data/accounts/`.
    pub fn open(data: &Path, cfg: &AuthConfig, e2e: E2eMode, registry: &Registry, fetch: Arc<dyn Fetch>) -> Result<Accounts, String> {
        cfg.check()?;
        let providers = cfg.provider.iter().map(|p| Ok((p.id.clone(), registry.build(p, fetch.clone())?))).collect::<Result<Vec<_>, String>>()?;
        Self::with_providers(data, cfg, e2e, providers)
    }

    /// Who has signed in on a stopped server's data directory, for the command line: the
    /// providers that can be built with the built-in kinds (nobody signs in through it).
    pub fn offline(data: &Path, cfg: &AuthConfig, e2e: E2eMode) -> Result<Accounts, String> {
        cfg.check()?;
        let registry = Registry::builtin();
        let fetch: Arc<dyn Fetch> = Arc::new(crate::fetch::Https::new());
        let providers = cfg.provider.iter().filter_map(|p| Some((p.id.clone(), registry.build(p, fetch.clone()).ok()?))).collect();
        Self::with_providers(data, cfg, e2e, providers)
    }

    fn with_providers(data: &Path, cfg: &AuthConfig, e2e: E2eMode, providers: Vec<(String, Box<dyn IdentityProvider>)>) -> Result<Accounts, String> {
        let dir = data.join(DIR);
        let people: Vec<Account> = read(&dir.join(PEOPLE))?;
        let sessions: Vec<Session> = read(&dir.join(SESSIONS))?;
        Ok(Accounts {
            mode: cfg.mode()?,
            e2e,
            policy: cfg.policy(),
            session_secs: cfg.session_secs(),
            providers,
            dir,
            state: Mutex::new(State { people, sessions, device: HashMap::new() }),
        })
    }

    /// No accounts (share links only).
    pub fn links_only(data: &Path) -> Accounts {
        Accounts {
            mode: AuthMode::Links,
            e2e: E2eMode::Off,
            policy: Policy::default(),
            session_secs: 0,
            providers: Vec::new(),
            dir: data.join(DIR),
            state: Mutex::new(State { people: Vec::new(), sessions: Vec::new(), device: HashMap::new() }),
        }
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    pub fn e2e(&self) -> E2eMode {
        self.e2e
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn save_people(&self, s: &State) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_vec_pretty(&s.people).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.dir.join(PEOPLE), &text).map_err(|e| e.to_string())
    }

    fn save_sessions(&self, s: &State) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_vec_pretty(&s.sessions).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.dir.join(SESSIONS), &text).map_err(|e| e.to_string())
    }

    /// The person with this account id.
    pub fn account(&self, id: &str) -> Option<Account> {
        self.state().people.iter().find(|a| a.id == id).cloned()
    }

    /// The person who signed in with this verified email, if any.
    pub fn by_email(&self, email: &str) -> Option<Account> {
        let email = email.trim().to_ascii_lowercase();
        self.state().people.iter().find(|a| a.email.as_deref() == Some(email.as_str())).cloned()
    }

    /// Everyone who has signed in.
    pub fn people(&self) -> Vec<Account> {
        self.state().people.clone()
    }

    fn person(&self, a: &Account) -> Person {
        let admin = self.is_admin(a);
        Person { account: a.id.clone(), name: a.name.clone(), email: a.email.clone(), admin }
    }

    fn provider(&self, id: &str) -> Result<&dyn IdentityProvider, String> {
        self.providers.iter().find(|(pid, _)| pid == id).map(|(_, p)| p.as_ref()).ok_or_else(|| format!("this server has no sign-in called {id:?}"))
    }

    /// Someone a provider vouched for: allowed by the policy? Then their account (made the first
    /// time) and a new session.
    fn signed_in(&self, who: Identity) -> (SignInReply, Option<Person>) {
        if let Err(reason) = self.policy.admit(&who) {
            log::info!("event=sign_in_refused provider={} reason=policy", who.provider);
            return (SignInReply::Refused { reason }, None);
        }
        match self.start_session(&who) {
            Ok((me, person)) => {
                log::info!("event=signed_in provider={} account={}", who.provider, person.account);
                (SignInReply::SignedIn(me), Some(person))
            }
            Err(reason) => (SignInReply::Refused { reason }, None),
        }
    }

    fn start_session(&self, who: &Identity) -> Result<(Me, Person), String> {
        let mut s = self.state();
        let t = now();
        // Whatever the provider sent, emails are kept trimmed and lowercase (allow-lists and invites
        // compare them).
        let email = who.email.as_deref().filter(|_| who.email_verified).map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty());
        let name = who.name.clone().or_else(|| email.clone()).unwrap_or_default();
        let i = match s.people.iter().position(|a| a.provider == who.provider && a.subject == who.subject) {
            Some(i) => i,
            None => {
                if s.people.len() >= MAX_PEOPLE {
                    return Err("this server can't take more people".into());
                }
                let id = format!("a{}", token::file_id()?);
                s.people.push(Account {
                    id,
                    provider: who.provider.clone(),
                    subject: who.subject.clone(),
                    email: None,
                    name: String::new(),
                    created: t,
                    seen: t,
                });
                s.people.len() - 1
            }
        };
        let account = {
            let Some(a) = s.people.get_mut(i) else { return Err("the account went missing".into()) };
            // A provider's newest word on the email and name wins.
            a.email = email;
            a.name = name;
            a.seen = t;
            a.clone()
        };
        let secret = format!("{}{}", token::secret()?, token::secret()?);
        let expires = t.saturating_add(self.session_secs);
        s.sessions.push(Session { hash: hash(&secret), account: account.id.clone(), created: t, expires });
        // Expired sessions go, and a person keeps at most MAX_SESSIONS_EACH (the newest).
        s.sessions.retain(|x| x.expires > t);
        let mine: Vec<usize> = s.sessions.iter().enumerate().filter(|(_, x)| x.account == account.id).map(|(i, _)| i).collect();
        if mine.len() > MAX_SESSIONS_EACH {
            let drop: Vec<usize> = mine.iter().take(mine.len() - MAX_SESSIONS_EACH).copied().collect();
            let mut k = 0;
            s.sessions.retain(|_| {
                let keep = !drop.contains(&k);
                k += 1;
                keep
            });
        }
        self.save_people(&s)?;
        self.save_sessions(&s)?;
        let person = self.person(&account);
        let me = Me { account: account.id, name: account.name, email: account.email, admin: person.admin, session: secret, expires };
        Ok((me, person))
    }

    fn session(&self, token: &str) -> Result<(Me, Person), String> {
        let h = hash(token);
        let mut s = self.state();
        let t = now();
        let Some(i) = s.sessions.iter().position(|x| x.hash == h && x.expires > t) else {
            return Err("your sign-in has ended: sign in again".into());
        };
        let account_id = s.sessions.get(i).map(|x| x.account.clone()).unwrap_or_default();
        let Some(account) = s.people.iter().find(|a| a.id == account_id).cloned() else {
            return Err("your account is gone from this server: sign in again".into());
        };
        // Still allowed? (The operator may have narrowed the allow-lists since.)
        let who = Identity {
            provider: account.provider.clone(),
            subject: account.subject.clone(),
            email: account.email.clone(),
            email_verified: account.email.is_some(),
            name: Some(account.name.clone()),
        };
        self.policy.admit(&who)?;
        let expires = t.saturating_add(self.session_secs);
        if let Some(x) = s.sessions.get_mut(i)
            && expires.saturating_sub(x.expires) >= TOUCH
        {
            x.expires = expires;
            self.save_sessions(&s)?;
        }
        let expires = s.sessions.get(i).map_or(expires, |x| x.expires);
        let person = self.person(&account);
        Ok((Me { account: account.id, name: account.name, email: account.email, admin: person.admin, session: String::new(), expires }, person))
    }

    /// End every session of `account` (an admin or the operator did): how many there were.
    pub fn end_sessions(&self, account: &str) -> Result<usize, String> {
        let mut s = self.state();
        let before = s.sessions.len();
        s.sessions.retain(|x| x.account != account);
        let ended = before - s.sessions.len();
        if ended > 0 {
            self.save_sessions(&s)?;
        }
        Ok(ended)
    }

    /// Forget `account`: its sessions end and its record goes. `None`: nobody had that id.
    pub fn remove_person(&self, account: &str) -> Result<Option<Account>, String> {
        let mut s = self.state();
        let Some(i) = s.people.iter().position(|a| a.id == account) else { return Ok(None) };
        let gone = s.people.remove(i);
        let before = s.sessions.len();
        s.sessions.retain(|x| x.account != account);
        self.save_people(&s)?;
        if s.sessions.len() != before {
            self.save_sessions(&s)?;
        }
        log::info!("event=person_removed account={account}");
        Ok(Some(gone))
    }

    /// Is this person an admin (their verified email is in `admins`)?
    pub fn is_admin(&self, a: &Account) -> bool {
        a.email.as_ref().is_some_and(|e| self.policy.admins.contains(e))
    }

    /// Everyone who has signed in, each with their sessions not expired.
    pub fn people_with_sessions(&self) -> Vec<(Account, usize)> {
        let s = self.state();
        let t = now();
        s.people.iter().map(|a| (a.clone(), s.sessions.iter().filter(|x| x.account == a.id && x.expires > t).count())).collect()
    }

    /// People who signed in, and sessions not expired.
    pub fn counts(&self) -> (usize, usize) {
        let s = self.state();
        let t = now();
        (s.people.len(), s.sessions.iter().filter(|x| x.expires > t).count())
    }

    fn refused(e: AuthError) -> (SignInReply, Option<Person>) {
        match e {
            AuthError::Pending => (SignInReply::Pending, None),
            e => (SignInReply::Refused { reason: e.to_string() }, None),
        }
    }
}

impl Gate for Accounts {
    fn info(&self) -> ServerInfo {
        ServerInfo { auth: self.mode, providers: self.providers.iter().map(|(_, p)| p.info()).collect(), e2e: self.e2e }
    }

    fn sign_in(&self, req: SignIn) -> (SignInReply, Option<Person>) {
        if !self.mode.accounts() {
            return figcraft_auth::Links.sign_in(req);
        }
        match req {
            SignIn::Session { token } => match self.session(&token) {
                Ok((me, person)) => (SignInReply::SignedIn(me), Some(person)),
                Err(reason) => (SignInReply::Refused { reason }, None),
            },
            SignIn::Code { provider, code, verifier, redirect_uri } => {
                let redirect_ok = redirect_uri.starts_with("http://127.0.0.1:")
                    || redirect_uri.starts_with("http://localhost:")
                    || redirect_uri.starts_with("http://[::1]:");
                if !redirect_ok || code.len() > 4096 || verifier.len() > 256 {
                    return (SignInReply::Refused { reason: "that sign-in isn't valid".into() }, None);
                }
                match self.provider(&provider) {
                    Ok(p) => match p.exchange_code(&code, &verifier, &redirect_uri) {
                        Ok(who) => self.signed_in(who),
                        Err(e) => Self::refused(e),
                    },
                    Err(reason) => (SignInReply::Refused { reason }, None),
                }
            }
            SignIn::DeviceStart { provider } => {
                let p = match self.provider(&provider) {
                    Ok(p) => p,
                    Err(reason) => return (SignInReply::Refused { reason }, None),
                };
                match p.start_device() {
                    Ok(d) => {
                        let Ok(handle) = token::secret() else { return (SignInReply::Refused { reason: "no secure random numbers".into() }, None) };
                        let mut s = self.state();
                        let t = now();
                        s.device.retain(|_, x| x.expires > t);
                        if s.device.len() >= MAX_DEVICE {
                            return (SignInReply::Refused { reason: "too many sign-ins are waiting: try again in a few minutes".into() }, None);
                        }
                        s.device.insert(
                            handle.clone(),
                            Device { provider, device_code: d.device_code, expires: t.saturating_add(u64::from(d.expires_in)) },
                        );
                        let code = DeviceCode {
                            user_code: d.user_code,
                            verification_uri: d.verification_uri,
                            handle,
                            interval: d.interval,
                            expires_in: d.expires_in,
                        };
                        (SignInReply::Device(code), None)
                    }
                    Err(e) => Self::refused(e),
                }
            }
            SignIn::DevicePoll { provider, handle } => {
                let device_code = {
                    let s = self.state();
                    match s.device.get(&handle) {
                        Some(d) if d.provider == provider && d.expires > now() => d.device_code.clone(),
                        _ => return (SignInReply::Refused { reason: "that sign-in expired: start again".into() }, None),
                    }
                };
                let p = match self.provider(&provider) {
                    Ok(p) => p,
                    Err(reason) => return (SignInReply::Refused { reason }, None),
                };
                match p.poll_device(&device_code) {
                    Ok(who) => {
                        self.state().device.remove(&handle);
                        self.signed_in(who)
                    }
                    Err(AuthError::Pending) => (SignInReply::Pending, None),
                    Err(e) => {
                        self.state().device.remove(&handle);
                        Self::refused(e)
                    }
                }
            }
            SignIn::Token { provider, token } => match self.provider(&provider) {
                Ok(p) => match p.verify_token(&token) {
                    Ok(who) => self.signed_in(who),
                    Err(e) => Self::refused(e),
                },
                Err(reason) => (SignInReply::Refused { reason }, None),
            },
            SignIn::SignOut { token } => {
                let h = hash(&token);
                let mut s = self.state();
                let before = s.sessions.len();
                s.sessions.retain(|x| x.hash != h);
                if s.sessions.len() != before
                    && let Err(e) = self.save_sessions(&s)
                {
                    log::warn!("couldn't save the sessions: {e}");
                }
                (SignInReply::SignedOut, None)
            }
        }
    }
}
