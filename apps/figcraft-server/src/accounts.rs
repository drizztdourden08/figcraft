//! People who sign in (`[auth]`, `docs/accounts-and-e2e.md`): the providers built from the
//! settings, who has signed in (`accounts/people.json`) and their sessions
//! (`accounts/sessions.json`, tokens kept only as hashes), and their devices and recovery copies
//! for sealed files (`accounts/devices.json`, `accounts/recovery.json`; see `devices`), and the
//! usernames and passwords of basic accounts (`accounts/passwords.json`, see
//! [`crate::passwords`]), the emails and admins admins added from the app (`accounts/allowed.json`)
//! and people's pictures (`avatars/`, see [`team`]). This is the server's [`Gate`]: sign-in
//! steps run in the connection's own thread, so a slow provider holds up only that connection.
//!
//! The store looks people up here too (who an invited email belongs to); everything sits behind
//! one lock, held only for in-memory work and the small atomic writes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use figcraft_auth::config::PASSWORD_KIND;
use figcraft_auth::registry::Registry;
use figcraft_auth::{
    AuthConfig, AuthError, AuthMode, DeviceCode, E2eMode, Fetch, FileAccess, Flow, Gate, Identity, IdentityProvider, Me, Origin, Person, Policy,
    ProviderConfig, ServerAbout, ServerInfo, SignIn, SignInReply,
};
use figcraft_collab::message::UserInfo;
use figcraft_collab_net::token;
use serde::{Deserialize, Serialize};

use crate::disk;
use crate::passwords::{self, Guard, PasswordProvider, Passwords};
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
    /// Where their provider says their picture is (kept as a small copy in `avatars/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// When the picture was last fetched (seconds since 1970; 0: never).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub avatar_at: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
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
    /// Registered devices and recovery copies (sealed files).
    devices: Vec<devices::DeviceRec>,
    recovery: Vec<devices::RecoveryRec>,
}

#[path = "devices.rs"]
pub mod devices;

#[path = "team.rs"]
pub mod team;

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
    /// The server's name (`name` in `server.toml`).
    name: String,
    /// Basic accounts: the `password` provider's id and its usernames.
    passwords: Option<(String, Arc<Passwords>)>,
    /// Holds back password guessing.
    guard: Mutex<Guard>,
    /// Who sees which files (`[auth] file_access`).
    file_access: FileAccess,
    /// The emails and admins admins added from the app (`allowed.json`). Taken after `state`
    /// when both are needed, never the other way round.
    allowed: Mutex<team::Allowed>,
    /// Where people's pictures are fetched from (none offline).
    fetch: Option<Arc<dyn Fetch>>,
    /// People's pictures (`<data>/avatars`).
    avatars: PathBuf,
}

/// Why a password sent in the clear is refused.
pub const PASSWORD_NEEDS_TLS: &str = "this server takes passwords only over TLS (wss://, through its reverse proxy) or from its own machine";

/// The providers `cfg` lists (`password` built here: its usernames are in the data directory),
/// and the usernames.
type Built = (Vec<(String, Box<dyn IdentityProvider>)>, Option<(String, Arc<Passwords>)>);

fn build_providers(
    dir: &Path,
    cfg: &AuthConfig,
    mut build: impl FnMut(&ProviderConfig) -> Result<Option<Box<dyn IdentityProvider>>, String>,
) -> Result<Built, String> {
    let mut providers = Vec::new();
    let mut basic = None;
    for p in &cfg.provider {
        if p.kind.trim().eq_ignore_ascii_case(PASSWORD_KIND) {
            let book = Arc::new(Passwords::open(dir)?);
            providers.push((p.id.clone(), Box::new(PasswordProvider::new(p, book.clone())?) as Box<dyn IdentityProvider>));
            basic = Some((p.id.clone(), book));
        } else if let Some(built) = build(p)? {
            providers.push((p.id.clone(), built));
        }
    }
    Ok((providers, basic))
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
        let built = build_providers(&data.join(DIR), cfg, |p| registry.build(p, fetch.clone()).map(Some))?;
        let mut a = Self::with_providers(data, cfg, e2e, built)?;
        a.fetch = Some(fetch);
        Ok(a)
    }

    /// Who has signed in on a stopped server's data directory, for the command line: the
    /// providers that can be built with the built-in kinds (nobody signs in through it).
    pub fn offline(data: &Path, cfg: &AuthConfig, e2e: E2eMode) -> Result<Accounts, String> {
        cfg.check()?;
        let registry = Registry::builtin();
        let fetch: Arc<dyn Fetch> = Arc::new(crate::fetch::Https::new()?);
        let built = build_providers(&data.join(DIR), cfg, |p| Ok(registry.build(p, fetch.clone()).ok()))?;
        Self::with_providers(data, cfg, e2e, built)
    }

    fn with_providers(data: &Path, cfg: &AuthConfig, e2e: E2eMode, (providers, passwords): Built) -> Result<Accounts, String> {
        let dir = data.join(DIR);
        let people: Vec<Account> = read(&dir.join(PEOPLE))?;
        let sessions: Vec<Session> = read(&dir.join(SESSIONS))?;
        let devices: Vec<devices::DeviceRec> = read(&dir.join(devices::DEVICES))?;
        let recovery: Vec<devices::RecoveryRec> = read(&dir.join(devices::RECOVERY))?;
        let allowed: team::Allowed = read(&dir.join(team::ALLOWED))?;
        Ok(Accounts {
            file_access: cfg.file_access()?,
            allowed: Mutex::new(allowed),
            fetch: None,
            avatars: data.join(team::AVATARS),
            mode: cfg.mode()?,
            e2e,
            policy: cfg.policy(),
            session_secs: cfg.session_secs(),
            providers,
            dir,
            state: Mutex::new(State { people, sessions, device: HashMap::new(), devices, recovery }),
            name: String::new(),
            passwords,
            guard: Mutex::new(Guard::default()),
        })
    }

    /// Give the server its name (what `About` says).
    pub fn with_name(mut self, name: &str) -> Accounts {
        self.name = name.trim().to_string();
        self
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
            state: Mutex::new(State { people: Vec::new(), sessions: Vec::new(), device: HashMap::new(), devices: Vec::new(), recovery: Vec::new() }),
            name: String::new(),
            passwords: None,
            guard: Mutex::new(Guard::default()),
            file_access: FileAccess::Members,
            allowed: Mutex::new(team::Allowed::default()),
            fetch: None,
            avatars: data.join(team::AVATARS),
        }
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    pub fn e2e(&self) -> E2eMode {
        self.e2e
    }

    /// Who sees which files (meaningful on a server with accounts).
    pub fn file_access(&self) -> FileAccess {
        self.file_access
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
        let known = self.state().people.iter().find(|a| a.provider == who.provider && a.subject == who.subject).map(|a| a.id.clone());
        if let Err(reason) = self.admit(&who, known.as_deref()) {
            log::info!("event=sign_in_refused provider={} reason=policy", who.provider);
            return (SignInReply::Refused { reason }, None);
        }
        match self.start_session(&who) {
            Ok((me, person)) => {
                log::info!("event=signed_in provider={} account={}", who.provider, person.account);
                // Their picture, fetched now and then (the sign-in doesn't wait for more).
                self.refresh_avatar(&person.account, who.picture.as_deref());
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
                    picture: None,
                    avatar_at: 0,
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
            picture: None,
        };
        self.admit(&who, Some(&account.id))?;
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
        // Someone with a username here loses it too (else signing in again would bring them back).
        if let Some((pid, book)) = &self.passwords
            && gone.provider == *pid
            && book.remove(&gone.subject).is_ok()
        {
            log::info!("event=user_removed account={account}");
        }
        let before = s.sessions.len();
        s.sessions.retain(|x| x.account != account);
        self.save_people(&s)?;
        if s.sessions.len() != before {
            self.save_sessions(&s)?;
        }
        self.forget_devices(&mut s, account)?;
        drop(s);
        self.forget_avatar(account);
        self.forget_admin(account)?;
        log::info!("event=person_removed account={account}");
        Ok(Some(gone))
    }

    /// Is this person an admin (their verified email is in `admins` or was made one from the app,
    /// or their account was)?
    pub fn is_admin(&self, a: &Account) -> bool {
        a.email.as_ref().is_some_and(|e| self.policy.admins.contains(e)) || self.allowed().is_admin(a)
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

    /// What this server accepts, with every flow (the answer to `About`).
    pub fn full_info(&self) -> ServerInfo {
        ServerInfo { auth: self.mode, providers: self.providers.iter().map(|(_, p)| p.info()).collect(), e2e: self.e2e }
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Guard> {
        self.guard.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A username and password (any provider offering the password flow), held back by the
    /// guard and only over a private channel.
    fn password_sign_in(&self, provider: &str, username: &str, password: &str, from: Origin) -> (SignInReply, Option<Person>) {
        let refuse = |reason: &str| (SignInReply::Refused { reason: reason.to_string() }, None);
        if !from.private {
            log::info!("event=password_refused ip={} reason=cleartext", from.ip);
            return refuse(PASSWORD_NEEDS_TLS);
        }
        let p = match self.provider(provider) {
            Ok(p) if p.info().flows.iter().any(|f| matches!(f, Flow::Password { .. })) => p,
            Ok(_) => return refuse("that sign-in doesn't take passwords"),
            Err(reason) => return refuse(&reason),
        };
        // Counted by the username as it would be kept (what can't be one counts as itself).
        let key = passwords::username(username).unwrap_or_else(|| username.trim().to_ascii_lowercase().chars().take(64).collect());
        if let Err(why) = self.guard().try_password(&key, Some(from.ip), std::time::Instant::now()) {
            log::info!("event=password_refused ip={} reason=held_back", from.ip);
            return refuse(why);
        }
        // The guard isn't held while the hash is computed (it is slow).
        match p.verify_password(username, password) {
            Ok(who) => {
                self.guard().right(&key, Some(from.ip));
                self.signed_in(who)
            }
            Err(AuthError::Refused(why)) => {
                self.guard().wrong(&key, Some(from.ip), std::time::Instant::now());
                log::info!("event=password_wrong ip={}", from.ip);
                refuse(&why)
            }
            Err(e) => Self::refused(e),
        }
    }

    /// Someone making their own account (a provider that allows it).
    fn sign_up(
        &self,
        provider: &str,
        username: &str,
        password: &str,
        email: Option<&str>,
        name: &str,
        from: Origin,
    ) -> (SignInReply, Option<Person>) {
        let refuse = |reason: &str| (SignInReply::Refused { reason: reason.to_string() }, None);
        if !from.private {
            return refuse(PASSWORD_NEEDS_TLS);
        }
        let p = match self.provider(provider) {
            Ok(p) if p.info().flows.contains(&Flow::SignUp) => p,
            Ok(_) => return refuse("this server doesn't let people make their own account: ask an admin for one"),
            Err(reason) => return refuse(&reason),
        };
        // An email typed here isn't verified: on a server that lets in only some, an admin adds people.
        if !self.policy().open() {
            return refuse("this server lets in only some email addresses: ask an admin for an account");
        }
        if let Err(why) = self.guard().try_signup(from.ip, std::time::Instant::now()) {
            return refuse(why);
        }
        match p.sign_up(username, password, email, name) {
            Ok(who) => {
                log::info!("event=signed_up provider={provider} ip={}", from.ip);
                self.signed_in(who)
            }
            Err(e) => Self::refused(e),
        }
    }

    /// The usernames, or why there are none.
    fn book(&self) -> Result<&(String, Arc<Passwords>), String> {
        self.passwords
            .as_ref()
            .ok_or_else(|| "this server has no usernames and passwords (add `[[auth.provider]]` with `kind = \"password\"`)".into())
    }

    /// The account of `username`, once they signed in.
    fn account_of_user(&self, username: &str) -> Option<String> {
        let (pid, _) = self.passwords.as_ref()?;
        let u = passwords::username(username)?;
        self.state().people.iter().find(|a| a.provider == *pid && a.subject == u).map(|a| a.id.clone())
    }

    /// Add someone with a username (an admin did): the password made, when none was given.
    pub fn create_user(&self, username: &str, email: Option<&str>, name: &str, password: Option<&str>) -> Result<Option<String>, String> {
        let (_, book) = self.book()?;
        let made = book.add(username, email, true, name, password)?;
        log::info!("event=user_added");
        Ok(made)
    }

    /// A new temporary password for `username`, and their account (its sessions ended).
    pub fn reset_password(&self, username: &str) -> Result<(String, Option<String>), String> {
        let (_, book) = self.book()?;
        let made = book.set(username, None)?.ok_or("no password was made")?;
        self.guard().unlock(&passwords::username(username).unwrap_or_default());
        let account = self.account_of_user(username);
        if let Some(a) = &account {
            self.end_sessions(a)?;
        }
        log::info!("event=password_reset");
        Ok((made, account))
    }

    /// Take `username`'s password away; their account (its sessions ended).
    pub fn remove_user(&self, username: &str) -> Result<Option<String>, String> {
        let (_, book) = self.book()?;
        let account = self.account_of_user(username);
        book.remove(username)?;
        if let Some(a) = &account {
            self.end_sessions(a)?;
        }
        log::info!("event=user_removed");
        Ok(account)
    }

    /// Everyone with a username.
    pub fn users(&self) -> Result<Vec<UserInfo>, String> {
        let (pid, book) = self.book()?;
        let t = std::time::Instant::now();
        let people = self.state().people.clone();
        let guard = self.guard();
        Ok(book
            .list()
            .into_iter()
            .map(|u| UserInfo {
                account: people.iter().find(|a| a.provider == *pid && a.subject == u.username).map(|a| a.id.clone()),
                locked: guard.user_locked(&u.username, t).map_or(0, |d| d.as_secs().max(1)),
                username: u.username,
                email: u.email,
                name: u.name,
                created: u.created,
                changed: u.changed,
                temporary: u.temporary,
            })
            .collect())
    }

    /// `who` changes their password: `old` must be right (a wrong one counts against them).
    pub fn change_password(&self, who: &Person, old: &str, new: &str) -> Result<(), String> {
        let (pid, book) = self.book()?;
        let account = self.account(&who.account).ok_or("your account is gone from this server")?;
        if account.provider != *pid {
            return Err("you sign in here with another provider: change your password there".into());
        }
        let user = account.subject;
        self.guard().try_password(&user, None, std::time::Instant::now())?;
        if book.check(&user, old).is_none() {
            self.guard().wrong(&user, None, std::time::Instant::now());
            return Err("your current password is wrong".into());
        }
        self.guard().right(&user, None);
        book.set(&user, Some(new))?;
        log::info!("event=password_changed account={}", who.account);
        Ok(())
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
        self.full_info().for_older_apps()
    }

    fn about(&self) -> ServerAbout {
        ServerAbout { name: self.name.clone(), info: self.full_info(), version: env!("CARGO_PKG_VERSION").to_string() }
    }

    fn sign_in(&self, req: SignIn) -> (SignInReply, Option<Person>) {
        // Not knowing where it came from, a password is taken as sent in the clear.
        self.sign_in_from(req, Origin { ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), private: false })
    }

    fn sign_in_from(&self, req: SignIn, from: Origin) -> (SignInReply, Option<Person>) {
        if !self.mode.accounts() {
            return figcraft_auth::Links.sign_in(req);
        }
        match req {
            SignIn::Password { provider, username, password } => self.password_sign_in(&provider, &username, &password, from),
            SignIn::SignUp { provider, username, password, email, name } => {
                self.sign_up(&provider, &username, &password, email.as_deref(), &name, from)
            }
            SignIn::Session { token } => match self.session(&token) {
                Ok((me, person)) => (SignInReply::SignedIn(me), Some(person)),
                Err(reason) => (SignInReply::Refused { reason }, None),
            },
            SignIn::Code { provider, code, verifier, redirect_uri } => {
                let p = match self.provider(&provider) {
                    Ok(p) => p,
                    Err(reason) => return (SignInReply::Refused { reason }, None),
                };
                // The desktop app's loopback page, or a page on the web the provider lists
                // exactly (`web_redirect_uris`): a code sent anywhere else isn't exchanged.
                let redirect_ok = figcraft_auth::loopback_redirect(&redirect_uri) || p.web_redirect(&redirect_uri);
                if !redirect_ok || code.len() > 4096 || verifier.len() > 256 {
                    return (SignInReply::Refused { reason: "that sign-in isn't valid".into() }, None);
                }
                match p.exchange_code(&code, &verifier, &redirect_uri) {
                    Ok(who) => self.signed_in(who),
                    Err(e) => Self::refused(e),
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
