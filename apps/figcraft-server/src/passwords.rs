//! Basic accounts: usernames and passwords the server keeps itself (`kind = "password"` in
//! `[[auth.provider]]`; `docs/server-accounts.md`).
//!
//! ```text
//! <data>/accounts/passwords.json   [{username, hash, email?, email_verified, name, created,
//!                                    changed, temporary}]
//! ```
//!
//! - **Hashes.** Argon2id (RFC 9106) with 19 MiB of memory, 2 passes and 1 lane ([`PARAMS`]: the
//!   OWASP recommendation, about 30 ms a try on a server core), a 128-bit random salt per password,
//!   kept as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. A hash records its parameters, so
//!   raising them later keeps old passwords working (they are hashed again when next set). The
//!   computed hash is compared in constant time; an unknown username is checked against a dummy
//!   hash so it takes as long as a known one.
//! - **Guessing** is held back by [`Guard`] (in memory, like join codes): [`WRONG_PER_USER`] wrong
//!   passwords in a row for a username, or [`WRONG_PER_ADDRESS`] from an address, lock that
//!   username (or address) out of password sign-ins for [`LOCKOUT`]; an address may try
//!   [`TRIES_PER_MINUTE`] a minute at most, and sign up [`SIGNUPS_PER_HOUR`] times an hour.
//! - **Rules** for a new password ([`check_new`]): 10 to 256 characters, not the username.
//!
//! Passwords are never logged, kept or shown; generated ones (an admin adding someone without
//! one, or resetting theirs) are shown once and marked temporary until their owner changes them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use figcraft_auth::{AuthError, Identity, IdentityProvider, ProviderConfig};
use figcraft_auth::{Flow, ProviderInfo};
use figcraft_collab::same_secret;
use figcraft_collab_net::net::Bucket;
use figcraft_collab_net::token;
use serde::{Deserialize, Serialize};

use crate::disk;
use crate::store::now;

/// The file in `accounts/`.
pub const FILE: &str = "passwords.json";

/// Argon2id's memory (KiB), passes and lanes for new hashes.
pub const PARAMS: (u32, u32, u32) = (19_456, 2, 1);
/// Hash length (bytes).
const HASH_LEN: usize = 32;
/// The most a stored hash may ask for (a damaged or hostile file can't make a sign-in take
/// gigabytes or minutes).
const MAX_M: u32 = 262_144;
const MAX_T: u32 = 10;
const MAX_P: u32 = 8;

/// Password length, in characters.
pub const MIN_LEN: usize = 10;
pub const MAX_LEN: usize = 256;
/// Most usernames one server keeps.
pub const MAX_USERS: usize = 100_000;

/// Wrong passwords in a row (each within [`LOCKOUT`] of the last) that lock a username out.
pub const WRONG_PER_USER: u32 = 5;
/// Wrong passwords in a row from one address (any usernames) that lock it out.
pub const WRONG_PER_ADDRESS: u32 = 20;
/// How long a lockout lasts.
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Password sign-ins one address may try a minute (right or wrong).
pub const TRIES_PER_MINUTE: f64 = 10.0;
/// Accounts one address may make an hour (signing up).
pub const SIGNUPS_PER_HOUR: f64 = 5.0;
/// Usernames and addresses the guard remembers (the half used longest ago go first beyond it).
const MAX_TRACKED: usize = 10_000;

/// Someone with a username (`passwords.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRec {
    /// Lowercase.
    pub username: String,
    /// The Argon2id hash (see the module docs).
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// An admin gave the email (it counts for the allow-lists); one typed when signing up doesn't.
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: String,
    pub created: u64,
    pub changed: u64,
    /// The password was made by the server and not changed since.
    #[serde(default)]
    pub temporary: bool,
}

impl UserRec {
    fn identity(&self, provider: &str) -> Identity {
        Identity {
            provider: provider.to_string(),
            subject: self.username.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified && self.email.is_some(),
            name: Some(if self.name.trim().is_empty() { self.username.clone() } else { self.name.clone() }),
        }
    }
}

/// A username as kept: trimmed, lowercase; 1–64 ASCII letters, digits, `.`, `-`, `_` or `@`,
/// starting with a letter or digit. `None`: it can't be one.
pub fn username(s: &str) -> Option<String> {
    let u = s.trim().to_ascii_lowercase();
    let ok = (1..=64).contains(&u.len())
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@'))
        && u.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    ok.then_some(u)
}

/// Why `password` can't be `username`'s new password, if it can't.
pub fn check_new(username: &str, password: &str) -> Result<(), String> {
    let n = password.chars().count();
    if n < MIN_LEN {
        return Err(format!("a password has at least {MIN_LEN} characters"));
    }
    if n > MAX_LEN {
        return Err(format!("a password has at most {MAX_LEN} characters"));
    }
    if password.trim().eq_ignore_ascii_case(username.trim()) {
        return Err("a password can't be the username".into());
    }
    if password.chars().any(char::is_control) {
        return Err("a password can't hold control characters".into());
    }
    Ok(())
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
}

fn argon(m: u32, t: u32, p: u32) -> Result<Argon2<'static>, String> {
    let params = Params::new(m, t, p, Some(HASH_LEN)).map_err(|e| format!("password hashing: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The Argon2id hash of `password` with a new random salt, with [`PARAMS`].
pub fn hash_password(password: &str) -> Result<String, String> {
    hash_with(password, PARAMS)
}

/// [`hash_password`] with other parameters (tests use cheap ones).
pub fn hash_with(password: &str, (m, t, p): (u32, u32, u32)) -> Result<String, String> {
    // 16 random bytes as base64url: the salt's bytes are its 22 characters.
    let salt = token::secret()?;
    let mut out = [0u8; HASH_LEN];
    argon(m, t, p)?.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out).map_err(|e| format!("password hashing: {e}"))?;
    Ok(format!("$argon2id$v=19$m={m},t={t},p={p}${}${}", b64(salt.as_bytes()), b64(&out)))
}

/// Does `password` match `stored` (a hash [`hash_password`] made)? The hashes are compared in
/// constant time; a damaged hash matches nothing.
pub fn verify(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    let [_, "argon2id", "v=19", params, salt, hash] = parts.as_slice() else { return false };
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in params.split(',') {
        match kv.split_once('=') {
            Some(("m", v)) => m = v.parse::<u32>().ok(),
            Some(("t", v)) => t = v.parse::<u32>().ok(),
            Some(("p", v)) => p = v.parse::<u32>().ok(),
            _ => return false,
        }
    }
    let (Some(m), Some(t), Some(p)) = (m, t, p) else { return false };
    if m > MAX_M || t > MAX_T || p > MAX_P {
        return false;
    }
    let dec = |s: &str| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s).ok();
    let (Some(salt), Some(want)) = (dec(salt), dec(hash)) else { return false };
    if want.len() != HASH_LEN {
        return false;
    }
    let mut got = [0u8; HASH_LEN];
    let Ok(a) = argon(m, t, p) else { return false };
    if a.hash_password_into(password.as_bytes(), &salt, &mut got).is_err() {
        return false;
    }
    same_secret(&b64(&got), &b64(&want))
}

/// A password the server makes: 20 random characters from an alphabet without look-alikes, in
/// groups of five (`k7mqp-…`), about 100 bits.
pub fn generate() -> Result<String, String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut out = String::with_capacity(23);
    let mut bits = 0u64;
    let mut left = 0;
    for i in 0..20 {
        if left == 0 {
            bits = token::random()?;
            left = 12;
        }
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        let n = ALPHABET.len() as u64;
        let c = ALPHABET.get(usize::try_from(bits % n).unwrap_or(0)).copied().unwrap_or(b'a');
        bits /= n;
        left -= 1;
        out.push(char::from(c));
    }
    Ok(out)
}

/// The usernames and passwords of a server (see the module docs).
pub struct Passwords {
    path: PathBuf,
    users: Mutex<Vec<UserRec>>,
    /// Parameters for new hashes.
    params: (u32, u32, u32),
    /// What an unknown username is checked against (so it takes as long).
    dummy: String,
}

impl Passwords {
    /// Read `dir/passwords.json` (missing: nobody yet).
    pub fn open(dir: &Path) -> Result<Passwords, String> {
        Self::open_with(dir, PARAMS)
    }

    /// [`open`](Self::open) with other parameters for new hashes (tests use cheap ones).
    pub fn open_with(dir: &Path, params: (u32, u32, u32)) -> Result<Passwords, String> {
        let path = dir.join(FILE);
        let users: Vec<UserRec> = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{} is damaged: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("can't read {}: {e}", path.display())),
        };
        let dummy = hash_with(&token::secret()?, params)?;
        Ok(Passwords { path, users: Mutex::new(users), params, dummy })
    }

    fn users(&self) -> std::sync::MutexGuard<'_, Vec<UserRec>> {
        self.users.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn save(&self, users: &[UserRec]) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_vec_pretty(users).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.path, &text).map_err(|e| format!("couldn't save the passwords: {e}"))
    }

    /// Everyone with a username.
    pub fn list(&self) -> Vec<UserRec> {
        self.users().clone()
    }

    /// The user called `name`, if any.
    pub fn get(&self, name: &str) -> Option<UserRec> {
        let name = username(name)?;
        self.users().iter().find(|u| u.username == name).cloned()
    }

    /// Is `password` `name`'s? Their record, or `None` (an unknown username takes as long).
    pub fn check(&self, name: &str, password: &str) -> Option<UserRec> {
        let user = username(name).and_then(|n| self.users().iter().find(|u| u.username == n).cloned());
        match user {
            Some(u) if verify(password, &u.hash) => Some(u),
            Some(_) => None,
            None => {
                let _ = verify(password, &self.dummy);
                None
            }
        }
    }

    /// Add `name` with `password` (else one made here, returned: shown once).
    pub fn add(
        &self,
        name: &str,
        email: Option<&str>,
        email_verified: bool,
        full_name: &str,
        password: Option<&str>,
    ) -> Result<Option<String>, String> {
        let name = username(name).ok_or("a username is 1–64 letters, digits, `.`, `-`, `_` or `@`, starting with a letter or digit")?;
        let email = match email.map(str::trim).filter(|e| !e.is_empty()) {
            Some(e) => Some(clean_email(e).ok_or("that isn't an email address")?),
            None => None,
        };
        let full_name: String = full_name.trim().chars().filter(|c| !c.is_control()).take(100).collect();
        let (password, made) = match password {
            Some(p) => {
                check_new(&name, p)?;
                (p.to_string(), None)
            }
            None => {
                let p = generate()?;
                (p.clone(), Some(p))
            }
        };
        // Hashed before taking the lock (it is slow).
        let hash = hash_with(&password, self.params)?;
        let mut users = self.users();
        if users.iter().any(|u| u.username == name) {
            return Err(format!("{name} is taken"));
        }
        if users.len() >= MAX_USERS {
            return Err("this server can't take more usernames".into());
        }
        let t = now();
        users.push(UserRec { username: name, hash, email, email_verified, name: full_name, created: t, changed: t, temporary: made.is_some() });
        self.save(&users)?;
        Ok(made)
    }

    /// Set `name`'s password: `password`, else a new temporary one (returned).
    pub fn set(&self, name: &str, password: Option<&str>) -> Result<Option<String>, String> {
        let name = username(name).ok_or("no such username")?;
        let (password, made) = match password {
            Some(p) => {
                check_new(&name, p)?;
                (p.to_string(), None)
            }
            None => {
                let p = generate()?;
                (p.clone(), Some(p))
            }
        };
        let hash = hash_with(&password, self.params)?;
        let mut users = self.users();
        let u = users.iter_mut().find(|u| u.username == name).ok_or("no such username")?;
        u.hash = hash;
        u.changed = now();
        u.temporary = made.is_some();
        self.save(&users)?;
        Ok(made)
    }

    /// Take `name` away; their record.
    pub fn remove(&self, name: &str) -> Result<UserRec, String> {
        let name = username(name).ok_or("no such username")?;
        let mut users = self.users();
        let i = users.iter().position(|u| u.username == name).ok_or("no such username")?;
        let gone = users.remove(i);
        self.save(&users)?;
        Ok(gone)
    }
}

/// An email as people type it (trimmed, lowercase), or `None`.
fn clean_email(s: &str) -> Option<String> {
    let e = s.trim().to_ascii_lowercase();
    let (user, domain) = e.split_once('@')?;
    let ok = !user.is_empty() && domain.contains('.') && e.len() <= 254 && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then_some(e)
}

/// The `password` provider: the server's own usernames ([`Passwords`]).
pub struct PasswordProvider {
    id: String,
    label: String,
    signup: bool,
    passwords: Arc<Passwords>,
}

impl PasswordProvider {
    /// From `[[auth.provider]]` with `kind = "password"`.
    pub fn new(cfg: &ProviderConfig, passwords: Arc<Passwords>) -> Result<PasswordProvider, String> {
        check_config(cfg)?;
        let label = if cfg.label.trim().is_empty() { "Username and password".to_string() } else { cfg.label.trim().to_string() };
        Ok(PasswordProvider { id: cfg.id.clone(), label, signup: cfg.allow_signup, passwords })
    }
}

/// What `kind = "password"` takes: none of the other kinds' keys.
pub fn check_config(cfg: &ProviderConfig) -> Result<(), String> {
    let other = [&cfg.preset, &cfg.issuer, &cfg.client_id, &cfg.client_secret, &cfg.client_secret_file, &cfg.verify_url];
    if other.iter().any(|v| !v.trim().is_empty()) || !cfg.scopes.is_empty() || !cfg.params.is_empty() || !cfg.flows.is_empty() || cfg.trust_email {
        return Err(format!("provider {:?}: `kind = \"password\"` takes only `id`, `label` and `allow_signup`", cfg.id));
    }
    Ok(())
}

impl IdentityProvider for PasswordProvider {
    fn info(&self) -> ProviderInfo {
        let mut flows = vec![Flow::Password { label: self.label.clone() }];
        if self.signup {
            flows.push(Flow::SignUp);
        }
        ProviderInfo { id: self.id.clone(), label: self.label.clone(), flows }
    }

    fn verify_password(&self, username: &str, password: &str) -> Result<Identity, AuthError> {
        if password.len() > 4 * MAX_LEN || username.len() > 256 {
            return Err(AuthError::Refused(WRONG.into()));
        }
        self.passwords.check(username, password).map(|u| u.identity(&self.id)).ok_or_else(|| AuthError::Refused(WRONG.into()))
    }

    fn sign_up(&self, username: &str, password: &str, email: Option<&str>, name: &str) -> Result<Identity, AuthError> {
        if !self.signup {
            return Err(AuthError::Unsupported);
        }
        self.passwords.add(username, email, false, name, Some(password)).map_err(AuthError::Refused)?;
        self.passwords.get(username).map(|u| u.identity(&self.id)).ok_or_else(|| AuthError::Refused("the account went missing".into()))
    }
}

/// What a wrong username or password says (the same for both).
pub const WRONG: &str = "wrong username or password";
/// What a lockout says.
pub const LOCKED: &str = "too many wrong passwords: password sign-in is paused for a while (try again in 15 minutes)";
/// What too many tries a minute say.
pub const SLOW_DOWN: &str = "too many sign-ins from your address: wait a minute";

/// Wrong passwords in a row and the lockout they led to.
#[derive(Clone, Copy, Debug)]
struct Strikes {
    wrong: u32,
    last: Instant,
    locked: Option<Instant>,
}

impl Strikes {
    fn new(now: Instant) -> Strikes {
        Strikes { wrong: 0, last: now, locked: None }
    }

    fn locked_for(&self, now: Instant) -> Option<Duration> {
        let d = self.locked?.saturating_duration_since(now);
        (!d.is_zero()).then_some(d)
    }

    fn wrong(&mut self, now: Instant, limit: u32) {
        if now.saturating_duration_since(self.last) > LOCKOUT {
            self.wrong = 0;
        }
        self.wrong = self.wrong.saturating_add(1);
        self.last = now;
        if self.wrong >= limit {
            self.locked = Some(now + LOCKOUT);
            self.wrong = 0;
        }
    }
}

/// An address's strikes and buckets.
struct Address {
    strikes: Strikes,
    tries: Bucket,
    signups: Bucket,
}

/// Holds back password guessing (see the module docs): per username and per address.
#[derive(Default)]
pub struct Guard {
    users: HashMap<String, Strikes>,
    addresses: HashMap<IpAddr, Address>,
}

impl Guard {
    fn trim(&mut self) {
        if self.users.len() > MAX_TRACKED {
            let mut by: Vec<(String, Instant)> = self.users.iter().map(|(k, v)| (k.clone(), v.last)).collect();
            by.sort_by_key(|(_, t)| *t);
            for (k, _) in by.into_iter().take(MAX_TRACKED / 2) {
                if self.users.get(&k).is_some_and(|s| s.locked.is_none()) {
                    self.users.remove(&k);
                }
            }
        }
        if self.addresses.len() > MAX_TRACKED {
            let mut by: Vec<(IpAddr, Instant)> = self.addresses.iter().map(|(k, v)| (*k, v.strikes.last)).collect();
            by.sort_by_key(|(_, t)| *t);
            for (k, _) in by.into_iter().take(MAX_TRACKED / 2) {
                if self.addresses.get(&k).is_some_and(|a| a.strikes.locked.is_none()) {
                    self.addresses.remove(&k);
                }
            }
        }
    }

    fn address(&mut self, ip: IpAddr, now: Instant) -> &mut Address {
        self.addresses.entry(ip).or_insert_with(|| Address {
            strikes: Strikes::new(now),
            tries: Bucket::new(TRIES_PER_MINUTE / 60.0, TRIES_PER_MINUTE),
            signups: Bucket::new(SIGNUPS_PER_HOUR / 3600.0, SIGNUPS_PER_HOUR),
        })
    }

    /// May `ip` (`None`: someone signed in already, changing their password) try a password for
    /// `user` now? Takes one of the address's tries.
    pub fn try_password(&mut self, user: &str, ip: Option<IpAddr>, now: Instant) -> Result<(), &'static str> {
        self.trim();
        if self.users.get(user).and_then(|s| s.locked_for(now)).is_some() {
            return Err(LOCKED);
        }
        let Some(ip) = ip else { return Ok(()) };
        let a = self.address(ip, now);
        if a.strikes.locked_for(now).is_some() {
            return Err(LOCKED);
        }
        if !a.tries.take(now) {
            return Err(SLOW_DOWN);
        }
        Ok(())
    }

    /// May `ip` make an account now? Takes one of its sign-ups.
    pub fn try_signup(&mut self, ip: IpAddr, now: Instant) -> Result<(), &'static str> {
        self.trim();
        let a = self.address(ip, now);
        if a.strikes.locked_for(now).is_some() {
            return Err(LOCKED);
        }
        if !a.signups.take(now) {
            return Err("too many new accounts from your address: try again in an hour");
        }
        Ok(())
    }

    /// A wrong password for `user` from `ip`.
    pub fn wrong(&mut self, user: &str, ip: Option<IpAddr>, now: Instant) {
        self.users.entry(user.to_string()).or_insert_with(|| Strikes::new(now)).wrong(now, WRONG_PER_USER);
        if let Some(ip) = ip {
            self.address(ip, now).strikes.wrong(now, WRONG_PER_ADDRESS);
        }
    }

    /// The right password: the strikes against `user` and `ip` are forgiven.
    pub fn right(&mut self, user: &str, ip: Option<IpAddr>) {
        self.users.remove(user);
        if let Some(a) = ip.and_then(|ip| self.addresses.get_mut(&ip)) {
            a.strikes.wrong = 0;
        }
    }

    /// How long `user` is still locked out.
    pub fn user_locked(&self, user: &str, now: Instant) -> Option<Duration> {
        self.users.get(user).and_then(|s| s.locked_for(now))
    }

    /// Lift `user`'s lockout (an admin reset their password).
    pub fn unlock(&mut self, user: &str) {
        self.users.remove(user);
    }
}

#[cfg(test)]
#[path = "passwords_tests.rs"]
mod tests;
