//! Team access on a server with accounts (`docs/server-accounts.md` › *Adding people* and
//! *Names and pictures*): the emails and admins admins add from the app, kept in
//! `accounts/allowed.json` beside the settings' `allow_emails`, `allow_domains` and `admins`; and
//! people's pictures, fetched from the address their identity provider gives (OpenID Connect's
//! `picture`) at most once a day, kept small in `avatars/<account>.png|jpg` and served to anyone
//! signed in on the server.
//!
//! Who may sign in, all lists together: admins always; else, when neither the settings'
//! allow-lists nor the admins' list has anything, anyone a provider vouches for; else only the
//! emails and domains listed (in the settings or by admins). People with a username and password
//! here were added by an admin: the admins' list doesn't narrow them (the settings' lists still
//! apply, as before).

use std::path::PathBuf;

use figcraft_auth::{Identity, Policy};
use figcraft_collab::message::{AllowList, AllowedEmail, TeamMember};
use serde::{Deserialize, Serialize};

use super::{Account, Accounts};
use crate::disk;
use crate::store::now;

/// What admins added (`accounts/allowed.json`).
pub const ALLOWED: &str = "allowed.json";
/// People's pictures, at the data directory's root.
pub const AVATARS: &str = "avatars";

/// Largest picture kept.
pub const MAX_AVATAR: usize = 256 << 10;
/// A picture is fetched again at most this often (seconds).
pub const AVATAR_EVERY: u64 = 86_400;
/// Most emails admins add.
pub const MAX_ALLOWED: usize = 10_000;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG: &[u8] = b"\xff\xd8\xff";

/// An email admins let in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedRec {
    pub email: String,
    #[serde(default)]
    pub admin: bool,
}

/// `allowed.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Allowed {
    pub emails: Vec<AllowedRec>,
    /// Accounts made admins from the app.
    pub admins: Vec<String>,
}

impl Allowed {
    pub fn is_admin(&self, a: &Account) -> bool {
        self.admins.contains(&a.id) || a.email.as_ref().is_some_and(|e| self.emails.iter().any(|r| r.admin && r.email == *e))
    }
}

/// An email as kept: trimmed and lowercase; `None` when it isn't one.
pub fn clean_email(s: &str) -> Option<String> {
    let e = s.trim().to_ascii_lowercase();
    let (user, domain) = e.split_once('@')?;
    let ok = !user.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && e.len() <= 254
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then_some(e)
}

/// The kind of picture `bytes` is (PNG or JPEG only).
pub fn image_kind(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    if bytes.starts_with(PNG) {
        Some(("png", "image/png"))
    } else if bytes.starts_with(JPEG) {
        Some(("jpg", "image/jpeg"))
    } else {
        None
    }
}

/// A picture address the server fetches: `https://`, or `http://` on this machine (development).
fn fetchable(url: &str) -> bool {
    let url = url.trim();
    if url.len() > 2048 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

impl Accounts {
    pub(super) fn allowed(&self) -> std::sync::MutexGuard<'_, Allowed> {
        self.allowed.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save_allowed(&self, a: &Allowed) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_vec_pretty(a).map_err(|e| e.to_string())?;
        disk::write_atomic(&self.dir.join(ALLOWED), &text).map_err(|e| format!("couldn't save who may sign in: {e}"))
    }

    /// The settings' policy with what admins added: what sign-ins go by.
    pub fn policy(&self) -> Policy {
        let a = self.allowed();
        let emails: Vec<String> = a.emails.iter().map(|r| r.email.clone()).collect();
        let admins: Vec<String> = a.emails.iter().filter(|r| r.admin).map(|r| r.email.clone()).collect();
        self.policy.with_allowed(&emails, &admins)
    }

    /// May `who` (`account`, when they signed in before) sign in? See the module docs.
    pub(super) fn admit(&self, who: &Identity, account: Option<&str>) -> Result<(), String> {
        let basic = self.passwords.as_ref().is_some_and(|(pid, _)| *pid == who.provider);
        let policy = if basic { self.policy.clone() } else { self.policy() };
        match policy.admit(who) {
            Ok(_) => Ok(()),
            Err(_) if account.is_some_and(|a| self.allowed().admins.iter().any(|x| x == a)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Let `email` sign in (and be an admin, or not).
    pub fn allow_email(&self, email: &str, admin: bool) -> Result<(), String> {
        let email = clean_email(email).ok_or("that isn't an email address")?;
        let mut a = self.allowed();
        let full = a.emails.len() >= MAX_ALLOWED;
        match a.emails.iter_mut().find(|r| r.email == email) {
            Some(r) => r.admin = admin,
            None if full => return Err(format!("at most {MAX_ALLOWED} emails are kept here")),
            None => a.emails.push(AllowedRec { email: email.clone(), admin }),
        }
        a.emails.sort_by(|x, y| x.email.cmp(&y.email));
        self.save_allowed(&a)?;
        log::info!("event=email_allowed admin={admin}");
        Ok(())
    }

    /// Take `email` off the admins' list: the account that signed in with it, if any (its
    /// sessions end when it may no longer sign in).
    pub fn disallow_email(&self, email: &str) -> Result<Option<String>, String> {
        let email = email.trim().to_ascii_lowercase();
        if self.policy.allow_emails.contains(&email) || self.policy.admins.contains(&email) {
            return Err("that email is in the server's settings (`allow_emails` or `admins` in server.toml): change it there".into());
        }
        {
            let mut a = self.allowed();
            let before = a.emails.len();
            a.emails.retain(|r| r.email != email);
            if a.emails.len() == before {
                return Err("that email isn't on the list".into());
            }
            self.save_allowed(&a)?;
        }
        log::info!("event=email_disallowed");
        let Some(person) = self.by_email(&email) else { return Ok(None) };
        let who = Identity {
            provider: person.provider.clone(),
            subject: person.subject.clone(),
            email: person.email.clone(),
            email_verified: true,
            name: None,
            picture: None,
        };
        if self.admit(&who, Some(&person.id)).is_err() {
            self.end_sessions(&person.id)?;
            return Ok(Some(person.id));
        }
        Ok(None)
    }

    /// Who may sign in, all lists together.
    pub fn allow_list(&self) -> AllowList {
        let policy = self.policy();
        let a = self.allowed().clone();
        let mut emails: Vec<AllowedEmail> = Vec::new();
        let mut add = |email: &str, admin: bool, settings: bool| match emails.iter_mut().find(|e| e.email == email) {
            Some(e) => {
                e.admin |= admin;
                e.settings |= settings;
            }
            None => emails.push(AllowedEmail { email: email.to_string(), admin, settings, account: None }),
        };
        for e in &self.policy.allow_emails {
            add(e, false, true);
        }
        for e in &self.policy.admins {
            add(e, true, true);
        }
        for r in &a.emails {
            add(&r.email, r.admin, false);
        }
        for e in &mut emails {
            e.account = self.by_email(&e.email).map(|p| p.id);
        }
        emails.sort_by(|x, y| x.email.cmp(&y.email));
        AllowList { open: policy.open(), emails, domains: self.policy.allow_domains.clone(), admin_accounts: a.admins }
    }

    /// Make `account` an admin, or not (an admin by the settings stays one).
    pub fn set_admin(&self, account: &str, admin: bool) -> Result<(), String> {
        let person = self.account(account).ok_or("nobody with that account is on this server")?;
        if !admin && person.email.as_ref().is_some_and(|e| self.policy.admins.contains(e)) {
            return Err("they are an admin in the server's settings (`admins` in server.toml): change it there".into());
        }
        let mut a = self.allowed();
        if admin {
            if !a.admins.iter().any(|x| x == account) {
                a.admins.push(account.to_string());
            }
        } else {
            a.admins.retain(|x| x != account);
            if let Some(mail) = &person.email {
                for r in a.emails.iter_mut().filter(|r| r.email == *mail) {
                    r.admin = false;
                }
            }
        }
        self.save_allowed(&a)?;
        log::info!("event=admin_set account={account} admin={admin}");
        Ok(())
    }

    /// `account` left the server: they are no admin any more.
    pub(super) fn forget_admin(&self, account: &str) -> Result<(), String> {
        let mut a = self.allowed();
        if a.admins.iter().any(|x| x == account) {
            a.admins.retain(|x| x != account);
            self.save_allowed(&a)?;
        }
        Ok(())
    }

    fn avatar_path(&self, account: &str, ext: &str) -> PathBuf {
        self.avatars.join(format!("{account}.{ext}"))
    }

    /// Fetch `account`'s picture from `picture` when it changed or a day went by (a failure keeps
    /// the copy there is, and is tried again a day later).
    pub fn refresh_avatar(&self, account: &str, picture: Option<&str>) {
        let Some(a) = self.account(account) else { return };
        let t = now();
        let picture = picture.map(str::trim).filter(|p| !p.is_empty());
        if picture.is_none() {
            if a.picture.is_some() {
                self.forget_avatar(account);
                self.note_avatar(account, None, 0);
            }
            return;
        }
        if a.picture.as_deref() == picture && t.saturating_sub(a.avatar_at) < AVATAR_EVERY {
            return;
        }
        let url = picture.unwrap_or_default();
        match self.fetch_avatar(url) {
            Ok((bytes, ext)) => {
                let write = std::fs::create_dir_all(&self.avatars)
                    .map_err(|e| e.to_string())
                    .and_then(|()| disk::write_atomic(&self.avatar_path(account, ext), &bytes).map_err(|e| e.to_string()));
                match write {
                    Ok(()) => {
                        // One picture a person: the other kind goes.
                        let other = if ext == "png" { "jpg" } else { "png" };
                        let _ = std::fs::remove_file(self.avatar_path(account, other));
                        log::info!("event=avatar_kept account={account} bytes={}", bytes.len());
                    }
                    Err(e) => log::warn!("couldn't keep the picture of {account}: {e}"),
                }
            }
            Err(e) => log::info!("event=avatar_not_fetched account={account} reason={e:?}"),
        }
        self.note_avatar(account, Some(url.to_string()), t);
    }

    fn fetch_avatar(&self, url: &str) -> Result<(Vec<u8>, &'static str), String> {
        if !fetchable(url) {
            return Err("only https:// pictures are fetched".into());
        }
        let fetch = self.fetch.as_ref().ok_or("no network here")?;
        let bytes = fetch.get_image(url, MAX_AVATAR).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_AVATAR {
            return Err(format!("larger than {MAX_AVATAR} bytes"));
        }
        let (ext, _) = image_kind(&bytes).ok_or("not a PNG or JPEG")?;
        Ok((bytes, ext))
    }

    fn note_avatar(&self, account: &str, picture: Option<String>, at: u64) {
        let mut s = self.state();
        let Some(a) = s.people.iter_mut().find(|a| a.id == account) else { return };
        a.picture = picture;
        a.avatar_at = at;
        if let Err(e) = self.save_people(&s) {
            log::warn!("{e}");
        }
    }

    /// Remove `account`'s picture.
    pub(super) fn forget_avatar(&self, account: &str) {
        for ext in ["png", "jpg"] {
            let _ = std::fs::remove_file(self.avatar_path(account, ext));
        }
    }

    /// `account`'s picture and its type, when the server keeps one.
    pub fn avatar(&self, account: &str) -> Option<(Vec<u8>, &'static str)> {
        // Only someone on the server (an account id is never a path).
        self.account(account)?;
        for ext in ["png", "jpg"] {
            let Ok(bytes) = disk::read_capped(&self.avatar_path(account, ext), MAX_AVATAR as u64) else { continue };
            if let Some((_, mime)) = image_kind(&bytes) {
                return Some((bytes, mime));
            }
        }
        None
    }

    fn has_avatar(&self, account: &str) -> bool {
        ["png", "jpg"].iter().any(|ext| self.avatar_path(account, ext).is_file())
    }

    /// Everyone who signed in here (`admin`: the one asking is an admin, who is told emails).
    pub fn team(&self, admin: bool) -> Vec<TeamMember> {
        let people = self.people();
        let mut out: Vec<TeamMember> = people
            .iter()
            .map(|a| TeamMember {
                account: a.id.clone(),
                name: a.name.clone(),
                admin: self.is_admin(a),
                avatar: self.has_avatar(&a.id),
                email: if admin { a.email.clone() } else { None },
            })
            .collect();
        out.sort_by_key(|x| x.name.to_lowercase());
        out
    }

    /// Everyone's devices (servers where everyone is in every file).
    pub fn all_devices(&self) -> Vec<super::devices::DeviceRec> {
        self.state().devices.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_this_machine_is_fetched() {
        assert!(fetchable("https://lh3.example.com/a.png"));
        assert!(fetchable("http://127.0.0.1:8080/a.png"));
        assert!(fetchable("http://localhost/a.png"));
        assert!(!fetchable("http://169.254.169.254/latest"));
        assert!(!fetchable("http://127.0.0.1.evil.test/a.png"));
        assert!(!fetchable("file:///etc/passwd"));
        assert!(!fetchable("https://x.test/a b.png"));
    }

    #[test]
    fn pictures_are_png_or_jpeg() {
        assert_eq!(image_kind(b"\x89PNG\r\n\x1a\nrest").map(|k| k.0), Some("png"));
        assert_eq!(image_kind(b"\xff\xd8\xff\xe0rest").map(|k| k.0), Some("jpg"));
        assert_eq!(image_kind(b"GIF89a"), None);
        assert_eq!(image_kind(b"<svg"), None);
    }
}
