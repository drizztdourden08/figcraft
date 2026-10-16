//! Who may sign in once a provider vouched for them, and who is an admin.

use crate::provider::Identity;

/// The `[auth]` allow-lists and admins. Emails count only when the provider verified them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// Lowercase emails that are admins.
    pub admins: Vec<String>,
    /// Lowercase emails allowed to sign in.
    pub allow_emails: Vec<String>,
    /// Lowercase domains (`example.com`) whose addresses may sign in.
    pub allow_domains: Vec<String>,
}

/// What the policy says about someone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub admin: bool,
}

impl Policy {
    /// From the settings' lists (trimmed, lowercased, empties dropped; a leading `@` on a domain is
    /// ignored).
    pub fn new(admins: &[String], allow_emails: &[String], allow_domains: &[String]) -> Policy {
        let clean = |v: &[String], strip_at: bool| -> Vec<String> {
            v.iter()
                .map(|s| {
                    let s = s.trim().to_ascii_lowercase();
                    if strip_at { s.trim_start_matches('@').to_string() } else { s }
                })
                .filter(|s| !s.is_empty())
                .collect()
        };
        Policy { admins: clean(admins, false), allow_emails: clean(allow_emails, false), allow_domains: clean(allow_domains, true) }
    }

    /// This policy with the emails admins allowed from the app (`allowed`, lowercase) added to
    /// the allow-list, and `admins` (lowercase emails) to the admins: what the server goes by.
    /// With both of the settings' allow-lists empty, a non-empty `allowed` turns the server from
    /// letting in anyone a provider vouches for to letting in only those emails (and admins).
    pub fn with_allowed(&self, allowed: &[String], admins: &[String]) -> Policy {
        let mut p = self.clone();
        for e in allowed {
            if !p.allow_emails.contains(e) {
                p.allow_emails.push(e.clone());
            }
        }
        for e in admins {
            if !p.admins.contains(e) {
                p.admins.push(e.clone());
            }
        }
        p
    }

    /// Nobody is restricted (both allow-lists empty): anyone a provider vouches for may sign in.
    pub fn open(&self) -> bool {
        self.allow_emails.is_empty() && self.allow_domains.is_empty()
    }

    /// May `who` sign in, and are they an admin? Admins may always sign in.
    pub fn admit(&self, who: &Identity) -> Result<Admitted, String> {
        let email = who.email.as_deref().filter(|_| who.email_verified).map(|e| e.trim().to_ascii_lowercase());
        let admin = email.as_ref().is_some_and(|e| self.admins.contains(e));
        if admin || self.open() {
            return Ok(Admitted { admin });
        }
        let Some(email) = email else {
            return Err("this server lets in only some email addresses, and your sign-in didn't give a verified one".into());
        };
        let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        if self.allow_emails.contains(&email) || self.allow_domains.iter().any(|d| d == domain) {
            Ok(Admitted { admin })
        } else {
            Err(format!("{email} isn't allowed on this server: ask one of its admins to add you"))
        }
    }
}
