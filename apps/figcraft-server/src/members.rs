//! Who is in a file on a server with accounts (`docs/accounts-and-e2e.md`): members with a role
//! (owner, editor, viewer) and emails invited before their person signed in here, kept in the
//! file's `meta.json`; and the requests of account connections (your files, publishing, members,
//! invites, and, on a server that also takes links, the links of the files you own).

use figcraft_auth::Person;
use figcraft_collab::Change;
use figcraft_collab::message::{AccountReply, AccountReq, Invited, Member, MyFile, Role};
use figcraft_collab_net::hub::{AccountHandled, Admission, OpenFile};
use serde::{Deserialize, Serialize};

use super::Store;

/// Most members (and invites) one file keeps.
pub const MAX_MEMBERS: usize = 500;
/// Most files one person owns.
pub const MAX_OWNED_FILES: usize = 1_000;

/// A member of a file (`meta.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRec {
    pub account: String,
    pub role: Role,
}

/// A file's people.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct People {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<MemberRec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invited: Vec<Invited>,
}

impl People {
    pub fn role(&self, account: &str) -> Option<Role> {
        self.members.iter().find(|m| m.account == account).map(|m| m.role)
    }

    fn owners(&self) -> usize {
        self.members.iter().filter(|m| m.role == Role::Owner).count()
    }
}

/// An email as people type it: trimmed and lowercased; `None` when it isn't one.
fn email(s: &str) -> Option<String> {
    let e = s.trim().to_ascii_lowercase();
    let (user, domain) = e.split_once('@')?;
    let ok = !user.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && e.len() <= 254
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then_some(e)
}

const NOT_IN: &str = "you aren't in this file: ask its owner to invite you";
const OWNERS_ONLY: &str = "only the file's owners can do that";

impl Store {
    /// `who`'s role in `file`; an invite to their verified email becomes membership now.
    pub fn role_of(&mut self, file: &str, who: &Person) -> Result<Option<Role>, String> {
        let entry = self.entry(file)?;
        if let Some(r) = entry.meta.people.role(&who.account) {
            return Ok(Some(r));
        }
        let Some(mail) = who.email.as_deref() else { return Ok(None) };
        let Some(i) = entry.meta.people.invited.iter().position(|v| v.email == mail) else { return Ok(None) };
        let role = entry.meta.people.invited.remove(i).role;
        entry.meta.people.members.push(MemberRec { account: who.account.clone(), role });
        self.save_meta(file)?;
        log::info!("event=invite_taken file={file} account={}", who.account);
        Ok(Some(role))
    }

    /// The access a signed-in hello gets (accounts mode; links are checked by the caller).
    pub fn admit_member(&mut self, file: &str, who: Option<&Person>) -> Result<Admission, String> {
        let Some(who) = who else { return Err("sign in to join files on this server".into()) };
        match self.role_of(file, who)? {
            Some(role) => Ok(Admission { access: role.access(), link: None }),
            // Admins can open everything (they hold the data directory anyway).
            None if who.admin => Ok(Admission { access: figcraft_collab::message::Access::Edit, link: None }),
            None => Err(NOT_IN.into()),
        }
    }

    /// Keep a document as a new file `who` owns.
    pub fn publish_as(&mut self, who: &Person, name: &str, snapshot: &[Change]) -> Result<figcraft_collab::message::FileInfo, String> {
        let owned = self.files_where(|p| p.role(&who.account) == Some(Role::Owner)).len();
        if owned >= MAX_OWNED_FILES {
            return Err(format!("you own {owned} files here, the most one person may: remove one first"));
        }
        let (info, edit, view) = self.publish(name, snapshot)?;
        let entry = self.entry(&info.id)?;
        entry.meta.people.members.push(MemberRec { account: who.account.clone(), role: Role::Owner });
        self.save_meta(&info.id)?;
        // Without links, the two a publish makes are of no use: they go.
        if !self.accounts.mode().links() {
            for l in [edit.link.id, view.link.id] {
                self.revoke(&info.id, &l)?;
            }
        }
        log::info!("event=published file={} by=account account={}", info.id, who.account);
        Ok(info)
    }

    /// The ids of the files whose people match.
    fn files_where(&self, f: impl Fn(&People) -> bool) -> Vec<String> {
        self.file_ids().into_iter().filter(|id| self.people(id).is_some_and(&f)).collect()
    }

    fn owner(&mut self, file: &str, who: &Person) -> Result<(), String> {
        match self.role_of(file, who)? {
            Some(Role::Owner) => Ok(()),
            _ if who.admin => Ok(()),
            Some(_) => Err(OWNERS_ONLY.into()),
            None => Err(NOT_IN.into()),
        }
    }

    fn members(&mut self, file: &str, who: &Person) -> Result<AccountReply, String> {
        if self.role_of(file, who)?.is_none() && !who.admin {
            return Err(NOT_IN.into());
        }
        let people = self.people(file).cloned().unwrap_or_default();
        let members = people
            .members
            .iter()
            .map(|m| {
                let a = self.accounts.account(&m.account);
                Member {
                    account: m.account.clone(),
                    name: a.as_ref().map(|a| a.name.clone()).unwrap_or_default(),
                    email: a.and_then(|a| a.email),
                    role: m.role,
                }
            })
            .collect();
        Ok(AccountReply::Members { members, invited: people.invited })
    }

    fn invite(&mut self, file: &str, who: &Person, mail: &str, role: Role) -> Result<(), String> {
        self.owner(file, who)?;
        let mail = email(mail).ok_or("that isn't an email address")?;
        let known = self.accounts.by_email(&mail);
        let entry = self.entry(file)?;
        let p = &mut entry.meta.people;
        if p.members.len() + p.invited.len() >= MAX_MEMBERS {
            return Err(format!("a file has at most {MAX_MEMBERS} people"));
        }
        let owners = p.owners();
        match known {
            Some(a) => match p.members.iter_mut().find(|m| m.account == a.id) {
                Some(m) if m.role == Role::Owner && role != Role::Owner && owners == 1 => {
                    return Err("a file keeps at least one owner".into());
                }
                Some(m) => m.role = role,
                None => p.members.push(MemberRec { account: a.id, role }),
            },
            None => match p.invited.iter_mut().find(|v| v.email == mail) {
                Some(v) => v.role = role,
                None => p.invited.push(Invited { email: mail, role }),
            },
        }
        self.save_meta(file)
    }

    fn set_role(&mut self, file: &str, who: &Person, account: &str, role: Role) -> Result<(), String> {
        self.owner(file, who)?;
        let entry = self.entry(file)?;
        let p = &mut entry.meta.people;
        let owners = p.owners();
        let m = p.members.iter_mut().find(|m| m.account == account).ok_or("they aren't in this file")?;
        if m.role == Role::Owner && role != Role::Owner && owners == 1 {
            return Err("a file keeps at least one owner".into());
        }
        m.role = role;
        self.save_meta(file)
    }

    /// Take `account` out of `file` (an owner doing it, or them leaving).
    fn take_out(&mut self, file: &str, who: &Person, account: &str) -> Result<(), String> {
        if account != who.account {
            self.owner(file, who)?;
        }
        let entry = self.entry(file)?;
        let p = &mut entry.meta.people;
        let Some(i) = p.members.iter().position(|m| m.account == account) else { return Err("they aren't in this file".into()) };
        if p.members.get(i).is_some_and(|m| m.role == Role::Owner) && p.owners() == 1 {
            return Err("a file keeps at least one owner: make someone else owner first, or remove the file".into());
        }
        p.members.remove(i);
        self.save_meta(file)
    }

    fn uninvite(&mut self, file: &str, who: &Person, mail: &str) -> Result<(), String> {
        self.owner(file, who)?;
        let mail = mail.trim().to_ascii_lowercase();
        let entry = self.entry(file)?;
        let before = entry.meta.people.invited.len();
        entry.meta.people.invited.retain(|v| v.email != mail);
        if entry.meta.people.invited.len() == before {
            return Err("that email isn't invited".into());
        }
        self.save_meta(file)
    }

    /// A request on `who`'s account connection.
    pub fn account_request(&mut self, who: &Person, req: AccountReq, open: &dyn Fn(&str) -> Option<OpenFile>) -> AccountHandled {
        let failed = |reason: String| AccountHandled::from(AccountReply::Failed { reason });
        let done = |r: Result<(), String>| r.map_or_else(failed, |()| AccountReply::Done.into());
        match req {
            AccountReq::Files => {
                // Invites to their email become membership first.
                for id in self.file_ids() {
                    let _ = self.role_of(&id, who);
                }
                let mine: Vec<MyFile> = self
                    .file_ids()
                    .into_iter()
                    .filter_map(|id| {
                        let role = self.people(&id)?.role(&who.account)?;
                        Some(MyFile { info: self.file_info(&id, open)?, role })
                    })
                    .collect();
                AccountReply::Files(mine).into()
            }
            AccountReq::Publish { name, snapshot } => match self.publish_as(who, &name, &snapshot) {
                Ok(file) => AccountReply::Published { file }.into(),
                Err(e) => failed(e),
            },
            AccountReq::Members { file } => self.members(&file, who).map_or_else(failed, Into::into),
            AccountReq::Invite { file, email, role } => done(self.invite(&file, who, &email, role)),
            AccountReq::SetRole { file, account, role } => done(self.set_role(&file, who, &account, role)),
            AccountReq::RemoveMember { file, account } => match self.take_out(&file, who, &account) {
                Ok(()) => AccountHandled { reply: AccountReply::Done, revoked: None, removed: None, left: vec![(file, account)] },
                Err(e) => failed(e),
            },
            AccountReq::Leave { file } => match self.take_out(&file, who, &who.account) {
                Ok(()) => AccountHandled { reply: AccountReply::Done, revoked: None, removed: None, left: vec![(file, who.account.clone())] },
                Err(e) => failed(e),
            },
            AccountReq::Uninvite { file, email } => done(self.uninvite(&file, who, &email)),
            AccountReq::Rename { file, name } => done(self.owner(&file, who).and_then(|()| self.rename(&file, &name))),
            AccountReq::RemoveFile { file } => match self.owner(&file, who).and_then(|()| self.remove(&file)) {
                Ok(()) => AccountHandled { reply: AccountReply::Done, revoked: None, removed: Some(file), left: Vec::new() },
                Err(e) => failed(e),
            },
            AccountReq::Links { file } | AccountReq::CreateLink { file, .. } | AccountReq::Revoke { file, .. } | AccountReq::Code { file, .. }
                if !self.accounts.mode().links() =>
            {
                let _ = file;
                failed("this server doesn't use share links: invite people instead".into())
            }
            AccountReq::Links { file } => match self.owner(&file, who).and_then(|()| self.links(&file)) {
                Ok(l) => AccountReply::Links(l).into(),
                Err(e) => failed(e),
            },
            AccountReq::CreateLink { file, access, label } => match self.owner(&file, who).and_then(|()| self.create_link(&file, access, &label)) {
                Ok(l) => AccountReply::Link(l).into(),
                Err(e) => failed(e),
            },
            AccountReq::Revoke { file, link } => match self.owner(&file, who).and_then(|()| self.revoke(&file, &link)) {
                Ok(()) => AccountHandled { reply: AccountReply::Done, revoked: Some((file, link)), removed: None, left: Vec::new() },
                Err(e) => failed(e),
            },
            AccountReq::Code { file, token } => match self.owner(&file, who).and_then(|()| self.set_code(&file, &token)) {
                Ok(code) => AccountReply::Code { code }.into(),
                Err(e) => failed(e),
            },
        }
    }

    /// May `who` manage the server without its key? Admins may, on a server with accounts.
    pub fn admin_may_manage(&self, who: Option<&Person>) -> bool {
        who.is_some_and(|w| w.admin) && self.accounts.mode().accounts()
    }
}
