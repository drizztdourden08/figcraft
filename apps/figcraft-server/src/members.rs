//! Who is in a file on a server with accounts (`docs/accounts-and-e2e.md`): members with a role
//! (owner, editor, viewer) and emails invited before their person signed in here, kept in the
//! file's `meta.json`; and the requests of account connections (your files, publishing, members,
//! invites, and, on a server that also takes links, the links of the files you own).

use std::collections::HashMap;

use figcraft_auth::{Gate, Person};
use figcraft_collab::Change;
use figcraft_collab::message::{AccountReply, AccountReq, Admin, AdminReply, Invited, Member, MyFile, OwnerlessFile, PersonInfo, Role, ServerStatus};
use figcraft_collab_net::hub::{AccountHandled, Admission, Handled, OpenFile};
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
const NOBODY: &str = "nobody with that account is on this server";
const NO_ACCOUNTS: &str = "this server has no accounts (people sign in only when its settings have [auth])";

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
        self.publish_new_as(who, super::NewFile::Plain { name, snapshot })
    }

    /// Keep a document, plain or sealed, as a new file `who` owns.
    pub fn publish_new_as(&mut self, who: &Person, new: super::NewFile<'_>) -> Result<figcraft_collab::message::FileInfo, String> {
        let owned = self.files_where(|p| p.role(&who.account) == Some(Role::Owner)).len();
        if owned >= MAX_OWNED_FILES {
            return Err(format!("you own {owned} files here, the most one person may: remove one first"));
        }
        let (info, edit, view) = self.publish_new(new)?;
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
        let (members, invited) = self.member_list(file)?;
        Ok(AccountReply::Members { members, invited })
    }

    /// A file's members (with their names and emails) and invites.
    fn member_list(&mut self, file: &str) -> Result<(Vec<Member>, Vec<Invited>), String> {
        let people = self.entry(file)?.meta.people.clone();
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
        Ok((members, people.invited))
    }

    fn invite(&mut self, file: &str, who: &Person, mail: &str, role: Role) -> Result<(), String> {
        self.owner(file, who)?;
        self.add_by_email(file, mail, role)
    }

    /// Let an email in with a role: whoever signed in here with it becomes a member now, anyone
    /// else is invited.
    fn add_by_email(&mut self, file: &str, mail: &str, role: Role) -> Result<(), String> {
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
        self.change_role(file, account, role, false)
    }

    /// Give a member `role` (a file keeps its last owner); `add`: someone who signed in here but
    /// isn't in the file becomes a member (admins recovering a file).
    fn change_role(&mut self, file: &str, account: &str, role: Role, add: bool) -> Result<(), String> {
        let known = add && self.accounts.account(account).is_some();
        let entry = self.entry(file)?;
        let p = &mut entry.meta.people;
        let owners = p.owners();
        match p.members.iter_mut().find(|m| m.account == account) {
            Some(m) => {
                if m.role == Role::Owner && role != Role::Owner && owners == 1 {
                    return Err("a file keeps at least one owner".into());
                }
                m.role = role;
            }
            None if known => {
                if p.members.len() + p.invited.len() >= MAX_MEMBERS {
                    return Err(format!("a file has at most {MAX_MEMBERS} people"));
                }
                p.members.push(MemberRec { account: account.to_string(), role });
            }
            None if add => return Err("nobody with that account has signed in here".into()),
            None => return Err("they aren't in this file".into()),
        }
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
            AccountReq::PublishSealed { file, name, snapshot } => {
                match self.publish_new_as(who, super::NewFile::Sealed { file: &file, name: &name, snapshot: &snapshot }) {
                    Ok(file) => AccountReply::Published { file }.into(),
                    Err(e) => failed(e),
                }
            }
            AccountReq::RenameSealed { file, name } => done(self.owner(&file, who).and_then(|()| self.rename_sealed(&file, &name))),
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

    /// Everyone who has signed in, as admins see them.
    pub fn people_info(&self) -> Vec<PersonInfo> {
        let mut owned: HashMap<&str, u32> = HashMap::new();
        for e in self.files.values() {
            for m in e.meta.people.members.iter().filter(|m| m.role == Role::Owner) {
                *owned.entry(m.account.as_str()).or_default() += 1;
            }
        }
        self.accounts
            .people_with_sessions()
            .into_iter()
            .map(|(a, sessions)| PersonInfo {
                admin: self.accounts.is_admin(&a),
                owned: owned.get(a.id.as_str()).copied().unwrap_or(0),
                sessions: u32::try_from(sessions).unwrap_or(u32::MAX),
                account: a.id,
                provider: a.provider,
                email: a.email,
                name: a.name,
                created: a.created,
                seen: a.seen,
            })
            .collect()
    }

    /// The files `account` is the only owner of.
    fn sole_owner_of(&self, account: &str) -> Vec<OwnerlessFile> {
        self.files
            .iter()
            .filter(|(_, e)| e.meta.people.role(account) == Some(Role::Owner) && e.meta.people.owners() == 1)
            .map(|(id, e)| OwnerlessFile { id: id.clone(), name: e.meta.shown_name() })
            .collect()
    }

    /// Take someone off the server ([`Admin::RemovePerson`]): out of every file (and their
    /// pending invites), then their account and sessions.
    fn remove_person(&mut self, account: &str, force: bool) -> Handled {
        let failed = |reason: String| Handled::from(AdminReply::Failed { reason });
        let known = self.accounts.account(account);
        let files = self.files_where(|p| p.role(account).is_some());
        if known.is_none() && files.is_empty() {
            return failed(NOBODY.into());
        }
        let blocking = self.sole_owner_of(account);
        if !blocking.is_empty() && !force {
            return AdminReply::LastOwner { files: blocking }.into();
        }
        let mail = known.as_ref().and_then(|a| a.email.clone());
        for id in self.file_ids() {
            let Ok(entry) = self.entry(&id) else { continue };
            let p = &mut entry.meta.people;
            let before = (p.members.len(), p.invited.len());
            p.members.retain(|m| m.account != account);
            if let Some(mail) = &mail {
                p.invited.retain(|v| v.email != *mail);
            }
            if (p.members.len(), p.invited.len()) != before
                && let Err(e) = self.save_meta(&id)
            {
                // Nothing is half done for the person: they are still on the server, and asking
                // again finishes the files left.
                return failed(e);
            }
        }
        if let Err(e) = self.accounts.remove_person(account) {
            return failed(e);
        }
        for f in &blocking {
            log::warn!("event=file_ownerless file={} account={account}", f.id);
        }
        Handled { ended: vec![account.to_string()], ..AdminReply::PersonRemoved { orphaned: blocking }.into() }
    }

    /// The people and file members requests of [`Admin`] (with the server key or as an admin).
    pub fn admin_people(&mut self, req: Admin) -> Handled {
        let failed = |reason: String| Handled::from(AdminReply::Failed { reason });
        let done = |r: Result<(), String>| r.map_or_else(failed, |()| AdminReply::Done.into());
        if !self.accounts.mode().accounts() && !matches!(req, Admin::ServerStatus) {
            return failed(NO_ACCOUNTS.into());
        }
        match req {
            Admin::People => AdminReply::People(self.people_info()).into(),
            Admin::RemovePerson { account, force } => self.remove_person(&account, force),
            Admin::EndSessions { account } => {
                if self.accounts.account(&account).is_none() {
                    return failed(NOBODY.into());
                }
                match self.accounts.end_sessions(&account) {
                    Ok(n) => {
                        log::info!("event=sessions_ended account={account} sessions={n}");
                        Handled { ended: vec![account], ..AdminReply::Done.into() }
                    }
                    Err(e) => failed(e),
                }
            }
            Admin::FileMembers { file } => {
                self.member_list(&file).map_or_else(failed, |(members, invited)| AdminReply::FileMembers { members, invited }.into())
            }
            Admin::SetFileRole { file, account, role } => done(self.change_role(&file, &account, role, true)),
            Admin::AddFileMember { file, email, role } => done(self.add_by_email(&file, &email, role)),
            Admin::ServerStatus => {
                let (people, sessions) = self.accounts.counts();
                let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
                AdminReply::ServerStatus(ServerStatus {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    info: self.accounts.info(),
                    people: count(people),
                    sessions: count(sessions),
                    files: count(self.len()),
                    free_bytes: crate::disk::free_bytes(&self.root),
                })
                .into()
            }
            _ => failed("that isn't a request about people".into()),
        }
    }
}
