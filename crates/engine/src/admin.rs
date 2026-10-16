//! Running a server with accounts as one of its admins (milestone M9; `docs/server-accounts.md`):
//! the people who signed in there, the files and who is in them, the server's status; ending
//! someone's sessions, taking someone off the server, and giving a file members (how an admin
//! recovers a file whose owner left). An admin is someone signed in whose email is in the
//! server's `admins` ([`SignedIn::admin`](crate::accounts::SignedIn)); each request signs in with
//! their session, never with the server's key.
//!
//! The app shows them in the server's section of the home screen. Every `admin.*` command takes
//! `server?` (default: the first server).

use figcraft_collab::message::{Admin, AdminReply, FileInfo, OwnerlessFile, PersonInfo, Secret, UserInfo};
use serde_json::{Value, json};

use crate::accounts::{info_json, invited_json, member_json, role, session_ended};
use crate::cmd::CommandSpec;
use crate::live::{NetReply, NetRequest};
use crate::params::{boolean, req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

impl Session {
    /// The server command `cmd` means, where you are signed in as an admin.
    fn admin_server(&self, cmd: &str, p: &Value) -> Result<String> {
        let server = self.account_server(cmd, p)?;
        match self.signed_in(&server) {
            None => Err(bad(cmd, format!("you aren't signed in to {}: sign in first (on the home screen)", crate::servers::host(&server)))),
            Some(me) if !me.admin => Err(bad(cmd, format!("you aren't an admin of {}", crate::servers::host(&server)))),
            Some(_) => Ok(server),
        }
    }

    /// One request as an admin of the server command `cmd` means; a [`AdminReply::Failed`] is an
    /// error.
    fn admin_request(&mut self, cmd: &str, p: &Value, req: Admin) -> Result<(String, AdminReply)> {
        let server = self.admin_server(cmd, p)?;
        let session = self.signed_in(&server).map(|me| me.session.clone()).unwrap_or_default();
        match self.net(NetRequest::Admin { server: server.clone(), session, req })?.0 {
            NetReply::Admin(Ok(AdminReply::Failed { reason })) => Err(EngineError::Other(reason)),
            NetReply::Admin(Ok(reply)) => Ok((server, reply)),
            NetReply::Admin(Err(why)) => {
                if session_ended(&why) {
                    self.signed_out(&server, &why);
                }
                Err(EngineError::Other(why))
            }
            _ => Err(EngineError::Other("the link answered something else".into())),
        }
    }
}

fn other() -> EngineError {
    EngineError::Other("the server answered something else".into())
}

fn person_json(p: &PersonInfo) -> Value {
    json!({
        "account": p.account, "provider": p.provider, "email": p.email, "name": p.name, "created": p.created, "seen": p.seen,
        "sessions": p.sessions, "admin": p.admin, "owned": p.owned,
    })
}

fn file_json(f: &FileInfo) -> Value {
    json!({"file": f.id, "name": f.name, "created": f.created, "updated": f.updated, "bytes": f.bytes, "people": f.people})
}

fn ownerless_json(list: &[OwnerlessFile]) -> Vec<Value> {
    list.iter().map(|f| json!({"file": f.id, "name": f.name})).collect()
}

fn people(s: &mut Session, p: &Value) -> Result<Value> {
    match s.admin_request("admin.people", p, Admin::People)? {
        (server, AdminReply::People(list)) => Ok(json!({"server": server, "people": list.iter().map(person_json).collect::<Vec<_>>()})),
        _ => Err(other()),
    }
}

fn files(s: &mut Session, p: &Value) -> Result<Value> {
    match s.admin_request("admin.files", p, Admin::Files)? {
        (server, AdminReply::Files(list)) => Ok(json!({"server": server, "files": list.iter().map(file_json).collect::<Vec<_>>()})),
        _ => Err(other()),
    }
}

fn file_members(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.fileMembers";
    let file = req_string(CMD, p, "file")?;
    match s.admin_request(CMD, p, Admin::FileMembers { file: file.clone() })? {
        (server, AdminReply::FileMembers { members, invited }) => Ok(json!({
            "server": server,
            "file": file,
            "members": members.iter().map(member_json).collect::<Vec<_>>(),
            "invited": invited.iter().map(invited_json).collect::<Vec<_>>(),
        })),
        _ => Err(other()),
    }
}

fn set_file_role(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.setFileRole";
    let (file, account, role) = (req_string(CMD, p, "file")?, req_string(CMD, p, "account")?, role(CMD, p)?);
    s.admin_request(CMD, p, Admin::SetFileRole { file: file.clone(), account: account.clone(), role })?;
    Ok(json!({"file": file, "account": account, "role": role.id()}))
}

fn add_file_member(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.addFileMember";
    let (file, email, role) = (req_string(CMD, p, "file")?, req_string(CMD, p, "email")?, role(CMD, p)?);
    s.admin_request(CMD, p, Admin::AddFileMember { file: file.clone(), email: email.clone(), role })?;
    Ok(json!({"file": file, "email": email, "role": role.id()}))
}

fn remove_person(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.removePerson";
    let account = req_string(CMD, p, "account")?;
    let force = boolean(p, "force").unwrap_or(false);
    match s.admin_request(CMD, p, Admin::RemovePerson { account: account.clone(), force })? {
        (_, AdminReply::PersonRemoved { orphaned }) => Ok(json!({"account": account, "removed": true, "orphaned": ownerless_json(&orphaned)})),
        (_, AdminReply::LastOwner { files }) => Ok(json!({"account": account, "removed": false, "lastOwner": ownerless_json(&files)})),
        _ => Err(other()),
    }
}

fn end_sessions(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.endSessions";
    let account = req_string(CMD, p, "account")?;
    s.admin_request(CMD, p, Admin::EndSessions { account: account.clone() })?;
    Ok(json!({"account": account, "ended": true}))
}

fn status(s: &mut Session, p: &Value) -> Result<Value> {
    match s.admin_request("admin.status", p, Admin::ServerStatus)? {
        (server, AdminReply::ServerStatus(st)) => {
            let mut v = info_json(&st.info);
            if let Some(o) = v.as_object_mut() {
                o.extend([
                    ("server".into(), json!(server)),
                    ("version".into(), json!(st.version)),
                    ("people".into(), json!(st.people)),
                    ("sessions".into(), json!(st.sessions)),
                    ("files".into(), json!(st.files)),
                    ("freeBytes".into(), json!(st.free_bytes)),
                ]);
            }
            Ok(v)
        }
        _ => Err(other()),
    }
}

fn user_json(u: &UserInfo) -> Value {
    json!({
        "username": u.username, "account": u.account, "email": u.email, "name": u.name, "created": u.created, "changed": u.changed,
        "temporary": u.temporary, "locked": u.locked,
    })
}

/// The answer to adding someone or resetting their password: the password the server made, shown
/// this once (null: the one given was kept).
fn user_made(reply: AdminReply) -> Result<Value> {
    match reply {
        AdminReply::User { username, password } => Ok(json!({"username": username, "password": password.map(|p| p.0)})),
        _ => Err(other()),
    }
}

fn users(s: &mut Session, p: &Value) -> Result<Value> {
    match s.admin_request("admin.users", p, Admin::Users)? {
        (server, AdminReply::Users(list)) => Ok(json!({"server": server, "users": list.iter().map(user_json).collect::<Vec<_>>()})),
        _ => Err(other()),
    }
}

fn create_user(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.createUser";
    let username = req_string(CMD, p, "username")?;
    let req = Admin::CreateUser {
        username: username.trim().to_string(),
        email: string(p, "email").filter(|e| !e.trim().is_empty()),
        name: string(p, "name").unwrap_or_default(),
        password: string(p, "password").filter(|p| !p.is_empty()).map(Secret),
    };
    user_made(s.admin_request(CMD, p, req)?.1)
}

fn reset_password(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.resetPassword";
    let username = req_string(CMD, p, "username")?;
    user_made(s.admin_request(CMD, p, Admin::ResetPassword { username })?.1)
}

fn remove_user(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "admin.removeUser";
    let username = req_string(CMD, p, "username")?;
    s.admin_request(CMD, p, Admin::RemoveUser { username: username.clone() })?;
    Ok(json!({"username": username, "removed": true}))
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "admin.users",
            "Server usernames",
            "{server?} → {server, users: [{username, account, email, name, created, changed, temporary, locked}]}: who signs in with a username and password there (admins)",
            false,
            users
        ),
        spec!(
            "admin.createUser",
            "Add server user",
            "{username, email?, name?, password? (default: the server makes one), server?} → {username, password (the one the server made, shown this once; null: yours was kept)}: lets someone sign in with a username and password (admins)",
            false,
            create_user
        ),
        spec!(
            "admin.resetPassword",
            "Reset password",
            "{username, server?} → {username, password (a new temporary one, shown this once)}: their sessions end (admins)",
            false,
            reset_password
        ),
        spec!(
            "admin.removeUser",
            "Remove server user",
            "{username, server?} → {username, removed}: they can't sign in with it any more; their account and files stay (admins)",
            false,
            remove_user
        ),
        spec!(
            "admin.people",
            "Server people",
            "{server?} → {server, people: [{account, provider, email, name, created, seen, sessions, admin, owned}]}: everyone who signed in there (admins)",
            false,
            people
        ),
        spec!(
            "admin.files",
            "Server files",
            "{server?} → {server, files: [{file, name, created, updated, bytes, people}]}: the files kept there (admins)",
            false,
            files
        ),
        spec!(
            "admin.fileMembers",
            "File members (admin)",
            "{file, server?} → {server, file, members: [{account, name, email, role}], invited: [{email, role}]}: who is in a file (admins)",
            false,
            file_members
        ),
        spec!(
            "admin.setFileRole",
            "Set file role (admin)",
            "{file, account, role (owner | editor | viewer), server?} → {file, account, role}: gives someone who signed in there a role in a file, adding them (admins: how a file whose owner left gets one)",
            false,
            set_file_role
        ),
        spec!(
            "admin.addFileMember",
            "Add file member (admin)",
            "{file, email, role? (default editor), server?} → {file, email, role}: lets an email into a file as an owner's invite does (admins)",
            false,
            add_file_member
        ),
        spec!(
            "admin.removePerson",
            "Remove person from server",
            "{account, force? (default false), server?} → {account, removed: true, orphaned: [{file, name}]} | {account, removed: false, lastOwner: [{file, name}]}: ends their sessions, takes them out of every file and forgets their account (admins). While they are the last owner of files nothing is done (lastOwner) unless `force`: those files are left without an owner (orphaned) until an admin gives them one (`admin.setFileRole`)",
            false,
            remove_person
        ),
        spec!(
            "admin.endSessions",
            "End sessions",
            "{account, server?} → {account, ended}: signs someone out everywhere (they must sign in again; their account and files stay) (admins)",
            false,
            end_sessions
        ),
        spec!(
            "admin.status",
            "Server status",
            "{server?} → {server, version, auth, accounts, links, providers, e2e, people, sessions, files, freeBytes}: what the server is and holds (admins)",
            false,
            status
        ),
    ]
}
