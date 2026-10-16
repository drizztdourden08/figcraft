//! Admins managing people end to end over loopback (the fake provider of `accounts_tests`):
//! listing people and the server's status, ending sessions and removing people (their
//! connections close at once), recovering a file whose owner left, who may do it, and the
//! command line on a running and a stopped server.

use std::net::SocketAddr;
use std::time::Duration;

use figcraft_auth::{AuthMode, SignIn};
use figcraft_collab::message::{AccountReply, AccountReq, Admin, AdminReply, ClientMsg, Manage, OwnerlessFile, PROTOCOL, Role, ServerMsg};
use figcraft_collab_net::{Endpoint, manage};

use crate::accounts_tests::{account, accounts_config, ask, join, signed, snapshot, start, token};
use crate::cli::{self, Cli, Command};
use crate::test_util::{Raw, TempDir, config, key};

/// A managing connection signed in as `sign` (no key).
fn admin_conn(addr: SocketAddr, sign: SignIn) -> Raw {
    let (mut raw, me) = signed(addr, sign);
    assert!(me.unwrap().admin);
    raw.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(raw.next(), ServerMsg::Admin(r) if *r == AdminReply::Ready));
    raw
}

fn admin(raw: &mut Raw, req: Admin) -> AdminReply {
    raw.send(&ClientMsg::Admin(req));
    match raw.next() {
        ServerMsg::Admin(r) => *r,
        other => panic!("{other:?}"),
    }
}

#[test]
fn admins_list_end_sessions_remove_people_and_recover_files() {
    let dir = TempDir::new("adm-people");
    let cfg = accounts_config(dir.path(), "accounts");
    let mut server = start(&cfg);
    let addr = server.addr();
    let ann = token("u1", "ann@example.com", "Ann");
    let bo = token("u2", "bo@example.com", "Bo");
    let (mut a, ann_me) = account(addr, ann.clone());
    let (mut b, bo_me) = account(addr, bo.clone());
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    let id = file.id.clone();
    assert_eq!(ask(&mut a, AccountReq::Invite { file: id.clone(), email: "bo@example.com".into(), role: Role::Editor }), AccountReply::Done);
    let mut boss = admin_conn(addr, token("b", "boss@example.com", "Boss"));

    // Everyone who signed in, with what they own; the server's status.
    let AdminReply::People(people) = admin(&mut boss, Admin::People) else { panic!() };
    assert_eq!(people.len(), 3);
    let p_ann = people.iter().find(|p| p.account == ann_me.account).unwrap();
    assert_eq!((p_ann.owned, p_ann.admin, p_ann.provider.as_str(), p_ann.email.as_deref()), (1, false, "fake", Some("ann@example.com")));
    assert!(p_ann.sessions >= 1);
    assert!(people.iter().any(|p| p.admin && p.name == "Boss"));
    let AdminReply::ServerStatus(status) = admin(&mut boss, Admin::ServerStatus) else { panic!() };
    assert_eq!((status.people, status.files, status.info.auth), (3, 1, AuthMode::Accounts));
    assert_eq!(status.info.providers[0].id, "fake");
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    assert!(status.sessions >= 3);
    let AdminReply::FileMembers { members, invited } = admin(&mut boss, Admin::FileMembers { file: id.clone() }) else { panic!() };
    assert_eq!((members.len(), invited.len()), (2, 0));

    // Ending Bo's sessions: his session token no longer signs in, and what he had open closes.
    let (mut bo_in, access) = join(addr, Some(SignIn::Session { token: bo_me.session.clone() }), &id, "");
    assert!(access.is_ok());
    assert_eq!(admin(&mut boss, Admin::EndSessions { account: bo_me.account.clone() }), AdminReply::Done);
    assert!(bo_in.closed_within(Duration::from_secs(5)));
    assert!(b.closed_within(Duration::from_secs(5)));
    assert!(signed(addr, SignIn::Session { token: bo_me.session.clone() }).1.is_err());
    assert!(matches!(admin(&mut boss, Admin::EndSessions { account: "nobody".into() }), AdminReply::Failed { .. }));

    // Removing Ann: refused while she is the file's last owner; with force, done (she is
    // disconnected, out of the file, forgotten) and the file is left with no owner.
    let (mut ann_in, _) = join(addr, Some(ann.clone()), &id, "");
    let blocked = admin(&mut boss, Admin::RemovePerson { account: ann_me.account.clone(), force: false });
    assert_eq!(blocked, AdminReply::LastOwner { files: vec![OwnerlessFile { id: id.clone(), name: "Plan".into() }] });
    let removed = admin(&mut boss, Admin::RemovePerson { account: ann_me.account.clone(), force: true });
    assert_eq!(removed, AdminReply::PersonRemoved { orphaned: vec![OwnerlessFile { id: id.clone(), name: "Plan".into() }] });
    assert!(ann_in.closed_within(Duration::from_secs(5)));
    assert!(a.closed_within(Duration::from_secs(5)));
    assert!(signed(addr, SignIn::Session { token: ann_me.session.clone() }).1.is_err());
    let AdminReply::People(people) = admin(&mut boss, Admin::People) else { panic!() };
    assert!(people.iter().all(|p| p.account != ann_me.account));
    let AdminReply::FileMembers { members, .. } = admin(&mut boss, Admin::FileMembers { file: id.clone() }) else { panic!() };
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].account, bo_me.account);
    assert!(matches!(admin(&mut boss, Admin::RemovePerson { account: ann_me.account.clone(), force: true }), AdminReply::Failed { .. }));

    // Recovering the file: Bo becomes its owner; an email is let in (invited until they sign in).
    assert_eq!(admin(&mut boss, Admin::SetFileRole { file: id.clone(), account: bo_me.account.clone(), role: Role::Owner }), AdminReply::Done);
    assert_eq!(admin(&mut boss, Admin::AddFileMember { file: id.clone(), email: "Cy@Example.com".into(), role: Role::Viewer }), AdminReply::Done);
    assert!(matches!(
        admin(&mut boss, Admin::SetFileRole { file: id.clone(), account: "nobody".into(), role: Role::Editor }),
        AdminReply::Failed { .. }
    ));
    assert!(matches!(
        admin(&mut boss, Admin::AddFileMember { file: id.clone(), email: "not an email".into(), role: Role::Editor }),
        AdminReply::Failed { .. }
    ));
    let AdminReply::FileMembers { members, invited } = admin(&mut boss, Admin::FileMembers { file: id.clone() }) else { panic!() };
    assert_eq!(members[0].role, Role::Owner);
    assert_eq!(invited.len(), 1);
    assert_eq!(invited[0].email, "cy@example.com");
    // A file keeps its last owner.
    assert!(matches!(
        admin(&mut boss, Admin::SetFileRole { file: id.clone(), account: bo_me.account.clone(), role: Role::Viewer }),
        AdminReply::Failed { .. }
    ));
    let (mut b, _) = account(addr, bo.clone());
    assert!(matches!(ask(&mut b, AccountReq::Files), AccountReply::Files(f) if f.len() == 1 && f[0].role == Role::Owner));
    // Ann may sign in again (the allow-lists let her): a new account, in no file.
    let (mut a2, ann2) = account(addr, ann);
    assert_ne!(ann2.account, ann_me.account);
    assert!(matches!(ask(&mut a2, AccountReq::Files), AccountReply::Files(f) if f.is_empty()));
    server.stop();
}

#[test]
fn only_admins_and_the_key_manage_people() {
    let dir = TempDir::new("adm-who");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let (_a, ann) = account(addr, token("u1", "ann@example.com", "Ann"));
    // Someone who isn't an admin can't open a managing connection without the key.
    let (mut raw, _) = signed(addr, token("u1", "ann@example.com", "Ann"));
    raw.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(raw.next(), ServerMsg::Refused { .. }));
    // The client helper: as an admin with a session token, or with the key.
    let limits = accounts_config(dir.path(), "accounts").net();
    let endpoint = Endpoint::plain(addr.to_string());
    assert!(manage::request_as_admin(&endpoint, &ann.session, vec![Admin::People], &limits, Duration::from_secs(5)).is_err());
    let (_, boss) = signed(addr, token("b", "boss@example.com", "Boss"));
    let replies = manage::request_as_admin(&endpoint, &boss.unwrap().session, vec![Admin::People], &limits, Duration::from_secs(5)).unwrap();
    assert!(matches!(&replies[..], [AdminReply::People(p)] if p.len() == 2));
    let replies = manage::request(&endpoint, &key(dir.path()), vec![Admin::People, Admin::ServerStatus], &limits, Duration::from_secs(5)).unwrap();
    assert!(matches!(&replies[..], [AdminReply::People(p), AdminReply::ServerStatus(_)] if p.len() == 2));
    // An open hosting connection (no key) can't ask about people.
    let (_, replies) = manage::hosting(&endpoint, "", "", vec![Admin::People], &limits, Duration::from_secs(5)).unwrap();
    assert!(matches!(&replies[..], [AdminReply::Failed { .. }]));
    server.stop();

    // A server without accounts: nobody to manage, but its status answers.
    let dir = TempDir::new("adm-links");
    let mut server = start(&config(dir.path()));
    let endpoint = Endpoint::plain(server.addr().to_string());
    let replies = manage::request(&endpoint, &key(dir.path()), vec![Admin::People, Admin::ServerStatus], &limits, Duration::from_secs(5)).unwrap();
    assert!(matches!(&replies[0], AdminReply::Failed { reason } if reason.contains("no accounts")));
    assert!(matches!(&replies[1], AdminReply::ServerStatus(s) if s.info.auth == AuthMode::Links && s.people == 0));
    server.stop();
}

#[test]
fn the_command_line_manages_people_running_or_stopped() {
    let dir = TempDir::new("adm-cli");
    let cfg = accounts_config(dir.path(), "accounts");
    let mut server = start(&cfg);
    let addr = server.addr();
    let (mut a, ann) = account(addr, token("u1", "ann@example.com", "Ann"));
    let (_b, bo) = account(addr, token("u2", "bo@example.com", "Bo"));
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    let run = |command: Command| cli::run(&Cli { config: cfg.clone(), command });
    // Through the running server (with the key).
    let people = run(Command::People).unwrap();
    assert!(people.contains(&ann.account) && people.contains("bo@example.com"), "{people}");
    let status = run(Command::Status).unwrap();
    assert!(status.contains("accounts") && status.contains("People:    2"), "{status}");
    let err = run(Command::RemovePerson { account: ann.account.clone(), force: false }).unwrap_err();
    assert!(err.contains("last owner") && err.contains(&file.id), "{err}");
    run(Command::AddMember { file: file.id.clone(), email: "bo@example.com".into(), role: Role::Editor }).unwrap();
    run(Command::SetRole { file: file.id.clone(), account: bo.account.clone(), role: Role::Owner }).unwrap();
    let out = run(Command::RemovePerson { account: ann.account.clone(), force: false }).unwrap();
    assert!(out.contains("Removed"), "{out}");
    assert!(a.closed_within(Duration::from_secs(5)));
    server.stop();
    drop(server);
    // On the stopped directory.
    let members = run(Command::Members { file: file.id.clone() }).unwrap();
    assert!(members.contains(&bo.account) && members.contains("owner"), "{members}");
    run(Command::EndSessions { account: bo.account.clone() }).unwrap();
    let people = run(Command::People).unwrap();
    assert!(people.contains(&bo.account) && !people.contains(&ann.account), "{people}");
    let status = run(Command::Status).unwrap();
    assert!(status.contains("People:    1 (0 sessions)"), "{status}");
    // Bo's session ended while the server was stopped.
    let mut server = start(&cfg);
    assert!(signed(server.addr(), SignIn::Session { token: bo.session }).1.is_err());
    server.stop();
}
