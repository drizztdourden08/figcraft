//! Accounts end to end over loopback: a fake identity provider (registered as a kind of its own,
//! as a server build can), signing in, sessions that survive a restart, publishing as a person,
//! members and invites, roles in sessions, people taken out being disconnected, and links next to
//! accounts.

use std::net::SocketAddr;
use std::time::Duration;

use figcraft_auth::registry::Registry;
use figcraft_auth::{AuthConfig, AuthError, AuthMode, Flow, Identity, IdentityProvider, Me, ProviderConfig, ProviderInfo, SignIn, SignInReply};
use figcraft_collab::Replica;
use figcraft_collab::message::{self, AccountReply, AccountReq, Admin, AdminReply, ClientMsg, Hello, Manage, OpenAccount, PROTOCOL, Role, ServerMsg};
use figcraft_doc::Document;

use crate::Running;
use crate::config::Config;
use crate::test_util::{Raw, TempDir, config, key};

/// Tokens are `subject|email|name`; `bad` is refused.
struct Fake;

impl IdentityProvider for Fake {
    fn info(&self) -> ProviderInfo {
        ProviderInfo { id: "fake".into(), label: "Fake".into(), flows: vec![Flow::Token { label: "Fake token".into() }] }
    }

    fn verify_token(&self, token: &str) -> Result<Identity, AuthError> {
        let mut p = token.split('|');
        let (Some(sub), Some(email), Some(name)) = (p.next(), p.next(), p.next()) else { return Err(AuthError::Refused("bad token".into())) };
        Ok(Identity { provider: "fake".into(), subject: sub.into(), email: Some(email.into()), email_verified: true, name: Some(name.into()) })
    }
}

fn registry() -> Registry {
    let mut r = Registry::builtin();
    r.register("fake", |_, _| Ok(Box::new(Fake)));
    r
}

fn accounts_config(dir: &std::path::Path, mode: &str) -> Config {
    Config {
        auth: AuthConfig {
            mode: mode.into(),
            admins: vec!["boss@example.com".into()],
            provider: vec![ProviderConfig { id: "fake".into(), kind: "fake".into(), ..ProviderConfig::default() }],
            ..AuthConfig::default()
        },
        ..config(dir)
    }
}

fn start(cfg: &Config) -> Running {
    crate::start_with(cfg, &registry()).unwrap()
}

fn snapshot(name: &str) -> Vec<figcraft_collab::Change> {
    Replica::new(Document::new(name)).snapshot().unwrap()
}

/// A connection signed in with `token`: who it is.
fn signed(addr: SocketAddr, sign: SignIn) -> (Raw, Result<Me, String>) {
    let mut raw = Raw::connect(addr);
    raw.send(&ClientMsg::SignIn(sign));
    let me = match raw.next() {
        ServerMsg::SignIn(r) => match *r {
            SignInReply::SignedIn(me) => Ok(me),
            SignInReply::Refused { reason } => Err(reason),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    (raw, me)
}

fn token(sub: &str, email: &str, name: &str) -> SignIn {
    SignIn::Token { provider: "fake".into(), token: format!("{sub}|{email}|{name}") }
}

/// An account connection for `sign`.
fn account(addr: SocketAddr, sign: SignIn) -> (Raw, Me) {
    let (mut raw, me) = signed(addr, sign);
    let me = me.unwrap();
    raw.send(&ClientMsg::OpenAccount(OpenAccount { protocol: PROTOCOL, client_version: message::client_version() }));
    assert!(matches!(raw.next(), ServerMsg::Account(r) if matches!(*r, AccountReply::Ready { ref account } if *account == me.account)));
    (raw, me)
}

fn ask(raw: &mut Raw, req: AccountReq) -> AccountReply {
    raw.send(&ClientMsg::Account(req));
    match raw.next() {
        ServerMsg::Account(r) => *r,
        other => panic!("{other:?}"),
    }
}

fn hello(file: &str, token: &str) -> ClientMsg {
    ClientMsg::Hello(Hello {
        protocol: PROTOCOL,
        file: file.into(),
        token: token.into(),
        name: "x".into(),
        color: String::new(),
        client_version: message::client_version(),
        resume: None,
    })
}

/// Join `file` signed in as `sign` (or nobody): the access, or the refusal.
fn join(addr: SocketAddr, sign: Option<SignIn>, file: &str, link_token: &str) -> (Raw, Result<message::Access, String>) {
    let mut raw = match sign {
        Some(s) => signed(addr, s).0,
        None => Raw::connect(addr),
    };
    raw.send(&hello(file, link_token));
    let r = match raw.next() {
        ServerMsg::Welcome { access, .. } => Ok(access),
        ServerMsg::Refused { reason } => Err(reason),
        other => panic!("{other:?}"),
    };
    (raw, r)
}

#[test]
fn info_lists_the_providers_and_sign_in_works() {
    let dir = TempDir::new("acc-info");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let mut raw = Raw::connect(addr);
    raw.send(&ClientMsg::Info);
    let ServerMsg::Info(info) = raw.next() else { panic!() };
    assert_eq!(info.auth, AuthMode::Accounts);
    assert_eq!(info.providers.len(), 1);
    assert_eq!(info.providers[0].flows, vec![Flow::Token { label: "Fake token".into() }]);
    // A sign-in: a new session token; signing in with it again gives the same account.
    let (_, me) = signed(addr, token("u1", "Ann@Example.com", "Ann"));
    let me = me.unwrap();
    assert!(me.session.len() >= 40);
    assert_eq!((me.name.as_str(), me.email.as_deref(), me.admin), ("Ann", Some("ann@example.com"), false));
    let (_, again) = signed(addr, SignIn::Session { token: me.session.clone() });
    let again = again.unwrap();
    assert_eq!(again.account, me.account);
    assert!(again.session.is_empty(), "no new token when signing in with one");
    // Refusals: a bad token, an unknown provider, a wrong session, other flows.
    assert!(signed(addr, SignIn::Token { provider: "fake".into(), token: "nonsense".into() }).1.unwrap_err().contains("bad token"));
    assert!(signed(addr, SignIn::Token { provider: "nope".into(), token: "a|b@c.d|e".into() }).1.unwrap_err().contains("no sign-in called"));
    assert!(signed(addr, SignIn::Session { token: "forged".into() }).1.is_err());
    assert!(
        signed(addr, SignIn::Code { provider: "fake".into(), code: "c".into(), verifier: "v".into(), redirect_uri: "http://127.0.0.1:1/".into() })
            .1
            .is_err()
    );
    // The admin is an admin.
    let (_, boss) = signed(addr, token("b", "boss@example.com", "Boss"));
    assert!(boss.unwrap().admin);
    // Sessions survive a restart; signing out ends one.
    server.stop();
    drop(server);
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    assert_eq!(signed(addr, SignIn::Session { token: me.session.clone() }).1.unwrap().account, me.account);
    let mut out = Raw::connect(addr);
    out.send(&ClientMsg::SignIn(SignIn::SignOut { token: me.session.clone() }));
    assert!(matches!(out.next(), ServerMsg::SignIn(r) if *r == SignInReply::SignedOut));
    assert!(signed(addr, SignIn::Session { token: me.session }).1.is_err());
    server.stop();
}

#[test]
fn people_publish_invite_and_join_by_role() {
    let dir = TempDir::new("acc-roles");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let ann = token("u1", "ann@example.com", "Ann");
    let bo = token("u2", "bo@example.com", "Bo");
    let cy = token("u3", "cy@example.com", "Cy");
    let (mut a, _) = account(addr, ann.clone());
    // Bo signs in once (known); Cy never has (invited by email).
    let (mut b, bo_me) = account(addr, bo.clone());
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    let id = file.id.clone();
    // Ann owns it; nobody else is in.
    assert!(matches!(ask(&mut a, AccountReq::Files), AccountReply::Files(f) if f.len() == 1 && f[0].role == Role::Owner && f[0].info.id == id));
    assert!(matches!(ask(&mut b, AccountReq::Files), AccountReply::Files(f) if f.is_empty()));
    assert!(join(addr, Some(bo.clone()), &id, "").1.unwrap_err().contains("aren't in this file"));
    assert!(join(addr, None, &id, "").1.unwrap_err().contains("sign in"));
    // Accounts only: the links a publish makes were dropped.
    assert!(matches!(ask(&mut a, AccountReq::Links { file: id.clone() }), AccountReply::Failed { .. }));
    // Bo can't invite (not an owner); Ann invites Bo (editor) and Cy (viewer, not signed in yet).
    assert!(matches!(ask(&mut b, AccountReq::Invite { file: id.clone(), email: "x@y.z".into(), role: Role::Editor }), AccountReply::Failed { .. }));
    assert_eq!(ask(&mut a, AccountReq::Invite { file: id.clone(), email: "Bo@Example.com".into(), role: Role::Editor }), AccountReply::Done);
    assert_eq!(ask(&mut a, AccountReq::Invite { file: id.clone(), email: "cy@example.com".into(), role: Role::Viewer }), AccountReply::Done);
    assert!(matches!(
        ask(&mut a, AccountReq::Invite { file: id.clone(), email: "not an email".into(), role: Role::Viewer }),
        AccountReply::Failed { .. }
    ));
    let AccountReply::Members { members, invited } = ask(&mut a, AccountReq::Members { file: id.clone() }) else { panic!() };
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m.account == bo_me.account && m.role == Role::Editor && m.name == "Bo"));
    assert_eq!(invited, vec![message::Invited { email: "cy@example.com".into(), role: Role::Viewer }]);
    // In sessions: Bo edits, Cy (on first sign-in) views.
    let (_bo_in, access) = join(addr, Some(bo.clone()), &id, "");
    assert_eq!(access, Ok(message::Access::Edit));
    let (_cy_in, access) = join(addr, Some(cy.clone()), &id, "");
    assert_eq!(access, Ok(message::Access::View));
    let AccountReply::Members { members, invited } = ask(&mut a, AccountReq::Members { file: id.clone() }) else { panic!() };
    assert_eq!((members.len(), invited.len()), (3, 0), "Cy's invite became membership");
    // A file keeps an owner.
    let ann_id = members.iter().find(|m| m.role == Role::Owner).unwrap().account.clone();
    assert!(matches!(ask(&mut a, AccountReq::Leave { file: id.clone() }), AccountReply::Failed { .. }));
    assert!(matches!(ask(&mut a, AccountReq::SetRole { file: id.clone(), account: ann_id, role: Role::Editor }), AccountReply::Failed { .. }));
    // Taking Bo out disconnects him from the file at once.
    let (mut bo_in, _) = join(addr, Some(bo.clone()), &id, "");
    assert_eq!(ask(&mut a, AccountReq::RemoveMember { file: id.clone(), account: bo_me.account.clone() }), AccountReply::Done);
    assert!(bo_in.closed_within(Duration::from_secs(5)));
    assert!(join(addr, Some(bo), &id, "").1.is_err());
    // Removing the file: gone for everyone.
    assert_eq!(ask(&mut a, AccountReq::RemoveFile { file: id.clone() }), AccountReply::Done);
    assert!(matches!(ask(&mut a, AccountReq::Files), AccountReply::Files(f) if f.is_empty()));
    server.stop();
}

#[test]
fn accounts_and_links_together_and_admins_manage() {
    let dir = TempDir::new("acc-links");
    let mut server = start(&accounts_config(dir.path(), "accounts+links"));
    let addr = server.addr();
    let (mut a, _) = account(addr, token("u1", "ann@example.com", "Ann"));
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Open".into(), snapshot: snapshot("Open") }) else { panic!() };
    // Owners make links; a view link lets anyone in without signing in.
    let AccountReply::Link(view) = ask(&mut a, AccountReq::CreateLink { file: file.id.clone(), access: message::Access::View, label: "v".into() })
    else {
        panic!()
    };
    assert_eq!(join(addr, None, &file.id, &view.token).1, Ok(message::Access::View));
    assert!(join(addr, None, &file.id, "wrong").1.is_err());
    // Revoking disconnects whoever came in with it.
    let (mut viewer, _) = join(addr, None, &file.id, &view.token);
    assert_eq!(ask(&mut a, AccountReq::Revoke { file: file.id.clone(), link: view.link.id.clone() }), AccountReply::Done);
    assert!(viewer.closed_within(Duration::from_secs(5)));
    // An admin manages the server without the key; others need it.
    let (mut boss, _) = signed(addr, token("b", "boss@example.com", "Boss"));
    boss.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(boss.next(), ServerMsg::Admin(r) if *r == AdminReply::Ready));
    boss.send(&ClientMsg::Admin(Admin::Files));
    assert!(matches!(boss.next(), ServerMsg::Admin(r) if matches!(*r, AdminReply::Files(ref f) if f.len() == 1)));
    let (mut ann, _) = signed(addr, token("u1", "ann@example.com", "Ann"));
    ann.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(ann.next(), ServerMsg::Refused { .. }));
    // The key still works for the operator.
    let mut op = Raw::connect(addr);
    op.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: key(dir.path()), client_version: "t".into() }));
    assert!(matches!(op.next(), ServerMsg::Admin(r) if *r == AdminReply::Ready));
    server.stop();
}

#[test]
fn links_only_servers_are_unchanged_and_settings_are_checked() {
    let dir = TempDir::new("acc-off");
    let mut server = start(&config(dir.path()));
    let addr = server.addr();
    // No accounts: sign-in and account connections are refused.
    assert!(signed(addr, token("u", "a@b.c", "A")).1.is_err());
    let mut raw = Raw::connect(addr);
    raw.send(&ClientMsg::OpenAccount(OpenAccount { protocol: PROTOCOL, client_version: "t".into() }));
    assert!(matches!(raw.next(), ServerMsg::Refused { .. }));
    server.stop();
    // Settings: accounts need a provider; open publishing and accounts don't mix; sealing isn't
    // available yet; unknown kinds are refused when the server starts.
    let mut c = accounts_config(dir.path(), "accounts");
    c.auth.provider.clear();
    assert!(c.check().unwrap_err().contains("provider"));
    let mut c = accounts_config(dir.path(), "accounts");
    c.open_publish = true;
    assert!(c.check().unwrap_err().contains("open_publish"));
    let mut c = config(dir.path());
    c.e2e.mode = "required".into();
    assert!(c.check().is_err());
    let mut c = accounts_config(dir.path(), "accounts");
    c.auth.provider[0].kind = "carrier-pigeon".into();
    assert!(crate::start(&c).err().unwrap().contains("unknown kind"));
    // The TOML form.
    let parsed: Config = toml::from_str(
        r#"
        listen = "127.0.0.1:0"
        [auth]
        mode = "accounts"
        allow_domains = ["example.com"]
        [[auth.provider]]
        id = "google"
        kind = "oidc"
        preset = "google"
        client_id = "abc.apps.googleusercontent.com"
        [e2e]
        mode = "off"
        "#,
    )
    .unwrap();
    assert_eq!(parsed.auth.mode().unwrap(), AuthMode::Accounts);
    assert_eq!(parsed.auth.provider[0].preset, "google");
}

#[test]
fn allow_lists_keep_strangers_out() {
    let dir = TempDir::new("acc-allow");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.auth.allow_domains = vec!["example.com".into()];
    let mut server = start(&cfg);
    let addr = server.addr();
    assert!(signed(addr, token("u1", "ann@example.com", "Ann")).1.is_ok());
    assert!(signed(addr, token("u9", "eve@evil.test", "Eve")).1.unwrap_err().contains("isn't allowed"));
    server.stop();
}
