//! Basic accounts end to end (usernames and passwords the server keeps): admins add people and
//! reset passwords, people sign in, get it wrong, are locked out, change their password and (where
//! allowed) sign up; passwords never cross the network in the clear; the old `Info` hides the new
//! flows from older apps while `About` names the server; the command line; an engine session
//! signing in with a password.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use figcraft_auth::registry::Registry;
use figcraft_auth::{AuthConfig, AuthMode, Flow, Gate, Origin, ProviderConfig, SignIn, SignInReply};
use figcraft_collab::message::{AccountReply, AccountReq, Admin, AdminReply, ClientMsg, Secret, ServerMsg};
use figcraft_collab_net::{Endpoint, NetLimits, manage};
use serde_json::json;

use crate::accounts::{Accounts, PASSWORD_NEEDS_TLS};
use crate::accounts_tests::{account, ask, signed};
use crate::cli::{self, Cli, Command};
use crate::config::Config;
use crate::passwords::{LOCKED, WRONG, WRONG_PER_USER};
use crate::test_util::{Raw, TempDir, config, key, session};

fn basic_config(dir: &Path, signup: bool) -> Config {
    Config {
        name: "Acme design".into(),
        auth: AuthConfig {
            mode: "accounts".into(),
            admins: vec!["boss@example.com".into()],
            provider: vec![ProviderConfig { id: "basic".into(), kind: "password".into(), allow_signup: signup, ..ProviderConfig::default() }],
            ..AuthConfig::default()
        },
        ..config(dir)
    }
}

fn admin(addr: SocketAddr, dir: &Path, req: Admin) -> AdminReply {
    let e = Endpoint::plain(addr.to_string());
    manage::request(&e, &key(dir), vec![req], &NetLimits::default(), Duration::from_secs(10)).unwrap().remove(0)
}

fn add(addr: SocketAddr, dir: &Path, user: &str, email: Option<&str>) -> String {
    let req = Admin::CreateUser { username: user.into(), email: email.map(String::from), name: user.into(), password: None };
    match admin(addr, dir, req) {
        AdminReply::User { password: Some(p), .. } => p.0,
        other => panic!("{other:?}"),
    }
}

fn pw(user: &str, password: &str) -> SignIn {
    SignIn::Password { provider: "basic".into(), username: user.into(), password: password.into() }
}

#[test]
fn people_an_admin_adds_sign_in_with_their_password() {
    let dir = TempDir::new("basic-signin");
    let mut server = crate::start(&basic_config(dir.path(), false)).unwrap();
    let addr = server.addr();
    // What older apps ask: the provider is there, without the flow they can't read.
    let mut raw = Raw::connect(addr);
    raw.send(&ClientMsg::Info);
    let ServerMsg::Info(info) = raw.next() else { panic!() };
    assert_eq!((info.auth, info.providers.len()), (AuthMode::Accounts, 1));
    assert!(info.providers[0].flows.is_empty(), "{info:?}");
    // What this version asks: its name, and the password flow.
    let mut raw = Raw::connect(addr);
    raw.send(&ClientMsg::About);
    let ServerMsg::About(about) = raw.next() else { panic!() };
    assert_eq!(about.name, "Acme design");
    assert_eq!(about.info.providers[0].flows, vec![Flow::Password { label: "Username and password".into() }]);
    assert_eq!(about.info.access(), "basic");

    let made = add(addr, dir.path(), "Ann", Some("Ann@Example.com"));
    let password = add(addr, dir.path(), "boss", Some("boss@example.com"));
    // The same username twice, and a bad one, are refused.
    let again = admin(addr, dir.path(), Admin::CreateUser { username: "ann".into(), email: None, name: String::new(), password: None });
    assert!(matches!(again, AdminReply::Failed { ref reason } if reason.contains("taken")), "{again:?}");
    let bad = admin(addr, dir.path(), Admin::CreateUser { username: "a b".into(), email: None, name: String::new(), password: None });
    assert!(matches!(bad, AdminReply::Failed { .. }));
    // An admin may give the password (it must follow the rules).
    let given = Admin::CreateUser { username: "cy".into(), email: None, name: "Cy".into(), password: Some(Secret("cy".into())) };
    assert!(matches!(admin(addr, dir.path(), given), AdminReply::Failed { ref reason } if reason.contains("at least 10")));
    let given = Admin::CreateUser { username: "cy".into(), email: None, name: "Cy".into(), password: Some(Secret("cy's own password".into())) };
    assert!(matches!(admin(addr, dir.path(), given), AdminReply::User { password: None, .. }));

    // Signing in: the username in any case; the identity is (basic, ann) with the admin's email.
    let (_, me) = signed(addr, pw("ANN", &made));
    let me = me.unwrap();
    assert_eq!((me.name.as_str(), me.email.as_deref(), me.admin), ("Ann", Some("ann@example.com"), false));
    let (_, again) = signed(addr, pw("ann", &made));
    assert_eq!(again.unwrap().account, me.account, "the same account every time");
    let (_, boss) = signed(addr, pw("boss", &password));
    assert!(boss.unwrap().admin, "admins go by the email an admin gave");
    let (_, cy) = signed(addr, pw("cy", "cy's own password"));
    assert!(cy.unwrap().email.is_none());
    // Wrong: the same words for a wrong password and for nobody.
    assert_eq!(signed(addr, pw("ann", "not her password")).1.unwrap_err(), WRONG);
    assert_eq!(signed(addr, pw("nobody", "not her password")).1.unwrap_err(), WRONG);
    // The list: Ann signed in, her password is still the one made for her.
    let AdminReply::Users(users) = admin(addr, dir.path(), Admin::Users) else { panic!() };
    let ann = users.iter().find(|u| u.username == "ann").unwrap();
    assert_eq!((ann.account.as_deref(), ann.temporary, ann.locked), (Some(me.account.as_str()), true, 0));
    // Nothing on disk holds a password.
    let text = std::fs::read_to_string(dir.path().join("accounts").join("passwords.json")).unwrap();
    assert!(!text.contains(&made) && !text.contains(&password) && text.contains("$argon2id$v=19$m=19456,t=2,p=1$"), "{text}");
    server.stop();
}

#[test]
fn wrong_passwords_lock_a_username_out_until_an_admin_resets_it() {
    let dir = TempDir::new("basic-lockout");
    let mut server = crate::start(&basic_config(dir.path(), false)).unwrap();
    let addr = server.addr();
    let made = add(addr, dir.path(), "ann", None);
    let (_, me) = signed(addr, pw("ann", &made));
    let session = me.unwrap().session;
    for _ in 0..WRONG_PER_USER {
        assert_eq!(signed(addr, pw("ann", "guess guess guess")).1.unwrap_err(), WRONG);
    }
    // Locked: even the right password waits.
    assert_eq!(signed(addr, pw("ann", &made)).1.unwrap_err(), LOCKED);
    let AdminReply::Users(users) = admin(addr, dir.path(), Admin::Users) else { panic!() };
    assert!(users[0].locked > 0);
    // An admin resets it: a new temporary password, the lockout lifted, her sessions ended.
    let AdminReply::User { password: Some(fresh), .. } = admin(addr, dir.path(), Admin::ResetPassword { username: "ann".into() }) else { panic!() };
    assert!(signed(addr, SignIn::Session { token: session }).1.is_err(), "signed out everywhere");
    assert_eq!(signed(addr, pw("ann", &made)).1.unwrap_err(), WRONG);
    assert!(signed(addr, pw("ann", &fresh.0)).1.is_ok());
    // Removed: she can't sign in any more, and her sessions end.
    let (_, me) = signed(addr, pw("ann", &fresh.0));
    let session = me.unwrap().session;
    assert!(matches!(admin(addr, dir.path(), Admin::RemoveUser { username: "ann".into() }), AdminReply::Done));
    assert_eq!(signed(addr, pw("ann", &fresh.0)).1.unwrap_err(), WRONG);
    assert!(signed(addr, SignIn::Session { token: session }).1.is_err());
    assert!(matches!(admin(addr, dir.path(), Admin::RemoveUser { username: "ann".into() }), AdminReply::Failed { .. }));
    server.stop();
}

#[test]
fn people_change_their_own_password() {
    let dir = TempDir::new("basic-change");
    let mut server = crate::start(&basic_config(dir.path(), false)).unwrap();
    let addr = server.addr();
    let made = add(addr, dir.path(), "ann", None);
    let (mut conn, _) = account(addr, pw("ann", &made));
    let change = |old: &str, new: &str| AccountReq::ChangePassword { old: Secret(old.into()), new: Secret(new.into()) };
    assert!(matches!(ask(&mut conn, change("wrong one!!", "a brand new password")), AccountReply::Failed { ref reason } if reason.contains("wrong")));
    assert!(matches!(ask(&mut conn, change(&made, "short")), AccountReply::Failed { ref reason } if reason.contains("at least 10")));
    assert!(matches!(ask(&mut conn, change(&made, "ANN")), AccountReply::Failed { .. }));
    assert_eq!(ask(&mut conn, change(&made, "a brand new password")), AccountReply::Done);
    assert_eq!(signed(addr, pw("ann", &made)).1.unwrap_err(), WRONG);
    assert!(signed(addr, pw("ann", "a brand new password")).1.is_ok());
    let AdminReply::Users(users) = admin(addr, dir.path(), Admin::Users) else { panic!() };
    assert!(!users[0].temporary);
    server.stop();
}

#[test]
fn signing_up_only_where_the_server_allows_it() {
    let dir = TempDir::new("basic-signup");
    let mut server = crate::start(&basic_config(dir.path(), true)).unwrap();
    let addr = server.addr();
    let up = |user: &str, password: &str| SignIn::SignUp {
        provider: "basic".into(),
        username: user.into(),
        password: password.into(),
        email: Some("dee@example.com".into()),
        name: "Dee".into(),
    };
    let (_, me) = signed(addr, up("dee", "dee's long password"));
    let me = me.unwrap();
    // The email typed when signing up isn't verified.
    assert_eq!((me.name.as_str(), me.email), ("Dee", None));
    assert!(signed(addr, up("dee", "another long password")).1.unwrap_err().contains("taken"));
    assert!(signed(addr, up("eve", "eve")).1.unwrap_err().contains("at least 10"));
    assert!(signed(addr, pw("dee", "dee's long password")).1.is_ok());
    server.stop();

    // Off (the default): refused.
    let dir = TempDir::new("basic-nosignup");
    let mut server = crate::start(&basic_config(dir.path(), false)).unwrap();
    assert!(signed(server.addr(), up("dee", "dee's long password")).1.unwrap_err().contains("ask an admin"));
    server.stop();
    // On, on a server that lets in only some emails: refused too (the email isn't verified).
    let dir = TempDir::new("basic-signup-allow");
    let mut cfg = basic_config(dir.path(), true);
    cfg.auth.allow_domains = vec!["example.com".into()];
    let mut server = crate::start(&cfg).unwrap();
    assert!(signed(server.addr(), up("dee", "dee's long password")).1.unwrap_err().contains("only some email"));
    server.stop();
}

#[test]
fn passwords_never_travel_in_the_clear() {
    let dir = TempDir::new("basic-clear");
    let cfg = basic_config(dir.path(), true);
    let fetch: Arc<dyn figcraft_auth::Fetch> = Arc::new(crate::fetch::Https::new().unwrap());
    let accounts = Accounts::open(dir.path(), &cfg.auth, figcraft_auth::E2eMode::Off, &Registry::builtin(), fetch).unwrap();
    accounts.create_user("ann", None, "Ann", Some("ann's long password")).unwrap();
    // On a connection that came over the network to the server's plain ws:// port: refused.
    let open = Origin { ip: "203.0.113.9".parse().unwrap(), private: false };
    let (reply, who) = accounts.sign_in_from(pw("ann", "ann's long password"), open);
    assert_eq!((reply, who), (SignInReply::Refused { reason: PASSWORD_NEEDS_TLS.into() }, None));
    let up =
        SignIn::SignUp { provider: "basic".into(), username: "bo".into(), password: "bo's long password".into(), email: None, name: String::new() };
    assert!(matches!(accounts.sign_in_from(up, open).0, SignInReply::Refused { ref reason } if reason == PASSWORD_NEEDS_TLS));
    // Without knowing where it came from, the same.
    assert!(matches!(accounts.sign_in(pw("ann", "ann's long password")).0, SignInReply::Refused { .. }));
    // Through the trusted proxy (TLS ends there) or from this machine: fine.
    let proxied = Origin { ip: "203.0.113.9".parse().unwrap(), private: true };
    assert!(matches!(accounts.sign_in_from(pw("ann", "ann's long password"), proxied).0, SignInReply::SignedIn(_)));
    assert!(matches!(accounts.sign_in_from(pw("ann", "ann's long password"), Origin::local()).0, SignInReply::SignedIn(_)));
    // And the app never sends one to a ws:// server on another machine.
    let far = Endpoint::parse("ws://203.0.113.9:47900/").unwrap().0;
    let err = manage::sign_in(&far, pw("ann", "x"), &NetLimits::default(), Duration::from_secs(1)).unwrap_err();
    assert_eq!(err, manage::PASSWORD_IN_CLEAR);
    let change = AccountReq::ChangePassword { old: Secret("a".into()), new: Secret("b".into()) };
    assert_eq!(manage::account(&far, "t", vec![change], &NetLimits::default(), Duration::from_secs(1)).unwrap_err(), manage::PASSWORD_IN_CLEAR);
    assert!(manage::password_safe(&Endpoint::parse("wss://figcraft.example.com/").unwrap().0));
    // `Debug` leaves the password out.
    assert!(!format!("{:?}", pw("ann", "ann's long password")).contains("long password"));
    assert!(!format!("{:?}", AccountReq::ChangePassword { old: Secret("old secret".into()), new: Secret("new secret".into()) }).contains("secret"));
}

#[test]
fn settings_for_basic_accounts() {
    let dir = TempDir::new("basic-settings");
    let mut cfg = basic_config(dir.path(), false);
    assert!(cfg.check().is_ok());
    cfg.auth.provider.push(ProviderConfig { id: "basic2".into(), kind: "password".into(), ..ProviderConfig::default() });
    assert!(cfg.check().unwrap_err().contains("at most one"));
    let mut cfg = basic_config(dir.path(), false);
    cfg.auth.provider[0].issuer = "https://issuer.example".into();
    assert!(cfg.check().is_err());
    let mut cfg = basic_config(dir.path(), false);
    cfg.auth.provider[0].kind = "oidc".into();
    cfg.auth.provider[0].allow_signup = true;
    assert!(cfg.auth.check().unwrap_err().contains("allow_signup"));
    let cfg = Config { name: "x".repeat(81), ..basic_config(dir.path(), false) };
    assert!(cfg.check().is_err());
    // On the network without TLS: a warning.
    let cfg = Config { listen: "0.0.0.0:47900".into(), ..basic_config(dir.path(), false) };
    assert!(cfg.warnings().iter().any(|w| w.contains("password")), "{:?}", cfg.warnings());
    let cfg = Config { public_url: Some("wss://f.example.com/".into()), ..cfg };
    assert!(!cfg.warnings().iter().any(|w| w.contains("password")));
    // "open" is links.
    let open: Config = toml::from_str("[auth]\nmode = \"open\"\n").unwrap();
    assert_eq!(open.auth.mode().unwrap(), AuthMode::Links);
    let named: Config = toml::from_str(
        "name = \"Acme design\"\n[auth]\nmode = \"accounts\"\n[[auth.provider]]\nid = \"basic\"\nkind = \"password\"\nallow_signup = true\n",
    )
    .unwrap();
    assert!(named.check().is_ok());
}

#[test]
fn the_command_line_manages_usernames() {
    let dir = TempDir::new("basic-cli");
    let cfg = basic_config(dir.path(), false);
    let run = |command: Command| cli::run(&Cli { config: cfg.clone(), command });
    // On a stopped server's directory.
    let out = run(Command::AddUser { username: "Ann".into(), email: Some("ann@example.com".into()), name: "Ann Lee".into() }).unwrap();
    assert!(out.contains("Added ann.") && out.contains("shown only now"), "{out}");
    let password = out.lines().find(|l| l.starts_with("  ")).unwrap().trim().to_string();
    let list = run(Command::Users).unwrap();
    assert!(list.contains("ann") && list.contains("ann@example.com") && list.contains("temporary"), "{list}");
    assert!(!list.contains(&password));
    // Through the running server.
    let mut server = crate::start(&cfg).unwrap();
    assert!(signed(server.addr(), pw("ann", &password)).1.is_ok());
    let out = run(Command::ResetPassword { username: "ann".into() }).unwrap();
    let fresh = out.lines().find(|l| l.starts_with("  ")).unwrap().trim().to_string();
    assert_ne!(fresh, password);
    assert!(signed(server.addr(), pw("ann", &fresh)).1.is_ok());
    assert!(run(Command::RemoveUser { username: "ann".into() }).unwrap().contains("Removed ann"));
    assert!(run(Command::Users).unwrap().contains("No usernames yet"));
    assert!(run(Command::RemoveUser { username: "ann".into() }).is_err());
    server.stop();
    // Parsing.
    let args = |s: &[&str]| s.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    assert_eq!(
        cli::parse(&args(&["users", "add", "bo", "--email", "bo@example.com", "--name", "Bo"])).unwrap().command,
        Command::AddUser { username: "bo".into(), email: Some("bo@example.com".into()), name: "Bo".into() }
    );
    assert_eq!(cli::parse(&args(&["users"])).unwrap().command, Command::Users);
    assert_eq!(cli::parse(&args(&["users", "reset", "bo"])).unwrap().command, Command::ResetPassword { username: "bo".into() });
    assert_eq!(cli::parse(&args(&["users", "remove", "bo"])).unwrap().command, Command::RemoveUser { username: "bo".into() });
    assert!(cli::USAGE.contains("users add USERNAME"));
    // A server without a password provider says so.
    let plain = crate::accounts_tests::accounts_config(dir.path(), "accounts");
    assert!(cli::run(&Cli { config: plain, command: Command::Users }).is_err());
}

#[test]
fn an_app_signs_in_with_a_password_and_changes_it() {
    let dir = TempDir::new("basic-engine");
    let mut server = crate::start(&basic_config(dir.path(), true)).unwrap();
    let addr = server.addr();
    let url = format!("ws://{addr}/");
    let made = add(addr, dir.path(), "ann", Some("ann@example.com"));
    let mut s = session("Ann");
    let info = s.execute("account.info", &json!({"server": url})).unwrap();
    assert_eq!((info["name"].as_str(), info["access"].as_str(), info["open"].as_bool()), (Some("Acme design"), Some("basic"), Some(false)));
    assert_eq!(info["providers"][0]["flows"], json!(["password", "signUp"]));
    let wrong = s.execute("account.signIn", &json!({"server": url, "username": "ann", "password": "not it at all"})).unwrap_err();
    assert!(wrong.to_string().contains(WRONG), "{wrong}");
    let r = s.execute("account.signIn", &json!({"server": url, "username": "ann", "password": made})).unwrap();
    assert_eq!(r["status"], "signedIn");
    assert!(!r.to_string().contains(&made), "never echoed");
    assert_eq!(r["account"]["email"], "ann@example.com");
    let r = s.execute("account.changePassword", &json!({"server": url, "old": made, "new": "ann's chosen password"})).unwrap();
    assert_eq!(r["changed"], true);
    assert!(!r.to_string().contains("chosen"));
    assert!(s.execute("account.changePassword", &json!({"server": url, "old": made, "new": "another password"})).is_err());
    // Signing up from the app.
    let mut bo = session("Bo");
    let r = bo.execute("account.signUp", &json!({"server": url, "username": "bo", "password": "bo's own password", "name": "Bo"})).unwrap();
    assert_eq!((r["status"].as_str(), r["account"]["name"].as_str()), (Some("signedIn"), Some("Bo")));
    // An open server says so.
    let open_dir = TempDir::new("basic-engine-open");
    let mut open = crate::start(&Config { name: "Board room".into(), ..config(open_dir.path()) }).unwrap();
    let info = s.execute("account.info", &json!({"server": format!("ws://{}/", open.addr())})).unwrap();
    assert_eq!((info["access"].as_str(), info["open"].as_bool(), info["name"].as_str()), (Some("open"), Some(true), Some("Board room")));
    open.stop();
    server.stop();
}
