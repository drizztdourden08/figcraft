//! The browser build's one-shot requests (`exchange.rs`), message by message.

use figcraft_auth::{Me, ServerAbout, SignIn, SignInReply};
use figcraft_collab::message::{self, AccountReply, AccountReq, Admin, AdminReply, ClientMsg, ServerMsg};
use figcraft_engine::live::{NetReply, NetRequest};

use crate::exchange::{Exchange, Next};
use crate::limits::NetLimits;

fn bytes(m: &ServerMsg) -> Vec<u8> {
    message::encode(m).unwrap()
}

fn start(req: NetRequest) -> (Exchange, ClientMsg) {
    Exchange::start(req, &NetLimits::default()).unwrap()
}

/// The answer `next` ends with.
fn done(next: Next) -> NetReply {
    match next {
        Next::Done(reply) => *reply,
        other => panic!("not done: {other:?}"),
    }
}

/// The error `next` ends with.
fn error(next: Next) -> String {
    match done(next) {
        NetReply::Info(Err(e)) | NetReply::SignIn(Err(e)) | NetReply::Account(Err(e)) | NetReply::Admin(Err(e)) => e,
        other => panic!("not an error: {other:?}"),
    }
}

#[test]
fn about_asks_for_every_flow_then_as_older_servers_are_asked() {
    let (mut x, first) = start(NetRequest::Info { server: "wss://share.example/".into() });
    assert_eq!(x.url, "wss://share.example:443/");
    assert_eq!(first, ClientMsg::AboutAll);
    assert_eq!(x.message(&bytes(&ServerMsg::Pong)), Next::Wait);
    // A server from before `AboutAll` closes the connection: ask `About` on a new one.
    assert_eq!(x.closed("the message couldn't be read"), Next::Reopen(ClientMsg::About));
    let about = ServerAbout { name: "Team".into(), ..ServerAbout::default() };
    assert_eq!(done(x.message(&bytes(&ServerMsg::About(Box::new(about.clone()))))), NetReply::Info(Ok(about)));
    // It is asked that way once only.
    let (mut x, _) = start(NetRequest::Info { server: "wss://share.example/".into() });
    assert_eq!(x.message(&bytes(&ServerMsg::Refused { reason: "no".into() })), Next::Reopen(ClientMsg::About));
    assert!(error(x.closed("")).contains("closed"));
}

#[test]
fn a_sign_in_step_and_its_reply() {
    let req = SignIn::Password { provider: "basic".into(), username: "ann".into(), password: "pw".into() };
    let (mut x, first) = start(NetRequest::SignIn { server: "wss://share.example/".into(), req: req.clone() });
    assert_eq!(first, ClientMsg::SignIn(req.clone()));
    let me = SignInReply::SignedIn(Me { account: "a1".into(), ..Me::default() });
    assert_eq!(done(x.message(&bytes(&ServerMsg::SignIn(Box::new(me.clone()))))), NetReply::SignIn(Ok(me)));
    // A password never goes to another machine in the clear.
    let clear = Exchange::start(NetRequest::SignIn { server: "ws://192.0.2.7:47900/".into(), req }, &NetLimits::default()).unwrap_err();
    assert!(matches!(*clear, NetReply::SignIn(Err(e)) if e.contains("TLS")));
    // Refusals and nonsense end it with the reason.
    let session = || NetRequest::SignIn { server: "wss://share.example/".into(), req: SignIn::Session { token: "t".into() } };
    let (mut x, _) = start(session());
    assert_eq!(error(x.message(&bytes(&ServerMsg::Refused { reason: "blocked".into() }))), "the server refused: blocked");
    let (mut x, _) = start(session());
    assert!(error(x.message(b"\xff\xff")).contains("can't read"));
    let (x, _) = start(session());
    assert!(error(x.text()).contains("text"));
    assert!(matches!(x.timed_out(), NetReply::SignIn(Err(_))));
    let (mut x, _) = start(session());
    assert!(error(x.closed("the message couldn't be read")).contains("no accounts"));
    let bad = Exchange::start(NetRequest::Info { server: "not a server".into() }, &NetLimits::default()).map(drop).unwrap_err();
    assert!(matches!(*bad, NetReply::Info(Err(_))));
}

#[test]
fn account_requests_sign_in_open_then_ask() {
    let req = AccountReq::Files;
    let (mut x, first) = start(NetRequest::Account { server: "wss://share.example/".into(), session: "tok".into(), req: req.clone() });
    assert_eq!(first, ClientMsg::SignIn(SignIn::Session { token: "tok".into() }));
    let signed = ServerMsg::SignIn(Box::new(SignInReply::SignedIn(Me::default())));
    assert!(matches!(x.message(&bytes(&signed)), Next::Send(ClientMsg::OpenAccount(_))));
    let ready = ServerMsg::Account(Box::new(AccountReply::Ready { account: "a1".into() }));
    assert_eq!(x.message(&bytes(&ready)), Next::Send(ClientMsg::Account(req)));
    let failed = AccountReply::Failed { reason: "x".into() };
    assert_eq!(done(x.message(&bytes(&ServerMsg::Account(Box::new(failed.clone()))))), NetReply::Account(Ok(failed)));
    // A session that ended says so the way the engine forgets it by.
    let (mut x, _) = start(NetRequest::Account { server: "wss://share.example/".into(), session: "old".into(), req: AccountReq::Files });
    let refused = ServerMsg::SignIn(Box::new(SignInReply::Refused { reason: "expired".into() }));
    assert!(error(x.message(&bytes(&refused))).contains("your sign-in to this server ended"));
}

#[test]
fn admin_requests_manage_as_the_signed_in_admin() {
    let req = Admin::Files;
    let (mut x, _) = start(NetRequest::Admin { server: "wss://share.example/".into(), session: "tok".into(), req: req.clone() });
    let signed = ServerMsg::SignIn(Box::new(SignInReply::SignedIn(Me::default())));
    assert!(matches!(x.message(&bytes(&signed)), Next::Send(ClientMsg::Manage(m)) if m.key.is_empty()));
    assert_eq!(x.message(&bytes(&ServerMsg::Admin(Box::new(AdminReply::Ready)))), Next::Send(ClientMsg::Admin(req)));
    let reply = AdminReply::Failed { reason: "nope".into() };
    assert_eq!(done(x.message(&bytes(&ServerMsg::Admin(Box::new(reply.clone()))))), NetReply::Admin(Ok(reply)));
    // Out of order: an answer before the connection opened.
    let (mut x, _) = start(NetRequest::Admin { server: "wss://share.example/".into(), session: "tok".into(), req: Admin::Files });
    assert!(error(x.message(&bytes(&ServerMsg::Admin(Box::new(AdminReply::Ready))))).contains("something other"));
}
