//! One request to a server outside a live session, as the browser build sends it: what the server
//! says about itself, a sign-in step, a request on your account and one as its admin, each on a
//! connection of its own with the same messages as `manage.rs` (the desktop app's blocking
//! version). Free of the browser so it runs (and is tested) on any target: `web.rs` opens the
//! socket, feeds an [`Exchange`] what arrives and sends what it says.

use figcraft_auth::{SignIn, SignInReply};
use figcraft_collab::message::{self, AccountReply, AccountReq, Admin, AdminReply, ClientMsg, Manage, OpenAccount, PROTOCOL, ServerMsg};
use figcraft_engine::live::{NetReply, NetRequest};

use crate::invite::Endpoint;
use crate::limits::NetLimits;

/// How an error starts when the server said no (then its reason), as with `manage.rs`.
const REFUSED: &str = "the server refused: ";

/// Why a password isn't sent (as `manage::PASSWORD_IN_CLEAR` says it).
const PASSWORD_IN_CLEAR: &str =
    "this server isn't reached over TLS (its address is ws://, not wss://): FigCraft sends passwords only over TLS or to this machine";

/// What is asked.
#[derive(Debug)]
enum Kind {
    /// What the server says about itself: with every flow first (`AboutAll`), then as older
    /// servers answer (`About`) when it can't read that.
    About {
        all: bool,
    },
    SignIn,
    /// A request on your account (`None` once sent).
    Account(Option<AccountReq>),
    /// A request as the server's admin (`None` once sent).
    Admin(Option<Admin>),
}

/// Where an account or admin request is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// The session token went out.
    SigningIn,
    /// The account (or managing) connection is being opened.
    Opening,
    /// The request went out.
    Asked,
}

/// What to do next.
#[derive(Debug, PartialEq)]
pub(crate) enum Next {
    /// Nothing yet.
    Wait,
    /// Send this.
    Send(ClientMsg),
    /// Close this connection and open a new one to the same address, then send this.
    Reopen(ClientMsg),
    /// The answer (close the connection).
    Done(Box<NetReply>),
}

/// One request on its way (see the module docs).
#[derive(Debug)]
pub(crate) struct Exchange {
    /// Where to connect.
    pub(crate) url: String,
    kind: Kind,
    stage: Stage,
    max: usize,
    failure: fn(String) -> NetReply,
}

impl Exchange {
    /// Start `req`: the exchange and the first message to send once the connection is open, or the
    /// answer at once (a request it doesn't send, an address that isn't one, a password that
    /// would go in the clear).
    pub(crate) fn start(req: NetRequest, limits: &NetLimits) -> Result<(Exchange, ClientMsg), Box<NetReply>> {
        let failure = req.failure();
        let (server, kind, first) = match req {
            NetRequest::Info { server } => (server, Kind::About { all: true }, ClientMsg::AboutAll),
            NetRequest::SignIn { server, req } => (server, Kind::SignIn, ClientMsg::SignIn(req)),
            NetRequest::Account { server, session, req } => (server, Kind::Account(Some(req)), session_msg(session)),
            NetRequest::Admin { server, session, req } => (server, Kind::Admin(Some(req)), session_msg(session)),
            other => return Err(Box::new(failure(format!("{} needs the desktop app", what(&other))))),
        };
        let (endpoint, _) = Endpoint::parse(&server).map_err(|e| Box::new(failure(e)))?;
        let password = matches!(first, ClientMsg::SignIn(SignIn::Password { .. } | SignIn::SignUp { .. }))
            || matches!(kind, Kind::Account(Some(AccountReq::ChangePassword { .. })));
        if password && !(endpoint.secure || endpoint.loopback()) {
            return Err(Box::new(failure(PASSWORD_IN_CLEAR.into())));
        }
        let stage = if matches!(kind, Kind::Account(_) | Kind::Admin(_)) { Stage::SigningIn } else { Stage::Asked };
        Ok((Exchange { url: endpoint.url(), kind, stage, max: limits.max_server_message, failure }, first))
    }

    fn fail(&self, why: impl Into<String>) -> Next {
        Next::Done(Box::new((self.failure)(why.into())))
    }

    /// A binary message arrived.
    pub(crate) fn message(&mut self, bytes: &[u8]) -> Next {
        let msg = match message::decode::<ServerMsg>(bytes, self.max) {
            Ok(m) => m,
            Err(e) => return self.fail(format!("the server sent a message this version can't read ({e})")),
        };
        match (msg, &mut self.kind, self.stage) {
            (ServerMsg::Pong, _, _) => Next::Wait,
            (ServerMsg::Refused { .. }, Kind::About { all }, _) if *all => self.older_about(),
            (ServerMsg::Refused { reason }, _, _) => self.fail(format!("{REFUSED}{reason}")),
            (ServerMsg::About(a), Kind::About { .. }, _) => Next::Done(Box::new(NetReply::Info(Ok(*a)))),
            (ServerMsg::SignIn(r), Kind::SignIn, _) => Next::Done(Box::new(NetReply::SignIn(Ok(*r)))),
            (ServerMsg::SignIn(r), Kind::Account(_) | Kind::Admin(_), Stage::SigningIn) => match *r {
                SignInReply::SignedIn(_) => {
                    self.stage = Stage::Opening;
                    Next::Send(match self.kind {
                        Kind::Account(_) => ClientMsg::OpenAccount(OpenAccount { protocol: PROTOCOL, client_version: message::client_version() }),
                        _ => ClientMsg::Manage(Manage {
                            protocol: PROTOCOL,
                            key: String::new(),
                            client_version: env!("CARGO_PKG_VERSION").to_string(),
                        }),
                    })
                }
                // As an account connection says it: the app forgets the sign-in and asks again.
                SignInReply::Refused { reason } => self.fail(format!("your sign-in to this server ended ({reason}): sign in again")),
                _ => self.fail("the server didn't sign you in"),
            },
            (ServerMsg::Account(r), Kind::Account(req), Stage::Opening) => match (*r, req.take()) {
                (AccountReply::Ready { .. }, Some(req)) => {
                    self.stage = Stage::Asked;
                    Next::Send(ClientMsg::Account(req))
                }
                (other, _) => self.fail(format!("the server answered {other:?} instead of opening your account")),
            },
            (ServerMsg::Account(r), Kind::Account(_), Stage::Asked) => Next::Done(Box::new(NetReply::Account(Ok(*r)))),
            (ServerMsg::Admin(r), Kind::Admin(req), Stage::Opening) => match (*r, req.take()) {
                (AdminReply::Ready, Some(req)) => {
                    self.stage = Stage::Asked;
                    Next::Send(ClientMsg::Admin(req))
                }
                (other, _) => self.fail(format!("the server answered {other:?} instead of letting this connection manage files")),
            },
            (ServerMsg::Admin(r), Kind::Admin(_), Stage::Asked) => Next::Done(Box::new(NetReply::Admin(Ok(*r)))),
            _ => self.fail("the server sent something other than an answer"),
        }
    }

    /// A text message arrived (servers send none).
    pub(crate) fn text(&self) -> Next {
        self.fail("the server sent a text message")
    }

    /// The connection closed (or couldn't be opened) before the answer.
    pub(crate) fn closed(&mut self, reason: &str) -> Next {
        if matches!(self.kind, Kind::About { all: true }) {
            // A server older than `AboutAll` can't read it and closes the connection.
            return self.older_about();
        }
        let why =
            if reason.is_empty() { "the server closed the connection".to_string() } else { format!("the server closed the connection: {reason}") };
        match self.kind {
            Kind::SignIn if why.contains("couldn't be read") => self.fail("this server has no accounts (it is older than this app)"),
            _ => self.fail(why),
        }
    }

    /// No answer in time.
    pub(crate) fn timed_out(&self) -> NetReply {
        (self.failure)("no answer from the server (it may be down, or the address may be wrong)".into())
    }

    /// Ask again as older servers are asked.
    fn older_about(&mut self) -> Next {
        self.kind = Kind::About { all: false };
        Next::Reopen(ClientMsg::About)
    }
}

fn session_msg(token: String) -> ClientMsg {
    ClientMsg::SignIn(SignIn::Session { token })
}

/// What a request the browser doesn't send is about.
fn what(req: &NetRequest) -> &'static str {
    match req {
        NetRequest::Plugins { .. } => "the plugin directory",
        NetRequest::Library { .. } => "team libraries",
        NetRequest::Upload(_) | NetRequest::Hosting { .. } | NetRequest::Share { .. } => "publishing to a server",
        _ => "this",
    }
}
