//! Requests to a server outside a live session, each on a connection of its own answered in
//! order: managing its files with the server's key ([`Manage`], [`request`]; the app publishes
//! through it, and the server's command line uses it to reach a running server), and using a
//! file's team library with one of the file's share links ([`OpenLibrary`], [`library`]), and its
//! plugin directory ([`OpenPlugins`], [`plugins`]: anyone browses, the key publishes).

use std::time::Duration;

use figcraft_auth::{ServerAbout, ServerInfo, SignIn, SignInReply};
use figcraft_collab::message::{
    self, Access, AccountReply, AccountReq, Admin, AdminReply, ClientMsg, HostInfo, LibraryReply, LibraryReq, Manage, NewLink, OpenAccount,
    OpenHosting, OpenLibrary, OpenPlugins, PROTOCOL, PluginReply, PluginReq, Resolve, ServerMsg,
};
use figcraft_engine::live::{Shared, SharedLink};
use tungstenite::{Bytes, Message, WebSocket};

use crate::invite::{Endpoint, Invite};
use crate::net::{Duplex, NetLimits, config, open};

type Ws = WebSocket<Duplex>;

/// Send `requests` to the server at `server` with its `key`; the replies, in order. Fails when the
/// server can't be reached, refuses the key or closes the connection (a request it can't do is a
/// [`AdminReply::Failed`] reply, not an error). Never echoes the key.
pub fn request(server: &Endpoint, key: &str, requests: Vec<Admin>, limits: &NetLimits, timeout: Duration) -> Result<Vec<AdminReply>, String> {
    let ws = connect(server, limits, timeout)?;
    managed(ws, key, requests, limits)
}

/// [`request`] as an admin of a server with accounts (their email is in its `admins`): signed in
/// with `session` (a session token from signing in), without the key. Fails when the session has
/// ended or the person isn't an admin there. Never echoes the token.
pub fn request_as_admin(
    server: &Endpoint,
    session: &str,
    requests: Vec<Admin>,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<Vec<AdminReply>, String> {
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::SignIn(SignIn::Session { token: session.to_string() }))?;
    match reply(&mut ws, limits, |m| match m {
        ServerMsg::SignIn(r) => Some(*r),
        _ => None,
    })? {
        SignInReply::SignedIn(_) => {}
        SignInReply::Refused { reason } => return Err(format!("{REFUSED}{reason}")),
        _ => return Err("the server didn't sign this session in".into()),
    }
    managed(ws, "", requests, limits)
}

/// Open managing on `ws` with `key` (empty: as the admin signed in on it), then the requests.
fn managed(mut ws: Ws, key: &str, requests: Vec<Admin>, limits: &NetLimits) -> Result<Vec<AdminReply>, String> {
    let admin = |m: ServerMsg| match m {
        ServerMsg::Admin(r) => Some(*r),
        _ => None,
    };
    let manage = Manage { protocol: PROTOCOL, key: key.to_string(), client_version: env!("CARGO_PKG_VERSION").to_string() };
    send(&mut ws, &ClientMsg::Manage(manage))?;
    match reply(&mut ws, limits, admin)? {
        AdminReply::Ready => {}
        other => return Err(format!("the server answered {other:?} instead of letting this connection manage files")),
    }
    let mut replies = Vec::with_capacity(requests.len());
    for r in requests {
        send(&mut ws, &ClientMsg::Admin(r))?;
        replies.push(reply(&mut ws, limits, admin)?);
    }
    close(ws);
    Ok(replies)
}

/// Ask the server at `server` about its hosting, with a file's owner token when `file` and `owner`
/// aren't empty; what it says, and its replies to `requests` (publishing without the key, managing
/// that file), in order. Fails when the server can't be reached or refuses (a wrong owner token, a
/// blocked address); a server older than open hosting can't read the request, and is reported as
/// taking files only with its key. Never echoes the token.
pub fn hosting(
    server: &Endpoint,
    file: &str,
    owner: &str,
    requests: Vec<Admin>,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<(HostInfo, Vec<AdminReply>), String> {
    let admin = |m: ServerMsg| match m {
        ServerMsg::Admin(r) => Some(*r),
        _ => None,
    };
    let open = OpenHosting { protocol: PROTOCOL, client_version: message::client_version(), file: file.to_string(), owner: owner.to_string() };
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::OpenHosting(open))?;
    let info = match reply(&mut ws, limits, |m| match m {
        ServerMsg::Hosting(i) => Some(*i),
        _ => None,
    }) {
        Ok(i) => i,
        Err(e) if e.contains("couldn't be read") => {
            return Err(format!("{} takes files only with its key (it is older than this app): add ?key=… to the address", server.display()));
        }
        Err(e) => return Err(e),
    };
    let mut replies = Vec::with_capacity(requests.len());
    for r in requests {
        send(&mut ws, &ClientMsg::Admin(r))?;
        replies.push(reply(&mut ws, limits, admin)?);
    }
    close(ws);
    Ok((info, replies))
}

/// Ask the server at `server` what it accepts: who may get in, how to sign in, whether files are
/// sealed. A server older than accounts can't read the question: it takes share links only
/// ([`ServerInfo::default`]).
pub fn info(server: &Endpoint, limits: &NetLimits, timeout: Duration) -> Result<ServerInfo, String> {
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::Info)?;
    let answer = match reply(&mut ws, limits, |m| match m {
        ServerMsg::Info(i) => Some(*i),
        _ => None,
    }) {
        Ok(i) => i,
        Err(e) if e.contains("couldn't be read") => ServerInfo::default(),
        Err(e) => return Err(e),
    };
    close(ws);
    Ok(answer)
}

/// Ask the server at `server` what it says about itself: its name and everything it accepts
/// (also the flows of basic accounts). A server older than this question is asked [`info`]
/// instead (no name).
pub fn about(server: &Endpoint, limits: &NetLimits, timeout: Duration) -> Result<ServerAbout, String> {
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::About)?;
    let answer = reply(&mut ws, limits, |m| match m {
        ServerMsg::About(a) => Some(*a),
        _ => None,
    });
    match answer {
        Ok(a) => {
            close(ws);
            Ok(a)
        }
        // An older server closed the connection: ask the older question on a new one.
        Err(e) if e.contains("couldn't be read") => Ok(ServerAbout { info: info(server, limits, timeout)?, ..ServerAbout::default() }),
        Err(e) => Err(e),
    }
}

/// Why a password isn't sent to `server`: it would cross the network in the clear (plain
/// `ws://` to another machine). The server refuses such passwords too.
pub const PASSWORD_IN_CLEAR: &str =
    "this server isn't reached over TLS (its address is ws://, not wss://): FigCraft sends passwords only over TLS or to this machine";

/// Is a password sent to `server` safe from the network? Over TLS, or to this machine.
pub fn password_safe(server: &Endpoint) -> bool {
    server.secure || server.loopback()
}

/// One sign-in step with the server at `server`, on a connection of its own (a session token from
/// it signs in later connections). A server older than accounts can't read it. A password
/// ([`SignIn::Password`], [`SignIn::SignUp`]) goes only over TLS or to this machine
/// ([`PASSWORD_IN_CLEAR`]).
pub fn sign_in(server: &Endpoint, req: SignIn, limits: &NetLimits, timeout: Duration) -> Result<SignInReply, String> {
    if matches!(req, SignIn::Password { .. } | SignIn::SignUp { .. }) && !password_safe(server) {
        return Err(PASSWORD_IN_CLEAR.into());
    }
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::SignIn(req))?;
    let answer = reply(&mut ws, limits, |m| match m {
        ServerMsg::SignIn(r) => Some(*r),
        _ => None,
    })
    .map_err(|e| if e.contains("couldn't be read") { format!("{} has no accounts (it is older than this app)", server.display()) } else { e })?;
    close(ws);
    Ok(answer)
}

/// Send `requests` on an account connection to the server at `server`, signed in with `session`:
/// the replies, in order. Fails when the sign-in has ended or the server has no accounts. Never
/// echoes the token. A password change goes only over TLS or to this machine.
pub fn account(
    server: &Endpoint,
    session: &str,
    requests: Vec<AccountReq>,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<Vec<AccountReply>, String> {
    if requests.iter().any(|r| matches!(r, AccountReq::ChangePassword { .. })) && !password_safe(server) {
        return Err(PASSWORD_IN_CLEAR.into());
    }
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::SignIn(SignIn::Session { token: session.to_string() }))?;
    match reply(&mut ws, limits, |m| match m {
        ServerMsg::SignIn(r) => Some(*r),
        _ => None,
    })? {
        SignInReply::SignedIn(_) => {}
        SignInReply::Refused { reason } => return Err(format!("your sign-in to this server ended ({reason}): sign in again")),
        _ => return Err("the server didn't sign you in".into()),
    }
    send(&mut ws, &ClientMsg::OpenAccount(OpenAccount { protocol: PROTOCOL, client_version: message::client_version() }))?;
    let account = |m: ServerMsg| match m {
        ServerMsg::Account(r) => Some(*r),
        _ => None,
    };
    match reply(&mut ws, limits, account)? {
        AccountReply::Ready { .. } => {}
        other => return Err(format!("the server answered {other:?} instead of opening your account")),
    }
    let mut replies = Vec::with_capacity(requests.len());
    for r in requests {
        send(&mut ws, &ClientMsg::Account(r))?;
        replies.push(reply(&mut ws, limits, account)?);
    }
    close(ws);
    Ok(replies)
}

/// Ask the server at `server` which file join code `code` opens: the file's id and its link's
/// token. Fails with the server's own words when it knows no such code (or the address tried too
/// many: the error starts with [`REFUSED`]); a server older than join codes can't read the
/// question ("couldn't be read").
pub fn resolve(server: &Endpoint, code: &str, limits: &NetLimits, timeout: Duration) -> Result<(String, String), String> {
    let ask = Resolve { protocol: PROTOCOL, client_version: message::client_version(), code: code.to_string() };
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::Resolve(ask))?;
    let answer = reply(&mut ws, limits, |m| match m {
        ServerMsg::Resolved { file, token } => Some((file, token)),
        _ => None,
    })?;
    close(ws);
    Ok(answer)
}

/// Change who else gets into `file`, as whoever manages it (with the server's `key`, else with the
/// file's `owner` token): revoke the links with the ids in `revoke` (whoever joined with them is
/// disconnected, and their join codes stop working; one already gone is fine), then, to `create`,
/// make a new edit link and a new view link and ask for their join codes: what others join with.
/// A server older than join codes makes the links without codes.
pub fn share(
    server: &Endpoint,
    key: Option<&str>,
    file: &str,
    owner: &str,
    revoke: &[String],
    create: bool,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<Option<Shared>, String> {
    let ask = |requests: Vec<Admin>| match key {
        Some(key) => request(server, key, requests, limits, timeout),
        None => hosting(server, file, owner, requests, limits, timeout).map(|(_, replies)| replies),
    };
    let link = |access: Access| Admin::CreateLink { file: file.to_string(), access, label: format!("Shared ({})", access.id()) };
    let mut requests: Vec<Admin> = revoke.iter().map(|id| Admin::Revoke { file: file.to_string(), link: id.clone() }).collect();
    requests.extend(create.then(|| [link(Access::Edit), link(Access::View)]).into_iter().flatten());
    let mut made = Vec::new();
    for reply in ask(requests)? {
        match reply {
            AdminReply::Link(l) => made.push(l),
            // A link that is gone already is as revoked as it gets.
            AdminReply::Failed { reason } if made.is_empty() && reason.contains("no such link") => {}
            AdminReply::Failed { reason } => return Err(reason),
            _ => {}
        }
    }
    let (Some(view), Some(edit)) = (made.pop(), made.pop()) else {
        return if create { Err("the server didn't make the links".into()) } else { Ok(None) };
    };
    // Their codes, on a connection of its own: a server from before join codes can't read the
    // request and closes it (the links are shared without codes then).
    let code = |token: &str| Admin::Code { file: file.to_string(), token: token.to_string() };
    let mut codes = ask(vec![code(&edit.token), code(&view.token)])
        .map_err(|e| log::info!("live session: no join codes from {}: {e}", server.display()))
        .unwrap_or_default()
        .into_iter()
        .map(|r| if let AdminReply::Code { code } = r { Some(code) } else { None });
    let mut shared = |l: NewLink| SharedLink {
        link: Invite { server: server.clone(), file: file.to_string(), token: l.token, key: None }.link(),
        id: l.link.id,
        code: codes.next().flatten(),
    };
    let edit = shared(edit);
    Ok(Some(Shared { edit, view: Some(shared(view)) }))
}

/// Send one library request about the file behind share link `link`; the reply. Fails when the
/// link isn't one, the server can't be reached or refuses the link (a request it can't do is a
/// [`LibraryReply::Failed`] reply). Never echoes the link.
pub fn library(link: &str, req: LibraryReq, limits: &NetLimits, timeout: Duration) -> Result<LibraryReply, String> {
    let lib = |m: ServerMsg| match m {
        ServerMsg::Library(r) => Some(*r),
        _ => None,
    };
    let invite = Invite::parse(link)?;
    let open = OpenLibrary {
        protocol: PROTOCOL,
        file: invite.file.clone(),
        token: invite.token.clone(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let mut ws = connect(&invite.server, limits, timeout)?;
    send(&mut ws, &ClientMsg::OpenLibrary(open))?;
    match reply(&mut ws, limits, lib)? {
        LibraryReply::Ready { .. } => {}
        other => return Err(format!("the server answered {other:?} instead of opening the library")),
    }
    // A sealed file's archive is sealed and opened with the link's key (`#k=`).
    send(&mut ws, &ClientMsg::Library(crate::sealing::library_out(&invite, req)?))?;
    let r = reply(&mut ws, limits, lib)?;
    close(ws);
    crate::sealing::library_in(&invite, r)
}

/// Send one request to the plugin directory of the server at `server`, with its `key` (empty: only
/// browsing); the reply. Fails when the server can't be reached, refuses the key or has no
/// directory (an older server); a request it can't do is a [`PluginReply::Failed`] reply. Never
/// echoes the key.
pub fn plugins(server: &Endpoint, key: &str, req: PluginReq, limits: &NetLimits, timeout: Duration) -> Result<PluginReply, String> {
    let pick = |m: ServerMsg| match m {
        ServerMsg::Plugins(r) => Some(*r),
        _ => None,
    };
    let open = OpenPlugins { protocol: PROTOCOL, key: key.to_string(), client_version: env!("CARGO_PKG_VERSION").to_string() };
    let mut ws = connect(server, limits, timeout)?;
    send(&mut ws, &ClientMsg::OpenPlugins(open))?;
    match reply(&mut ws, limits, pick) {
        Ok(PluginReply::Ready { .. }) => {}
        // An older server can't read the request at all.
        Err(e) if e.contains("couldn't be read") => return Err(format!("{} has no plugin directory (update the server)", server.display())),
        Err(e) => return Err(e),
        Ok(other) => return Err(format!("the server answered {other:?} instead of opening its plugin directory")),
    }
    send(&mut ws, &ClientMsg::Plugins(req))?;
    let r = reply(&mut ws, limits, pick)?;
    close(ws);
    Ok(r)
}

/// A WebSocket to `server` that waits for answers up to the idle timeout (a large upload takes the
/// server a while to keep).
fn connect(server: &Endpoint, limits: &NetLimits, timeout: Duration) -> Result<Ws, String> {
    let (stream, _, _) = open(server, timeout, limits)?;
    let (ws, _) = tungstenite::client::client_with_config(server.url(), stream, Some(config(limits.max_server_message)))
        .map_err(|e| format!("{} doesn't answer as a FigCraft server: {e}", server.display()))?;
    ws.get_ref().set_read_timeout(Some(limits.idle_timeout)).map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Close politely: read until the server's close arrives (or the socket ends), so it isn't lost.
fn close(mut ws: Ws) {
    let _ = ws.close(None);
    while ws.read().is_ok() {}
}

fn send(ws: &mut Ws, msg: &ClientMsg) -> Result<(), String> {
    let bytes = message::encode(msg).map_err(|e| e.to_string())?;
    ws.send(Message::Binary(Bytes::from(bytes))).map_err(|e| format!("the connection to the server dropped ({e})"))
}

/// How an error starts when the server said no (then its reason), rather than not answering.
pub(crate) const REFUSED: &str = "the server refused: ";

/// The next answer `pick` takes, or why there is none.
fn reply<T>(ws: &mut Ws, limits: &NetLimits, pick: impl Fn(ServerMsg) -> Option<T>) -> Result<T, String> {
    loop {
        return match ws.read() {
            Ok(Message::Binary(b)) => match message::decode::<ServerMsg>(&b, limits.max_server_message) {
                Ok(ServerMsg::Refused { reason }) => Err(format!("{REFUSED}{reason}")),
                Ok(ServerMsg::Pong) => continue,
                Ok(m) => pick(m).ok_or_else(|| "the server sent something other than an answer".into()),
                Err(e) => Err(format!("the server sent a message this version can't read ({e})")),
            },
            Ok(Message::Close(f)) => Err(match f.map(|f| f.reason.to_string()).filter(|r| !r.is_empty()) {
                Some(r) => format!("the server closed the connection: {r}"),
                None => "the server closed the connection".into(),
            }),
            Ok(Message::Text(_)) => Err("the server sent a text message".into()),
            Ok(_) => continue,
            Err(e) => Err(format!("no answer from the server ({e})")),
        };
    }
}
