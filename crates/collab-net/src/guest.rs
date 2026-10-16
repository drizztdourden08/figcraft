//! Joining a session: the client end of the transport, with reconnect.
//!
//! A supervisor thread connects, says hello, then writes (presence throttled to about 30 a
//! second, latest wins; a ping when quiet) while a reader thread takes in what the host sends.
//! When the connection drops after having been live, it reconnects with growing pauses; a
//! refusal or the host ending the session is final.
//!
//! Publishing ([`Guest::publish`]) first uploads the document to a server over a managing
//! connection, then joins the new file with its edit link on the same thread. A sealed
//! (end-to-end encrypted) publish makes a new file key, seals the document and its name for a file
//! id of its own choosing ([`upload_sealed`]), and its links carry the key after `#k=`.

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use figcraft_auth::E2eMode;
use figcraft_collab::Replica;
use figcraft_collab::message::{self, AccountReply, AccountReq, Admin, AdminReply, ClientMsg, HostInfo, Presence, ServerMsg};
use figcraft_collab_seal::{FileKey, Slot, link_fragment, seal, seal_change};
use figcraft_doc::Document;
use figcraft_engine::live::{Event, Published, Shared, Status};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, Role as WsRole, WebSocket};
use tungstenite::{Bytes, Message};

use crate::inbox::Inbox;
use crate::invite::{Endpoint, Invite};
pub use crate::join::GuestConfig;
use crate::join::{Next, Outcome, Resuming, Seen, Taken, after, closed, hello, outgoing, resolved, sign_in, take, unresolved};
use crate::manage;
use crate::net::{Duplex, NetLimits, config, open, shutdown};
use crate::throttle::{PRESENCE_INTERVAL, Throttle, earliest};
use crate::token;

/// What [`Guest::publish`] uploads, and where.
pub struct Publish {
    pub server: Endpoint,
    /// The server's key (`None`: publish as anyone may, on a server open to the public).
    pub key: Option<String>,
    /// The file's name on the server.
    pub name: String,
    pub doc: Arc<Document>,
    /// Share the file once it is there: links and join codes for others ([`Event::Shared`]).
    pub share: bool,
    /// Your session token there: published as yours on a server with accounts (no key).
    pub session: Option<String>,
    /// Sealed (end-to-end encrypted): `Some(true)` sealed, `Some(false)` plain, `None` as the
    /// server prefers (sealed when its `e2e` mode is `required`). See [`sealed_or_not`].
    pub sealed: Option<bool>,
}

/// What a server whose `[e2e] mode` is off (or that is older than sealed files) says to a sealed
/// publish, before anything is sent.
pub const NO_SEALED_FILES: &str = "this server doesn't keep end-to-end encrypted files (its operator turned them off, or it is older than this app): publish without encryption, or use another server";

/// A joined (or joining) session. Dropping it leaves.
pub struct Guest {
    cmd: Sender<Cmd>,
    thread: Option<JoinHandle<()>>,
}

enum Cmd {
    Presence(Presence),
    /// For the server, in order (document changes).
    Send(ClientMsg),
    Leave,
    /// The reader of connection `epoch` got its welcome.
    Welcomed(u64),
    /// Connection `epoch` ended.
    Lost(u64, Outcome),
}

impl Guest {
    /// Start joining (returns at once; progress arrives in `inbox`).
    pub fn start(mut cfg: GuestConfig, inbox: Inbox) -> io::Result<Guest> {
        let (tx, rx) = channel();
        let me = tx.clone();
        let thread = std::thread::Builder::new().name("live-guest".into()).spawn(move || {
            // A join code: the server says which file it opens, then the join goes on as with a link.
            if let Some(code) = cfg.code.clone() {
                inbox.push(Event::Status(Status::Connecting));
                let asked =
                    manage::resolve(&cfg.invite.server, &code, &cfg.limits, cfg.connect_timeout).map_err(|e| match e.strip_prefix(manage::REFUSED) {
                        Some(why) => Outcome::Refused(why.to_string()),
                        None => Outcome::Retry(e),
                    });
                if let Err(o) = asked.and_then(|(file, token)| resolved(&mut cfg, file, token)) {
                    if let Next::Stop(Some(e)) = after(unresolved(&cfg, o), &cfg, false, &mut 0, &inbox) {
                        inbox.push(e);
                    }
                    return;
                }
            }
            supervise(&cfg, &inbox, &rx, &me);
        })?;
        Ok(Guest { cmd: tx, thread: Some(thread) })
    }

    /// Upload `job.doc` to the server as a new file, then join it with its edit link (returns at
    /// once: [`Event::Published`] with the file's links, then the session, arrive in `inbox`).
    /// `cfg` says how to join; its invite is replaced by the new file's.
    pub fn publish(job: Publish, cfg: GuestConfig, inbox: Inbox) -> io::Result<Guest> {
        let (tx, rx) = channel();
        let me = tx.clone();
        let thread = std::thread::Builder::new().name("live-publish".into()).spawn(move || {
            inbox.push(Event::Status(Status::Connecting));
            let (cfg, published, hosting) = match upload(&job, cfg) {
                Ok(done) => done,
                Err(e) => return inbox.push(Event::Status(Status::Failed { reason: format!("Couldn't publish to the server: {e}") })),
            };
            // Before anyone hears the file is there, so what others join with shows with it. The
            // file's first links stay its owner's (this app joins with one): others get their own,
            // which stopping takes away again.
            let shared = job.share.then(|| {
                if job.session.is_some() {
                    return Err("on a server with accounts, invite people to the file (collab.invite) instead".to_string());
                }
                let owner = published.owner.as_deref().unwrap_or_default();
                let made = manage::share(&job.server, job.key.as_deref(), &published.file, owner, &[], true, &cfg.limits, cfg.connect_timeout);
                made.and_then(|s| s.ok_or_else(|| "the server didn't make the links".to_string())).map(|s| keyed(s, cfg.invite.key.as_ref()))
            });
            if let Some(h) = hosting {
                inbox.push(Event::Hosting(h));
            }
            inbox.push(Event::Published(published));
            if let Some(shared) = shared {
                inbox.push(Event::Shared(shared));
            }
            // Left while uploading: the file stays on the server, nobody joins it. Anything else
            // that came meanwhile (presence) waits for the session.
            let mut waiting = Vec::new();
            loop {
                match rx.try_recv() {
                    Ok(Cmd::Leave) | Err(TryRecvError::Disconnected) => return,
                    Ok(c) => waiting.push(c),
                    Err(TryRecvError::Empty) => break,
                }
            }
            for c in waiting {
                let _ = me.send(c);
            }
            supervise(&cfg, &inbox, &rx, &me);
        })?;
        Ok(Guest { cmd: tx, thread: Some(thread) })
    }

    /// Your latest presence.
    pub fn presence(&self, p: Presence) {
        let _ = self.cmd.send(Cmd::Presence(p));
    }

    /// A message from the sync client (sent once the connection is welcomed; dropped when it
    /// breaks: the next welcome starts over).
    pub fn send(&self, msg: ClientMsg) {
        let _ = self.cmd.send(Cmd::Send(msg));
    }

    /// Leave (returns at once: a connection attempt in progress ends on its own).
    pub fn leave(&mut self) {
        let _ = self.cmd.send(Cmd::Leave);
    }

    /// The connection thread has ended.
    pub fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.leave();
        if let Some(t) = self.thread.take()
            && t.is_finished()
        {
            let _ = t.join();
        }
    }
}

/// A connected socket: reader and writer ends.
struct Conn {
    reader: WebSocket<Duplex>,
    writer: WebSocket<Duplex>,
    sock: TcpStream,
}

/// Keep `doc` on `server` as a new file you own, signed in with `session` (a server with
/// accounts): the member's link (no secret: who you are lets you in) and where it is.
pub(crate) fn upload_owned(
    server: &Endpoint,
    session: &str,
    name: &str,
    doc: &Document,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<(Invite, Published), String> {
    let snapshot = Replica::new(doc.clone()).snapshot().map_err(|e| e.to_string())?;
    let file =
        match manage::account(server, session, vec![AccountReq::Publish { name: name.to_string(), snapshot }], limits, timeout)?.into_iter().next() {
            Some(AccountReply::Published { file }) => file,
            Some(AccountReply::Failed { reason }) => return Err(reason),
            _ => return Err("the server didn't say where the file is".into()),
        };
    let member = Invite { server: server.clone(), file: file.id.clone(), token: String::new(), key: None };
    let published =
        Published { server: server.display(), file: file.id, name: file.name, edit: member.link(), view: member.link(), owner: None, expires: None };
    Ok((member, published))
}

/// Keep `doc` on `server` as a new file named `name`, with the server's `key` (or, without one, as
/// anyone may on a server open to the public): its edit link, where it is with its links (and its
/// owner token without a key), and what the server says about its hosting (without a key).
pub(crate) fn upload_file(
    server: &Endpoint,
    key: Option<&str>,
    name: &str,
    doc: &Document,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<(Invite, Published, Option<HostInfo>), String> {
    let snapshot = Replica::new(doc.clone()).snapshot().map_err(|e| e.to_string())?;
    let publish = vec![Admin::Publish { name: name.to_string(), snapshot }];
    let (replies, hosting) = match key {
        Some(key) => (manage::request(server, key, publish, limits, timeout)?, None),
        None => {
            let (info, replies) = manage::hosting(server, "", "", publish, limits, timeout)?;
            (replies, Some(info))
        }
    };
    let (file, edit, view, owner, expires) = match replies.into_iter().next() {
        Some(AdminReply::Published { file, edit, view }) => (file, edit, view, None, None),
        Some(AdminReply::Hosted { file, edit, view, owner, expires }) => (file, edit, view, Some(owner), expires),
        Some(AdminReply::Failed { reason }) => return Err(reason),
        _ => return Err("the server didn't say where the file is".into()),
    };
    let link = |token: String| Invite { server: server.clone(), file: file.id.clone(), token, key: None };
    let (edit, view) = (link(edit.token), link(view.token));
    let published =
        Published { server: server.display(), file: file.id.clone(), name: file.name, edit: edit.link(), view: view.link(), owner, expires };
    Ok((edit, published, hosting))
}

/// Links others join a sealed file with carry its key; a join code can't, so they have none.
pub(crate) fn keyed(mut shared: Shared, key: Option<&FileKey>) -> Shared {
    let Some(key) = key else { return shared };
    let fragment = format!("#{}", link_fragment(key));
    for l in std::iter::once(&mut shared.edit).chain(shared.view.as_mut()) {
        if !l.link.contains('#') {
            l.link.push_str(&fragment);
        }
        l.code = None;
    }
    shared
}

/// Whether a publish to `server` is sealed: as asked (a sealed one only where the server keeps
/// them), or without a choice as the server prefers. The server is asked first, so a document
/// meant to be sealed never reaches a server that would refuse it; one that can't be asked takes
/// plain files only when there is no choice (its own answer to the publish says why).
pub(crate) fn sealed_or_not(server: &Endpoint, want: Option<bool>, limits: &NetLimits, timeout: Duration) -> Result<bool, String> {
    if want == Some(false) {
        return Ok(false);
    }
    match (want, manage::info(server, limits, timeout)) {
        (Some(true), Ok(info)) if info.e2e == E2eMode::Off => Err(NO_SEALED_FILES.into()),
        (Some(true), Ok(_)) => Ok(true),
        (Some(true), Err(e)) => Err(e),
        (_, Ok(info)) => Ok(info.e2e == E2eMode::Required),
        (_, Err(_)) => Ok(false),
    }
}

/// How many file ids a sealed publish tries when the server says one is taken.
const ID_TRIES: usize = 4;

/// Keep `doc` on `server` as a new sealed file named `name`: a new file key, a random file id the
/// document and its name are sealed for (another when the server says that one is taken). As
/// yours when signed in with `session` (and no `key`), else with the server's `key` or as anyone
/// may on a server open to the public. Its edit link (with the key), where it is with its links
/// (`#k=…` in each: what opens it), and what the server says about its hosting (without a key).
pub(crate) fn upload_sealed(
    server: &Endpoint,
    key: Option<&str>,
    session: Option<&str>,
    name: &str,
    doc: &Document,
    limits: &NetLimits,
    timeout: Duration,
) -> Result<(Invite, Published, Option<HostInfo>), String> {
    let file_key = FileKey::generate().map_err(|e| e.to_string())?;
    let plain = Replica::new(doc.clone()).snapshot().map_err(|e| e.to_string())?;
    let sealing = |e: figcraft_collab_seal::SealError| format!("couldn't encrypt the file: {e}");
    let mut last = String::from("the server didn't say where the file is");
    for _ in 0..ID_TRIES {
        let id = token::file_id()?;
        let snapshot = plain.iter().map(|c| seal_change(&file_key, &id, c)).collect::<Result<Vec<_>, _>>().map_err(sealing)?;
        let sealed_name = seal(&file_key, &id, &Slot::Meta { what: "name".into() }, name.as_bytes()).map_err(sealing)?;
        let link = |token: String| Invite { server: server.clone(), file: id.clone(), token, key: Some(file_key.clone()) };
        let refused = match (session, key) {
            // Signed in, without the server's key: as yours (a server with accounts).
            (Some(session), None) => {
                let publish = AccountReq::PublishSealed { file: id.clone(), name: sealed_name, snapshot };
                match manage::account(server, session, vec![publish], limits, timeout)?.into_iter().next() {
                    Some(AccountReply::Published { file }) => {
                        let member = link(String::new());
                        let published = Published {
                            server: server.display(),
                            file: file.id,
                            name: name.to_string(),
                            edit: member.link(),
                            view: member.link(),
                            owner: None,
                            expires: None,
                        };
                        return Ok((member, published, None));
                    }
                    Some(AccountReply::Failed { reason }) => reason,
                    _ => return Err("the server didn't say where the file is".into()),
                }
            }
            _ => {
                let publish = vec![Admin::PublishSealed { file: id.clone(), name: sealed_name, snapshot }];
                let (replies, hosting) = match key {
                    Some(key) => (manage::request(server, key, publish, limits, timeout)?, None),
                    None => {
                        let (info, replies) = manage::hosting(server, "", "", publish, limits, timeout)?;
                        (replies, Some(info))
                    }
                };
                let (file, edit, view, owner, expires) = match replies.into_iter().next() {
                    Some(AdminReply::Published { file, edit, view }) => (file, edit, view, None, None),
                    Some(AdminReply::Hosted { file, edit, view, owner, expires }) => (file, edit, view, Some(owner), expires),
                    Some(AdminReply::Failed { reason }) => {
                        last = reason;
                        if last.contains("taken") {
                            continue;
                        }
                        break;
                    }
                    _ => return Err("the server didn't say where the file is".into()),
                };
                let (edit, view) = (link(edit.token), link(view.token));
                let published = Published {
                    server: server.display(),
                    file: file.id,
                    name: name.to_string(),
                    edit: edit.link(),
                    view: view.link(),
                    owner,
                    expires,
                };
                return Ok((edit, published, hosting));
            }
        };
        // Another id when that one is taken (two apps picked the same 64 random bits).
        last = refused;
        if !last.contains("taken") {
            break;
        }
    }
    Err(last)
}

/// Upload the document; the join settings for the new file, its links and the server's hosting.
fn upload(job: &Publish, mut cfg: GuestConfig) -> Result<(GuestConfig, Published, Option<HostInfo>), String> {
    if sealed_or_not(&job.server, job.sealed, &cfg.limits, cfg.connect_timeout)? {
        let session = job.session.as_deref().filter(|_| job.key.is_none());
        let (invite, published, hosting) =
            upload_sealed(&job.server, job.key.as_deref(), session, &job.name, &job.doc, &cfg.limits, cfg.connect_timeout)?;
        cfg.invite = invite;
        if let Some(s) = session {
            cfg.session = Some(s.to_string());
        }
        return Ok((cfg, published, hosting));
    }
    // Signed in, without the key: as yours (a server with accounts).
    if let (Some(session), None) = (&job.session, &job.key) {
        let (member, published) = upload_owned(&job.server, session, &job.name, &job.doc, &cfg.limits, cfg.connect_timeout)?;
        cfg.invite = member;
        cfg.session = Some(session.clone());
        return Ok((cfg, published, None));
    }
    let (edit, published, hosting) = upload_file(&job.server, job.key.as_deref(), &job.name, &job.doc, &cfg.limits, cfg.connect_timeout)?;
    cfg.invite = edit;
    Ok((cfg, published, hosting))
}

fn connect(cfg: &GuestConfig) -> Result<Conn, String> {
    let (rd, wr, sock) = open(&cfg.invite.server, cfg.connect_timeout, &cfg.limits)?;
    let (reader, _) = tungstenite::client::client_with_config(cfg.invite.endpoint(), rd, Some(config(cfg.limits.max_server_message)))
        .map_err(|e| format!("{} doesn't answer as a FigCraft session: {e}", cfg.invite.server.display()))?;
    let writer = WebSocket::from_raw_socket(wr, WsRole::Client, Some(config(cfg.limits.max_client_message)));
    reader.get_ref().set_read_timeout(Some(cfg.limits.idle_timeout)).map_err(|e| e.to_string())?;
    Ok(Conn { reader, writer, sock })
}

fn supervise(cfg: &GuestConfig, inbox: &Inbox, rx: &Receiver<Cmd>, me: &Sender<Cmd>) {
    let resume: Arc<Resuming> = Arc::new(std::sync::Mutex::new(cfg.resume));
    let mut attempt = 0u32;
    let mut was_live = false;
    let mut pending: Option<Presence> = None;
    let mut epoch = 0u64;
    inbox.push(Event::Status(Status::Connecting));
    loop {
        epoch += 1;
        let outcome = match connect(cfg) {
            Ok(c) => session(c, cfg, inbox, rx, me, epoch, &resume, &mut pending, &mut was_live, &mut attempt),
            Err(e) => Outcome::Retry(e),
        };
        match after(outcome, cfg, was_live, &mut attempt, inbox) {
            Next::Stop(e) => {
                if let Some(e) = e {
                    inbox.push(e);
                }
                return;
            }
            Next::Reconnect(pause) => {
                let until = Instant::now() + pause;
                loop {
                    match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
                        Ok(Cmd::Leave) | Err(RecvTimeoutError::Disconnected) => return,
                        Ok(Cmd::Presence(p)) => pending = Some(p),
                        // From the old connection's client: the next welcome starts over.
                        Ok(_) => {}
                        Err(RecvTimeoutError::Timeout) => break,
                    }
                }
            }
        }
    }
}

/// One connection: say hello, then write until it ends.
fn session(
    c: Conn,
    cfg: &GuestConfig,
    inbox: &Inbox,
    rx: &Receiver<Cmd>,
    me: &Sender<Cmd>,
    epoch: u64,
    resume: &Arc<Resuming>,
    pending: &mut Option<Presence>,
    was_live: &mut bool,
    attempt: &mut u32,
) -> Outcome {
    let Conn { reader, mut writer, sock } = c;
    let reader = {
        let ctx = ReaderCtx { inbox: inbox.clone(), tx: me.clone(), epoch, cfg: cfg.clone(), resume: resume.clone() };
        match std::thread::Builder::new().name("live-guest-read".into()).spawn(move || read_loop(reader, &ctx)) {
            Ok(t) => t,
            Err(e) => {
                shutdown(&sock);
                return Outcome::Retry(e.to_string());
            }
        }
    };
    let mut last_sent = Instant::now();
    let hello = hello(cfg, resume);
    let mut welcomed = false;
    let mut throttle = Throttle::new(PRESENCE_INTERVAL);
    let signed = sign_in(cfg).is_none_or(|m| send(&mut writer, &m, &mut last_sent));
    let outcome = if signed && send(&mut writer, &hello, &mut last_sent) {
        loop {
            let ping_at = last_sent + cfg.limits.keepalive;
            let wake = earliest([throttle.due(), Some(ping_at)]).unwrap_or(ping_at);
            let mut out = None;
            let mut now_send = Vec::new();
            match rx.recv_timeout(wake.saturating_duration_since(Instant::now())) {
                Ok(Cmd::Send(m)) if welcomed => now_send.push(m),
                // Made for the previous connection (the sync client sends again what the server
                // didn't get once it has caught up with this connection's welcome).
                Ok(Cmd::Send(_)) => {}
                Ok(Cmd::Presence(p)) if welcomed => out = throttle.offer(p, Instant::now()),
                Ok(Cmd::Presence(p)) => *pending = Some(p),
                Ok(Cmd::Welcomed(e)) if e == epoch => {
                    welcomed = true;
                    *was_live = true;
                    *attempt = 0;
                    out = pending.take().and_then(|p| throttle.offer(p, Instant::now()));
                }
                Ok(Cmd::Lost(e, o)) if e == epoch => break o,
                Ok(Cmd::Leave) | Err(RecvTimeoutError::Disconnected) => {
                    let _ = writer.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() }));
                    break Outcome::Left;
                }
                // From an earlier connection.
                Ok(Cmd::Welcomed(_) | Cmd::Lost(..)) => {}
                Err(RecvTimeoutError::Timeout) => {}
            }
            // A sealed file's: sealed on their way out.
            let mut unsealable = None;
            let now_send: Vec<ClientMsg> = now_send
                .into_iter()
                .filter_map(|m| match outgoing(cfg, resume, m) {
                    Ok(m) => m,
                    Err(e) => {
                        unsealable.get_or_insert(e);
                        None
                    }
                })
                .collect();
            if let Some(why) = unsealable {
                break Outcome::Failed(why);
            }
            if !now_send.iter().all(|m| send(&mut writer, m, &mut last_sent)) {
                break Outcome::Retry("the connection dropped".into());
            }
            let now = Instant::now();
            let out = match out.or_else(|| throttle.take_due(now)).map(|p| outgoing(cfg, resume, ClientMsg::Presence(p))).transpose() {
                Ok(p) => p.flatten(),
                Err(why) => break Outcome::Failed(why),
            };
            let ok = match out {
                Some(p) => send(&mut writer, &p, &mut last_sent),
                None if now >= last_sent + cfg.limits.keepalive => send(&mut writer, &ClientMsg::Ping, &mut last_sent),
                None => true,
            };
            if !ok {
                break Outcome::Retry("the connection dropped".into());
            }
        }
    } else {
        Outcome::Retry("the connection dropped".into())
    };
    shutdown(&sock);
    let _ = reader.join();
    outcome
}

/// Send one message; false when the connection is gone.
fn send(ws: &mut WebSocket<Duplex>, msg: &ClientMsg, last_sent: &mut Instant) -> bool {
    *last_sent = Instant::now();
    message::encode(msg).is_ok_and(|b| ws.send(Message::Binary(Bytes::from(b))).is_ok())
}

struct ReaderCtx {
    inbox: Inbox,
    tx: Sender<Cmd>,
    epoch: u64,
    cfg: GuestConfig,
    resume: Arc<Resuming>,
}

fn read_loop(mut ws: WebSocket<Duplex>, ctx: &ReaderCtx) {
    let mut seen = Seen::default();
    let outcome = loop {
        match ws.read() {
            Ok(Message::Binary(b)) => match message::decode::<ServerMsg>(&b, ctx.cfg.limits.max_server_message) {
                Ok(m) => {
                    let welcomed = || {
                        let _ = ctx.tx.send(Cmd::Welcomed(ctx.epoch));
                    };
                    match take(m, &ctx.cfg, &ctx.inbox, &mut seen, &ctx.resume, &welcomed) {
                        Taken::Continue | Taken::Welcomed => {}
                        Taken::End(o) => break o,
                    }
                }
                Err(e) => break Outcome::Refused(format!("the host sent a message this version can't read ({e})")),
            },
            Ok(Message::Close(f)) => break f.map_or_else(|| closed(0, ""), |f| closed(f.code.into(), &f.reason)),
            Ok(Message::Text(_)) => break Outcome::Refused("the host sent a text message".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Capacity(_)) => break Outcome::Refused("the host sent a message over the size limit".into()),
            Err(e) => break Outcome::Retry(e.to_string()),
        }
    };
    let _ = ctx.tx.send(Cmd::Lost(ctx.epoch, outcome));
}
