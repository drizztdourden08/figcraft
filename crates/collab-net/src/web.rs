//! The browser client (step 4 of `docs/collab-protocol.md`): the web build joins a session a
//! desktop app hosts, or a file on a `figcraft-server` (also over `wss://` behind a TLS reverse
//! proxy), through the browser's WebSocket API (`web-sys`), with the same messages as the native
//! guest. The connection logic is the [`Driver`]'s; this file feeds it the socket's
//! events and wakes it with a timer. Hosting needs the desktop app (a page can't listen on a
//! socket).
//!
//! The page runs everything on one thread: each session's socket, callbacks and timer live in a
//! thread-local table, and [`NetLink`] (the engine needs it to be `Send`) holds only each session's
//! number there and its [`Inbox`](crate::inbox::Inbox). It joins any number of sessions at once
//! (one per open document). Whatever arrives wakes egui through the [`Waker`]; nothing polls.
//!
//! An `https://` page can't open an unencrypted `ws://` connection (browsers block mixed content)
//! except to this machine; [`NetLink::join`] says so up front.
//!
//! Requests outside a session (what a server accepts, signing in, your files there, an admin's
//! requests) go out in the background ([`LiveLink::background`]), each on a connection of its own
//! driven by an [`Exchange`]. Signing in with a provider sends the whole tab to its page
//! ([`LiveLink::redirect_sign_in`]); when it comes back, [`redirect_back`] reads the code.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use figcraft_collab::Replica;
use figcraft_collab::message::{self, AccountReply, AccountReq, ClientMsg, Presence};
use figcraft_engine::live::{
    Event, Flow, HostOptions, LiveLink, NO_SESSION, NetReply, NetRequest, PublishOptions, Published, SessionId, SessionInfo, Status,
};
use wasm_bindgen::JsCast as _;
use wasm_bindgen::closure::Closure;
use web_sys::{BinaryType, CloseEvent, MessageEvent, WebSocket};
use web_time::Instant;

use crate::driver::{Driver, Socket};
use crate::exchange::{Exchange, Next};
use crate::inbox::{Inbox, Waker};
use crate::invite::{Endpoint, Invite};
use crate::join::GuestConfig;
use crate::limits::NetLimits;
use crate::pkce::{self, Back, Redirect};
use crate::sessions::Sessions;

/// Close code for leaving normally.
const CLOSE_NORMAL: u16 = 1000;

/// One session's driver and the timer that wakes it.
struct Guest {
    driver: Driver<BrowserSocket>,
    /// Runs the driver's `tick` (one closure for the session's life, reused for every wake).
    timer: Closure<dyn FnMut()>,
    /// The pending `setTimeout`.
    timeout: Option<i32>,
}

impl Guest {
    /// Set the timer for the driver's next deadline (replacing the last one).
    fn arm(&mut self) {
        let Some(w) = web_sys::window() else { return };
        if let Some(t) = self.timeout.take() {
            w.clear_timeout_with_handle(t);
        }
        let Some(at) = self.driver.deadline() else { return };
        let ms = i32::try_from(at.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(i32::MAX);
        self.timeout = w.set_timeout_with_callback_and_timeout_and_arguments_0(self.timer.as_ref().unchecked_ref(), ms).ok();
    }
}

thread_local! {
    static GUESTS: RefCell<BTreeMap<u64, Rc<RefCell<Guest>>>> = RefCell::default();
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
}

/// Run `f` on session `id`'s driver, then set its timer for what's next, or forget the session
/// once it's over. (Callbacks may drop their own closures: wasm-bindgen frees a closure only
/// after it has returned.)
fn with_driver(id: u64, f: impl FnOnce(&mut Driver<BrowserSocket>, Instant)) {
    let Some(g) = GUESTS.with(|t| t.borrow().get(&id).cloned()) else { return };
    let done = {
        let Ok(mut g) = g.try_borrow_mut() else {
            log::warn!("live session: an event arrived while the session was busy");
            return;
        };
        f(&mut g.driver, Instant::now());
        g.arm();
        g.driver.done()
    };
    if done {
        GUESTS.with(|t| t.borrow_mut().remove(&id));
    }
}

/// The socket's callbacks (alive while the connection is in use).
struct Handlers {
    _open: Closure<dyn FnMut()>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _close: Closure<dyn FnMut(CloseEvent)>,
}

/// The browser's WebSocket behind the driver's [`Socket`].
struct BrowserSocket {
    id: u64,
    ws: Option<(WebSocket, Handlers)>,
}

impl Socket for BrowserSocket {
    fn open(&mut self, url: &str) -> Result<(), String> {
        self.close();
        let ws = WebSocket::new(url).map_err(|e| format!("the browser won't open {url}: {}", js_error(&e)))?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let id = self.id;
        let open = Closure::<dyn FnMut()>::new(move || with_driver(id, |d, now| d.opened(now)));
        let message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| match e.data().dyn_into::<js_sys::ArrayBuffer>() {
            Ok(buf) => {
                let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                with_driver(id, |d, now| d.message(&bytes, now));
            }
            Err(_) => with_driver(id, |d, now| d.text(now)),
        });
        let close = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
            let (code, reason) = (e.code(), e.reason());
            with_driver(id, |d, now| d.closed(code, &reason, now));
        });
        ws.set_onopen(Some(open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
        ws.set_onclose(Some(close.as_ref().unchecked_ref()));
        self.ws = Some((ws, Handlers { _open: open, _message: message, _close: close }));
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) -> bool {
        self.ws.as_ref().is_some_and(|(ws, _)| ws.ready_state() == WebSocket::OPEN && ws.send_with_u8_array(bytes).is_ok())
    }

    fn close(&mut self) {
        let Some((ws, _handlers)) = self.ws.take() else { return };
        ws.set_onopen(None);
        ws.set_onmessage(None);
        ws.set_onclose(None);
        let _ = ws.close_with_code(CLOSE_NORMAL);
    }
}

fn js_error(e: &wasm_bindgen::JsValue) -> String {
    e.dyn_ref::<js_sys::Error>().map_or_else(|| format!("{e:?}"), |e| String::from(e.message()))
}

/// The page was loaded over `https://`.
fn secure_page() -> bool {
    web_sys::window().and_then(|w| w.location().protocol().ok()).is_some_and(|p| p == "https:")
}

/// How long a request outside a session waits for the server (milliseconds).
const REQUEST_TIMEOUT_MS: i32 = 20_000;

/// One request outside a session, on its connection.
struct Request {
    job: u64,
    x: Exchange,
    /// What to send once the connection is open.
    first: Option<ClientMsg>,
    ws: Option<(WebSocket, Handlers)>,
    /// Where the answer goes.
    inbox: Inbox,
    /// Gives up when the server doesn't answer in time (kept alive while the request is).
    _timer: Closure<dyn FnMut()>,
    timeout: Option<i32>,
}

thread_local! {
    static REQUESTS: RefCell<BTreeMap<u64, Rc<RefCell<Request>>>> = RefCell::default();
}

/// Send `req` on a connection of its own; its answer arrives in `inbox` as [`Event::Net`] with
/// `job`.
fn start_request(job: u64, req: NetRequest, inbox: Inbox, limits: &NetLimits) {
    let (x, first) = match Exchange::start(req, limits) {
        Ok(started) => started,
        Err(reply) => return inbox.push(Event::Net { job, reply }),
    };
    let id = NEXT_ID.with(|n| n.replace(n.get() + 1));
    let timer = Closure::<dyn FnMut()>::new(move || with_request(id, |r| Next::Done(Box::new(r.x.timed_out()))));
    let timeout = web_sys::window()
        .and_then(|w| w.set_timeout_with_callback_and_timeout_and_arguments_0(timer.as_ref().unchecked_ref(), REQUEST_TIMEOUT_MS).ok());
    let r = Rc::new(RefCell::new(Request { job, x, first: Some(first), ws: None, inbox, _timer: timer, timeout }));
    REQUESTS.with(|t| t.borrow_mut().insert(id, r));
    with_request(id, |r| match open_request(id, &r.x.url) {
        Ok(ws) => {
            r.ws = Some(ws);
            Next::Wait
        }
        Err(e) => r.x.closed(&e),
    });
}

/// Run `f` on request `id`, then do what it says (send, open again, or finish).
fn with_request(id: u64, f: impl FnOnce(&mut Request) -> Next) {
    let Some(rc) = REQUESTS.with(|t| t.borrow().get(&id).cloned()) else { return };
    let Ok(mut r) = rc.try_borrow_mut() else {
        log::warn!("server request: an event arrived while the request was busy");
        return;
    };
    let mut next = f(&mut r);
    // Opening again may fail at once: that is a close too (`Reopen` comes once, so this ends).
    for _ in 0..4 {
        next = match next {
            Next::Wait => return,
            Next::Send(m) => match message::encode(&m) {
                Ok(b) if r.ws.as_ref().is_some_and(|(ws, _)| ws.send_with_u8_array(&b).is_ok()) => return,
                _ => r.x.closed("the message couldn't be sent"),
            },
            Next::Reopen(m) => {
                close_socket(r.ws.take());
                r.first = Some(m);
                match open_request(id, &r.x.url) {
                    Ok(ws) => {
                        r.ws = Some(ws);
                        return;
                    }
                    Err(e) => r.x.closed(&e),
                }
            }
            Next::Done(reply) => {
                close_socket(r.ws.take());
                if let (Some(w), Some(t)) = (web_sys::window(), r.timeout.take()) {
                    w.clear_timeout_with_handle(t);
                }
                r.inbox.push(Event::Net { job: r.job, reply });
                REQUESTS.with(|t| t.borrow_mut().remove(&id));
                return;
            }
        };
    }
}

/// A connection for request `id` to `url`, its events going to the request.
fn open_request(id: u64, url: &str) -> Result<(WebSocket, Handlers), String> {
    let ws = WebSocket::new(url).map_err(|e| format!("the browser won't open {url}: {}", js_error(&e)))?;
    ws.set_binary_type(BinaryType::Arraybuffer);
    let open = Closure::<dyn FnMut()>::new(move || {
        with_request(id, |r| match r.first.take() {
            Some(m) => Next::Send(m),
            None => Next::Wait,
        })
    });
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| match e.data().dyn_into::<js_sys::ArrayBuffer>() {
        Ok(buf) => {
            let bytes = js_sys::Uint8Array::new(&buf).to_vec();
            with_request(id, |r| r.x.message(&bytes));
        }
        Err(_) => with_request(id, |r| r.x.text()),
    });
    let close = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
        let reason = e.reason();
        with_request(id, |r| r.x.closed(&reason));
    });
    ws.set_onopen(Some(open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
    ws.set_onclose(Some(close.as_ref().unchecked_ref()));
    Ok((ws, Handlers { _open: open, _message: message, _close: close }))
}

/// Close a connection normally; it reports nothing more.
fn close_socket(ws: Option<(WebSocket, Handlers)>) {
    let Some((ws, _handlers)) = ws else { return };
    ws.set_onopen(None);
    ws.set_onmessage(None);
    ws.set_onclose(None);
    let _ = ws.close_with_code(CLOSE_NORMAL);
}

/// Where a redirect sign-in keeps what it needs while the tab is away (the tab's session storage).
const REDIRECT_KEY: &str = "figcraft.signIn";

fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.session_storage().ok().flatten())
}

/// The page's own address: its origin and path (what a redirect comes back to).
fn page_address() -> Option<String> {
    let l = web_sys::window()?.location();
    Some(format!("{}{}", l.origin().ok()?, l.pathname().ok()?))
}

/// The page was loaded by a provider sending it back from a sign-in this tab started: the sign-in
/// to finish (`account.signIn` with `flow: "code"` and these), or why it stopped. `None` for any
/// other page load. The answer is taken off the page's address either way, so a reload doesn't
/// send it again.
pub fn redirect_back() -> Option<Result<Back, String>> {
    let window = web_sys::window()?;
    let location = window.location();
    let search = location.search().ok()?;
    let query = search.strip_prefix('?').unwrap_or(&search);
    let storage = session_storage();
    let kept = storage.as_ref().and_then(|s| s.get_item(REDIRECT_KEY).ok().flatten());
    let back = pkce::came_back(query, kept.as_deref())?;
    if let Some(s) = &storage {
        let _ = s.remove_item(REDIRECT_KEY);
    }
    let rest = pkce::without_answer(query);
    let clean = format!(
        "{}{}{}",
        location.pathname().unwrap_or_default(),
        if rest.is_empty() { String::new() } else { format!("?{rest}") },
        location.hash().unwrap_or_default()
    );
    if let Ok(history) = window.history() {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&clean));
    }
    Some(back)
}

/// A file being put on a server from the page: the upload goes out as a request of its own; once
/// the server says where the file is, session `session` joins it as you.
struct Publishing {
    session: SessionId,
    /// Where the upload's answer arrives.
    answer: Inbox,
    server: Endpoint,
    /// Your name in the session.
    me: String,
}

/// What the page says about a file it can't put on a server.
const PUBLISH_SIGNED_IN: &str = "in the browser, files go on a server with accounts you are signed in to: sign in on its page first";

/// The browser's [`LiveLink`]: joins sessions, and puts files on a server you are signed in to;
/// hosting needs the desktop app.
pub struct NetLink {
    wake: Waker,
    /// Files on their way to a server.
    publishing: Vec<Publishing>,
    /// Each session's number in the thread-local table.
    sessions: Sessions<u64>,
    /// Answers to requests outside a session.
    requests: Inbox,
    /// The servers you are signed in to and your session tokens there (by [`Endpoint::url`]).
    sign_ins: Vec<(String, String)>,
    limits: NetLimits,
}

impl NetLink {
    /// `wake` is called whenever something arrives for the UI (egui's `request_repaint`).
    pub fn new(wake: Waker) -> Self {
        Self {
            requests: Inbox::new(wake.clone()),
            sessions: Sessions::new(wake.clone()),
            wake,
            publishing: Vec::new(),
            sign_ins: Vec::new(),
            limits: NetLimits::default(),
        }
    }

    /// Your session token on `server`, if you are signed in there.
    fn session_for(&self, server: &Endpoint) -> Option<String> {
        let url = server.url();
        self.sign_ins.iter().find(|(s, _)| *s == url).map(|(_, t)| t.clone())
    }

    /// The uploads the servers answered: each file's links, and its session joins it (or why it
    /// isn't there).
    fn published(&mut self) -> Vec<(SessionId, Event)> {
        let mut out = Vec::new();
        let mut joins = Vec::new();
        self.publishing.retain(|p| {
            let Some(reply) = p.answer.drain().into_iter().find_map(|e| match e {
                Event::Net { reply, .. } => Some(*reply),
                _ => None,
            }) else {
                return true;
            };
            match reply {
                NetReply::Account(Ok(AccountReply::Published { file })) => {
                    let member = Invite { server: p.server.clone(), file: file.id.clone(), token: String::new(), key: None };
                    let link = member.link();
                    let published = Published {
                        server: p.server.display(),
                        file: file.id,
                        name: file.name,
                        edit: link.clone(),
                        view: link.clone(),
                        owner: None,
                        expires: None,
                    };
                    out.push((p.session, Event::Published(published)));
                    joins.push((p.session, link, p.me.clone()));
                }
                NetReply::Account(Ok(AccountReply::Failed { reason }) | Err(reason)) => {
                    out.push((p.session, Event::Status(Status::Failed { reason: format!("Couldn't put the file on the server: {reason}") })));
                }
                _ => out.push((p.session, Event::Status(Status::Failed { reason: "the server didn't say where the file is".into() }))),
            }
            false
        });
        for (session, link, me) in joins {
            if let Err(reason) = self.join(session, &link, &me) {
                out.push((session, Event::Status(Status::Failed { reason })));
            }
        }
        out
    }

    fn with(&self, session: SessionId, f: impl FnOnce(&mut Driver<BrowserSocket>, Instant)) {
        if let Some(id) = self.sessions.get(session) {
            with_driver(*id, f);
        }
    }
}

impl LiveLink for NetLink {
    fn can_host(&self) -> bool {
        false
    }

    fn host(&mut self, _: SessionId, _: HostOptions) -> Result<SessionInfo, String> {
        Err("hosting a live session needs the desktop app; in the browser you can join one".into())
    }

    fn join(&mut self, session: SessionId, link: &str, name: &str) -> Result<(), String> {
        let (invite, code) = Invite::parse_join(link)?;
        if secure_page() && !invite.server.secure && !invite.loopback() {
            return Err("this page was loaded over https, and browsers block unencrypted ws:// connections; use a wss:// link (a server behind TLS), open FigCraft from an http:// address (like http://localhost:8767), or join from the desktop app".into());
        }
        let id = NEXT_ID.with(|n| n.replace(n.get() + 1));
        let inbox = self.sessions.inbox();
        let token = self.session_for(&invite.server);
        let cfg = GuestConfig { code, session: token, ..GuestConfig::new(invite, name.to_string()) };
        let driver = Driver::start(BrowserSocket { id, ws: None }, cfg, inbox.clone(), Instant::now());
        let timer = Closure::<dyn FnMut()>::new(move || with_driver(id, |d, now| d.tick(now)));
        let mut g = Guest { driver, timer, timeout: None };
        g.arm();
        if !g.driver.done() {
            GUESTS.with(|t| t.borrow_mut().insert(id, Rc::new(RefCell::new(g))));
        }
        if let Some(old) = self.sessions.insert(session, id, inbox) {
            with_driver(old, |d, now| d.leave(now));
        }
        Ok(())
    }

    /// Signed in to the server: the file goes there as yours (a request of its own), then this
    /// session joins it. Sealed files and share codes are the desktop app's for now.
    fn publish(&mut self, session: SessionId, o: PublishOptions) -> Result<(), String> {
        let (server, _) = Endpoint::parse(&o.server)?;
        if secure_page() && !server.secure && !server.loopback() {
            return Err("this page was loaded over https, and browsers block unencrypted ws:// connections: use a wss:// server".into());
        }
        let token = o.session.clone().or_else(|| self.session_for(&server)).ok_or_else(|| PUBLISH_SIGNED_IN.to_string())?;
        if o.share {
            return Err("sharing with a join code needs the desktop app; on a server with accounts people find the file there".into());
        }
        if o.sealed == Some(true) {
            return Err("end-to-end encrypted files are put on a server from the desktop app for now".into());
        }
        let snapshot = Replica::new((*o.doc).clone()).snapshot().map_err(|e| e.to_string())?;
        let answer = Inbox::new(self.wake.clone());
        let req = NetRequest::Account { server: o.server.clone(), session: token, req: AccountReq::Publish { name: o.name.clone(), snapshot } };
        start_request(0, req, answer.clone(), &self.limits);
        self.publishing.retain(|p| p.session != session);
        self.publishing.push(Publishing { session, answer, server, me: o.me });
        Ok(())
    }

    fn leave(&mut self, session: SessionId) {
        // An upload on its way: the file stays on the server, nobody joins it.
        self.publishing.retain(|p| p.session != session);
        if let Some(id) = self.sessions.remove(session) {
            with_driver(id, |d, now| d.leave(now));
        }
    }

    fn rekey(&mut self, session: SessionId, keys: &str) -> Result<(), String> {
        let ring = figcraft_collab_seal::parse_ring_fragment(keys).map_err(|_| "those aren't keys of a sealed file".to_string())?;
        let Some(id) = self.sessions.get(session).copied() else { return Err("this session is over".into()) };
        let mut out = Err("this session's file isn't end-to-end encrypted".to_string());
        with_driver(id, |d, _| {
            if let Some(k) = d.keys() {
                k.add(&ring);
                out = Ok(());
            }
        });
        out
    }

    fn presence(&mut self, session: SessionId, p: &Presence) {
        self.with(session, |d, now| d.presence(p.clone(), now));
    }

    fn send(&mut self, session: SessionId, msg: ClientMsg) {
        self.with(session, |d, now| d.send(msg, now));
    }

    fn background(&mut self, job: u64, req: NetRequest) -> bool {
        start_request(job, req, self.requests.clone(), &self.limits);
        true
    }

    fn sign_ins(&mut self, list: Vec<(String, String)>) {
        self.sign_ins = list.into_iter().filter_map(|(s, t)| Endpoint::parse(&s).ok().map(|(e, _)| (e.url(), t))).collect();
    }

    fn redirect_sign_in(&mut self, server: &str, provider: &str, flow: &Flow) -> Result<String, String> {
        let page = page_address().ok_or("this page has no address")?;
        let (pending, url) = Redirect::start(server, provider, flow, &page)?;
        let storage = session_storage().ok_or("this browser keeps nothing for the tab (session storage is off): sign in from the desktop app")?;
        storage.set_item(REDIRECT_KEY, &pending.to_text()).map_err(|e| format!("couldn't keep the sign-in for the tab: {}", js_error(&e)))?;
        let location = web_sys::window().ok_or("no window")?.location();
        location.assign(&url).map_err(|e| format!("couldn't go to the sign-in page: {}", js_error(&e)))?;
        Ok(url)
    }

    fn accounts(&mut self, req: NetRequest) -> NetReply {
        // A page can't wait for a socket: requests go out in the background only.
        req.failure()("the browser asks servers in the background only".into())
    }

    fn poll(&mut self) -> Vec<(SessionId, Event)> {
        let mut out: Vec<(SessionId, Event)> = self.requests.drain().into_iter().map(|e| (NO_SESSION, e)).collect();
        out.extend(self.published());
        out.extend(self.sessions.poll());
        out
    }
}

impl Drop for NetLink {
    fn drop(&mut self) {
        for id in self.sessions.ids() {
            self.leave(id);
        }
    }
}
