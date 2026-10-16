//! Sealed (end-to-end encrypted) files on the server: `[e2e]` modes, publishing, the session over
//! sealed changes, persistence across a crash and compaction, plain and sealed messages kept
//! apart, and a canary: marker strings put in every kind of content never reach the server's disk
//! or memory in the clear.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use figcraft_auth::{AuthConfig, E2eMode};
use figcraft_collab::message::{
    self, AcceptedOf, Access, Admin, AdminReply, CatchUpOf, ClientMsg, Hello, LibraryReply, LibraryReq, Manage, OpenLibrary, PROTOCOL, ServerMsg,
    Signal,
};
use figcraft_collab::sealed::{Sealed, SealedChange, parse_sealed_name};
use figcraft_collab::{Change, Client, FileServer, NoRecompute, Outgoing, Replica};
use figcraft_collab_net::hub::Backend;
use figcraft_collab_seal::{FileKey, Keyring, Slot, open, open_change, seal, seal_change, seal_presence, seal_signal};
use figcraft_doc::{Comment, Document, Message, NodeKind, Style, StyleKind, TextData};

use crate::accounts::Accounts;
use crate::disk::{META, SNAPSHOT};
use crate::store::{FILES, NAME_PLAIN, NAME_SEALED, NO_SEALED, NewFile, SEALED_ONLY, Store, StoreConfig};
use crate::test_util::{Raw, TempDir, config, key};
use figcraft_collab::server::{NEEDS_SEALED, SEALED_FILE};

const FILE: &str = "00112233aabbccdd";

/// What must never be found on the server in the clear.
const MARKERS: [&str; 7] = [
    "CANARY-TEXT-7f3a",
    "CANARY-LAYER-1b9c",
    "CANARY-STYLE-55d2",
    "CANARY-COMMENT-a0e4",
    "CANARY-CHAT-c311",
    "CANARY-FILENAME-9e77",
    "CANARY-EDIT-4c1d",
];

fn store(dir: &Path, cfg: StoreConfig, mode: E2eMode) -> Store {
    let mut s = Store::open(dir, cfg).unwrap();
    s.set_accounts(Arc::new(Accounts::offline(dir, &AuthConfig::default(), mode).unwrap()));
    s
}

/// A document holding every marker but the chat's and the edit's.
fn secret_doc() -> Document {
    let mut d = Document::new("Doc");
    let page = d.first_page().unwrap();
    let f = d.create(page, NodeKind::Frame, MARKERS[1], 0.0, 0.0, 200.0, 100.0).unwrap();
    d.create(f, NodeKind::Text(TextData::new(MARKERS[0])), "Label", 0.0, 0.0, 100.0, 20.0).unwrap();
    d.styles.push(Style {
        id: "S:1".into(),
        name: MARKERS[2].into(),
        description: String::new(),
        kind: StyleKind::Paint { paints: vec![] },
        bound: Default::default(),
    });
    d.comments.push(Comment {
        id: 7,
        page,
        x: 1.0,
        y: 2.0,
        anchor: None,
        first: Message::new("Ada", MARKERS[3], 0),
        resolved: false,
        replies: Vec::new(),
        read_by: None,
    });
    d.repair();
    d.take_dirty();
    d
}

fn sealed_snapshot(key: &FileKey, file: &str, d: Document) -> Vec<SealedChange> {
    Replica::new(d).snapshot().unwrap().iter().map(|c| seal_change(key, file, c).unwrap()).collect()
}

fn sealed_name(key: &FileKey, file: &str, name: &str) -> Sealed {
    seal(key, file, &Slot::Meta { what: "name".into() }, name.as_bytes()).unwrap()
}

fn open_all(ring: &Keyring, changes: &[SealedChange]) -> Vec<Change> {
    changes.iter().map(|c| open_change(ring, FILE, c).unwrap()).collect()
}

/// A sealed message opened into the plain one a [`Client`] reads.
fn opened(ring: &Keyring, msg: ServerMsg) -> ServerMsg {
    let acc = |a: AcceptedOf<SealedChange>| AcceptedOf { seq: a.seq, author: a.author, batch_id: a.batch_id, changes: open_all(ring, &a.changes) };
    match msg {
        ServerMsg::SealedWelcome { session, client_id, seq, catch_up, processed, peers, access } => {
            let catch_up = match catch_up {
                CatchUpOf::Snapshot(s) => CatchUpOf::Snapshot(open_all(ring, &s)),
                CatchUpOf::Delta(d) => CatchUpOf::Delta(d.into_iter().map(acc).collect()),
            };
            ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
        }
        ServerMsg::SealedChanges(a) => ServerMsg::Changes(acc(a)),
        ServerMsg::SealedReject { batch_id, reason, fixes } => ServerMsg::Reject { batch_id, reason, fixes: open_all(ring, &fixes) },
        other => other,
    }
}

fn sealed_batch(key: &FileKey, msg: ClientMsg) -> ClientMsg {
    match msg {
        ClientMsg::Changes { base_seq, batch_id, changes } => {
            ClientMsg::SealedChanges { base_seq, batch_id, changes: changes.iter().map(|c| seal_change(key, FILE, c).unwrap()).collect() }
        }
        other => other,
    }
}

fn hello(token: &str) -> Hello {
    let ClientMsg::Hello(mut h) = Client::hello(FILE, token, "Ada", "#FF8800") else { panic!() };
    h.client_version.push_str(" sealed");
    h
}

/// A sealing client in `server` (as the hub would let it in).
fn join(server: &mut FileServer, ring: &Keyring) -> Client {
    let (_, out) = server.join_as(hello(""), Access::Edit).unwrap();
    let Some(Outgoing::To(_, w)) = out.into_iter().next() else { panic!() };
    Client::join(opened(ring, w)).unwrap()
}

/// Rename the frame through `c`, sealed; the server takes the batch.
fn rename(server: &mut FileServer, key: &FileKey, c: &mut Client, name: &str) {
    let ring = Keyring::from(key.clone());
    let mut d = c.document().clone();
    let frame = d.ids().find(|id| d.node(*id).is_some_and(|n| matches!(n.kind, NodeKind::Frame))).unwrap();
    d.node_mut(frame).unwrap().name = name.into();
    let m = c.edit(&d).unwrap().unwrap();
    for o in server.receive(c.id(), sealed_batch(key, m)) {
        if let Outgoing::All(m) | Outgoing::To(_, m) = o {
            c.receive(opened(&ring, m), &NoRecompute).unwrap();
        }
    }
}

fn frame_name(c: &Client) -> String {
    let d = c.document();
    d.nodes().find(|n| matches!(n.kind, NodeKind::Frame)).unwrap().name.clone()
}

/// Every file under `dir`, read.
fn all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else {
            out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn hits(bytes: &[u8]) -> Vec<&'static str> {
    MARKERS.iter().copied().filter(|m| bytes.windows(m.len()).any(|w| w == m.as_bytes())).collect()
}

fn publish_sealed(s: &mut Store, key: &FileKey) -> String {
    let snapshot = sealed_snapshot(key, FILE, secret_doc());
    let name = sealed_name(key, FILE, MARKERS[5]);
    let (info, _, _) = s.publish_new(NewFile::Sealed { file: FILE, name: &name, snapshot: &snapshot }).unwrap();
    assert_eq!(info.id, FILE, "the id the app sealed for");
    // Listings show the sealed name, which the app opens.
    let listed = parse_sealed_name(&info.name).unwrap();
    assert_eq!(open(&Keyring::from(key.clone()), FILE, &Slot::Meta { what: "name".into() }, &listed).unwrap(), MARKERS[5].as_bytes());
    info.id
}

#[test]
fn e2e_modes_decide_which_files_are_kept() {
    let key = FileKey::generate().unwrap();
    let snapshot = sealed_snapshot(&key, FILE, secret_doc());
    let name = sealed_name(&key, FILE, "N");
    let sealed = NewFile::Sealed { file: FILE, name: &name, snapshot: &snapshot };
    let plain_snap = Replica::new(secret_doc()).snapshot().unwrap();
    let plain = NewFile::Plain { name: "P", snapshot: &plain_snap };

    let dir = TempDir::new("e2e-off");
    let mut s = store(dir.path(), config(dir.path()).store(), E2eMode::Off);
    assert_eq!(s.publish_new(sealed).unwrap_err(), NO_SEALED);
    assert!(s.publish_new(plain).is_ok());

    let dir = TempDir::new("e2e-required");
    let mut s = store(dir.path(), config(dir.path()).store(), E2eMode::Required);
    assert_eq!(s.publish_new(plain).unwrap_err(), SEALED_ONLY);
    assert!(s.publish_new(sealed).is_ok());
    // An id is the app's to choose, once.
    assert!(s.publish_new(sealed).unwrap_err().contains("taken"));
    let bad = NewFile::Sealed { file: "../x", name: &name, snapshot: &snapshot };
    assert!(s.publish_new(bad).unwrap_err().contains("16 random"));

    let dir = TempDir::new("e2e-optional");
    let mut s = store(dir.path(), config(dir.path()).store(), E2eMode::Optional);
    let (p, _, _) = s.publish_new(plain).unwrap();
    s.publish_new(sealed).unwrap();
    // Names: a sealed file's is renamed sealed, a plain file's in the clear.
    assert_eq!(s.rename(FILE, "Clear").unwrap_err(), NAME_SEALED);
    assert_eq!(s.rename_sealed(&p.id, &name).unwrap_err(), NAME_PLAIN);
    let renamed = sealed_name(&key, FILE, "Renamed");
    s.rename_sealed(FILE, &renamed).unwrap();
    let listed = s.list(&|_| None).into_iter().find(|f| f.id == FILE).unwrap();
    assert_eq!(parse_sealed_name(&listed.name), Some(renamed));
    // A plain or sealed file opens as its kind of session.
    assert!(s.open(FILE).unwrap().is_sealed());
    assert!(!s.open(&p.id).unwrap().is_sealed());
    // A sealed file's team library is kept as it came (the apps check it after opening it).
    let lib = seal(&key, FILE, &Slot::Meta { what: "library".into() }, b"not an archive the server could read").unwrap();
    assert_eq!(s.publish_library(FILE, lib.as_bytes()).unwrap(), 1);
    assert_eq!(s.publish_library(FILE, lib.as_bytes()).unwrap(), 2);
    assert!(s.publish_library(&p.id, lib.as_bytes()).is_err(), "a plain file's library is still checked");
}

#[test]
fn a_sealed_file_survives_a_crash_and_compacts() {
    let dir = TempDir::new("sealed-crash");
    let key = FileKey::generate().unwrap();
    let ring = Keyring::from(key.clone());
    let c = StoreConfig { compact_after: 1000, ..config(dir.path()).store() };
    let mut s = store(dir.path(), c.clone(), E2eMode::Optional);
    publish_sealed(&mut s, &key);
    let mut server = s.open(FILE).unwrap();
    let mut a = join(&mut server, &ring);
    s.changed(FILE, &mut server);
    for i in 0..5 {
        rename(&mut server, &key, &mut a, &format!("{} {i}", MARKERS[6]));
        s.changed(FILE, &mut server);
    }
    s.flush();
    assert_eq!(frame_name(&a), format!("{} 4", MARKERS[6]));
    // In memory: the state and the journal the store logs hold no marker (a probe edit on a copy).
    let o = server.sealed().unwrap();
    assert!(hits(&message::encode(&o.state().unwrap()).unwrap()).is_empty());
    let (mut probe, mut pa) = (server.clone(), a.clone());
    rename(&mut probe, &key, &mut pa, MARKERS[6]);
    let journal = probe.sealed_mut().unwrap().take_journal();
    assert!(!journal.is_empty());
    assert!(hits(&message::encode(&journal).unwrap()).is_empty());
    let state = o.synced().snapshot();
    let (seq, session) = (o.seq(), o.session());
    // A crash: no compaction, nothing else written.
    drop(s);
    let folder = dir.path().join(FILES).join(FILE);
    let snap = std::fs::read(folder.join(SNAPSHOT)).unwrap();
    assert_eq!(snap.get(4), Some(&2), "a sealed file's snapshot format");
    assert!(std::fs::read_to_string(folder.join(META)).unwrap().contains("\"sealed\": true"));
    let mut s = store(dir.path(), c, E2eMode::Optional);
    assert!(s.problems().is_empty(), "{:?}", s.problems());
    let mut server = s.open(FILE).unwrap();
    assert_eq!(server.sealed().unwrap().synced().snapshot(), state, "the log brought it back");
    assert_eq!(server.seq(), seq);
    // The client resumes into the same session and catches up.
    a.disconnect();
    let ClientMsg::Hello(h) = a.reconnect(hello("")) else { panic!() };
    assert_eq!(h.resume.unwrap().session, session);
    let (_, out) = server.join_as(h, Access::Edit).unwrap();
    let Some(Outgoing::To(_, w)) = out.into_iter().next() else { panic!() };
    assert!(matches!(w, ServerMsg::SealedWelcome { catch_up: CatchUpOf::Delta(_), .. }));
    a.receive(opened(&ring, w), &NoRecompute).unwrap();
    rename(&mut server, &key, &mut a, "After");
    s.changed(FILE, &mut server);
    let state = server.sealed().unwrap().synced().snapshot();
    // Compaction when everyone left: a new generation, the same state.
    let generation = crate::disk::check_snapshot(&std::fs::read(folder.join(SNAPSHOT)).unwrap()).unwrap();
    server.leave(a.id());
    assert!(s.idle(FILE, &mut server));
    assert!(crate::disk::check_snapshot(&std::fs::read(folder.join(SNAPSHOT)).unwrap()).unwrap() > generation);
    drop(s);
    let mut s = store(dir.path(), config(dir.path()).store(), E2eMode::Optional);
    assert_eq!(s.open(FILE).unwrap().sealed().unwrap().synced().snapshot(), state);
    drop(s);
    // Nothing on disk reads in the clear.
    for (path, bytes) in all_bytes(dir.path()) {
        assert!(hits(&bytes).is_empty(), "{path}: {:?}", hits(&bytes));
    }
}

/// Read until `f` picks a message.
fn until<T>(raw: &mut Raw, mut f: impl FnMut(ServerMsg) -> Option<T>) -> T {
    for _ in 0..50 {
        if let Some(t) = f(raw.next()) {
            return t;
        }
    }
    panic!("not told");
}

#[test]
fn canary_a_sealed_session_leaves_nothing_readable_on_the_server() {
    let dir = TempDir::new("canary");
    let mut cfg = config(dir.path());
    cfg.e2e.mode = "optional".into();
    let mut running = crate::start(&cfg).unwrap();
    let addr = running.addr();
    let key = FileKey::generate().unwrap();
    let ring = Keyring::from(key.clone());
    // Published with the server key.
    let mut admin = Raw::connect(addr);
    admin.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: key_of(dir.path()), client_version: String::new() }));
    assert!(matches!(admin.next(), ServerMsg::Admin(r) if *r == AdminReply::Ready));
    let snapshot = sealed_snapshot(&key, FILE, secret_doc());
    admin.send(&ClientMsg::Admin(Admin::PublishSealed { file: FILE.into(), name: sealed_name(&key, FILE, MARKERS[5]), snapshot }));
    let ServerMsg::Admin(r) = admin.next() else { panic!() };
    let AdminReply::Published { edit, .. } = *r else { panic!("{r:?}") };
    // An app that doesn't know sealed files is told so.
    let mut old = Raw::connect(addr);
    let ClientMsg::Hello(plain) = Client::hello(FILE, &edit.token, "Old", "#000000") else { panic!() };
    old.send(&ClientMsg::Hello(plain));
    assert_eq!(old.next(), ServerMsg::Refused { reason: NEEDS_SEALED.into() });
    // Two sealing clients.
    let mut a = Raw::connect(addr);
    a.send(&ClientMsg::Hello(hello(&edit.token)));
    let mut ca = until(&mut a, |m| matches!(m, ServerMsg::SealedWelcome { .. }).then(|| Client::join(opened(&ring, m)).unwrap()));
    let mut b = Raw::connect(addr);
    b.send(&ClientMsg::Hello(hello(&edit.token)));
    let cb = until(&mut b, |m| matches!(m, ServerMsg::SealedWelcome { .. }).then(|| Client::join(opened(&ring, m)).unwrap()));
    assert!(cb.document().nodes().any(|n| matches!(&n.kind, NodeKind::Text(t) if t.characters == MARKERS[0])), "the app opens the text");
    // A plain batch is refused; a sealed one goes to everyone.
    a.send(&ClientMsg::Changes { base_seq: 0, batch_id: 99, changes: Vec::new() });
    until(&mut a, |m| matches!(m, ServerMsg::Reject { batch_id: 99, ref reason, .. } if reason == SEALED_FILE).then_some(()));
    let mut d = ca.document().clone();
    let frame = d.ids().find(|id| d.node(*id).is_some_and(|n| matches!(n.kind, NodeKind::Frame))).unwrap();
    d.node_mut(frame).unwrap().name = MARKERS[6].into();
    let m = ca.edit(&d).unwrap().unwrap();
    a.send(&sealed_batch(&key, m));
    let got = until(&mut b, |m| match m {
        ServerMsg::SealedChanges(acc) => Some(acc),
        _ => None,
    });
    let opened_changes = open_all(&ring, &got.changes);
    assert!(opened_changes.iter().any(|c| matches!(c, Change::Set { value, .. } if value.0 == MARKERS[6])));
    // Presence and chat go sealed; a spotlight plain.
    a.send(&ClientMsg::SealedPresence(seal_presence(&key, FILE, ca.id(), &figcraft_collab::Presence::default()).unwrap()));
    a.send(&ClientMsg::SealedSignal(seal_signal(&key, FILE, ca.id(), &Signal::chat(MARKERS[4])).unwrap()));
    let chat = until(&mut b, |m| match m {
        ServerMsg::SealedSignal { blob, .. } => Some(blob),
        _ => None,
    });
    assert_eq!(figcraft_collab_seal::open_signal(&ring, FILE, ca.id(), &chat).unwrap(), Signal::chat(MARKERS[4]));
    a.send(&ClientMsg::Signal(Signal::spotlight(true)));
    until(&mut b, |m| matches!(m, ServerMsg::Signal { ref signal, .. } if *signal == Signal::spotlight(true)).then_some(()));
    // A team library, sealed.
    let mut lib = Raw::connect(addr);
    lib.send(&ClientMsg::OpenLibrary(OpenLibrary {
        protocol: PROTOCOL,
        file: FILE.into(),
        token: edit.token.clone(),
        client_version: String::new(),
    }));
    assert!(matches!(lib.next(), ServerMsg::Library(r) if matches!(*r, LibraryReply::Ready { .. })));
    let archive = seal(&key, FILE, &Slot::Meta { what: "library".into() }, MARKERS.join(" ").as_bytes()).unwrap();
    lib.send(&ClientMsg::Library(LibraryReq::Publish { archive: archive.into_bytes() }));
    assert!(matches!(lib.next(), ServerMsg::Library(r) if matches!(*r, LibraryReply::Published { version: 1 })));
    // Let the edit be logged, then stop (open files are compacted) and look at every byte kept.
    ca.receive(opened(&ring, ServerMsg::SealedChanges(got)), &NoRecompute).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drop((a, b, lib, admin, old));
    running.stop();
    assert_eq!(hits(format!("x{}y", MARKERS[4]).as_bytes()), [MARKERS[4]], "the scan finds a marker in the clear");
    let files = all_bytes(dir.path());
    assert!(files.iter().any(|(p, _)| p.contains(FILE)), "the file is there");
    for (path, bytes) in files {
        assert!(hits(&bytes).is_empty(), "{path}: {:?}", hits(&bytes));
    }
}

fn key_of(dir: &Path) -> String {
    key(dir)
}
