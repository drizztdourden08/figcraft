//! A sealed file's session end to end: several clients seal their batches with the same file key,
//! the session server ([`OpaqueServer`]) orders and checks them without reading them, links
//! deliver after random delays and drop now and then, and every client opens what it gets.
//! Everyone ends up with the same document, the one the server's sealed snapshot opens to: what
//! the app's sealing layer does around [`Client`], in miniature.

use std::collections::VecDeque;

use figcraft_collab::message::{self, AcceptedOf, CatchUpOf, ClientMsg, Hello, ServerMsg};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab::sim::{Rng, describe};
use figcraft_collab::{Change, Client, Limits, NoRecompute, OpaqueReplica, OpaqueServer, Outgoing, Replica};
use figcraft_doc::{Document, NodeId, NodeKind, Style, StyleKind};

use crate::{FileKey, Keyring, open_change, open_presence, seal_change, seal_presence};

const FILE: &str = "0123456789abcdef";

fn seal_all(key: &FileKey, changes: &[Change]) -> Vec<SealedChange> {
    changes.iter().map(|c| seal_change(key, FILE, c).unwrap()).collect()
}

/// Open what can be opened (a change that doesn't open is skipped, the same way everywhere).
fn open_all(ring: &Keyring, changes: &[SealedChange]) -> Vec<Change> {
    changes.iter().filter_map(|c| open_change(ring, FILE, c).ok()).collect()
}

/// What a client sends, sealed (batches and presence; everything else goes as it is).
fn seal_msg(key: &FileKey, me: u32, msg: ClientMsg) -> ClientMsg {
    match msg {
        ClientMsg::Changes { base_seq, batch_id, changes } => ClientMsg::SealedChanges { base_seq, batch_id, changes: seal_all(key, &changes) },
        ClientMsg::Presence(p) => ClientMsg::SealedPresence(seal_presence(key, FILE, me, &p).unwrap()),
        other => other,
    }
}

/// What a client gets, opened into the plain messages [`Client`] reads.
fn open_msg(ring: &Keyring, msg: ServerMsg) -> ServerMsg {
    let open_acc =
        |a: AcceptedOf<SealedChange>| AcceptedOf { seq: a.seq, author: a.author, batch_id: a.batch_id, changes: open_all(ring, &a.changes) };
    match msg {
        ServerMsg::SealedWelcome { session, client_id, seq, catch_up, processed, peers, access } => {
            let catch_up = match catch_up {
                CatchUpOf::Snapshot(s) => CatchUpOf::Snapshot(open_all(ring, &s)),
                CatchUpOf::Delta(d) => CatchUpOf::Delta(d.into_iter().map(open_acc).collect()),
            };
            ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
        }
        ServerMsg::SealedChanges(a) => ServerMsg::Changes(open_acc(a)),
        ServerMsg::SealedReject { batch_id, reason, fixes } => ServerMsg::Reject { batch_id, reason, fixes: open_all(ring, &fixes) },
        ServerMsg::SealedPresence { client_id, blob } => {
            ServerMsg::Presence { client_id, presence: open_presence(ring, FILE, client_id, &blob).unwrap_or_default() }
        }
        other => other,
    }
}

fn base() -> Document {
    let mut d = Document::new("Shared");
    let page = d.first_page().unwrap();
    for i in 0..3 {
        let f = d.create(page, NodeKind::Frame, &format!("F{i}"), i as f64 * 200.0, 0.0, 100.0, 100.0).unwrap();
        for j in 0..2 {
            d.create(f, NodeKind::Rectangle, &format!("R{i}{j}"), 0.0, j as f64 * 20.0, 10.0, 10.0).unwrap();
        }
    }
    d.take_dirty();
    d
}

/// One random edit, as a command would make it.
fn random_edit(doc: &mut Document, rng: &mut Rng) {
    let ids: Vec<NodeId> = doc.ids().collect();
    let containers: Vec<NodeId> = ids.iter().copied().filter(|i| doc.node(*i).is_some_and(|n| n.kind.is_container())).collect();
    let layers: Vec<NodeId> = ids.iter().copied().filter(|i| doc.node(*i).is_some_and(|n| !n.is_page())).collect();
    let pick = |rng: &mut Rng, v: &[NodeId]| rng.pick(v).copied();
    match rng.below(10) {
        0 | 1 => {
            if let Some(p) = pick(rng, &containers) {
                let kind = if rng.chance(0.3) { NodeKind::Frame } else { NodeKind::Rectangle };
                let _ = doc.create(p, kind, "New", rng.below(500) as f64, 0.0, 10.0, 10.0);
            }
        }
        2 => {
            if let (Some(x), Some(p)) = (pick(rng, &layers), pick(rng, &containers)) {
                let at = rng.below(4);
                let _ = doc.place(x, p, at);
            }
        }
        3 => {
            if let Some(x) = pick(rng, &layers) {
                let at = rng.below(5);
                let _ = doc.reorder(x, at);
            }
        }
        4 => {
            if let Some(x) = pick(rng, &layers).filter(|_| rng.chance(0.5)) {
                let _ = doc.remove(x);
            }
        }
        5 | 6 => {
            if let Some(n) = pick(rng, &layers).and_then(|x| doc.node_mut(x)) {
                n.name = format!("Secret name {}", rng.below(100));
                n.opacity = rng.below(11) as f32 / 10.0;
            }
        }
        7 => {
            if rng.chance(0.5) || doc.pages.len() < 2 {
                doc.add_page("Page");
            } else if let Some(p) = pick(rng, &doc.pages.clone()) {
                let _ = doc.remove(p);
            }
        }
        8 => {
            if doc.pages.len() > 1 {
                doc.pages.rotate_left(1);
            }
        }
        _ => {
            let id = format!("style{}", rng.below(5));
            match doc.styles.iter().position(|s| s.id == id) {
                Some(i) if rng.chance(0.4) => {
                    doc.styles.remove(i);
                }
                Some(i) => doc.styles[i].name = format!("Renamed {}", rng.below(100)),
                None => doc.styles.push(Style {
                    id,
                    name: "S".into(),
                    description: String::new(),
                    kind: StyleKind::Paint { paints: vec![] },
                    bound: Default::default(),
                }),
            }
            if doc.styles.len() > 1 && rng.chance(0.3) {
                doc.styles.rotate_left(1);
            }
        }
    }
    doc.take_dirty();
}

/// One direction of one connection: encoded messages, each due at a time.
type Link = VecDeque<(u64, Vec<u8>)>;

/// A sealed session in memory.
struct Sim {
    key: FileKey,
    ring: Keyring,
    server: OpaqueServer,
    clients: Vec<Client>,
    ids: Vec<u32>,
    hellos: Vec<Hello>,
    online: Vec<bool>,
    /// Encoded messages to the server (0) and to the client (1), each due at a time.
    links: [Vec<Link>; 2],
    rng: Rng,
    now: u64,
}

impl Sim {
    fn new(n: usize, seed: u64) -> Sim {
        let key = FileKey::generate().unwrap();
        let ring = Keyring::from(key.clone());
        // Published: the app seals its document's snapshot for the file id.
        let snapshot = seal_all(&key, &Replica::new(base()).snapshot().unwrap());
        let server =
            OpaqueServer::with_state(OpaqueReplica::from_snapshot(&snapshot).unwrap(), "", Limits { max_log_batches: 20, ..Limits::default() });
        let mut sim = Sim {
            key,
            ring,
            server,
            clients: Vec::new(),
            ids: Vec::new(),
            hellos: Vec::new(),
            online: Vec::new(),
            links: [Vec::new(), Vec::new()],
            rng: Rng::new(seed),
            now: 0,
        };
        for i in 0..n {
            let ClientMsg::Hello(mut hello) = Client::hello(FILE, "", &format!("P{i}"), "#3366FF") else { panic!() };
            hello.client_version.push_str(" sealed");
            let (id, out) = sim.server.join(hello.clone()).unwrap();
            let mut client = None;
            let mut rest = Vec::new();
            for o in out {
                match o {
                    Outgoing::To(to, w @ ServerMsg::SealedWelcome { .. }) if to == id => client = Some(Client::join(open_msg(&sim.ring, w)).unwrap()),
                    other => rest.push(other),
                }
            }
            sim.clients.push(client.unwrap());
            sim.ids.push(id);
            sim.hellos.push(hello);
            sim.online.push(true);
            sim.links[0].push(VecDeque::new());
            sim.links[1].push(VecDeque::new());
            sim.route(rest);
        }
        sim
    }

    fn send(&mut self, dir: usize, i: usize, bytes: Vec<u8>) {
        let delay = 1 + self.rng.next_u64() % 10;
        let q = &mut self.links[dir][i];
        let due = (self.now + delay).max(q.back().map_or(0, |(d, _)| *d));
        q.push_back((due, bytes));
    }

    fn send_up(&mut self, i: usize, msgs: Vec<ClientMsg>) {
        if !self.online[i] {
            return;
        }
        for m in msgs {
            let sealed = seal_msg(&self.key, self.ids[i], m);
            let bytes = message::encode(&sealed).unwrap();
            self.send(0, i, bytes);
        }
    }

    fn route(&mut self, out: Vec<Outgoing>) {
        for o in out {
            let (msg, to): (ServerMsg, Vec<usize>) = match o {
                Outgoing::To(id, m) => (m, self.ids.iter().position(|c| *c == id).into_iter().collect()),
                Outgoing::All(m) => (m, (0..self.clients.len()).collect()),
                Outgoing::Others(id, m) => (m, (0..self.clients.len()).filter(|i| self.ids[*i] != id).collect()),
            };
            let to: Vec<usize> = to.into_iter().filter(|t| self.online[*t]).collect();
            for t in to {
                let bytes = message::encode(&msg).unwrap();
                self.send(1, t, bytes);
            }
        }
    }

    fn edit(&mut self, i: usize) {
        let mut doc = self.clients[i].document().clone();
        let mut rng = Rng::new(self.rng.next_u64());
        random_edit(&mut doc, &mut rng);
        let msg = self.clients[i].edit(&doc).unwrap();
        self.send_up(i, msg.into_iter().collect());
    }

    fn disconnect(&mut self, i: usize) {
        if !self.online[i] {
            return;
        }
        self.links[0][i].clear();
        self.links[1][i].clear();
        self.online[i] = false;
        self.clients[i].disconnect();
        let out = self.server.leave(self.ids[i]);
        self.route(out);
    }

    fn reconnect(&mut self, i: usize) {
        if self.online[i] {
            return;
        }
        let ClientMsg::Hello(hello) = self.clients[i].reconnect(self.hellos[i].clone()) else { panic!() };
        let (id, out) = self.server.join(hello).unwrap();
        self.ids[i] = id;
        self.online[i] = true;
        self.route(out);
    }

    fn step(&mut self) -> bool {
        let next = (0..2).flat_map(|d| self.links[d].iter().enumerate().filter_map(move |(i, q)| q.front().map(|(due, _)| (*due, d, i)))).min();
        let Some((due, dir, i)) = next else { return false };
        self.now = self.now.max(due);
        let Some((_, bytes)) = self.links[dir][i].pop_front() else { return false };
        if dir == 0 {
            let msg: ClientMsg = message::decode(&bytes, usize::MAX).unwrap();
            assert!(!matches!(msg, ClientMsg::Changes { .. } | ClientMsg::Presence(_)), "only sealed batches and presence go up");
            let out = self.server.receive(self.ids[i], msg);
            self.route(out);
        } else {
            let msg: ServerMsg = message::decode(&bytes, usize::MAX).unwrap();
            let replies = self.clients[i].receive(open_msg(&self.ring, msg), &NoRecompute).unwrap();
            self.send_up(i, replies);
        }
        true
    }

    fn settle(&mut self) {
        let mut n = 0;
        while self.step() {
            n += 1;
            assert!(n < 200_000, "still busy");
        }
    }

    /// Every client holds what the server's sealed snapshot opens to.
    fn converged(&self) -> Result<(), String> {
        let opened = Replica::from_snapshot(&open_all(&self.ring, &self.server.synced().snapshot())).map_err(|e| e.to_string())?;
        for c in &self.clients {
            if c.pending() > 0 || c.seq() != self.server.seq() {
                return Err(format!("client {} at seq {} with {} pending; server at {}", c.id(), c.seq(), c.pending(), self.server.seq()));
            }
            if c.view() != &opened || c.confirmed() != &opened {
                return Err(format!("client {}: {}", c.id(), describe(&opened, c.view())));
            }
        }
        Ok(())
    }
}

#[test]
fn sealed_clients_converge_through_a_server_that_cant_read_them() {
    for seed in 0..40 {
        let mut sim = Sim::new(3, seed);
        for _ in 0..60 {
            let i = sim.rng.below(3);
            match sim.rng.below(12) {
                0 => sim.disconnect(i),
                1 => sim.reconnect(i),
                2 if sim.online[i] => {
                    let msgs = sim.clients[i].undo(&NoRecompute).unwrap();
                    sim.send_up(i, msgs);
                }
                3 => {
                    let p = figcraft_collab::Presence { cursor: Some((NodeId(1), 1.0, 2.0)), ..Default::default() };
                    sim.send_up(i, vec![ClientMsg::Presence(p)]);
                }
                _ => sim.edit(i),
            }
            for _ in 0..sim.rng.below(4) {
                sim.step();
            }
        }
        for i in 0..3 {
            sim.reconnect(i);
        }
        sim.settle();
        if let Err(e) = sim.converged() {
            panic!("seed {seed}: {e}");
        }
        assert!(sim.server.seq() > 10, "seed {seed}: only {} batches", sim.server.seq());
    }
}
