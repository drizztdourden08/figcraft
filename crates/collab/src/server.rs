//! The session server for one file: the single authority that orders, validates and rebroadcasts
//! batches. A pure state machine: the transport feeds it messages and delivers what it returns.
//!
//! [`SessionServer`] is generic over the state it keeps ([`Synced`]): a plain file's [`Replica`]
//! ([`Server`]) or a sealed file's [`OpaqueReplica`] ([`OpaqueServer`]), which checks a batch's
//! structure without reading its values. Ordering, id spaces, the log for reconnecting clients,
//! the journal, presence and signals are the same code for both.

use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map};

use figcraft_doc::{Document, NodeId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::change::{Change, Entry, Prop, Target};
use crate::message::{
    AcceptedOf, Access, CatchUpOf, ClientMsg, Hello, PROTOCOL, Peer, Presence, Processed, ServerMsg, Signal, reads_sealed, reads_signals,
    sealed_rules,
};
use crate::opaque::OpaqueReplica;
use crate::replica::{Mode, Replica, create_change};
use crate::sealed::{EntryKey, SealedChange};
use crate::{Error, Limits, docprops, same_secret};

/// The synced state a [`SessionServer`] keeps for one file: what it applies batches to, checks
/// them against, snapshots and restores.
pub trait Synced: Clone + std::fmt::Debug + Sized {
    /// What a batch is made of.
    type Change: Clone + std::fmt::Debug + PartialEq + Serialize + DeserializeOwned;
    /// A document-level entry, as the id-space checks see it.
    type Entry: Clone + std::fmt::Debug + Ord + Serialize + DeserializeOwned;
    /// A sealed file's state (its messages are the sealed ones).
    const SEALED: bool;

    /// Rebuild the state from a [`snapshot`](Self::snapshot).
    fn from_snapshot(changes: &[Self::Change]) -> Result<Self, Error>;
    /// The whole state as changes that build it from nothing.
    fn snapshot(&self) -> Result<Vec<Self::Change>, Error>;
    /// Whether node `id` exists.
    fn contains(&self, id: NodeId) -> bool;
    /// How many nodes there are.
    fn node_count(&self) -> usize;
    /// The highest client id space the state's ids use (session client ids start above it).
    fn highest_id_space(&self) -> u32;
    /// The node a change creates, if it does.
    fn created(change: &Self::Change) -> Option<NodeId>;
    /// Apply a batch with every check the server makes (on failure the state is left partly
    /// changed: apply to a clone). The nodes deleted, subtrees included.
    fn apply_strict(&mut self, changes: &[Self::Change]) -> Result<Vec<NodeId>, Error>;
    /// The entries with an id space a batch added or removed, going from `self` to `after`, each
    /// with whether it is there afterwards.
    fn entries_changed(&self, after: &Self, changes: &[Self::Change]) -> Vec<(Self::Entry, bool)>;
    /// The client id space of an entry's id, if it has one.
    fn entry_space(entry: &Self::Entry) -> Option<u32>;
    /// What the entry is, for messages.
    fn describe_entry(entry: &Self::Entry) -> String;
    /// The current values of what a refused batch touched (see [`ServerMsg::Reject`]).
    fn fixes(&self, changes: &[Self::Change]) -> Result<Vec<Self::Change>, Error>;
    /// About how many bytes `changes` take in memory.
    fn weight(changes: &[Self::Change]) -> usize;
    /// The welcome message.
    fn welcome(welcome: Welcome<Self::Change>) -> ServerMsg;
    /// An accepted batch, to everyone.
    fn accepted(acc: AcceptedOf<Self::Change>) -> ServerMsg;
    /// A refused batch, to its author.
    fn rejected(batch_id: u64, reason: String, fixes: Vec<Self::Change>) -> ServerMsg;
    /// The batch in `msg`, when it is one of this kind of file (`Err`: the message as it was).
    fn batch(msg: ClientMsg) -> Result<Batch<Self::Change>, Box<ClientMsg>>;
}

/// What a welcome says ([`ServerMsg::Welcome`], [`ServerMsg::SealedWelcome`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Welcome<C> {
    pub session: u64,
    pub client_id: u32,
    pub seq: u64,
    pub catch_up: CatchUpOf<C>,
    pub processed: Processed,
    pub peers: Vec<Peer>,
    pub access: Access,
}

/// One client batch: made on top of server state `base_seq`, the client's `batch_id`.
#[derive(Clone, Debug, PartialEq)]
pub struct Batch<C> {
    pub base_seq: u64,
    pub batch_id: u64,
    pub changes: Vec<C>,
}

impl Synced for Replica {
    type Change = Change;
    type Entry = Entry;
    const SEALED: bool = false;

    fn from_snapshot(changes: &[Change]) -> Result<Replica, Error> {
        Replica::from_snapshot(changes)
    }

    fn snapshot(&self) -> Result<Vec<Change>, Error> {
        Replica::snapshot(self)
    }

    fn contains(&self, id: NodeId) -> bool {
        self.document().contains(id)
    }

    fn node_count(&self) -> usize {
        self.document().node_count()
    }

    fn highest_id_space(&self) -> u32 {
        self.document().highest_id_space()
    }

    fn created(change: &Change) -> Option<NodeId> {
        match change {
            Change::Create { id, .. } => Some(*id),
            _ => None,
        }
    }

    fn apply_strict(&mut self, changes: &[Change]) -> Result<Vec<NodeId>, Error> {
        self.apply(changes, Mode::Strict).map(|a| a.deleted)
    }

    /// The document-level entries (styles, variables, collections, comments) a batch adds or
    /// removes, put or removed one by one or in a whole list (the fallback for lists whose ids
    /// aren't unique).
    fn entries_changed(&self, after: &Replica, changes: &[Change]) -> Vec<(Entry, bool)> {
        let (before, after) = (self.document(), after.document());
        let mut touched: BTreeSet<Entry> = BTreeSet::new();
        for c in changes {
            match c {
                Change::Put { entry, .. } | Change::Remove { entry } if entry.id_space().is_some() => {
                    touched.insert(entry.clone());
                }
                Change::SetDoc { prop, .. } => {
                    if let Some(Ok(family)) = prop.list() {
                        touched.extend(docprops::entries(before, family));
                        touched.extend(docprops::entries(after, family));
                    }
                }
                _ => {}
            }
        }
        touched
            .into_iter()
            .filter_map(|entry| {
                let (was, now) = (docprops::has(before, &entry), docprops::has(after, &entry));
                (was != now).then_some((entry, now))
            })
            .collect()
    }

    fn entry_space(entry: &Entry) -> Option<u32> {
        entry.id_space()
    }

    fn describe_entry(entry: &Entry) -> String {
        entry.describe()
    }

    /// Nodes that don't exist are deleted, deleted subtrees come back whole, edited properties get
    /// their current values, document-level data likewise.
    fn fixes(&self, changes: &[Change]) -> Result<Vec<Change>, Error> {
        let doc = self.document();
        let mut props: BTreeMap<NodeId, BTreeSet<Prop>> = BTreeMap::new();
        let mut gone: BTreeSet<NodeId> = BTreeSet::new();
        let mut out = Vec::new();
        for c in changes {
            match c {
                Change::Create { id, .. } => {
                    props.entry(*id).or_default().extend(Prop::FIELDS.iter().copied().chain([Prop::Parent, Prop::Position]));
                }
                Change::Set { id, prop, .. } => {
                    props.entry(*id).or_default().insert(*prop);
                }
                Change::Delete { id } => {
                    gone.insert(*id);
                }
                other => {
                    if let Some(fix) = docprops::current(doc, other)?
                        && !out.contains(&fix)
                    {
                        out.push(fix);
                    }
                }
            }
        }
        let mut nodes = Vec::new();
        for (id, ps) in props {
            if !doc.contains(id) {
                nodes.push(Change::Delete { id });
                continue;
            }
            for p in ps {
                let t = Target::Node(id, p);
                nodes.extend(t.write(self.value(&t)?.as_ref()));
            }
        }
        for id in gone {
            match doc.node(id) {
                Some(_) => {
                    for d in doc.subtree(id) {
                        if let Some(n) = doc.node(d) {
                            nodes.push(create_change(n, self.key(d))?);
                        }
                    }
                }
                None => nodes.push(Change::Delete { id }),
            }
        }
        nodes.extend(out);
        Ok(nodes)
    }

    fn weight(changes: &[Change]) -> usize {
        weight(changes)
    }

    fn welcome(w: Welcome<Change>) -> ServerMsg {
        let Welcome { session, client_id, seq, catch_up, processed, peers, access } = w;
        ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
    }

    fn accepted(acc: AcceptedOf<Change>) -> ServerMsg {
        ServerMsg::Changes(acc)
    }

    fn rejected(batch_id: u64, reason: String, fixes: Vec<Change>) -> ServerMsg {
        ServerMsg::Reject { batch_id, reason, fixes }
    }

    fn batch(msg: ClientMsg) -> Result<Batch<Change>, Box<ClientMsg>> {
        match msg {
            ClientMsg::Changes { base_seq, batch_id, changes } => Ok(Batch { base_seq, batch_id, changes }),
            other => Err(Box::new(other)),
        }
    }
}

impl Synced for OpaqueReplica {
    type Change = SealedChange;
    type Entry = EntryKey;
    const SEALED: bool = true;

    fn from_snapshot(changes: &[SealedChange]) -> Result<OpaqueReplica, Error> {
        OpaqueReplica::from_snapshot(changes)
    }

    fn snapshot(&self) -> Result<Vec<SealedChange>, Error> {
        Ok(OpaqueReplica::snapshot(self))
    }

    fn contains(&self, id: NodeId) -> bool {
        OpaqueReplica::contains(self, id)
    }

    fn node_count(&self) -> usize {
        OpaqueReplica::node_count(self)
    }

    fn highest_id_space(&self) -> u32 {
        OpaqueReplica::highest_id_space(self)
    }

    fn created(change: &SealedChange) -> Option<NodeId> {
        match change {
            SealedChange::Create { id, .. } => Some(*id),
            _ => None,
        }
    }

    fn apply_strict(&mut self, changes: &[SealedChange]) -> Result<Vec<NodeId>, Error> {
        self.apply(changes)
    }

    fn entries_changed(&self, after: &OpaqueReplica, changes: &[SealedChange]) -> Vec<(EntryKey, bool)> {
        let mut touched: BTreeSet<&EntryKey> = BTreeSet::new();
        for c in changes {
            if let SealedChange::Put { entry, .. } | SealedChange::Remove { entry } = c
                && entry.key.id_space().is_some()
            {
                touched.insert(&entry.key);
            }
        }
        touched
            .into_iter()
            .filter_map(|key| {
                let (was, now) = (self.has_entry(key), after.has_entry(key));
                (was != now).then(|| (key.clone(), now))
            })
            .collect()
    }

    fn entry_space(entry: &EntryKey) -> Option<u32> {
        entry.id_space()
    }

    fn describe_entry(entry: &EntryKey) -> String {
        entry.describe()
    }

    fn fixes(&self, changes: &[SealedChange]) -> Result<Vec<SealedChange>, Error> {
        Ok(OpaqueReplica::fixes(self, changes))
    }

    fn weight(changes: &[SealedChange]) -> usize {
        changes.iter().map(SealedChange::weight).fold(0, usize::saturating_add)
    }

    fn welcome(w: Welcome<SealedChange>) -> ServerMsg {
        let Welcome { session, client_id, seq, catch_up, processed, peers, access } = w;
        ServerMsg::SealedWelcome { session, client_id, seq, catch_up, processed, peers, access }
    }

    fn accepted(acc: AcceptedOf<SealedChange>) -> ServerMsg {
        ServerMsg::SealedChanges(acc)
    }

    fn rejected(batch_id: u64, reason: String, fixes: Vec<SealedChange>) -> ServerMsg {
        ServerMsg::SealedReject { batch_id, reason, fixes }
    }

    fn batch(msg: ClientMsg) -> Result<Batch<SealedChange>, Box<ClientMsg>> {
        match msg {
            ClientMsg::SealedChanges { base_seq, batch_id, changes } => Ok(Batch { base_seq, batch_id, changes }),
            other => Err(Box::new(other)),
        }
    }
}

/// A message for the transport to deliver.
#[derive(Clone, Debug, PartialEq)]
pub enum Outgoing {
    /// To one client.
    To(u32, ServerMsg),
    /// To every client.
    All(ServerMsg),
    /// To every client but one.
    Others(u32, ServerMsg),
}

/// Why a viewer's batch is refused.
pub const VIEW_ONLY: &str = "you can only view this file (your link is view-only)";

/// Why a plain batch or presence sent to a sealed file is refused.
pub const SEALED_FILE: &str = "this file is sealed (end-to-end encrypted): its changes, presence and chat must be sealed";

/// Why a sealed batch or presence sent to a file that isn't sealed is refused.
pub const PLAIN_FILE: &str = "this file isn't sealed: send its changes and presence as they are";

/// Why a client that doesn't read sealed messages can't join a sealed file.
pub const NEEDS_SEALED: &str = "this file is sealed (end-to-end encrypted): open it with a FigCraft that knows sealed files";

/// Why a client checking a sealed file's values with other rules (an older or newer FigCraft) can't
/// join it: its copy could come out different from everyone else's.
pub const OTHER_RULES: &str = "this file is sealed (end-to-end encrypted) and every app checks its changes the same way: this FigCraft checks them differently (update FigCraft, or ask the server's operator to)";

/// What changed a server's lasting state, in order: what a store appends to its log between
/// snapshots ([`SessionServer::journaling`]) and replays over the last snapshot after a restart
/// ([`SessionServer::replay`]). Presence and who is connected aren't in it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JournalOf<C> {
    /// A client id was handed out.
    Issued { client: u32 },
    /// A batch was accepted.
    Accepted(AcceptedOf<C>),
    /// A client's batch was refused.
    Refused { client: u32, batch_id: u64 },
}

/// A plain file's journal entry.
pub type Journal = JournalOf<Change>;
/// A sealed file's journal entry.
pub type SealedJournal = JournalOf<SealedChange>;

/// The session server of a plain file.
pub type Server = SessionServer<Replica>;
/// The session server of a sealed file: it orders, checks the structure of, stores and catches
/// clients up on changes it can't read.
pub type OpaqueServer = SessionServer<OpaqueReplica>;

/// A session server for one file.
#[derive(Clone, Debug)]
pub struct SessionServer<S: Synced> {
    /// This session's identity (random): clients resume only into the session they were in.
    session: u64,
    state: S,
    seq: u64,
    token: String,
    limits: Limits,
    next_client: u32,
    peers: BTreeMap<u32, Peer>,
    presence: BTreeMap<u32, Presence>,
    acked: BTreeMap<u32, u64>,
    /// Deleted node ids: only these may be created again (by undo); new ids must come from the
    /// creating client's id space.
    deleted: BTreeSet<NodeId>,
    /// Removed document-level entries (styles, variables, collections, comments): these may be
    /// put back by anyone (undo); a new one must not have an id from another client's space.
    removed: BTreeSet<S::Entry>,
    /// Every client id handed out (a reconnecting client keeps its id) and what was done with
    /// its batches.
    issued: BTreeMap<u32, Processed>,
    /// The latest accepted batches, oldest first (a reconnecting client gets what it missed).
    log: VecDeque<AcceptedOf<S::Change>>,
    /// Changes in `log`, and about how many bytes it holds ([`weight`]).
    log_changes: usize,
    log_bytes: usize,
    /// The connected clients that may only view.
    viewers: BTreeSet<u32>,
    /// What changed the lasting state since it was last taken (`None`: not kept).
    journal: Option<Vec<JournalOf<S::Change>>>,
    /// The connected clients that read signals (cursor chat, spotlight).
    signals: BTreeSet<u32>,
    /// Who spotlights now (a newcomer is told).
    spotlight: Option<u32>,
}

/// The most client ids a session remembers for reconnecting (the oldest disconnected ones go
/// first; a forgotten client joins as new).
const MAX_REMEMBERED: usize = 65_536;

/// What a session server needs to carry on after a restart: the document, the sequence number,
/// the client-id counter (so ids are never handed out twice), the clients that can reconnect,
/// the deleted ids and removed entries that may be created again and the log of recent batches.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize = "C: Serialize, E: Serialize", deserialize = "C: Deserialize<'de>, E: Deserialize<'de> + Ord"))]
pub struct SessionStateOf<C, E> {
    pub session: u64,
    pub snapshot: Vec<C>,
    pub seq: u64,
    pub next_client: u32,
    pub issued: BTreeMap<u32, Processed>,
    pub deleted: BTreeSet<NodeId>,
    /// Absent in states saved before entries were tracked.
    #[serde(default)]
    pub removed: BTreeSet<E>,
    pub log: Vec<AcceptedOf<C>>,
}

/// What a plain file's session server saves.
pub type SessionState = SessionStateOf<Change, Entry>;
/// What a sealed file's session server saves.
pub type SealedSessionState = SessionStateOf<SealedChange, EntryKey>;

impl Server {
    /// A session for `doc`. Joining requires `token` (empty: no token). Client ids start above every
    /// client id space already used in the document (by layers, styles, variables, collections,
    /// modes or comments), so ids from earlier sessions are never handed out again.
    pub fn new(doc: Document, token: impl Into<String>, limits: Limits) -> Server {
        let next_client = doc.highest_id_space().saturating_add(1);
        let mut server = Server::with_state(Replica::new(doc), token, limits);
        server.next_client = next_client;
        server
    }

    /// The authoritative document.
    pub fn document(&self) -> &Document {
        self.state.document()
    }

    /// The authoritative state (document and positions).
    pub fn replica(&self) -> &Replica {
        &self.state
    }
}

impl<S: Synced> SessionServer<S> {
    /// A session for `state`. Joining requires `token` (empty: no token). Client ids start above
    /// every client id space the state already uses.
    pub fn with_state(state: S, token: impl Into<String>, limits: Limits) -> SessionServer<S> {
        let next_client = state.highest_id_space().saturating_add(1);
        SessionServer {
            session: new_session_id(),
            state,
            seq: 0,
            token: token.into(),
            limits,
            next_client,
            peers: BTreeMap::new(),
            presence: BTreeMap::new(),
            acked: BTreeMap::new(),
            deleted: BTreeSet::new(),
            removed: BTreeSet::new(),
            issued: BTreeMap::new(),
            log: VecDeque::new(),
            log_changes: 0,
            log_bytes: 0,
            viewers: BTreeSet::new(),
            journal: None,
            signals: BTreeSet::new(),
            spotlight: None,
        }
    }

    /// The session's state, to save (see [`restore`](Self::restore)).
    pub fn state(&self) -> Result<SessionStateOf<S::Change, S::Entry>, Error> {
        Ok(SessionStateOf {
            session: self.session,
            snapshot: self.state.snapshot()?,
            seq: self.seq,
            next_client: self.next_client,
            issued: self.issued.clone(),
            deleted: self.deleted.clone(),
            removed: self.removed.clone(),
            log: self.log.iter().cloned().collect(),
        })
    }

    /// A session carrying on from a saved [`state`](Self::state) (nobody is connected yet; clients
    /// reconnect with their ids). A log that doesn't lead up to the sequence number is dropped
    /// (clients then catch up with a snapshot).
    pub fn restore(state: SessionStateOf<S::Change, S::Entry>, token: impl Into<String>, limits: Limits) -> Result<SessionServer<S>, Error> {
        let replica = S::from_snapshot(&state.snapshot)?;
        let mut server = SessionServer::with_state(replica, token, limits);
        server.session = state.session;
        server.seq = state.seq;
        server.next_client = server.next_client.max(state.next_client);
        server.issued = state.issued.into_iter().filter(|(id, _)| *id < server.next_client).collect();
        server.deleted = state.deleted;
        server.removed = state.removed;
        let contiguous = state.log.windows(2).all(|w| matches!(w, [a, b] if a.seq + 1 == b.seq));
        if contiguous && state.log.last().is_none_or(|a| a.seq == state.seq) {
            for a in state.log {
                server.remember(a);
            }
        }
        Ok(server)
    }

    /// Keep a [`JournalOf`] of what changes the lasting state (`on`), or stop (dropping what wasn't
    /// taken).
    pub fn journaling(&mut self, on: bool) {
        self.journal = on.then(|| self.journal.take().unwrap_or_default());
    }

    /// What changed the lasting state since the last call, oldest first.
    pub fn take_journal(&mut self) -> Vec<JournalOf<S::Change>> {
        self.journal.as_mut().map(std::mem::take).unwrap_or_default()
    }

    fn note(&mut self, j: JournalOf<S::Change>) {
        if let Some(v) = self.journal.as_mut() {
            v.push(j);
        }
    }

    /// Apply a journal entry over a restored state (after a restart). What the state already has
    /// (a batch at or below its sequence number, a client id it knows, a refusal it noted)
    /// changes nothing; a batch that doesn't follow the sequence number, or doesn't apply, is an
    /// error (the rest of that log can't be trusted). Replayed entries aren't journaled again.
    pub fn replay(&mut self, j: JournalOf<S::Change>) -> Result<(), Error> {
        match j {
            JournalOf::Issued { client } => {
                if let btree_map::Entry::Vacant(v) = self.issued.entry(client) {
                    v.insert(Processed::default());
                    self.next_client = self.next_client.max(client.saturating_add(1));
                    self.forget_oldest();
                }
                Ok(())
            }
            JournalOf::Accepted(acc) if acc.seq <= self.seq => Ok(()),
            JournalOf::Accepted(acc) => {
                if acc.seq != self.seq + 1 {
                    return Err(Error::Protocol(format!("batch {} after {}", acc.seq, self.seq)));
                }
                self.accept(acc.author, self.seq, &acc.changes)?;
                self.issued.entry(acc.author).or_default().note(acc.batch_id, false);
                self.next_client = self.next_client.max(acc.author.saturating_add(1));
                self.remember(acc);
                Ok(())
            }
            JournalOf::Refused { client, batch_id } => {
                if let Some(p) = self.issued.get_mut(&client).filter(|p| batch_id > p.last_batch) {
                    p.note(batch_id, true);
                }
                Ok(())
            }
        }
    }

    /// Beyond [`MAX_REMEMBERED`] client ids, forget the oldest one that isn't connected.
    fn forget_oldest(&mut self) {
        if self.issued.len() > MAX_REMEMBERED
            && let Some(old) = self.issued.keys().copied().find(|k| !self.peers.contains_key(k))
        {
            self.issued.remove(&old);
        }
    }

    /// The authoritative synced state.
    pub fn synced(&self) -> &S {
        &self.state
    }

    /// The session's identity.
    pub fn session(&self) -> u64 {
        self.session
    }

    /// The sequence number of the last accepted batch (0: none yet).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Who is in the session.
    pub fn peers(&self) -> btree_map::Values<'_, u32, Peer> {
        self.peers.values()
    }

    /// The highest sequence number client `id` reported applying.
    pub fn acked(&self, id: u32) -> Option<u64> {
        self.acked.get(&id).copied()
    }

    /// A new connection says hello: on success its client id and the messages to send (its
    /// `Welcome`, everyone else's `PeerJoined`); otherwise the `Refused` to send back. A client
    /// coming back ([`Hello::resume`]) keeps its id (taking over from its old connection if that
    /// is still open: the transport closes the old one) and gets the batches it missed, or a
    /// snapshot when they are no longer in the log; an id this session never gave out joins as
    /// new. A sealed file takes only clients that announce [`SEALED`](crate::message::SEALED) and
    /// this build's sealed value rules ([`RULES`](crate::message::RULES), [`OTHER_RULES`]).
    pub fn join(&mut self, hello: Hello) -> Result<(u32, Vec<Outgoing>), ServerMsg> {
        self.join_as(hello, Access::Edit)
    }

    /// [`join`](Self::join) with what the client may do: every batch of a viewer is refused.
    pub fn join_as(&mut self, hello: Hello, access: Access) -> Result<(u32, Vec<Outgoing>), ServerMsg> {
        let refuse = |reason: &str| ServerMsg::Refused { reason: reason.to_string() };
        if hello.protocol != PROTOCOL {
            return Err(refuse(&format!("protocol {} isn't supported (this server speaks {PROTOCOL})", hello.protocol)));
        }
        if !same_secret(&hello.token, &self.token) {
            return Err(refuse("wrong session token"));
        }
        if S::SEALED && !reads_sealed(&hello.client_version) {
            return Err(refuse(NEEDS_SEALED));
        }
        if S::SEALED && sealed_rules(&hello.client_version) != Some(crate::rules::SEALED_RULES) {
            return Err(refuse(OTHER_RULES));
        }
        let resume = hello.resume.filter(|r| r.session == self.session && self.issued.contains_key(&r.client_id));
        if self.peers.len() >= self.limits.max_peers && resume.is_none_or(|r| !self.peers.contains_key(&r.client_id)) {
            return Err(refuse("the session is full"));
        }
        if hello.name.chars().count() > self.limits.max_name || hello.color.chars().count() > self.limits.max_name {
            return Err(refuse("name or colour too long"));
        }
        if resume.is_none() && self.next_client == u32::MAX {
            return Err(refuse("no client ids left in this session"));
        }
        // The log holds every batch after `floor`.
        let floor = self.log.front().map_or(self.seq, |a| a.seq.saturating_sub(1));
        let catch_up = match resume {
            Some(r) if r.seq <= self.seq && r.seq >= floor => CatchUpOf::Delta(self.log.iter().filter(|a| a.seq > r.seq).cloned().collect()),
            _ => CatchUpOf::Snapshot(self.state.snapshot().map_err(|e| refuse(&e.to_string()))?),
        };
        let id = match resume {
            Some(r) => r.client_id,
            None => {
                let id = self.next_client;
                self.next_client += 1;
                self.issued.insert(id, Processed::default());
                self.forget_oldest();
                self.note(JournalOf::Issued { client: id });
                id
            }
        };
        let processed = self.issued.get(&id).cloned().unwrap_or_default();
        self.presence.remove(&id);
        let signals = reads_signals(&hello.client_version);
        let peer = Peer { client_id: id, name: hello.name, color: hello.color };
        let others = self.peers.values().filter(|p| p.client_id != id).cloned().collect();
        let welcome = S::welcome(Welcome { session: self.session, client_id: id, seq: self.seq, catch_up, processed, peers: others, access });
        self.peers.insert(id, peer.clone());
        if access == Access::View {
            self.viewers.insert(id);
        } else {
            self.viewers.remove(&id);
        }
        let mut outs = vec![Outgoing::To(id, welcome), Outgoing::Others(id, ServerMsg::PeerJoined(peer))];
        if signals {
            self.signals.insert(id);
            outs.push(Outgoing::To(id, ServerMsg::Signal { client_id: id, signal: Signal::ready() }));
            if let Some(p) = self.spotlight.filter(|p| *p != id) {
                outs.push(Outgoing::To(id, ServerMsg::Signal { client_id: p, signal: Signal::spotlight(true) }));
            }
        } else {
            self.signals.remove(&id);
        }
        Ok((id, outs))
    }

    /// Client `id`'s connection closed.
    pub fn leave(&mut self, id: u32) -> Vec<Outgoing> {
        self.presence.remove(&id);
        self.acked.remove(&id);
        self.viewers.remove(&id);
        self.signals.remove(&id);
        if self.spotlight == Some(id) {
            self.spotlight = None;
        }
        match self.peers.remove(&id) {
            Some(_) => vec![Outgoing::Others(id, ServerMsg::PeerLeft { client_id: id })],
            None => Vec::new(),
        }
    }

    /// A message from client `from` (which has joined). A batch, presence or chat of the other
    /// kind of file (plain to a sealed one, sealed to a plain one) is refused with the reason.
    pub fn receive(&mut self, from: u32, msg: ClientMsg) -> Vec<Outgoing> {
        if !self.peers.contains_key(&from) {
            return vec![Outgoing::To(from, ServerMsg::Refused { reason: "say hello first".into() })];
        }
        let msg = match S::batch(msg) {
            Ok(batch) => return self.batch(from, batch),
            Err(other) => *other,
        };
        match msg {
            ClientMsg::Hello(_) => vec![Outgoing::To(from, ServerMsg::Refused { reason: "already joined".into() })],
            // A batch of the other kind of file (this one's were taken above).
            ClientMsg::Changes { batch_id, .. } => {
                vec![Outgoing::To(from, ServerMsg::Reject { batch_id, reason: SEALED_FILE.into(), fixes: Vec::new() })]
            }
            ClientMsg::SealedChanges { batch_id, .. } => {
                vec![Outgoing::To(from, ServerMsg::SealedReject { batch_id, reason: PLAIN_FILE.into(), fixes: Vec::new() })]
            }
            ClientMsg::Presence(p) if !S::SEALED => {
                self.presence.insert(from, p.clone());
                vec![Outgoing::Others(from, ServerMsg::Presence { client_id: from, presence: p })]
            }
            // Passed on as it came: only those holding the file's key can open it.
            ClientMsg::SealedPresence(blob) if S::SEALED => vec![Outgoing::Others(from, ServerMsg::SealedPresence { client_id: from, blob })],
            ClientMsg::Presence(_) => vec![Outgoing::To(from, ServerMsg::Refused { reason: SEALED_FILE.into() })],
            ClientMsg::SealedPresence(_) => vec![Outgoing::To(from, ServerMsg::Refused { reason: PLAIN_FILE.into() })],
            // Checked and cleaned, then passed on to those who read signals; never stored but the
            // current spotlight. On a sealed file only a spotlight goes plain (chat is sealed).
            ClientMsg::Signal(sig) => {
                let Some(sig) = sig.clean().filter(|s| s.kind != Signal::READY) else { return Vec::new() };
                if S::SEALED && sig.kind != Signal::SPOTLIGHT {
                    return Vec::new();
                }
                if sig.kind == Signal::SPOTLIGHT {
                    if sig.on() {
                        self.spotlight = Some(from);
                    } else if self.spotlight == Some(from) {
                        self.spotlight = None;
                    }
                }
                let to = self.signals.iter().filter(|id| **id != from);
                to.map(|id| Outgoing::To(*id, ServerMsg::Signal { client_id: from, signal: sig.clone() })).collect()
            }
            ClientMsg::SealedSignal(blob) if S::SEALED => {
                let to = self.signals.iter().filter(|id| **id != from);
                to.map(|id| Outgoing::To(*id, ServerMsg::SealedSignal { client_id: from, blob: blob.clone() })).collect()
            }
            ClientMsg::SealedSignal(_) => Vec::new(),
            ClientMsg::Ack { seq } => {
                self.acked.insert(from, seq.min(self.seq));
                Vec::new()
            }
            ClientMsg::Ping => vec![Outgoing::To(from, ServerMsg::Pong)],
            ClientMsg::Manage(_)
            | ClientMsg::Admin(_)
            | ClientMsg::OpenLibrary(_)
            | ClientMsg::Library(_)
            | ClientMsg::OpenPlugins(_)
            | ClientMsg::Plugins(_)
            | ClientMsg::OpenHosting(_)
            | ClientMsg::Resolve(_)
            | ClientMsg::Info
            | ClientMsg::SignIn(_)
            | ClientMsg::OpenAccount(_)
            | ClientMsg::Account(_)
            | ClientMsg::Report { .. } => {
                vec![Outgoing::To(from, ServerMsg::Refused { reason: "managing files and libraries needs a connection of its own".into() })]
            }
        }
    }

    /// A batch from client `from`.
    fn batch(&mut self, from: u32, batch: Batch<S::Change>) -> Vec<Outgoing> {
        let Batch { base_seq, batch_id, changes } = batch;
        // A batch already processed (a copy sent again around a reconnect) is ignored: the client
        // learned what happened to it from the catch-up.
        if self.issued.get(&from).is_some_and(|p| batch_id <= p.last_batch) {
            return Vec::new();
        }
        let result = if self.viewers.contains(&from) { Err(Error::Invalid(VIEW_ONLY.into())) } else { self.accept(from, base_seq, &changes) };
        if let Some(p) = self.issued.get_mut(&from) {
            p.note(batch_id, result.is_err());
        }
        match result {
            Ok(()) => {
                let acc = AcceptedOf { seq: self.seq, author: from, batch_id, changes };
                self.remember(acc.clone());
                self.note(JournalOf::Accepted(acc.clone()));
                vec![Outgoing::All(S::accepted(acc))]
            }
            Err(e) => {
                self.note(JournalOf::Refused { client: from, batch_id });
                let fixes = self.state.fixes(&changes).unwrap_or_default();
                vec![Outgoing::To(from, S::rejected(batch_id, reason(&e), fixes))]
            }
        }
    }

    /// Keep an accepted batch in the log (dropping the oldest beyond the limits).
    fn remember(&mut self, acc: AcceptedOf<S::Change>) {
        self.log_changes += acc.changes.len();
        self.log_bytes = self.log_bytes.saturating_add(S::weight(&acc.changes));
        self.log.push_back(acc);
        while !self.log.is_empty()
            && (self.log.len() > self.limits.max_log_batches
                || self.log_changes > self.limits.max_log_changes
                || self.log_bytes > self.limits.max_log_bytes)
        {
            if let Some(old) = self.log.pop_front() {
                self.log_changes = self.log_changes.saturating_sub(old.changes.len());
                self.log_bytes = self.log_bytes.saturating_sub(S::weight(&old.changes));
            }
        }
    }

    /// About how many bytes the batches kept for reconnecting clients hold.
    pub fn log_bytes(&self) -> usize {
        self.log_bytes
    }

    /// Validate and apply a batch; on success it has the next sequence number.
    fn accept(&mut self, from: u32, base_seq: u64, changes: &[S::Change]) -> Result<(), Error> {
        if changes.len() > self.limits.max_changes {
            return Err(Error::Invalid(format!("{} changes in one batch (at most {})", changes.len(), self.limits.max_changes)));
        }
        if base_seq > self.seq {
            return Err(Error::Protocol(format!("based on sequence {base_seq}, but the server is at {}", self.seq)));
        }
        for id in changes.iter().filter_map(S::created) {
            if !self.state.contains(id) && !self.deleted.contains(&id) && id.0 >> 32 != u64::from(from) {
                return Err(Error::Invalid(format!("new node {id} isn't in client {from}'s id space")));
            }
        }
        let mut next = self.state.clone();
        let deleted = next.apply_strict(changes)?;
        if next.node_count() > self.limits.max_nodes {
            return Err(Error::Invalid(format!("more than {} layers", self.limits.max_nodes)));
        }
        let entries = self.check_entries(from, changes, &next)?;
        for id in changes.iter().filter_map(S::created) {
            self.deleted.remove(&id);
        }
        self.deleted.extend(deleted);
        for (entry, now) in entries {
            if now {
                self.removed.remove(&entry);
            } else {
                self.removed.insert(entry);
            }
        }
        self.state = next;
        self.seq += 1;
        Ok(())
    }

    /// The document-level entries (styles, variables, collections, comments) a batch adds or
    /// removes, each with whether it is there afterwards. A new one is refused when its id lies in
    /// the space of another client this session gave an id to (unless it was removed before: undo
    /// puts entries back); ids from before the session (space 0, earlier sessions, other files)
    /// are fine.
    fn check_entries(&self, from: u32, changes: &[S::Change], after: &S) -> Result<Vec<(S::Entry, bool)>, Error> {
        let changed = self.state.entries_changed(after, changes);
        for (entry, now) in &changed {
            if *now
                && !self.removed.contains(entry)
                && let Some(space) = S::entry_space(entry).filter(|s| *s != from && self.issued.contains_key(s))
            {
                return Err(Error::Invalid(format!("new {} isn't in client {from}'s id space (it is client {space}'s)", S::describe_entry(entry))));
            }
        }
        Ok(changed)
    }
}

/// A file's session server, plain or sealed: what a transport runs per open file.
// One per open file, moved only when the file opens: not worth a box.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum FileServer {
    Plain(Server),
    Sealed(OpaqueServer),
}

impl From<Server> for FileServer {
    fn from(s: Server) -> FileServer {
        FileServer::Plain(s)
    }
}

impl From<OpaqueServer> for FileServer {
    fn from(s: OpaqueServer) -> FileServer {
        FileServer::Sealed(s)
    }
}

macro_rules! both {
    ($self:expr, $s:ident => $e:expr) => {
        match $self {
            FileServer::Plain($s) => $e,
            FileServer::Sealed($s) => $e,
        }
    };
}

impl FileServer {
    /// A sealed file's.
    pub fn is_sealed(&self) -> bool {
        matches!(self, FileServer::Sealed(_))
    }

    /// The plain file's server.
    pub fn plain(&self) -> Option<&Server> {
        match self {
            FileServer::Plain(s) => Some(s),
            FileServer::Sealed(_) => None,
        }
    }

    pub fn plain_mut(&mut self) -> Option<&mut Server> {
        match self {
            FileServer::Plain(s) => Some(s),
            FileServer::Sealed(_) => None,
        }
    }

    /// The sealed file's server.
    pub fn sealed(&self) -> Option<&OpaqueServer> {
        match self {
            FileServer::Sealed(s) => Some(s),
            FileServer::Plain(_) => None,
        }
    }

    pub fn sealed_mut(&mut self) -> Option<&mut OpaqueServer> {
        match self {
            FileServer::Sealed(s) => Some(s),
            FileServer::Plain(_) => None,
        }
    }

    /// See [`SessionServer::join_as`].
    pub fn join_as(&mut self, hello: Hello, access: Access) -> Result<(u32, Vec<Outgoing>), ServerMsg> {
        both!(self, s => s.join_as(hello, access))
    }

    /// See [`SessionServer::join`].
    pub fn join(&mut self, hello: Hello) -> Result<(u32, Vec<Outgoing>), ServerMsg> {
        both!(self, s => s.join(hello))
    }

    /// See [`SessionServer::leave`].
    pub fn leave(&mut self, id: u32) -> Vec<Outgoing> {
        both!(self, s => s.leave(id))
    }

    /// See [`SessionServer::receive`].
    pub fn receive(&mut self, from: u32, msg: ClientMsg) -> Vec<Outgoing> {
        both!(self, s => s.receive(from, msg))
    }

    pub fn peers(&self) -> btree_map::Values<'_, u32, Peer> {
        both!(self, s => s.peers())
    }

    pub fn seq(&self) -> u64 {
        both!(self, s => s.seq())
    }

    pub fn acked(&self, id: u32) -> Option<u64> {
        both!(self, s => s.acked(id))
    }

    pub fn log_bytes(&self) -> usize {
        both!(self, s => s.log_bytes())
    }

    pub fn journaling(&mut self, on: bool) {
        both!(self, s => s.journaling(on))
    }
}

/// A fresh session identity: random per server (std's hasher keys are seeded from the OS).
fn new_session_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0);
    h.finish()
}

/// Why a batch was refused, for the person who made it.
fn reason(e: &Error) -> String {
    match e {
        Error::Unknown(_) => "a layer it changes was deleted by someone else".into(),
        e => e.to_string(),
    }
}

/// About how many bytes `changes` take in memory: their values' text and a little per change.
pub fn weight(changes: &[Change]) -> usize {
    fn json(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::String(s) => s.len() + 2,
            serde_json::Value::Array(a) => a.iter().map(json).fold(2, usize::saturating_add),
            serde_json::Value::Object(o) => o.iter().map(|(k, v)| k.len() + 3 + json(v)).fold(2, usize::saturating_add),
            _ => 8,
        }
    }
    changes
        .iter()
        .map(|c| match c {
            Change::Create { kind, position, props, .. } => {
                props.iter().map(|(_, v)| 16 + json(&v.0)).fold(64 + json(&kind.0) + position.len(), usize::saturating_add)
            }
            Change::Set { value, .. } | Change::SetDoc { value, .. } => 32 + json(&value.0),
            Change::Put { value, .. } => 64 + json(&value.0),
            Change::Delete { .. } => 16,
            Change::Remove { .. } => 64,
        })
        .fold(0, usize::saturating_add)
}
