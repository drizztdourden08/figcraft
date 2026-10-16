//! The session server of sealed files: structure checks without values, snapshots, catch-up,
//! fixes, and refusing the other kind of message.

use figcraft_doc::NodeId;

use crate::change::{DocProp, Json, Prop};
use crate::message::{CatchUpOf, ClientMsg, Hello, PROTOCOL, ServerMsg, Signal};
use crate::message::{client_version, sealed_rules};
use crate::rules::SEALED_RULES;
use crate::sealed::{BatchSignature, EntryKey, Sealed, SealedChange, SealedEntry};
use crate::server::{NEEDS_SEALED, OTHER_RULES, PLAIN_FILE, SEALED_FILE};
use crate::sim::Rng;
use crate::{Change, Limits, OpaqueReplica, OpaqueServer, Outgoing, Synced};

/// A stand-in for a sealed value (the server only checks its shape): `n` marks it.
fn blob(n: u8) -> Sealed {
    Sealed::from_bytes(vec![n; 4 + 24 + 64 + 16]).unwrap()
}

const PAGE: NodeId = NodeId(1);
const FRAME: NodeId = NodeId(2);

fn create(id: NodeId, tag: &str, parent: Option<NodeId>, position: &str) -> SealedChange {
    SealedChange::Create { id, kind_tag: tag.into(), kind: blob(1), parent, position: position.into(), props: vec![(Prop::Name, blob(2))] }
}

/// A page holding a frame, made before the session (id space 0).
fn base() -> Vec<SealedChange> {
    vec![create(PAGE, "page", None, "a0"), create(FRAME, "frame", Some(PAGE), "a0")]
}

fn hello(sealed: bool) -> Hello {
    Hello {
        protocol: PROTOCOL,
        file: "f".into(),
        token: String::new(),
        name: "Ada".into(),
        color: "#FF8800".into(),
        client_version: if sealed { "1 signals sealed rules1".into() } else { "1 signals".into() },
        resume: None,
    }
}

fn server() -> OpaqueServer {
    OpaqueServer::with_state(OpaqueReplica::from_snapshot(&base()).unwrap(), "", Limits { max_nodes: 6, ..Limits::default() })
}

fn join(s: &mut OpaqueServer) -> u32 {
    s.join(hello(true)).unwrap().0
}

/// Client `c`'s id `n`.
fn id(c: u32, n: u64) -> NodeId {
    NodeId((u64::from(c) << 32) | n)
}

/// Send a batch: `Ok` with the accepted sequence number, or the reason it was refused.
fn send(s: &mut OpaqueServer, from: u32, batch_id: u64, changes: Vec<SealedChange>) -> Result<u64, String> {
    let out = s.receive(from, ClientMsg::SealedChanges { base_seq: s.seq(), batch_id, changes });
    match out.into_iter().next() {
        Some(Outgoing::All(ServerMsg::SealedChanges(acc))) => Ok(acc.seq),
        Some(Outgoing::To(_, ServerMsg::SealedReject { reason, .. })) => Err(reason),
        other => panic!("unexpected {other:?}"),
    }
}

fn tree(id: NodeId, prop: Prop, v: impl serde::Serialize) -> SealedChange {
    SealedChange::SetTree { id, prop, value: Json::of(&v).unwrap() }
}

#[test]
fn a_sealed_file_takes_only_clients_that_read_sealed_messages() {
    let mut s = server();
    assert_eq!(s.join(hello(false)).unwrap_err(), ServerMsg::Refused { reason: NEEDS_SEALED.into() });
    let (me, out) = s.join(hello(true)).unwrap();
    let Some(Outgoing::To(to, ServerMsg::SealedWelcome { client_id, catch_up: CatchUpOf::Snapshot(snap), .. })) = out.into_iter().next() else {
        panic!("no sealed welcome")
    };
    assert_eq!((to, client_id), (me, me));
    assert_eq!(snap, base());
}

#[test]
fn the_tree_rules_hold_without_reading_values() {
    let mut s = server();
    let c = join(&mut s);
    let refused = |r: Result<u64, String>, what: &str| assert!(r.as_ref().is_err_and(|e| e.contains(what)), "{what}: {r:?}");
    // New ids come from the author's space; existing ones can't be created again.
    refused(send(&mut s, c, 1, vec![create(id(c + 1, 1), "rectangle", Some(FRAME), "a1")]), "id space");
    refused(send(&mut s, c, 2, vec![create(FRAME, "frame", Some(PAGE), "a1")]), "already exists");
    // Pages, and only pages, have no parent.
    refused(send(&mut s, c, 3, vec![create(id(c, 1), "frame", None, "a1")]), "only pages");
    refused(send(&mut s, c, 4, vec![create(id(c, 1), "page", Some(PAGE), "a1")]), "only pages");
    // A parent must exist and hold layers.
    refused(send(&mut s, c, 5, vec![create(id(c, 1), "rectangle", Some(NodeId(99)), "a1")]), "deleted by someone else");
    let rect = id(c, 2);
    assert!(send(&mut s, c, 6, vec![create(rect, "rectangle", Some(FRAME), "a1")]).is_ok());
    refused(send(&mut s, c, 7, vec![create(id(c, 3), "ellipse", Some(rect), "a0")]), "can't contain layers");
    refused(send(&mut s, c, 8, vec![tree(FRAME, Prop::Parent, Some(rect))]), "");
    // A layer can't go inside itself, or into a missing node.
    let inner = id(c, 4);
    assert!(send(&mut s, c, 9, vec![create(inner, "frame", Some(FRAME), "a2")]).is_ok());
    refused(send(&mut s, c, 10, vec![tree(FRAME, Prop::Parent, Some(inner))]), "inside itself");
    refused(send(&mut s, c, 11, vec![tree(FRAME, Prop::Parent, Some(FRAME))]), "inside itself");
    // Kinds: unknown tags, a node becoming or ceasing to be a page, a container that stops being one.
    refused(send(&mut s, c, 12, vec![SealedChange::SetKind { id: FRAME, kind_tag: "blob".into(), value: blob(3) }]), "unknown layer kind");
    refused(send(&mut s, c, 13, vec![SealedChange::SetKind { id: FRAME, kind_tag: "page".into(), value: blob(3) }]), "page");
    refused(send(&mut s, c, 14, vec![SealedChange::SetKind { id: PAGE, kind_tag: "frame".into(), value: blob(3) }]), "page");
    refused(send(&mut s, c, 15, vec![SealedChange::SetKind { id: FRAME, kind_tag: "text".into(), value: blob(3) }]), "can't contain layers");
    // Positions are fractional keys; tree properties go plain, every other one sealed.
    refused(send(&mut s, c, 16, vec![tree(FRAME, Prop::Position, "")]), "");
    refused(send(&mut s, c, 17, vec![create(id(c, 5), "frame", Some(PAGE), "not a key!")]), "");
    refused(send(&mut s, c, 18, vec![SealedChange::Set { id: FRAME, prop: Prop::Parent, value: blob(3) }]), "sealed value");
    refused(send(&mut s, c, 19, vec![tree(FRAME, Prop::Fills, 1)]), "tree property");
    // A file keeps a page.
    refused(send(&mut s, c, 20, vec![SealedChange::Delete { id: PAGE }]), "at least one page");
    // The node cap (6): page, frame, rect, inner are 4.
    let many: Vec<SealedChange> = (10..13).map(|n| create(id(c, n), "rectangle", Some(PAGE), "a5")).collect();
    refused(send(&mut s, c, 21, many), "more than 6 layers");
    // Entry names must fit their kind.
    let unnamed = SealedEntry { key: EntryKey::Style("x".into()), name: None };
    refused(send(&mut s, c, 22, vec![SealedChange::Put { entry: unnamed, value: blob(3) }]), "entry name");
    // Moving, then deleting a subtree.
    assert!(send(&mut s, c, 23, vec![tree(inner, Prop::Parent, Some(PAGE)), tree(inner, Prop::Position, "a3")]).is_ok());
    assert_eq!(s.synced().parent(inner), Some(Some(PAGE)));
    assert!(send(&mut s, c, 24, vec![tree(rect, Prop::Parent, Some(inner))]).is_ok());
    assert!(send(&mut s, c, 25, vec![SealedChange::Delete { id: inner }]).is_ok());
    assert!(!s.synced().contains(rect), "the subtree went with it");
    assert_eq!(s.synced().node_count(), 2);
    // Undo may bring a deleted id back, even someone else's.
    let d = join(&mut s);
    assert!(send(&mut s, d, 1, vec![create(rect, "rectangle", Some(FRAME), "a1")]).is_ok());
}

#[test]
fn comment_ids_belong_to_their_author() {
    let mut s = server();
    let (a, b) = (join(&mut s), join(&mut s));
    let comment = |c: u32, n: u64| SealedEntry { key: EntryKey::Comment((u64::from(c) << 32) | n), name: None };
    let r = send(&mut s, a, 1, vec![SealedChange::Put { entry: comment(b, 1), value: blob(5) }]);
    assert!(r.is_err_and(|e| e.contains("id space")));
    assert!(send(&mut s, a, 2, vec![SealedChange::Put { entry: comment(a, 1), value: blob(5) }]).is_ok());
    // Removed, anyone may put it back (undo).
    assert!(send(&mut s, a, 3, vec![SealedChange::Remove { entry: comment(a, 1) }]).is_ok());
    assert!(send(&mut s, b, 1, vec![SealedChange::Put { entry: comment(a, 1), value: blob(6) }]).is_ok());
}

#[test]
fn a_snapshot_rebuilds_the_same_state_and_list_order() {
    let mut r = OpaqueReplica::from_snapshot(&base()).unwrap();
    let style = |n: &str| SealedEntry { key: EntryKey::Style(n.into()), name: Some(blob(9)) };
    let changes = vec![
        SealedChange::SetDoc { prop: DocProp::Name, value: blob(1) },
        SealedChange::Put { entry: style("a"), value: blob(1) },
        SealedChange::Put { entry: style("b"), value: blob(2) },
        SealedChange::SetDoc { prop: DocProp::StyleOrder, value: blob(3) },
        SealedChange::Remove { entry: style("a") },
        SealedChange::Put { entry: style("a"), value: blob(4) },
        SealedChange::Put { entry: style("c"), value: blob(5) },
        SealedChange::Put { entry: SealedEntry { key: EntryKey::Image("i".into()), name: Some(blob(6)) }, value: blob(7) },
    ];
    r.apply(&changes).unwrap();
    let snap = r.snapshot();
    // b was there when the order was set; a came back and c came after it, in that order.
    let puts: Vec<String> = snap
        .iter()
        .filter_map(|c| match c {
            SealedChange::Put { entry: SealedEntry { key: EntryKey::Style(n), .. }, .. } => Some(n.clone()),
            SealedChange::SetDoc { prop: DocProp::StyleOrder, .. } => Some("order".into()),
            _ => None,
        })
        .collect();
    assert_eq!(puts, ["b", "order", "a", "c"]);
    assert_eq!(OpaqueReplica::from_snapshot(&snap).unwrap().snapshot(), snap);
    // A whole list replaces the entries; removing one of it afterwards is kept as a removal.
    r.apply(&[SealedChange::SetDoc { prop: DocProp::Styles, value: blob(8) }, SealedChange::Remove { entry: style("z") }]).unwrap();
    let snap = r.snapshot();
    assert!(snap.contains(&SealedChange::Remove { entry: style("z") }));
    assert!(!snap.iter().any(|c| matches!(c, SealedChange::Put { entry, .. } if entry.key == EntryKey::Style("b".into()))));
    assert_eq!(OpaqueReplica::from_snapshot(&snap).unwrap().snapshot(), snap);
}

#[test]
fn a_refused_batch_gets_the_current_sealed_values_back() {
    let mut s = server();
    let c = join(&mut s);
    let gone = id(c, 7);
    let out = s.receive(
        c,
        ClientMsg::SealedChanges {
            base_seq: 0,
            batch_id: 1,
            changes: vec![
                SealedChange::Set { id: FRAME, prop: Prop::Name, value: blob(8) },
                SealedChange::Delete { id: FRAME },
                create(gone, "frame", Some(NodeId(99)), "a1"),
                SealedChange::SetDoc { prop: DocProp::Name, value: blob(8) },
            ],
        },
    );
    let Some(Outgoing::To(_, ServerMsg::SealedReject { fixes, .. })) = out.into_iter().next() else { panic!("not refused") };
    assert!(fixes.contains(&SealedChange::Set { id: FRAME, prop: Prop::Name, value: blob(2) }));
    assert!(fixes.contains(&create(FRAME, "frame", Some(PAGE), "a0")), "the deleted frame comes back whole");
    assert!(fixes.contains(&SealedChange::Delete { id: gone }));
}

#[test]
fn plain_and_sealed_messages_dont_mix() {
    let mut s = server();
    let c = join(&mut s);
    let other = join(&mut s);
    let plain = s.receive(c, ClientMsg::Changes { base_seq: 0, batch_id: 1, changes: Vec::<Change>::new() });
    assert_eq!(plain, vec![Outgoing::To(c, ServerMsg::Reject { batch_id: 1, reason: SEALED_FILE.into(), fixes: Vec::new() })]);
    let presence = s.receive(c, ClientMsg::Presence(Default::default()));
    assert_eq!(presence, vec![Outgoing::To(c, ServerMsg::Refused { reason: SEALED_FILE.into() })]);
    // Chat goes sealed; a plain chat is dropped, a plain spotlight passes.
    assert!(s.receive(c, ClientMsg::Signal(Signal::chat("secret"))).is_empty());
    assert_eq!(
        s.receive(c, ClientMsg::Signal(Signal::spotlight(true))),
        vec![Outgoing::To(other, ServerMsg::Signal { client_id: c, signal: Signal::spotlight(true) })]
    );
    assert_eq!(s.receive(c, ClientMsg::SealedSignal(blob(4))), vec![Outgoing::To(other, ServerMsg::SealedSignal { client_id: c, blob: blob(4) })]);
    assert_eq!(
        s.receive(c, ClientMsg::SealedPresence(blob(4))),
        vec![Outgoing::Others(c, ServerMsg::SealedPresence { client_id: c, blob: blob(4) })]
    );
    // And the other way round, on a plain file.
    let mut d = figcraft_doc::Document::new("Plain");
    d.repair();
    let mut p = crate::Server::new(d, "", Limits::default());
    let ClientMsg::Hello(h) = crate::Client::hello("f", "", "Ada", "#FF8800") else { panic!() };
    let (pc, _) = p.join(h).unwrap();
    let sealed = p.receive(pc, ClientMsg::SealedChanges { base_seq: 0, batch_id: 1, changes: Vec::new() });
    assert_eq!(sealed, vec![Outgoing::To(pc, ServerMsg::SealedReject { batch_id: 1, reason: PLAIN_FILE.into(), fixes: Vec::new() })]);
    assert_eq!(p.receive(pc, ClientMsg::SealedPresence(blob(1))), vec![Outgoing::To(pc, ServerMsg::Refused { reason: PLAIN_FILE.into() })]);
    assert!(p.receive(pc, ClientMsg::SealedSignal(blob(1))).is_empty());
}

#[test]
fn a_sealed_session_restores_and_replays_its_journal() {
    let mut s = server();
    s.journaling(true);
    let c = join(&mut s);
    assert!(send(&mut s, c, 1, vec![create(id(c, 1), "rectangle", Some(FRAME), "a1")]).is_ok());
    let state = s.state().unwrap();
    assert!(send(&mut s, c, 2, vec![SealedChange::Set { id: id(c, 1), prop: Prop::Opacity, value: blob(7) }]).is_ok());
    let journal = s.take_journal();
    let mut back = OpaqueServer::restore(state, "", Limits::default()).unwrap();
    for j in journal {
        back.replay(j).unwrap();
    }
    assert_eq!(back.seq(), s.seq());
    assert_eq!(back.synced().snapshot(), s.synced().snapshot());
    // Wire round trip of the saved state.
    let bytes = crate::message::encode(&back.state().unwrap()).unwrap();
    let decoded: crate::SealedSessionState = crate::message::decode(&bytes, bytes.len()).unwrap();
    assert_eq!(decoded, back.state().unwrap());
    // Highest id space: the client's layer.
    assert_eq!(<OpaqueReplica as Synced>::highest_id_space(back.synced()), c);
}

#[test]
fn sealed_file_names_round_trip_as_text() {
    let n = blob(3);
    let text = crate::sealed::sealed_name_text(&n);
    assert!(text.starts_with(crate::sealed::SEALED_NAME_PREFIX));
    assert_eq!(crate::sealed::parse_sealed_name(&text), Some(n));
    assert_eq!(crate::sealed::parse_sealed_name("Plain name"), None);
    assert_eq!(crate::sealed::parse_sealed_name("sealed:not base64!"), None);
}

#[test]
fn a_sealed_file_takes_only_clients_with_its_value_rules() {
    let mut s = server();
    for version in ["1 signals sealed", "1 signals sealed rules0", "1 signals sealed rules2", "1 signals sealed rulesx"] {
        let h = Hello { client_version: version.into(), ..hello(true) };
        assert_eq!(s.join(h).unwrap_err(), ServerMsg::Refused { reason: OTHER_RULES.into() }, "{version}");
    }
    assert!(s.join(hello(true)).is_ok());
    // This build announces its rules; a plain file doesn't care.
    assert_eq!(sealed_rules(&client_version()), Some(SEALED_RULES));
    assert_eq!(sealed_rules("0.5.0 signals hosting sealed"), None);
}

fn signature(n: u8) -> SealedChange {
    SealedChange::Signature(BatchSignature { device: [n; 32], epoch: 1, base_seq: 0, signature: [n; 64] })
}

#[test]
fn a_batch_signature_is_last_and_passed_on_but_never_kept_in_the_file() {
    let mut s = server();
    let c = join(&mut s);
    let rect = id(c, 1);
    // Last, once: taken and passed on as it came (the apps check it).
    let batch = vec![create(rect, "rectangle", Some(FRAME), "a1"), signature(1)];
    let out = s.receive(c, ClientMsg::SealedChanges { base_seq: 0, batch_id: 1, changes: batch.clone() });
    let Some(Outgoing::All(ServerMsg::SealedChanges(acc))) = out.into_iter().next() else { panic!("not accepted") };
    assert_eq!(acc.changes, batch);
    // Anywhere else, or twice: refused.
    let mut next = 9;
    for bad in [vec![signature(2), tree(rect, Prop::Position, "a2")], vec![tree(rect, Prop::Position, "a2"), signature(2), signature(3)]] {
        let r = send(&mut s, c, next, bad);
        next += 1;
        assert!(r.as_ref().is_err_and(|e| e.contains("signature")), "{r:?}");
    }
    // A batch of a signature only changes nothing (and is fine).
    assert!(send(&mut s, c, next, vec![signature(4)]).is_ok());
    // In the log (a reconnecting client's catch-up) as sent; never in a snapshot or a fix.
    let state = s.state().unwrap();
    assert!(state.log.iter().any(|a| a.changes == batch));
    assert!(!state.snapshot.iter().any(|c| matches!(c, SealedChange::Signature(_))));
    assert!(s.synced().fixes(&batch).iter().all(|c| !matches!(c, SealedChange::Signature(_))));
    let restored = OpaqueServer::restore(state, "", Limits::default()).unwrap();
    assert_eq!(restored.synced().snapshot(), s.synced().snapshot());
}

/// A random sealed change over the ids around: any shape the wire can carry.
fn random_sealed(rng: &mut Rng, ids: &[NodeId]) -> SealedChange {
    let tags = ["page", "frame", "rectangle", "text", "group", "blob", ""];
    let id = rng.pick(ids).copied().unwrap_or(NodeId(rng.next_u64()));
    let prop = *rng.pick(Prop::FIELDS).unwrap_or(&Prop::Name);
    let tree_prop = *rng.pick(&[Prop::Parent, Prop::Position, Prop::Name]).unwrap_or(&Prop::Parent);
    let parent = if rng.chance(0.2) { None } else { rng.pick(ids).copied() };
    let positions = ["a0", "a1", "Zz", "", "a0V", "!!"];
    let position = rng.pick(&positions).copied().unwrap_or("a0").to_string();
    let entry = |rng: &mut Rng| match rng.below(4) {
        0 => SealedEntry { key: EntryKey::Style(format!("s{}", rng.below(3))), name: rng.chance(0.8).then(|| blob(1)) },
        1 => SealedEntry { key: EntryKey::Comment((rng.next_u64() % 4) | (u64::from(rng.next_u64() as u32 % 3) << 32)), name: None },
        2 => SealedEntry { key: EntryKey::Image("i".into()), name: Some(blob(2)) },
        _ => SealedEntry { key: EntryKey::DevSnapshot(id), name: rng.chance(0.2).then(|| blob(3)) },
    };
    let tag = rng.pick(&tags).copied().unwrap_or("frame").to_string();
    let doc_props = [DocProp::Name, DocProp::Styles, DocProp::StyleOrder, DocProp::Comments, DocProp::VariableOrder];
    match rng.below(10) {
        0 | 1 => SealedChange::Create {
            id: NodeId((rng.next_u64() % 8) | ((rng.next_u64() % 3) << 32)),
            kind_tag: tag,
            kind: blob(1),
            parent,
            position,
            props: vec![(prop, blob(2))],
        },
        2 => SealedChange::Set { id, prop, value: blob(3) },
        3 => SealedChange::SetKind { id, kind_tag: tag, value: blob(4) },
        4 => {
            let value = match tree_prop {
                Prop::Parent => Json::of(&parent).unwrap(),
                _ => Json::of(&position).unwrap(),
            };
            SealedChange::SetTree { id, prop: tree_prop, value }
        }
        5 => SealedChange::Delete { id },
        6 => SealedChange::SetDoc { prop: *rng.pick(&doc_props).unwrap_or(&DocProp::Name), value: blob(5) },
        7 => SealedChange::Put { entry: entry(rng), value: blob(6) },
        8 => SealedChange::Remove { entry: entry(rng) },
        _ => signature(rng.below(255) as u8),
    }
}

#[test]
fn random_sealed_batches_never_panic_the_server() {
    let mut rng = Rng::new(7);
    for round in 0..300 {
        let mut s = OpaqueServer::with_state(OpaqueReplica::from_snapshot(&base()).unwrap(), "", Limits { max_nodes: 40, ..Limits::default() });
        let clients: Vec<u32> = (0..3).map(|_| join(&mut s)).collect();
        for b in 0..40u64 {
            let mut ids: Vec<NodeId> = vec![PAGE, FRAME, NodeId(99)];
            ids.extend((0..8).map(|n| id(clients[0], n)));
            let batch: Vec<SealedChange> = (0..1 + rng.below(6)).map(|_| random_sealed(&mut rng, &ids)).collect();
            let from = clients[rng.below(clients.len())];
            let base_seq = if rng.chance(0.1) { rng.next_u64() } else { s.seq() };
            let _ = s.receive(from, ClientMsg::SealedChanges { base_seq, batch_id: b + 1, changes: batch });
        }
        // Whatever it took, its state still snapshots, restores and rebuilds the same.
        let snap = s.synced().snapshot();
        let rebuilt = OpaqueReplica::from_snapshot(&snap).unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert_eq!(rebuilt.snapshot(), snap, "round {round}");
        assert!(OpaqueServer::restore(s.state().unwrap(), "", Limits::default()).is_ok(), "round {round}");
    }
}

#[test]
fn a_node_whose_kind_changed_is_snapshot_with_the_kind_it_was_made_with() {
    let mut r = OpaqueReplica::from_snapshot(&base()).unwrap();
    let rect = NodeId(3);
    r.apply(&[create(rect, "rectangle", Some(FRAME), "a1")]).unwrap();
    r.apply(&[SealedChange::SetKind { id: rect, kind_tag: "frame".into(), value: blob(7) }]).unwrap();
    r.apply(&[create(NodeId(4), "rectangle", Some(rect), "a0")]).unwrap();
    r.apply(&[SealedChange::SetKind { id: rect, kind_tag: "group".into(), value: blob(8) }]).unwrap();
    let snap = r.snapshot();
    // Made a rectangle (its properties start from a rectangle's defaults in every app), then the
    // group it is now, before its layers.
    let at = snap.iter().position(|c| matches!(c, SealedChange::Create { id, .. } if *id == rect)).unwrap();
    assert!(matches!(&snap[at], SealedChange::Create { kind_tag, kind, .. } if kind_tag == "rectangle" && *kind == blob(1)));
    assert_eq!(snap[at + 1], SealedChange::SetKind { id: rect, kind_tag: "group".into(), value: blob(8) });
    assert!(matches!(&snap[at + 2], SealedChange::Create { id, .. } if *id == NodeId(4)));
    let again = OpaqueReplica::from_snapshot(&snap).unwrap();
    assert_eq!(again.snapshot(), snap);
    assert_eq!(again.kind_tag(rect), Some("group"));
}
