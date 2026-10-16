//! Step 10's hardening of sealed sessions: every app checks values the same way (a hostile editor
//! can't make copies differ), editors sign their batches, and safety numbers.

use std::collections::VecDeque;

use figcraft_collab::message::{self, AcceptedOf, CatchUpOf, ClientMsg, ServerMsg};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab::sim::Rng;
use figcraft_collab::{Change, Client, DocProp, Entry, Json, Limits, NoRecompute, OpaqueReplica, OpaqueServer, Outgoing, Prop, Replica};
use figcraft_doc::{Document, NodeId};
use serde_json::{Value, json};

use crate::sim_tests::{FILE, base, open_all, random_edit, seal_all};
use crate::*;

/// What the app's sealing layer does with what arrives (`crates/collab-net/src/sealing.rs`): check
/// each batch's signature against `editors`, then open what opens.
fn open_msg(ring: &Keyring, editors: &dyn EditorKeys, msg: ServerMsg) -> Result<ServerMsg, BatchRefused> {
    let open_acc = |a: AcceptedOf<SealedChange>| -> Result<AcceptedOf<Change>, BatchRefused> {
        let body = check_batch(editors, FILE, a.batch_id, &a.changes)?;
        Ok(AcceptedOf { seq: a.seq, author: a.author, batch_id: a.batch_id, changes: open_all(ring, body) })
    };
    Ok(match msg {
        ServerMsg::SealedWelcome { session, client_id, seq, catch_up, processed, peers, access } => {
            let catch_up = match catch_up {
                CatchUpOf::Snapshot(s) => CatchUpOf::Snapshot(open_all(ring, &s)),
                CatchUpOf::Delta(d) => CatchUpOf::Delta(d.into_iter().map(open_acc).collect::<Result<_, _>>()?),
            };
            ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
        }
        ServerMsg::SealedChanges(a) => ServerMsg::Changes(open_acc(a)?),
        ServerMsg::SealedReject { batch_id, reason, fixes } => ServerMsg::Reject { batch_id, reason, fixes: open_all(ring, &fixes) },
        other => other,
    })
}

/// Values no honest app writes: out of range, the wrong type, nonsense.
fn hostile_value(rng: &mut Rng) -> Value {
    let pool = [
        json!(5.0),
        json!(-1.0),
        json!(1e300),
        json!(-1e300),
        json!(2e9),
        json!(0.5),
        json!("text"),
        json!(null),
        json!(true),
        json!([]),
        json!([1e300, 0, 0, 1, 0, 0]),
        json!({"type": "solid"}),
        json!({"a": [1, 2, {"b": null}]}),
        json!(u64::MAX),
    ];
    rng.pick(&pool).cloned().unwrap_or(Value::Null)
}

/// Kinds with a known type name (the server checks the tag) and maybe nonsense inside.
fn hostile_kind(rng: &mut Rng) -> Value {
    let pool = [
        json!({"type": "rectangle"}),
        json!({"type": "frame"}),
        json!({"type": "polygon", "count": "many"}),
        json!({"type": "star", "count": -3}),
        json!({"type": "text", "runs": 7}),
        json!({"type": "instance"}),
        json!({"type": "ellipse", "sweep": "round"}),
        json!({"type": "booleanOp", "op": "melt"}),
    ];
    rng.pick(&pool).cloned().unwrap_or(Value::Null)
}

/// A hostile editor's batch: plain changes as no honest app makes them (sealed with the file key:
/// it holds the key like everyone else).
fn hostile_batch(doc: &Document, me: u32, n: &mut u64, rng: &mut Rng) -> Vec<Change> {
    let ids: Vec<NodeId> = doc.ids().filter(|i| doc.node(*i).is_some_and(|x| !x.is_page())).collect();
    let containers: Vec<NodeId> = doc.ids().filter(|i| doc.node(*i).is_some_and(|x| x.kind.is_container())).collect();
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(4) {
        let prop = *rng.pick(Prop::FIELDS).unwrap_or(&Prop::Opacity);
        let prop = if prop == Prop::Kind || rng.chance(0.4) {
            *rng.pick(&[Prop::Opacity, Prop::Width, Prop::Height, Prop::Transform]).unwrap()
        } else {
            prop
        };
        match rng.below(6) {
            0 | 1 => {
                if let Some(id) = rng.pick(&ids).copied() {
                    out.push(Change::Set { id, prop, value: Json(hostile_value(rng)) });
                }
            }
            2 => {
                if let Some(parent) = rng.pick(&containers).copied() {
                    *n += 1;
                    let props = vec![(prop, Json(hostile_value(rng))), (Prop::Name, Json(json!("Planted")))];
                    out.push(Change::Create {
                        id: NodeId((u64::from(me) << 32) | *n),
                        kind: Json(hostile_kind(rng)),
                        parent: Some(parent),
                        position: "a5".into(),
                        props,
                    });
                }
            }
            3 => {
                if let Some(id) = rng.pick(&ids).copied().filter(|i| doc.node(*i).is_some_and(|x| x.children.is_empty())) {
                    out.push(Change::Set { id, prop: Prop::Kind, value: Json(hostile_kind(rng)) });
                }
            }
            4 => {
                let prop = *rng.pick(&[DocProp::Name, DocProp::DocumentColors, DocProp::ColorProfile, DocProp::AnnotationCategories]).unwrap();
                out.push(Change::SetDoc { prop, value: Json(hostile_value(rng)) });
            }
            // Entries the honest apps don't touch: an unreadable entry is removed, and one put
            // again later goes to the end of its list in the apps that saw it removed but stays in
            // place for the server (a known difference in order only, see the rules' docs).
            _ => out.push(Change::Put { entry: Entry::Style(format!("evil{}", rng.below(3))), value: Json(hostile_value(rng)) }),
        }
    }
    out
}

/// Two honest apps and a hostile editor in one sealed session; a third app joins at the end.
struct Session {
    key: FileKey,
    ring: Keyring,
    server: OpaqueServer,
    apps: Vec<(u32, Client)>,
    hostile: u32,
}

impl Session {
    fn new() -> Session {
        let key = FileKey::generate().unwrap();
        let ring = Keyring::from(key.clone());
        let snapshot = seal_all(&key, &Replica::new(base()).snapshot().unwrap());
        let server = OpaqueServer::with_state(OpaqueReplica::from_snapshot(&snapshot).unwrap(), "", Limits::default());
        let mut s = Session { key, ring, server, apps: Vec::new(), hostile: 0 };
        for _ in 0..2 {
            let app = s.join();
            s.apps.push(app);
        }
        let ClientMsg::Hello(h) = Client::hello(FILE, "", "Mallory", "") else { panic!() };
        s.hostile = s.server.join(h).unwrap().0;
        s
    }

    /// A new app joins: its sealed welcome, opened.
    fn join(&mut self) -> (u32, Client) {
        let ClientMsg::Hello(h) = Client::hello(FILE, "", "App", "") else { panic!() };
        let (id, out) = self.server.join(h).unwrap();
        let welcome = out.into_iter().find_map(|o| match o {
            Outgoing::To(to, w @ ServerMsg::SealedWelcome { .. }) if to == id => Some(w),
            _ => None,
        });
        (id, Client::join_sealed(open_msg(&self.ring, &AnyEditor, welcome.unwrap()).unwrap()).unwrap())
    }

    /// Send `msg` from client `from` and deliver everything that follows, in order, over the wire
    /// encoding (as the apps get it).
    fn send(&mut self, from: u32, msg: ClientMsg) {
        let mut queue = VecDeque::from([(from, msg)]);
        while let Some((from, msg)) = queue.pop_front() {
            let msg: ClientMsg = message::decode(&message::encode(&msg).unwrap(), usize::MAX).unwrap();
            for o in self.server.receive(from, msg) {
                let (m, to): (ServerMsg, Vec<u32>) = match o {
                    Outgoing::To(id, m) => (m, vec![id]),
                    Outgoing::All(m) => (m, self.apps.iter().map(|a| a.0).collect()),
                    Outgoing::Others(id, m) => (m, self.apps.iter().map(|a| a.0).filter(|a| *a != id).collect()),
                };
                let m: ServerMsg = message::decode(&message::encode(&m).unwrap(), usize::MAX).unwrap();
                for (id, client) in self.apps.iter_mut().filter(|a| to.contains(&a.0)) {
                    let opened = open_msg(&self.ring, &AnyEditor, m.clone()).unwrap();
                    for reply in client.receive(opened, &NoRecompute).unwrap() {
                        queue.push_back((*id, sealed(&self.key, reply)));
                    }
                }
            }
        }
    }
}

fn sealed(key: &FileKey, msg: ClientMsg) -> ClientMsg {
    match msg {
        ClientMsg::Changes { base_seq, batch_id, changes } => ClientMsg::SealedChanges { base_seq, batch_id, changes: seal_all(key, &changes) },
        other => other,
    }
}

/// The document as saved, without which client's copy it is (its id allocator).
fn bytes(doc: &Document) -> Vec<u8> {
    let mut doc = doc.clone();
    doc.set_client_id(0);
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn every_app_comes_to_the_same_document_whatever_a_hostile_editor_sends() {
    let mut defaulted = 0;
    for seed in 0..100 {
        let mut rng = Rng::new(seed);
        let mut s = Session::new();
        let mut planted = 0u64;
        let mut hostile_batch_id = 0;
        for _ in 0..40 {
            if rng.chance(0.5) {
                hostile_batch_id += 1;
                let doc = s.apps[0].1.confirmed().document().clone();
                let batch = hostile_batch(&doc, s.hostile, &mut planted, &mut rng);
                let base_seq = s.server.seq();
                let changes = seal_all(&s.key, &batch);
                s.send(s.hostile, ClientMsg::SealedChanges { base_seq, batch_id: hostile_batch_id, changes });
            } else {
                let i = rng.below(2);
                let mut doc = s.apps[i].1.document().clone();
                random_edit(&mut doc, &mut rng);
                if let Some(m) = s.apps[i].1.edit(&doc).unwrap() {
                    let id = s.apps[i].0;
                    let m = sealed(&s.key, m);
                    s.send(id, m);
                }
            }
            for (_, c) in &mut s.apps {
                for n in c.take_notices() {
                    if let figcraft_collab::Notice::Checked { defaulted: d, skipped, .. } = n {
                        defaulted += d + skipped;
                    }
                }
            }
        }
        // A latecomer opens the server's sealed snapshot: the latest values, bad ones too.
        let late = s.join();
        let first = bytes(s.apps[0].1.confirmed().document());
        for (id, c) in s.apps.iter().chain([&late]) {
            assert_eq!(c.seq(), s.server.seq(), "seed {seed}: app {id} is behind");
            assert!(
                bytes(c.confirmed().document()) == first,
                "seed {seed}: app {id} differs: {}",
                figcraft_collab::sim::describe(s.apps[0].1.confirmed(), c.confirmed())
            );
        }
    }
    assert!(defaulted > 100, "the hostile batches broke the rules ({defaulted} values)");
}

fn signed_batch(device: &DeviceKeys, key: &FileKey, batch_id: u64) -> Vec<SealedChange> {
    let mut changes = seal_all(key, &[Change::Set { id: NodeId(2), prop: Prop::Name, value: Json(json!("Signed")) }]);
    changes.push(sign_batch(device, FILE, key.epoch(), 3, batch_id, &changes).unwrap());
    changes
}

#[test]
fn editors_sign_their_batches_and_apps_check_them() {
    let key = FileKey::generate().unwrap();
    let (ann, bob, eve) = (DeviceKeys::generate().unwrap(), DeviceKeys::generate().unwrap(), DeviceKeys::generate().unwrap());
    let batch = signed_batch(&ann, &key, 7);
    // Over the wire and back, the signature still holds.
    let wire = ClientMsg::SealedChanges { base_seq: 3, batch_id: 7, changes: batch.clone() };
    let ClientMsg::SealedChanges { changes: back, .. } = message::decode(&message::encode(&wire).unwrap(), usize::MAX).unwrap() else { panic!() };
    let json_back: ClientMsg = message::decode_json(&message::encode_json(&wire).unwrap(), usize::MAX).unwrap();
    assert_eq!(json_back, wire);
    assert_eq!(verify_batch(FILE, 7, &back), Signed::By(ann.public().unwrap().signing));
    // Another batch id or file, a changed value, a moved signature: it doesn't hold.
    assert_eq!(verify_batch(FILE, 8, &batch), Signed::Bad);
    assert_eq!(verify_batch("fedcba9876543210", 7, &batch), Signed::Bad);
    let mut changed = batch.clone();
    if let SealedChange::Set { value, .. } = &mut changed[0] {
        let mut b = value.as_bytes().to_vec();
        b[40] ^= 1;
        *value = Sealed::from_bytes(b).unwrap();
    }
    assert_eq!(verify_batch(FILE, 7, &changed), Signed::Bad);
    let moved: Vec<SealedChange> = batch.iter().rev().cloned().collect();
    assert_eq!(verify_batch(FILE, 7, &moved), Signed::Bad);
    assert_eq!(verify_batch(FILE, 7, &batch[..1]), Signed::Unsigned);
    // Against the editors an app knows.
    let editors = KnownEditors::new([&ann.public().unwrap(), &bob.public().unwrap()]);
    assert_eq!(check_batch(&editors, FILE, 7, &batch).unwrap(), &batch[..1]);
    assert_eq!(check_batch(&editors, FILE, 7, &batch[..1]), Err(BatchRefused::Unsigned));
    assert_eq!(check_batch(&editors, FILE, 9, &signed_batch(&eve, &key, 9)), Err(BatchRefused::NotEditor));
    assert_eq!(check_batch(&editors, FILE, 7, &changed), Err(BatchRefused::Bad));
    // Without a list (a link to a server without accounts): intact or unsigned is fine.
    assert!(check_batch(&AnyEditor, FILE, 9, &signed_batch(&eve, &key, 9)).is_ok());
    assert_eq!(check_batch(&AnyEditor, FILE, 7, &batch[..1]).unwrap().len(), 1);
    assert_eq!(check_batch(&AnyEditor, FILE, 7, &changed), Err(BatchRefused::Bad));
    // A server passes signatures on but never keeps them in the file.
    let snapshot = seal_all(&key, &Replica::new(base()).snapshot().unwrap());
    let mut server = OpaqueServer::with_state(OpaqueReplica::from_snapshot(&snapshot).unwrap(), "", Limits::default());
    let ClientMsg::Hello(h) = Client::hello(FILE, "", "Ann", "") else { panic!() };
    let (me, _) = server.join(h).unwrap();
    let mut mine = seal_all(&key, &[Change::Set { id: NodeId(2), prop: Prop::Name, value: Json(json!("Mine")) }]);
    mine.push(sign_batch(&ann, FILE, key.epoch(), 0, 1, &mine).unwrap());
    let out = server.receive(me, ClientMsg::SealedChanges { base_seq: 0, batch_id: 1, changes: mine });
    let Some(Outgoing::All(ServerMsg::SealedChanges(acc))) = out.into_iter().next() else { panic!("not accepted") };
    assert!(check_batch(&editors, FILE, acc.batch_id, &acc.changes).is_ok());
    assert!(!server.synced().snapshot().iter().any(|c| matches!(c, SealedChange::Signature(_))));
}

#[test]
fn safety_numbers() {
    let devices: Vec<DevicePublic> = (0..3).map(|_| DeviceKeys::generate().unwrap().public().unwrap()).collect();
    let n = safety_number(&devices);
    assert_eq!(n.len(), 14);
    assert!(n.split(' ').all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_digit())), "{n}");
    // Any order, duplicates once: the same number.
    let mut shuffled = vec![devices[2].clone(), devices[0].clone(), devices[1].clone(), devices[0].clone()];
    assert_eq!(safety_number(&shuffled), n);
    // A device more, less or changed: another number.
    shuffled.push(DeviceKeys::generate().unwrap().public().unwrap());
    assert_ne!(safety_number(&shuffled), n);
    assert_ne!(safety_number(&devices[..2]), n);
    let mut changed = devices.clone();
    changed[1].signing[0] ^= 1;
    assert_ne!(safety_number(&changed), n);
    // A fixed vector, so the number never changes between versions.
    let fixed = DevicePublic { agreement: [1; 32], signing: [2; 32] };
    assert_eq!(safety_number(&[fixed]), "3271 4339 5047");
    assert_eq!(safety_number(&[]).len(), 14);
}

#[test]
fn junk_signatures_never_panic() {
    let key = FileKey::generate().unwrap();
    let mut rng = Rng::new(3);
    let body = seal_all(&key, &[Change::Set { id: NodeId(2), prop: Prop::Name, value: Json(json!("x")) }]);
    for _ in 0..2000 {
        let mut device = [0u8; 32];
        let mut signature = [0u8; 64];
        device.iter_mut().chain(signature.iter_mut()).for_each(|b| *b = rng.next_u64() as u8);
        if rng.chance(0.2) {
            device = [0; 32];
        }
        let sig = SealedChange::Signature(figcraft_collab::sealed::BatchSignature {
            device,
            epoch: rng.next_u64() as u32,
            base_seq: rng.next_u64(),
            signature,
        });
        let mut changes = body.clone();
        if rng.chance(0.5) {
            changes.push(sig);
        } else {
            changes.insert(0, sig);
        }
        let _ = verify_batch(FILE, rng.next_u64(), &changes);
        assert!(check_batch(&KnownEditors::default(), FILE, 1, &changes).is_err());
    }
}
