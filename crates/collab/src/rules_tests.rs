//! The sealed value rules ([`Mode::Sealed`]): values that break them take their defaults, changes
//! that can't apply are skipped, nothing fails; and a document built from a snapshot of the same
//! (bad) values comes out the same as one that applied them batch by batch.

use figcraft_doc::{Document, NodeId, NodeKind};
use serde_json::json;

use crate::change::{Change, DocProp, Entry, Json, Prop};
use crate::message::{Accepted, CatchUp, Processed, ServerMsg};
use crate::{Access, Client, Mode, NoRecompute, Notice, Replica};

fn doc() -> (Replica, NodeId, NodeId) {
    let mut d = Document::new("Rules");
    let page = d.first_page().unwrap();
    let frame = d.create(page, NodeKind::Frame, "F", 0.0, 0.0, 100.0, 100.0).unwrap();
    let rect = d.create(frame, NodeKind::Rectangle, "R", 0.0, 0.0, 10.0, 10.0).unwrap();
    d.node_mut(rect).unwrap().opacity = 0.5;
    d.take_dirty();
    (Replica::new(d), frame, rect)
}

fn set(id: NodeId, prop: Prop, v: serde_json::Value) -> Change {
    Change::Set { id, prop, value: Json(v) }
}

#[test]
fn bad_values_take_their_defaults_and_nothing_fails() {
    let (mut r, frame, rect) = doc();
    let batch = vec![
        set(rect, Prop::Opacity, json!(5.0)),
        set(rect, Prop::Width, json!(-3.0)),
        set(rect, Prop::Height, json!(1e300)),
        set(rect, Prop::Transform, json!([1e300, 0, 0, 1, 0, 0])),
        set(rect, Prop::Fills, json!("not paints")),
        set(rect, Prop::Name, json!("Kept")),
        // Can't apply: skipped.
        set(NodeId(999), Prop::Name, json!("x")),
        Change::Create { id: NodeId(50), kind: Json(json!({"type": "rectangle"})), parent: Some(rect), position: "a5".into(), props: vec![] },
    ];
    // A server checking values would refuse the whole batch.
    assert!(r.clone().apply(&batch, Mode::Strict).is_err());
    let applied = r.apply(&batch, Mode::Sealed).unwrap();
    assert_eq!((applied.defaulted, applied.skipped), (5, 2));
    let n = r.document().node(rect).unwrap();
    let blank = figcraft_doc::Node::new(rect, NodeKind::Rectangle, "", 0.0, 0.0);
    assert_eq!(n.opacity, 1.0, "a new node's opacity, not the 0.5 it had");
    assert_eq!((n.width, n.height), (0.0, 0.0));
    assert_eq!(n.transform, blank.transform);
    assert_eq!(n.fills, blank.fills);
    assert_eq!(n.name, "Kept");
    assert!(!r.document().contains(NodeId(50)), "a rectangle holds no layers");
    assert!(r.document().contains(frame));
}

#[test]
fn bad_kinds_documents_and_entries_fall_back() {
    let (mut r, frame, rect) = doc();
    let batch = vec![
        // The type name is kept (the sealing layer checked it against the server's tag).
        set(rect, Prop::Kind, json!({"type": "polygon", "count": "many"})),
        Change::Create {
            id: NodeId(60),
            kind: Json(json!({"type": "star", "count": -1})),
            parent: Some(frame),
            position: "a9".into(),
            props: vec![],
        },
        Change::Create { id: NodeId(61), kind: Json(json!({"type": "nothing"})), parent: Some(frame), position: "a8".into(), props: vec![] },
        // A frame with layers can't become a rectangle.
        set(frame, Prop::Kind, json!({"type": "rectangle"})),
        Change::SetDoc { prop: DocProp::Name, value: Json(json!(42)) },
        Change::SetDoc { prop: DocProp::StyleOrder, value: Json(json!({"no": "order"})) },
        Change::Put { entry: Entry::Style("S:1".into()), value: Json(json!("not a style")) },
    ];
    let applied = r.apply(&batch, Mode::Sealed).unwrap();
    assert_eq!((applied.defaulted, applied.skipped), (5, 2), "{applied:?}");
    let d = r.document();
    assert_eq!(d.node(rect).unwrap().kind, NodeKind::Polygon { count: 3 });
    assert!(matches!(d.node(NodeId(60)).unwrap().kind, NodeKind::Star { .. }));
    assert!(!d.contains(NodeId(61)));
    assert_eq!(d.node(frame).unwrap().kind, NodeKind::Frame);
    assert_eq!(d.name, Document::without_pages("").name);
    assert!(d.styles.is_empty());
}

#[test]
fn a_snapshot_of_bad_values_opens_like_the_batches_that_wrote_them() {
    let (mut live, frame, rect) = doc();
    let batches = vec![
        vec![set(rect, Prop::Opacity, json!(7)), set(rect, Prop::Name, json!("Bad then good"))],
        vec![Change::Create {
            id: NodeId(70),
            kind: Json(json!({"type": "ellipse"})),
            parent: Some(frame),
            position: "a3".into(),
            props: vec![(Prop::Width, Json(json!(-1))), (Prop::Visible, Json(json!("yes")))],
        }],
        vec![set(NodeId(70), Prop::Transform, json!({"bad": true})), set(frame, Prop::Height, json!(2e9))],
        vec![Change::SetDoc { prop: DocProp::DocumentColors, value: Json(json!(false)) }],
    ];
    for b in &batches {
        live.apply(b, Mode::Sealed).unwrap();
    }
    // What a sealed file's server keeps: the latest value of each property, as written (here: a
    // plain replica that took them without checking, then its snapshot with the raw values put
    // back where the checks reset them).
    let mut raw = live.snapshot().unwrap();
    for b in &batches {
        for c in b {
            match c {
                Change::Set { id, prop, value } => {
                    if let Some(Change::Create { props, .. }) = raw.iter_mut().find(|r| matches!(r, Change::Create { id: i, .. } if i == id)) {
                        props.retain(|(p, _)| p != prop);
                        props.push((*prop, value.clone()));
                    }
                }
                Change::Create { id, props: bad, .. } => {
                    if let Some(Change::Create { props, .. }) = raw.iter_mut().find(|r| matches!(r, Change::Create { id: i, .. } if i == id)) {
                        props.retain(|(p, _)| !bad.iter().any(|(b, _)| b == p));
                        props.extend(bad.iter().cloned());
                    }
                }
                other => raw.push(other.clone()),
            }
        }
    }
    let joined = Replica::from_snapshot_in(&raw, Mode::Sealed).unwrap();
    assert_eq!(joined.document(), live.document());
    assert_eq!(serde_json::to_vec(joined.document()).unwrap(), serde_json::to_vec(live.document()).unwrap());
}

#[test]
fn a_sealed_client_skips_what_a_plain_one_fails_on() {
    let (r, _, rect) = doc();
    let welcome = || ServerMsg::Welcome {
        session: 1,
        client_id: 9,
        seq: 0,
        catch_up: CatchUp::Snapshot(r.snapshot().unwrap()),
        processed: Processed::default(),
        peers: vec![],
        access: Access::Edit,
    };
    let hostile = || ServerMsg::Changes(Accepted { seq: 1, author: 3, batch_id: 1, changes: vec![set(rect, Prop::Opacity, json!(-2))] });
    let mut plain = Client::join(welcome()).unwrap();
    assert!(plain.receive(hostile(), &NoRecompute).is_err(), "a plain session trusts its server's checks");
    let mut sealed = Client::join_sealed(welcome()).unwrap();
    assert!(sealed.is_sealed() && !plain.is_sealed());
    sealed.receive(hostile(), &NoRecompute).unwrap();
    assert_eq!(sealed.document().node(rect).unwrap().opacity, 1.0);
    assert_eq!(sealed.seq(), 1);
    let notices = sealed.take_notices();
    assert!(matches!(notices.as_slice(), [Notice::Checked { seq: 1, author: 3, skipped: 0, defaulted: 1 }]), "{notices:?}");
    assert!(!notices[0].message().contains("-2"), "says how many, never what");
}
