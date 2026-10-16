//! The sealing layer's editor signatures: batches go out signed with the device key, and those that
//! arrive are checked against the editors the app knows before they open.

use std::sync::Arc;

use figcraft_collab::message::{AcceptedOf, CatchUpOf, ClientMsg, Processed, ServerMsg};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab::{Access, Change, Json, Prop};
use figcraft_collab_seal::{BatchRefused, DeviceKeys, FileKey, KnownEditors, Signed, seal_change, sign_batch, verify_batch};
use figcraft_doc::NodeId;

use crate::invite::{Endpoint, Invite};
use crate::sealing::{SealingKeys, incoming, outgoing};

const FILE: &str = "00112233aabbccdd";

fn invite(key: &FileKey) -> Invite {
    Invite { server: Endpoint::plain("127.0.0.1:47900"), file: FILE.into(), token: "t".repeat(24), key: Some(key.clone().into()) }
}

fn rename(name: &str) -> Vec<Change> {
    vec![Change::Set { id: NodeId(2), prop: Prop::Name, value: Json::of(name).unwrap() }]
}

/// A batch someone else sent, as the server passes it on.
fn arriving(key: &FileKey, signer: Option<&DeviceKeys>, batch_id: u64) -> AcceptedOf<SealedChange> {
    let mut changes: Vec<SealedChange> = rename("Theirs").iter().map(|c| seal_change(key, FILE, c).unwrap()).collect();
    if let Some(d) = signer {
        changes.push(sign_batch(d, FILE, key.epoch(), 0, batch_id, &changes).unwrap());
    }
    AcceptedOf { seq: 1, author: 7, batch_id, changes }
}

#[test]
fn batches_go_out_signed_by_the_device() {
    let key = FileKey::generate().unwrap();
    let me = Arc::new(DeviceKeys::generate().unwrap());
    let keys = SealingKeys { signer: Some(me.clone()), editors: None };
    let out = outgoing(&invite(&key), &keys, Some(3), ClientMsg::Changes { base_seq: 4, batch_id: 9, changes: rename("Mine") }).unwrap();
    let Some(ClientMsg::SealedChanges { base_seq: 4, batch_id: 9, changes }) = out else { panic!("{out:?}") };
    assert!(matches!(changes.last(), Some(SealedChange::Signature(s)) if s.base_seq == 4));
    assert_eq!(verify_batch(FILE, 9, &changes), Signed::By(me.public().unwrap().signing));
    // Without a device key: unsigned, as before.
    let out = outgoing(&invite(&key), &SealingKeys::default(), Some(3), ClientMsg::Changes { base_seq: 4, batch_id: 9, changes: rename("Mine") });
    let Ok(Some(ClientMsg::SealedChanges { changes, .. })) = out else { panic!() };
    assert_eq!(verify_batch(FILE, 9, &changes), Signed::Unsigned);
    assert!(!format!("{keys:?}").contains(&format!("{:?}", me.public().unwrap().signing)), "Debug shows no keys");
}

#[test]
fn arriving_batches_are_checked_against_the_editors() {
    let key = FileKey::generate().unwrap();
    let (ann, eve) = (DeviceKeys::generate().unwrap(), DeviceKeys::generate().unwrap());
    let editors = SealingKeys { signer: None, editors: Some(Arc::new(KnownEditors::new([&ann.public().unwrap()]))) };
    let inv = invite(&key);
    // An editor's batch opens.
    let Ok(Some(ServerMsg::Changes(acc))) = incoming(&inv, &editors, ServerMsg::SealedChanges(arriving(&key, Some(&ann), 1))) else { panic!() };
    assert_eq!(acc.changes, rename("Theirs"));
    // Anyone else's, or an unsigned one, ends the session: the same in a reconnect's catch-up.
    let refused = |m: ServerMsg| incoming(&inv, &editors, m).unwrap_err();
    assert_eq!(refused(ServerMsg::SealedChanges(arriving(&key, Some(&eve), 2))), BatchRefused::NotEditor.to_string());
    assert_eq!(refused(ServerMsg::SealedChanges(arriving(&key, None, 3))), BatchRefused::Unsigned.to_string());
    let welcome = |d| ServerMsg::SealedWelcome {
        session: 1,
        client_id: 3,
        seq: 1,
        catch_up: CatchUpOf::Delta(d),
        processed: Processed::default(),
        peers: vec![],
        access: Access::Edit,
    };
    assert_eq!(refused(welcome(vec![arriving(&key, Some(&eve), 2)])), BatchRefused::NotEditor.to_string());
    assert!(matches!(incoming(&inv, &editors, welcome(vec![arriving(&key, Some(&ann), 2)])), Ok(Some(ServerMsg::Welcome { .. }))));
    // A changed batch: its signature doesn't hold.
    let mut changed = arriving(&key, Some(&ann), 4);
    changed.batch_id = 5;
    assert_eq!(refused(ServerMsg::SealedChanges(changed)), BatchRefused::Bad.to_string());
    // Without a list of editors (links mode): unsigned and intact batches open.
    for m in [arriving(&key, None, 6), arriving(&key, Some(&eve), 7)] {
        assert!(matches!(incoming(&inv, &SealingKeys::default(), ServerMsg::SealedChanges(m)), Ok(Some(ServerMsg::Changes(_)))));
    }
}

/// A server's list of editors: signatures required only after `signed_from`, and a device the list
/// doesn't know fetched for once before its batch is refused.
#[test]
fn member_editors_require_signatures_from_a_point_and_refresh_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use figcraft_collab::message::EditorDevice;

    use crate::editors::{EditorList, MemberEditors};
    use crate::inbox::Inbox;

    let key = FileKey::generate().unwrap();
    let (ann, cy) = (Arc::new(DeviceKeys::generate().unwrap()), DeviceKeys::generate().unwrap());
    let entry =
        |account: &str, d: &DeviceKeys| EditorDevice { account: account.into(), device: "d".into(), public: d.public().unwrap(), recovery: false };
    let (ann_entry, cy_entry) = (entry("a", &ann), entry("c", &cy));
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    // Cy shows up in the list from the second answer on.
    let fetch = move |_: &str| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let mut editors = vec![ann_entry.clone()];
        if n > 0 {
            editors.push(cy_entry.clone());
        }
        Ok(EditorList { signed_from: Some(1), editors })
    };
    let m = Arc::new(MemberEditors::new("ws://x/".into(), ann.clone(), Box::new(fetch)));
    let inbox = Inbox::new(Arc::new(|| {}));
    assert!(m.load(FILE, inbox.clone()).unwrap(), "this device is an editor's: it signs");
    assert!(inbox.drain().iter().any(|e| matches!(e, figcraft_engine::live::Event::Editors { .. })));
    let keys = SealingKeys { signer: None, editors: Some(m.clone()) };
    let inv = invite(&key);
    let at = |seq: u64, signer: Option<&DeviceKeys>, batch_id: u64| {
        let mut a = arriving(&key, signer, batch_id);
        a.seq = seq;
        ServerMsg::SealedChanges(a)
    };
    // Up to batch 1 unsigned batches are taken (made before the file required signatures).
    assert!(incoming(&inv, &keys, at(1, None, 1)).is_ok());
    assert_eq!(incoming(&inv, &keys, at(2, None, 2)).unwrap_err(), BatchRefused::Unsigned.to_string());
    // Cy isn't known yet: fetched again, and taken.
    assert!(incoming(&inv, &keys, at(3, Some(&cy), 3)).is_ok());
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    // Someone the list never has: fetched again once, then refused without asking again.
    let eve = DeviceKeys::generate().unwrap();
    assert_eq!(incoming(&inv, &keys, at(4, Some(&eve), 4)).unwrap_err(), BatchRefused::NotEditor.to_string());
    assert_eq!(incoming(&inv, &keys, at(5, Some(&eve), 5)).unwrap_err(), BatchRefused::NotEditor.to_string());
    assert_eq!(asked.load(Ordering::SeqCst), 3);
}
