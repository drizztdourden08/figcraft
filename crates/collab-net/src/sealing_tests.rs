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
