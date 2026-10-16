//! Editor signatures switched on (`docs/accounts-and-e2e.md` › *Editor signatures*): engine
//! sessions on a real server with accounts and a fake identity provider. The owner's and the
//! editors' apps sign their batches and the file starts requiring signatures; an editor added
//! later is taken once the apps fetch the editors again; a revoked device's batches end the
//! sessions that see them; a viewer holding the file key can't pass forged batches off as an
//! editor's, even through a server that lets them through; safety numbers of other people, and
//! the key-change warning when their devices change.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use figcraft_collab::message::{self, AccountReply, AccountReq, ClientMsg, Hello, PROTOCOL, ServerMsg};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab::{Change, Json, Prop};
use figcraft_collab_net::hub::UNSIGNED;
use figcraft_collab_seal::{BatchRefused, DeviceKeys, Keyring, Signed, parse_ring_fragment, seal_change, sign_batch, verify_batch};
use figcraft_doc::NodeId;
use figcraft_engine::Session;
use figcraft_engine::live::Status;
use serde_json::{Value, json};

use crate::accounts_tests::{accounts_config, ask, signed, start, token};
use crate::test_util::{Raw, TempDir, live, pump, same, session};

fn ex(s: &mut Session, cmd: &str, p: Value) -> Value {
    s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

fn signed_in(name: &str, url: &str, tok: &str) -> Session {
    let mut s = session(name);
    ex(&mut s, "account.signIn", json!({"server": url, "token": tok}));
    s
}

fn rect(s: &mut Session, name: &str) -> u64 {
    let id = ex(s, "shape.rectangle", json!({"x": 10, "y": 10, "width": 40, "height": 30}))["id"].as_u64().unwrap();
    ex(s, "node.set", json!({"ids": [id], "props": {"name": name}}));
    id
}

fn rename(s: &mut Session, id: u64, name: &str) {
    ex(s, "node.set", json!({"ids": [id], "props": {"name": name}}));
}

fn named(s: &Session, id: u64, name: &str) -> bool {
    s.doc().is_ok_and(|d| d.node(NodeId(id)).is_some_and(|n| n.name == name))
}

fn failed(s: &Session) -> Option<String> {
    match &s.live().status {
        Status::Failed { reason } => Some(reason.clone()),
        _ => None,
    }
}

fn device(s: &mut Session, url: &str) -> String {
    ex(s, "account.devices", json!({"server": url}))["device"].as_str().unwrap().to_string()
}

/// This session's device keys (kept with the preferences in tests: no keychain).
fn keys_of(s: &Session) -> DeviceKeys {
    DeviceKeys::from_secret_bytes(&URL_SAFE_NO_PAD.decode(&s.prefs.device.secret).unwrap()).unwrap()
}

fn ring_of(s: &Session) -> Keyring {
    parse_ring_fragment(&s.prefs.file_keys[0].key).unwrap()
}

fn account_of(s: &mut Session, email: &str) -> String {
    let m = ex(s, "collab.members", json!({}));
    m["members"].as_array().unwrap().iter().find(|m| m["email"] == email).unwrap()["account"].as_str().unwrap().to_string()
}

fn number(s: &mut Session, url: &str, account: Option<&str>) -> Value {
    let p = match account {
        Some(a) => json!({"server": url, "account": a}),
        None => json!({"server": url}),
    };
    ex(s, "account.safetyNumber", p)
}

/// A raw connection signed in as `tok` joined to `file`: it, the welcome's sequence number and
/// what it may do.
fn raw_member(addr: std::net::SocketAddr, tok: (&str, &str, &str), file: &str) -> (Raw, u64, message::Access) {
    let (raw, me) = signed(addr, token(tok.0, tok.1, tok.2));
    me.unwrap();
    raw_join(raw, file, "")
}

/// `raw` joins `file` (with a share link's `link_token`, or none).
fn raw_join(mut raw: Raw, file: &str, link_token: &str) -> (Raw, u64, message::Access) {
    raw.send(&ClientMsg::Hello(Hello {
        protocol: PROTOCOL,
        file: file.into(),
        token: link_token.into(),
        name: "raw".into(),
        color: String::new(),
        client_version: message::client_version(),
        resume: None,
    }));
    loop {
        match raw.next() {
            ServerMsg::SealedWelcome { seq, access, .. } => return (raw, seq, access),
            ServerMsg::Refused { reason } => panic!("refused: {reason}"),
            _ => {}
        }
    }
}

/// A batch renaming `layer`, sealed with `ring`'s newest key, signed by `by` (or not).
fn forged(ring: &Keyring, file: &str, layer: u64, name: &str, base_seq: u64, batch_id: u64, by: Option<&DeviceKeys>) -> ClientMsg {
    let key = ring.current().unwrap();
    let change = Change::Set { id: NodeId(layer), prop: Prop::Name, value: Json::of(name).unwrap() };
    let mut changes = vec![seal_change(key, file, &change).unwrap()];
    if let Some(d) = by {
        changes.push(sign_batch(d, file, key.epoch(), base_seq, batch_id, &changes).unwrap());
    }
    ClientMsg::SealedChanges { base_seq, batch_id, changes }
}

/// An account connection's answer to `req`.
fn account_ask(addr: std::net::SocketAddr, tok: (&str, &str, &str), req: AccountReq) -> AccountReply {
    let (mut raw, _) = crate::accounts_tests::account(addr, token(tok.0, tok.1, tok.2));
    ask(&mut raw, req)
}

const ANN: (&str, &str, &str) = ("u1", "ann@example.com", "Ann");
const BO: (&str, &str, &str) = ("u2", "bo@example.com", "Bo");
const CY: (&str, &str, &str) = ("u3", "cy@example.com", "Cy");
const VI: (&str, &str, &str) = ("u4", "vi@example.com", "Vi");

fn tok(t: (&str, &str, &str)) -> String {
    format!("{}|{}|{}", t.0, t.1, t.2)
}

/// Ann publishes sealed signed in: the file requires signatures from its first batch on, and
/// her batches carry her device's signature. Bo (editor) signs too; an app that doesn't sign is
/// refused by the server; a share link only views the file. Cy, made editor while the others are
/// in the file, is taken once their apps fetch the editors again. Bo's second device changes his
/// safety number (Ann is warned); his first device, revoked, can't edit anymore: the sessions
/// that see its batch end.
#[test]
fn editors_sign_and_their_apps_check_each_other() {
    let dir = TempDir::new("sign-editors");
    let mut cfg = accounts_config(dir.path(), "accounts+links");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let addr = server.addr();
    let url = format!("ws://{addr}/");
    let mut ann = signed_in("Ann", &url, &tok(ANN));
    let mut bo = signed_in("Bo", &url, &tok(BO));
    let mut vi = signed_in("Vi", &url, &tok(VI));
    let bo_first = device(&mut bo, &url);
    device(&mut vi, &url);
    let layer = rect(&mut ann, "Plan");
    ex(&mut ann, "collab.publish", json!({"server": url, "name": "Roadmap", "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    ex(&mut ann, "account.syncKeys", json!({"server": url}));
    // Signatures are required from the first batch on: the publisher's app asked, and every
    // owner had a device.
    let AccountReply::EditorKeys { signed_from, editors } = account_ask(addr, ANN, AccountReq::EditorKeys { file: p.file.clone() }) else { panic!() };
    assert_eq!(signed_from, Some(0));
    let ann_keys = keys_of(&ann);
    assert_eq!(editors.iter().map(|e| e.public.signing).collect::<Vec<_>>(), vec![ann_keys.public().unwrap().signing]);

    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "editor"}));
    ex(&mut ann, "collab.invite", json!({"email": "vi@example.com", "role": "viewer"}));
    let bo_account = account_of(&mut ann, "bo@example.com");
    ex(&mut bo, "collab.join", json!({"link": bare}));
    ex(&mut vi, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut bo, &mut vi], "Bo and Vi in", |s| live(s[1]) && live(s[2]));
    // A viewer's raw connection sees Ann's batch signed by her device.
    let (mut watcher, _, access) = raw_member(addr, VI, &p.file);
    assert_eq!(access, message::Access::View);
    rename(&mut ann, layer, "By Ann");
    let batch = loop {
        if let ServerMsg::SealedChanges(a) = watcher.next() {
            break a;
        }
    };
    assert!(matches!(batch.changes.last(), Some(SealedChange::Signature(_))));
    assert_eq!(verify_batch(&p.file, batch.batch_id, &batch.changes), Signed::By(ann_keys.public().unwrap().signing));
    drop(watcher);
    // Bo's edits are signed and taken everywhere.
    rename(&mut bo, layer, "By Bo");
    pump(&mut [&mut ann, &mut bo, &mut vi], "Bo's edit everywhere", |s| named(s[0], layer, "By Bo") && named(s[2], layer, "By Bo"));
    assert!(live(&ann) && live(&vi));

    // An app that doesn't sign (one from before signed changes) is refused by the server.
    let (mut old, seq, access) = raw_member(addr, BO, &p.file);
    assert_eq!(access, message::Access::Edit);
    old.send(&forged(&ring_of(&bo), &p.file, layer, "Unsigned", seq, 1, None));
    let reason = loop {
        if let ServerMsg::SealedReject { reason, .. } = old.next() {
            break reason;
        }
    };
    assert_eq!(reason, UNSIGNED);
    drop(old);
    // A share link only views a file whose changes must be signed.
    let req = AccountReq::CreateLink { file: p.file.clone(), access: message::Access::Edit, label: "Edit".into() };
    let AccountReply::Link(link) = account_ask(addr, ANN, req) else { panic!() };
    let (_, _, access) = raw_join(Raw::connect(addr), &p.file, &link.token);
    assert_eq!(access, message::Access::View);

    // Cy is made an editor while everyone is in: the apps learn her device when her first batch
    // comes (they fetch the editors again once for a device they don't know).
    ex(&mut ann, "collab.invite", json!({"email": "cy@example.com", "role": "editor"}));
    let mut cy = signed_in("Cy", &url, &tok(CY));
    ex(&mut cy, "collab.join", json!({"link": bare}));
    // Her device registered as she joined; the next owner's sync wraps the key for it.
    pump(&mut [&mut ann, &mut bo, &mut vi, &mut cy], "Cy waiting", |s| s[3].live_summary()["waitingForAccess"] == true || live(s[3]));
    ex(&mut ann, "account.syncKeys", json!({"server": url}));
    if !live(&cy) {
        ex(&mut cy, "collab.join", json!({"link": bare}));
    }
    pump(&mut [&mut ann, &mut bo, &mut vi, &mut cy], "Cy in", |s| live(s[3]) && same(s[0].doc().unwrap(), s[3].doc().unwrap()));
    rename(&mut cy, layer, "By Cy");
    pump(&mut [&mut ann, &mut bo, &mut vi, &mut cy], "Cy's edit everywhere", |s| {
        named(s[0], layer, "By Cy") && named(s[1], layer, "By Cy") && named(s[2], layer, "By Cy")
    });
    assert!(live(&ann) && live(&bo) && live(&vi), "{:?} {:?} {:?}", failed(&ann), failed(&bo), failed(&vi));

    // Safety numbers: Ann's view of Bo's devices is the number Bo sees for himself; a second
    // device of his changes it, and Ann is told.
    let seen = number(&mut ann, &url, Some(&bo_account));
    assert_eq!(seen["safetyNumber"], number(&mut bo, &url, None)["safetyNumber"]);
    assert_eq!((seen["you"].clone(), seen["devices"].clone()), (json!(false), json!(1)));
    let mut bo2 = signed_in("Bo", &url, &tok(BO));
    device(&mut bo2, &url);
    let now = number(&mut ann, &url, Some(&bo_account));
    assert_ne!(now["safetyNumber"], seen["safetyNumber"]);
    assert_eq!((now["changed"].clone(), now["devices"].clone()), (json!(true), json!(2)));
    assert_eq!(number(&mut ann, &url, Some(&bo_account))["changed"], false, "seen now");
    // Someone who shares no file with you: no number.
    let mut stranger = signed_in("Zed", &url, "u9|zed@example.com|Zed");
    assert!(stranger.execute("account.safetyNumber", &json!({"server": url, "account": bo_account})).is_err());

    // Bo revokes his first device from his second: once Ann's app fetched the editors again (her
    // next sync), the batch his first device's app still signs ends the sessions that see it.
    ex(&mut bo2, "account.revokeDevice", json!({"server": url, "device": bo_first}));
    let after = number(&mut bo2, &url, None)["safetyNumber"].clone();
    ex(&mut ann, "account.syncKeys", json!({"server": url}));
    pump(&mut [&mut ann, &mut bo, &mut vi, &mut cy], "Ann told Bo's devices changed", |s| {
        s[0].keys.changes.iter().any(|c| c.account == bo_account && json!(c.now) == after)
    });
    let status = ex(&mut ann, "account.status", json!({}));
    assert!(status["keyChanges"].as_array().unwrap().iter().any(|c| c["account"] == bo_account.as_str()), "{status}");
    rename(&mut bo, layer, "By a revoked device");
    pump(&mut [&mut ann, &mut bo, &mut vi, &mut cy], "Ann's session ends", |s| failed(s[0]).is_some());
    assert_eq!(failed(&ann).as_deref(), Some(BatchRefused::NotEditor.to_string().as_str()));
    assert!(!named(&ann, layer, "By a revoked device"));
    drop((ann, bo, bo2, vi, cy, stranger));
    server.stop();
}

/// Vi, a viewer, holds the file's key. Through a server that lets her edit and passes on what
/// she sends (hostile, or broken into), her batches reach the editors' apps, which refuse them:
/// signed with her own device (not an editor's), or not signed at all. Their sessions end with
/// the reason, and the forged name isn't applied.
#[test]
fn a_viewers_forged_batches_are_refused_by_the_apps() {
    let dir = TempDir::new("sign-forged");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "required".into();
    let mut server = start(&cfg);
    let addr = server.addr();
    let url = format!("ws://{addr}/");
    let mut ann = signed_in("Ann", &url, &tok(ANN));
    let mut bo = signed_in("Bo", &url, &tok(BO));
    let mut vi = signed_in("Vi", &url, &tok(VI));
    device(&mut bo, &url);
    device(&mut vi, &url);
    let layer = rect(&mut ann, "Plan");
    ex(&mut ann, "collab.publish", json!({"server": url, "name": "Roadmap"}));
    pump(&mut [&mut ann], "Ann's publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "editor"}));
    ex(&mut ann, "collab.invite", json!({"email": "vi@example.com", "role": "viewer"}));
    ex(&mut bo, "collab.join", json!({"link": bare}));
    ex(&mut vi, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut bo, &mut vi], "everyone in", |s| live(s[1]) && live(s[2]));
    rename(&mut bo, layer, "By Bo");
    pump(&mut [&mut ann, &mut bo, &mut vi], "Bo's edit", |s| named(s[0], layer, "By Bo") && named(s[2], layer, "By Bo"));
    let (ring, vi_keys) = (ring_of(&vi), keys_of(&vi));
    // The server turns hostile for this file.
    crate::store::HOSTILE.lock().unwrap().push(p.file.clone());

    // Signed with Vi's own device: not an editor's.
    let (mut forger, seq, access) = raw_member(addr, VI, &p.file);
    assert_eq!(access, message::Access::Edit, "the hostile server lets her edit");
    forger.send(&forged(&ring, &p.file, layer, "Forged", seq, 1, Some(&vi_keys)));
    pump(&mut [&mut ann, &mut bo], "the editors' sessions end", |s| failed(s[0]).is_some() && failed(s[1]).is_some());
    for s in [&ann, &bo] {
        assert_eq!(failed(s).as_deref(), Some(BatchRefused::NotEditor.to_string().as_str()));
        assert!(!named(s, layer, "Forged"));
    }

    // Unsigned: the file requires signatures, so the apps refuse it too (the server passed it on).
    ex(&mut ann, "collab.join", json!({"link": bare}));
    ex(&mut bo, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut bo], "back in", |s| live(s[0]) && live(s[1]));
    // The welcome of a fresh connection says where the session is now.
    let (_, seq, _) = raw_member(addr, VI, &p.file);
    forger.send(&forged(&ring, &p.file, layer, "Forged unsigned", seq, 2, None));
    pump(&mut [&mut ann, &mut bo], "the editors' sessions end again", |s| failed(s[0]).is_some() && failed(s[1]).is_some());
    for s in [&ann, &bo] {
        assert_eq!(failed(s).as_deref(), Some(BatchRefused::Unsigned.to_string().as_str()));
        assert!(!named(s, layer, "Forged unsigned"));
    }
    crate::store::HOSTILE.lock().unwrap().retain(|f| *f != p.file);
    drop((ann, bo, vi, forger));
    server.stop();
}
