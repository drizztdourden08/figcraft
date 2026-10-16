//! Sealed files with accounts end to end (step 9 of `docs/accounts-and-e2e.md`): engine sessions
//! on a real server with a fake identity provider. The owner publishes sealed while signed in and
//! the key reaches the owner's second device and invited members through the server's keyring
//! (no `#k=` in any link they use); someone taken out can't read what is written after (the file
//! moves to a new epoch, their app is disconnected and can't join again); a recovery key gives a
//! fresh device access; the server's data directory holds nothing readable.

use std::path::Path;

use figcraft_collab::message::{self, ClientMsg, Hello, PROTOCOL, ServerMsg};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab_seal::{Keyring, open_change, parse_ring_fragment};
use figcraft_engine::Session;
use figcraft_engine::devices::WAITING_FOR_ACCESS;
use figcraft_engine::live::Status;
use serde_json::{Value, json};

use crate::accounts_tests::{accounts_config, signed, start, token};
use crate::store::keyrings::KeyringFile;
use crate::test_util::{TempDir, live, pump, same, session};

const MARKERS: [&str; 4] = ["CANARY-KEYS-LAYER-31c", "CANARY-KEYS-NAME-8a2", "CANARY-KEYS-EDIT-5d7", "CANARY-KEYS-AFTER-0f9"];

fn ex(s: &mut Session, cmd: &str, p: Value) -> Value {
    s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

fn rect(s: &mut Session, name: &str) -> u64 {
    let id = ex(s, "shape.rectangle", json!({"x": 10, "y": 10, "width": 40, "height": 30}))["id"].as_u64().unwrap();
    ex(s, "node.set", json!({"ids": [id], "props": {"name": name}}));
    id
}

fn named(s: &Session, id: u64, name: &str) -> bool {
    s.doc().is_ok_and(|d| d.node(figcraft_doc::NodeId(id)).is_some_and(|n| n.name == name))
}

fn failed(s: &Session) -> Option<String> {
    match &s.live().status {
        Status::Failed { reason } => Some(reason.clone()),
        _ => None,
    }
}

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

/// Nothing readable on the server's disk: no marker, no file key, no device secret.
fn clean_disk(dir: &Path, secrets: &[String]) {
    for (path, bytes) in all_bytes(dir) {
        for m in MARKERS {
            assert!(!bytes.windows(m.len()).any(|w| w == m.as_bytes()), "{path} has {m} in the clear");
        }
        for s in secrets.iter().filter(|s| s.len() > 20) {
            assert!(!bytes.windows(s.len()).any(|w| w == s.as_bytes()), "{path} has a secret in it");
        }
    }
}

fn keyring(dir: &Path, file: &str) -> KeyringFile {
    serde_json::from_slice(&std::fs::read(dir.join("files").join(file).join("keyring.json")).unwrap()).unwrap()
}

/// Signed in on a server with accounts and sealed files.
fn signed_in(name: &str, url: &str, tok: &str) -> Session {
    let mut s = session(name);
    ex(&mut s, "account.signIn", json!({"server": url, "token": tok}));
    s
}

fn device(s: &mut Session, url: &str) -> String {
    ex(s, "account.devices", json!({"server": url}))["device"].as_str().unwrap().to_string()
}

fn sync(s: &mut Session, url: &str) -> Value {
    ex(s, "account.syncKeys", json!({"server": url}))
}

fn waiting(s: &Session) -> bool {
    s.live_summary()["waitingForAccess"] == true
}

/// Ann publishes sealed while signed in: her key goes into the file's keyring for her device. Her
/// second device gets access once it registered and her first device wrapped the key for it; Bo,
/// invited, waits for access until Ann's app wraps for his device, then joins with the member's
/// link (no `#k=`). Edits flow; the disk keeps ciphertext only.
#[test]
fn the_key_reaches_your_other_devices_and_invited_members() {
    let dir = TempDir::new("keys-devices");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let url = format!("ws://{}/", server.addr());
    let mut ann = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let layer = rect(&mut ann, MARKERS[0]);
    ex(&mut ann, "collab.publish", json!({"server": url, "name": MARKERS[1], "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    assert!(!bare.contains("token="), "a member's link: {bare}");
    // The key goes into the file's keyring, wrapped to Ann's device.
    let first = device(&mut ann, &url);
    sync(&mut ann, &url);
    let ring = keyring(dir.path(), &p.file);
    assert_eq!(ring.epochs.keys().copied().collect::<Vec<_>>(), vec![0]);
    assert!(ring.epochs[&0].contains_key(&first), "{ring:?}");
    assert_eq!(ann.live_summary()["sealed"], true);

    // Ann's second device: the member's link waits for access until her first device wraps.
    let mut ann2 = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let r = ex(&mut ann2, "collab.join", json!({"link": bare}));
    assert_eq!(r["status"], "failed");
    assert_eq!(failed(&ann2).as_deref(), Some(WAITING_FOR_ACCESS));
    assert!(waiting(&ann2));
    let devices = ex(&mut ann2, "account.devices", json!({"server": url}));
    assert_eq!(devices["devices"].as_array().unwrap().len(), 2, "{devices}");
    assert_eq!(devices["keyStore"], "preferences", "no keychain in tests");
    let second = devices["device"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    // Not yet: nobody wrapped for the second device.
    assert_eq!(sync(&mut ann2, &url)["joined"], json!([]));
    assert!(waiting(&ann2));
    let r = sync(&mut ann, &url);
    assert!(r["wrapped"].as_u64().unwrap() >= 1, "{r}");
    assert!(keyring(dir.path(), &p.file).epochs[&0].contains_key(&second));
    // The second device's next sync opens the file.
    let r = sync(&mut ann2, &url);
    assert_eq!(r["joined"], json!([p.file]), "{r}");
    pump(&mut [&mut ann, &mut ann2], "Ann's second device in", |s| live(s[1]) && same(s[0].doc().unwrap(), s[1].doc().unwrap()));
    assert!(named(&ann2, layer, MARKERS[0]));
    assert!(!waiting(&ann2));
    // Its list opens the name with the key it holds now.
    let files = ex(&mut ann2, "account.files", json!({"server": url}));
    assert_eq!(files["files"][0]["name"], MARKERS[1]);

    // Bo is invited before he ever signed in: he waits for access, Ann's app wraps for him.
    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "editor"}));
    let mut bo = signed_in("Bo", &url, "u2|bo@example.com|Bo");
    ex(&mut bo, "collab.join", json!({"link": bare}));
    assert_eq!(failed(&bo).as_deref(), Some(WAITING_FOR_ACCESS));
    assert!(waiting(&bo));
    let theirs = ex(&mut bo, "account.files", json!({"server": url}));
    assert_eq!(theirs["files"][0]["name"], "Encrypted file");
    let r = sync(&mut ann, &url);
    assert!(r["wrapped"].as_u64().unwrap() >= 1, "{r}");
    // Joining again (the button the UI shows) opens it now.
    ex(&mut bo, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut ann2, &mut bo], "Bo in", |s| live(s[2]) && same(s[0].doc().unwrap(), s[2].doc().unwrap()));
    ex(&mut bo, "node.set", json!({"ids": [layer], "props": {"name": MARKERS[2]}}));
    pump(&mut [&mut ann, &mut ann2, &mut bo], "Bo's edit everywhere", |s| named(s[0], layer, MARKERS[2]) && named(s[1], layer, MARKERS[2]));
    assert_eq!(ex(&mut bo, "account.files", json!({"server": url}))["files"][0]["name"], MARKERS[1]);
    // No key in any result or in Debug.
    let kept = ann.prefs.file_keys[0].key.clone();
    assert!(!ex(&mut ann, "account.devices", json!({"server": url})).to_string().contains(&kept));
    assert!(!format!("{:?}", bo.prefs).contains(&bo.prefs.device.secret));
    let secrets = vec![kept, ann.prefs.device.secret.clone(), ann2.prefs.device.secret.clone(), bo.prefs.device.secret.clone()];
    drop((ann, ann2, bo));
    server.stop();
    clean_disk(dir.path(), &secrets);
}

/// A raw member connection that joins `file` signed in as `tok`: the sealed welcome's changes.
fn sealed_snapshot(addr: std::net::SocketAddr, tok: (&str, &str, &str), file: &str) -> Vec<SealedChange> {
    let (mut raw, me) = signed(addr, token(tok.0, tok.1, tok.2));
    me.unwrap();
    raw.send(&ClientMsg::Hello(Hello {
        protocol: PROTOCOL,
        file: file.into(),
        token: String::new(),
        name: "raw".into(),
        color: String::new(),
        client_version: message::client_version(),
        resume: None,
    }));
    loop {
        match raw.next() {
            ServerMsg::SealedWelcome { catch_up: figcraft_collab::message::CatchUpOf::Snapshot(s), .. } => return s,
            ServerMsg::Refused { reason } => panic!("refused: {reason}"),
            _ => {}
        }
    }
}

/// Whether some change of `snapshot` opens with `ring` and names a layer `name`.
fn opens_to(ring: &Keyring, file: &str, snapshot: &[SealedChange], name: &str) -> bool {
    snapshot.iter().filter_map(|c| open_change(ring, file, c).ok()).any(|c| serde_json::to_string(&c).is_ok_and(|t| t.contains(name)))
}

/// Ann takes Bo out of her sealed file: the server disconnects him, Ann's app starts epoch 1 for
/// the devices left (hers and Cy's) and seals new writes with it; Cy's app picks the new key up
/// by itself and keeps editing; Bo's keys open nothing written after, and he can't join again.
#[test]
fn someone_taken_out_cant_read_the_new_epoch() {
    let dir = TempDir::new("keys-removal");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "required".into();
    let mut server = start(&cfg);
    let addr = server.addr();
    let url = format!("ws://{addr}/");
    let mut ann = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let mut bo = signed_in("Bo", &url, "u2|bo@example.com|Bo");
    let mut cy = signed_in("Cy", &url, "u3|cy@example.com|Cy");
    let bo_device = device(&mut bo, &url);
    device(&mut cy, &url);
    let layer = rect(&mut ann, "Plan");
    ex(&mut ann, "collab.publish", json!({"server": url, "name": "Roadmap"}));
    pump(&mut [&mut ann], "Ann's publish (sealed: the server requires it)", |s| live(s[0]) && s[0].live().published.is_some());
    assert_eq!(ann.live_summary()["sealed"], true);
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    sync(&mut ann, &url);
    // Inviting people who registered a device wraps the key for them at once.
    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "editor"}));
    ex(&mut ann, "collab.invite", json!({"email": "cy@example.com", "role": "editor"}));
    let members = ex(&mut ann, "collab.members", json!({}));
    let bo_account =
        members["members"].as_array().unwrap().iter().find(|m| m["email"] == "bo@example.com").unwrap()["account"].as_str().unwrap().to_string();
    let ring = keyring(dir.path(), &p.file);
    assert!(ring.epochs[&0].contains_key(&bo_device), "wrapped for Bo when he was invited: {ring:?}");
    ex(&mut bo, "collab.join", json!({"link": bare}));
    ex(&mut cy, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut bo, &mut cy], "Bo and Cy in", |s| live(s[1]) && live(s[2]) && s[0].live().peers.len() == 2);
    let bo_keys: Keyring = parse_ring_fragment(&bo.prefs.file_keys[0].key).unwrap();
    assert_eq!(bo_keys.epochs().collect::<Vec<_>>(), vec![0]);

    // Bo is taken out: disconnected, and the file starts epoch 1 without his devices.
    ex(&mut ann, "collab.removeMember", json!({"account": bo_account}));
    let ring = keyring(dir.path(), &p.file);
    assert_eq!(ring.epochs.keys().copied().collect::<Vec<_>>(), vec![0, 1], "{ring:?}");
    assert!(!ring.rotate);
    assert!(!ring.epochs.values().any(|w| w.contains_key(&bo_device)), "Bo's copies are gone");
    pump(&mut [&mut ann, &mut bo, &mut cy], "Bo out", |s| !s[1].live().status.active() && s[0].live().peers.len() == 1);

    // Ann writes with the new epoch; Cy's app fetches it and keeps up.
    ex(&mut ann, "node.set", json!({"ids": [layer], "props": {"name": MARKERS[3]}}));
    pump(&mut [&mut ann, &mut cy], "Ann's edit at Cy (after Cy got the new key)", |s| named(s[1], layer, MARKERS[3]) && live(s[1]));
    pump(&mut [&mut ann, &mut cy], "the same document", |s| same(s[0].doc().unwrap(), s[1].doc().unwrap()));
    let cy_keys: Keyring = parse_ring_fragment(&cy.prefs.file_keys[0].key).unwrap();
    assert_eq!(cy_keys.epochs().collect::<Vec<_>>(), vec![0, 1]);
    ex(&mut cy, "node.set", json!({"ids": [layer], "props": {"name": "Cy was here"}}));
    pump(&mut [&mut ann, &mut cy], "Cy's edit at Ann", |s| named(s[0], layer, "Cy was here"));
    ex(&mut ann, "node.set", json!({"ids": [layer], "props": {"name": MARKERS[3]}}));
    pump(&mut [&mut ann, &mut cy], "Ann's edit at Cy", |s| named(s[1], layer, MARKERS[3]));

    // What the server holds now: Cy's (current) keys open the new name, Bo's keys don't.
    let snapshot = sealed_snapshot(addr, ("u3", "cy@example.com", "Cy"), &p.file);
    assert!(opens_to(&cy_keys, &p.file, &snapshot, MARKERS[3]), "Cy opens the new name");
    assert!(!opens_to(&bo_keys, &p.file, &snapshot, MARKERS[3]), "Bo's old key doesn't");
    // Bo can't join again, with or without his old key.
    let mut again = signed_in("Bo", &url, "u2|bo@example.com|Bo");
    again.prefs.file_keys = bo.prefs.file_keys.clone();
    again.prefs.device = bo.prefs.device.clone();
    let _ = again.execute("collab.join", &json!({"link": bare}));
    pump(&mut [&mut again], "Bo refused", |s| failed(s[0]).is_some());
    assert!(failed(&again).is_some_and(|r| r.contains("aren't in this file")), "{:?}", failed(&again));
    let secrets = vec![ann.prefs.device.secret.clone(), cy.prefs.device.secret.clone(), cy.prefs.file_keys[0].key.clone()];
    drop((ann, bo, cy, again));
    server.stop();
    clean_disk(dir.path(), &secrets);
}

/// Ann makes a recovery key (shown once; asking again doesn't show it), loses her device, and a
/// fresh device opens her sealed file with the recovery key. A wrong key is refused.
#[test]
fn a_recovery_key_restores_access_on_a_fresh_device() {
    let dir = TempDir::new("keys-recovery");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let url = format!("ws://{}/", server.addr());
    let mut ann = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let layer = rect(&mut ann, MARKERS[0]);
    ex(&mut ann, "collab.publish", json!({"server": url, "name": MARKERS[1], "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    sync(&mut ann, &url);
    let made = ex(&mut ann, "account.recoveryKey", json!({"server": url}));
    assert_eq!(made["created"], true);
    let recovery = made["recoveryKey"].as_str().unwrap().to_string();
    assert_eq!(recovery.len(), 65, "11 groups of 5: {recovery}");
    let rdev = made["device"].as_str().unwrap().to_string();
    assert!(keyring(dir.path(), &p.file).epochs[&0].contains_key(&rdev), "wrapped for the recovery device");
    // Asked again: there is one, and it isn't shown.
    let again = ex(&mut ann, "account.recoveryKey", json!({"server": url}));
    assert_eq!(again["created"], false);
    assert!(again.get("recoveryKey").is_none());
    let list = ex(&mut ann, "account.devices", json!({"server": url}));
    assert!(list["devices"].as_array().unwrap().iter().any(|d| d["recovery"] == true));
    let secrets = vec![ann.prefs.device.secret.clone(), ann.prefs.file_keys[0].key.clone(), recovery.replace('-', "")];
    drop(ann);

    // A fresh device: no key until the recovery key is typed.
    let mut fresh = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let e = fresh.execute("account.recover", &json!({"server": url, "recoveryKey": "AAAAA-BBBBB"})).unwrap_err().to_string();
    assert!(e.contains("recovery key"), "{e}");
    let other = figcraft_collab_seal::RecoveryKey::generate().unwrap().to_display().to_string();
    let e = fresh.execute("account.recover", &json!({"server": url, "recoveryKey": other})).unwrap_err().to_string();
    assert!(e.contains("doesn't open"), "{e}");
    let r = ex(&mut fresh, "account.recover", json!({"server": url, "recoveryKey": recovery.to_lowercase()}));
    assert_eq!(r["files"], json!([p.file]), "{r}");
    assert!(!r.to_string().contains(&recovery));
    ex(&mut fresh, "collab.join", json!({"link": bare}));
    pump(&mut [&mut fresh], "the fresh device in", |s| live(s[0]));
    assert!(named(&fresh, layer, MARKERS[0]));
    let mut secrets = secrets;
    secrets.push(fresh.prefs.device.secret.clone());
    drop(fresh);
    server.stop();
    clean_disk(dir.path(), &secrets);
}

/// Revoking a device takes its copies away and starts a new epoch (an owner's app does it); a
/// server keeps at most ten devices per person; viewers can't wrap for others.
#[test]
fn devices_are_revoked_and_capped() {
    let dir = TempDir::new("keys-revoke");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let url = format!("ws://{}/", server.addr());
    let mut ann = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    rect(&mut ann, "Card");
    ex(&mut ann, "collab.publish", json!({"server": url, "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let file = ann.live().published.clone().unwrap().file;
    sync(&mut ann, &url);
    let mut laptop = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let lost = device(&mut laptop, &url);
    sync(&mut ann, &url);
    assert!(keyring(dir.path(), &file).epochs[&0].contains_key(&lost));
    let r = ex(&mut ann, "account.revokeDevice", json!({"server": url, "device": lost}));
    assert_eq!(r["rotated"], json!([file]), "{r}");
    let ring = keyring(dir.path(), &file);
    assert_eq!(ring.epochs.len(), 2);
    assert!(!ring.epochs.values().any(|w| w.contains_key(&lost)));
    assert_eq!(ex(&mut ann, "account.devices", json!({"server": url}))["devices"].as_array().unwrap().len(), 1);
    // At most ten devices per person.
    for _ in 0..9 {
        let mut d = signed_in("Ann", &url, "u1|ann@example.com|Ann");
        device(&mut d, &url);
    }
    let mut eleventh = signed_in("Ann", &url, "u1|ann@example.com|Ann");
    let e = eleventh.execute("account.devices", &json!({"server": url})).unwrap_err().to_string();
    assert!(e.contains("most one person may"), "{e}");
    server.stop();
}
