//! Sealed (end-to-end encrypted) files from the app (step 8 of `docs/accounts-and-e2e.md`): engine
//! sessions publish sealed files to a real server (with its key, as anyone may on an open server,
//! and signed in on a server with accounts), others join with the link that carries the key,
//! edits, presence and cursor chat flow, and the server's data directory holds none of it in the
//! clear. Joins with a missing or wrong key, a key for a plain file, and the server's `[e2e]` mode
//! all end with a clear reason.

use std::path::Path;

use figcraft_collab_net::guest::NO_SEALED_FILES;
use figcraft_collab_net::sealing::{NEEDS_KEY, NOT_SEALED, WRONG_KEY};
use figcraft_engine::Session;
use figcraft_engine::live::Status;
use serde_json::{Value, json};

use crate::accounts_tests::{accounts_config, start};
use crate::config::Config;
use crate::test_util::{TempDir, config, join, key, live, pump, same, session};

/// What must never be found on the server in the clear.
const MARKERS: [&str; 4] = ["CANARY-LAYER-51ab", "CANARY-FILENAME-77c0", "CANARY-EDIT-0e2f", "CANARY-CHAT-9d14"];

fn ex(s: &mut Session, cmd: &str, p: Value) -> Value {
    s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

fn sealed_config(dir: &Path, mode: &str) -> Config {
    let mut c = config(dir);
    c.e2e.mode = mode.into();
    c
}

/// A rectangle named `name` in the open file: its id.
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

/// Ada publishes with the server's key, sealed; Bo joins with the link (its key after `#k=`);
/// edits, presence and chat go both ways; nothing readable reaches the server's disk.
#[test]
fn a_sealed_file_published_with_the_key_is_joined_by_its_link() {
    let dir = TempDir::new("app-sealed");
    let mut server = crate::start(&sealed_config(dir.path(), "optional")).unwrap();
    let addr = server.addr();
    let mut a = session("Ada");
    let layer = rect(&mut a, MARKERS[0]);
    let r = ex(&mut a, "collab.publish", json!({"server": format!("ws://{addr}/?key={}", key(dir.path())), "name": MARKERS[1], "sealed": true}));
    assert_eq!(r["status"], "connecting");
    pump(&mut [&mut a], "the sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = a.live().published.clone().unwrap();
    assert!(p.edit.contains("#k=") && p.view.contains("#k="), "the links carry the key: {p:?}");
    assert_eq!(p.name, MARKERS[1], "the app knows the name it sealed");
    assert_eq!(p.file.len(), 16, "an id the app picked");
    let summary = a.live_summary();
    assert_eq!(summary["sealed"], true);
    assert_eq!(a.prefs.file_keys.len(), 1, "the key is kept with the preferences");
    assert!(!format!("{:?}", a.prefs).contains(&a.prefs.file_keys[0].key), "Debug leaves the key out");
    // Bo joins with the edit link.
    let mut b = join(&p.edit, "Bo");
    pump(&mut [&mut a, &mut b], "Bo in", |s| live(s[1]) && s[0].live().peers.len() == 1);
    assert_eq!(b.live_summary()["sealed"], true);
    assert!(named(&b, layer, MARKERS[0]), "Bo opens the layer's name");
    // Edits both ways.
    ex(&mut b, "node.set", json!({"ids": [layer], "props": {"name": MARKERS[2]}}));
    pump(&mut [&mut a, &mut b], "Bo's edit at Ada", |s| named(s[0], layer, MARKERS[2]));
    let second = rect(&mut a, "Second");
    pump(&mut [&mut a, &mut b], "Ada's layer at Bo", |s| named(s[1], second, "Second") && same(s[0].doc().unwrap(), s[1].doc().unwrap()));
    // Presence and cursor chat, sealed on the way.
    pump(&mut [&mut a, &mut b], "signals", |s| s[0].live().signals && s[1].live().signals);
    let ada = a.live().info.as_ref().unwrap().me;
    ex(&mut a, "collab.cursor", json!({"x": 12, "y": 34}));
    pump(&mut [&mut a, &mut b], "Ada's cursor at Bo", |s| s[1].live().presence.get(&ada).and_then(|p| p.cursor).is_some_and(|c| c.1 == 12.0));
    ex(&mut a, "collab.cursorChat", json!({"text": MARKERS[3]}));
    pump(&mut [&mut a, &mut b], "Ada's chat at Bo", |s| s[1].live().chats.get(&ada).is_some_and(|t| t == MARKERS[3]));
    // A late joiner with the view link opens the same document from the server's sealed copy.
    let mut c = join(&p.view, "Cy");
    pump(&mut [&mut a, &mut b, &mut c], "Cy in", |s| live(s[2]) && same(s[0].doc().unwrap(), s[2].doc().unwrap()));
    assert_eq!(c.live_summary()["access"], "view");
    drop((a, b, c));
    server.stop();
    let files = all_bytes(dir.path());
    assert!(files.iter().any(|(path, _)| path.contains(&p.file)), "the file is on disk");
    for (path, bytes) in files {
        assert!(hits(&bytes).is_empty(), "{path}: {:?}", hits(&bytes));
    }
}

/// A join without the key, with a wrong one, or with a key for a plain file ends with the reason.
#[test]
fn joins_with_a_missing_or_wrong_key_fail_clearly() {
    let dir = TempDir::new("app-sealed-keys");
    let mut server = crate::start(&sealed_config(dir.path(), "optional")).unwrap();
    let addr = server.addr();
    let address = format!("ws://{addr}/?key={}", key(dir.path()));
    let mut a = session("Ada");
    rect(&mut a, "Secret");
    ex(&mut a, "collab.publish", json!({"server": address, "sealed": true}));
    pump(&mut [&mut a], "the sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let sealed = a.live().published.clone().unwrap().edit;
    let (bare, fragment) = sealed.split_once('#').unwrap();
    // No key.
    let mut x = join(bare, "X");
    pump(&mut [&mut x], "no key", |s| failed(s[0]).is_some());
    assert_eq!(failed(&x).as_deref(), Some(NEEDS_KEY));
    // Another file's key.
    let mut other = session("Other");
    ex(&mut other, "collab.publish", json!({"server": address, "sealed": true}));
    pump(&mut [&mut other], "another sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let other_key = other.live().published.clone().unwrap().edit.split_once('#').unwrap().1.to_string();
    assert_ne!(other_key, fragment);
    let mut y = join(&format!("{bare}#{other_key}"), "Y");
    pump(&mut [&mut y], "the wrong key", |s| failed(s[0]).is_some());
    assert_eq!(failed(&y).as_deref(), Some(WRONG_KEY));
    // A broken key isn't even tried.
    let mut z = session("Z");
    let e = z.execute("collab.join", &json!({"link": format!("{bare}#k=nope")})).unwrap_err().to_string();
    assert!(e.contains("key") && !e.contains("nope"), "{e}");
    // A plain file's link with a key: the server sent it in the clear, so it isn't opened.
    let mut plain = session("Plain");
    ex(&mut plain, "collab.publish", json!({"server": address}));
    pump(&mut [&mut plain], "a plain publish", |s| live(s[0]) && s[0].live().published.is_some());
    let plain_link = plain.live().published.clone().unwrap().edit;
    assert!(!plain_link.contains('#'));
    assert_eq!(plain.live_summary()["sealed"], false);
    let mut w = join(&format!("{plain_link}#{fragment}"), "W");
    pump(&mut [&mut w], "a key for a plain file", |s| failed(s[0]).is_some());
    assert_eq!(failed(&w).as_deref(), Some(NOT_SEALED));
    server.stop();
}

/// The server's `[e2e]` mode decides: `required` seals by default, `off` refuses a sealed
/// publish before anything is sent, `optional` publishes plain unless asked.
#[test]
fn the_servers_e2e_mode_decides_by_default() {
    let publish = |mode: &str, sealed: Option<bool>| -> (Session, TempDir, crate::Running) {
        let dir = TempDir::new(&format!("app-sealed-{mode}"));
        let server = crate::start(&sealed_config(dir.path(), mode)).unwrap();
        let mut a = session("Ada");
        let mut p = json!({"server": format!("ws://{}/?key={}", server.addr(), key(dir.path()))});
        if let Some(s) = sealed {
            p["sealed"] = json!(s);
        }
        ex(&mut a, "collab.publish", p);
        pump(&mut [&mut a], "the publish", |s| (live(s[0]) && s[0].live().published.is_some()) || failed(s[0]).is_some());
        (a, dir, server)
    };
    let (a, _d, mut s) = publish("required", None);
    assert_eq!(a.live_summary()["sealed"], true, "sealed by default: {}", a.live_summary());
    s.stop();
    let (a, _d, mut s) = publish("required", Some(false));
    assert!(failed(&a).is_some_and(|r| r.contains("only sealed")), "{:?}", failed(&a));
    s.stop();
    let (a, _d, mut s) = publish("off", Some(true));
    assert!(failed(&a).is_some_and(|r| r.contains(NO_SEALED_FILES)), "{:?}", failed(&a));
    s.stop();
    let (a, _d, mut s) = publish("off", None);
    assert_eq!(a.live_summary()["sealed"], false);
    s.stop();
    let (a, _d, mut s) = publish("optional", None);
    assert_eq!(a.live_summary()["sealed"], false);
    s.stop();
}

/// Shared as anyone may on an open server: the links others get carry the key and have no join
/// codes; the owner's list shows the name the server only has sealed.
#[test]
fn a_sealed_file_shared_on_an_open_server() {
    let dir = TempDir::new("app-sealed-open");
    let mut server = crate::start(&Config { open_publish: true, ..sealed_config(dir.path(), "optional") }).unwrap();
    let url = format!("ws://{}/", server.addr());
    let mut a = session("Ada");
    ex(&mut a, "pref.publishServer", json!({"url": url}));
    rect(&mut a, "Card");
    ex(&mut a, "collab.share", json!({"name": "Plans", "sealed": true}));
    pump(&mut [&mut a], "the share", |s| live(s[0]) && s[0].live().share.as_ref().is_some_and(|sh| sh.links.is_some()));
    let summary = a.live_summary();
    assert_eq!(summary["sealed"], true);
    assert!(summary["code"].is_null() && summary["share"]["editCode"].is_null(), "no join codes: {summary}");
    let link = summary["share"]["editLink"].as_str().unwrap().to_string();
    assert!(link.contains("#k="), "{link}");
    let mut b = join(&link, "Bo");
    pump(&mut [&mut a, &mut b], "Bo in", |s| live(s[1]) && same(s[0].doc().unwrap(), s[1].doc().unwrap()));
    // The server lists the file's name sealed; the app shows it opened.
    let list = ex(&mut a, "collab.files", json!({"refresh": true}));
    assert_eq!(
        (&list["files"][0]["name"], &list["files"][0]["sealed"], &list["files"][0]["state"]),
        (&json!("Plans"), &json!(true), &json!("online"))
    );
    // Renamed from the list: sealed for the server too.
    let file = list["files"][0]["file"].as_str().unwrap().to_string();
    ex(&mut a, "collab.manageFile", json!({"file": file, "action": "rename", "name": "Renamed plans"}));
    let list = ex(&mut a, "collab.files", json!({"refresh": true}));
    assert_eq!(list["files"][0]["name"], "Renamed plans");
    drop((a, b));
    server.stop();
    for (path, bytes) in all_bytes(dir.path()) {
        assert!(!bytes.windows(5).any(|w| w == b"Plans"), "{path} has the name in the clear");
    }
}

/// Signed in on a server with accounts: published sealed as yours, the member's link carries the
/// key, your files list opens the name with the key kept here, an invited member joins with the
/// link, and your app opens the file again from a link without the key.
#[test]
fn a_sealed_file_of_your_account() {
    let dir = TempDir::new("app-sealed-accounts");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let url = format!("ws://{}/", server.addr());
    let mut ann = session("Ann");
    ex(&mut ann, "account.signIn", json!({"server": url, "token": "u1|ann@example.com|Ann"}));
    let layer = rect(&mut ann, MARKERS[0]);
    ex(&mut ann, "collab.publish", json!({"server": url, "name": MARKERS[1], "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let p = ann.live().published.clone().unwrap();
    assert!(!p.edit.contains("token=") && p.edit.contains("#k="), "a member's link with the key: {}", p.edit);
    assert_eq!(ann.live_summary()["sealed"], true);
    let files = ex(&mut ann, "account.files", json!({"server": url}));
    assert_eq!(
        (&files["files"][0]["name"], &files["files"][0]["sealed"], &files["files"][0]["role"]),
        (&json!(MARKERS[1]), &json!(true), &json!("owner"))
    );
    assert!(!files.to_string().contains(&ann.prefs.file_keys[0].key), "no key in results");
    // Bo is invited and joins with the link.
    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "editor"}));
    let mut bo = session("Bo");
    ex(&mut bo, "account.signIn", json!({"server": url, "token": "u2|bo@example.com|Bo"}));
    ex(&mut bo, "collab.join", json!({"link": p.edit}));
    pump(&mut [&mut ann, &mut bo], "Bo in", |s| live(s[1]) && s[0].live().peers.len() == 1);
    ex(&mut bo, "node.set", json!({"ids": [layer], "props": {"name": MARKERS[2]}}));
    pump(&mut [&mut ann, &mut bo], "Bo's edit at Ann", |s| named(s[0], layer, MARKERS[2]));
    // Bo has no key kept: his list shows the file as encrypted.
    let theirs = ex(&mut bo, "account.files", json!({"server": url}));
    assert_eq!((&theirs["files"][0]["name"], &theirs["files"][0]["sealed"]), (&json!("Encrypted file"), &json!(true)));
    // Ann's app again (only the preferences): the file opens from a link without the key.
    let prefs: figcraft_engine::Prefs = serde_json::from_value(serde_json::to_value(&ann.prefs).unwrap()).unwrap();
    drop(ann);
    let mut again = session("Ann");
    again.prefs = prefs;
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    ex(&mut again, "collab.join", json!({"link": bare}));
    pump(&mut [&mut again, &mut bo], "Ann back in", |s| live(s[0]) && same(s[0].doc().unwrap(), s[1].doc().unwrap()));
    assert!(named(&again, layer, MARKERS[2]));
    drop((again, bo));
    server.stop();
    for (path, bytes) in all_bytes(dir.path()) {
        assert!(hits(&bytes).is_empty(), "{path}: {:?}", hits(&bytes));
    }
}
