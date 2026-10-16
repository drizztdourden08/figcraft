//! Folders, recent files and previews on a server with accounts: folders made, renamed, removed
//! and files moved with the roles' permissions, what each person sees, recents noted on joining,
//! previews of plain files checked and kept, previews of sealed files sealed by the app (the
//! server's disk never holds the picture), and an app browsing its files.

use std::net::SocketAddr;
use std::path::Path;

use base64::Engine as _;
use figcraft_collab::message::{AccountReply, AccountReq, FileEntry, MAX_THUMBNAIL, Role};
use figcraft_engine::Session;
use serde_json::{Value, json};

use crate::accounts_tests::{account, accounts_config, ask, join, snapshot, start, token};
use crate::store::folders::{folder_path, within};
use crate::test_util::{Raw, TempDir, live, pump, session};

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 13, 10, 26, 10];

/// What the server takes as a PNG (it checks the signature only).
fn png() -> Vec<u8> {
    let mut b = PNG.to_vec();
    b.extend_from_slice(b"rest of a picture");
    b
}

fn done(r: AccountReply) {
    assert_eq!(r, AccountReply::Done);
}

fn failed(r: AccountReply) -> String {
    match r {
        AccountReply::Failed { reason } => reason,
        other => panic!("{other:?}"),
    }
}

fn folders(raw: &mut Raw) -> Vec<String> {
    match ask(raw, AccountReq::Folders) {
        AccountReply::Folders(f) => f,
        other => panic!("{other:?}"),
    }
}

fn browse(raw: &mut Raw) -> (Vec<FileEntry>, Vec<String>) {
    match ask(raw, AccountReq::Browse) {
        AccountReply::Browse { files, folders } => (files, folders),
        other => panic!("{other:?}"),
    }
}

/// Ann's file with Bo as viewer and Cy as editor: the connections and the file's id.
fn team(addr: SocketAddr) -> (Raw, Raw, Raw, String) {
    let (mut ann, _) = account(addr, token("u1", "ann@example.com", "Ann"));
    let (bo, _) = account(addr, token("u2", "bo@example.com", "Bo"));
    let (cy, _) = account(addr, token("u3", "cy@example.com", "Cy"));
    let AccountReply::Published { file } = ask(&mut ann, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    for (email, role) in [("bo@example.com", Role::Viewer), ("cy@example.com", Role::Editor)] {
        done(ask(&mut ann, AccountReq::Invite { file: file.id.clone(), email: email.into(), role }));
    }
    (ann, bo, cy, file.id)
}

#[test]
fn folder_paths() {
    assert_eq!(folder_path(" Marketing / 2026 ").unwrap(), "Marketing/2026");
    assert_eq!(folder_path("/a//b/").unwrap(), "a/b");
    assert_eq!(folder_path("").unwrap(), "");
    for bad in ["a/../b", "./a", "a\\b", "tab\there", &"x".repeat(65), &["a"; 9].join("/")] {
        assert!(folder_path(bad).is_err(), "{bad}");
    }
    assert!(within("a/b", "a") && within("a", "a") && !within("ab", "a") && !within("a", ""));
}

#[test]
fn folders_move_with_the_files_people_may_edit() {
    let dir = TempDir::new("folders-crud");
    let cfg = accounts_config(dir.path(), "accounts");
    let mut server = start(&cfg);
    let addr = server.addr();
    let (mut ann, mut bo, mut cy, file) = team(addr);
    let move_to = |f: &str| AccountReq::MoveFile { file: file.clone(), folder: f.into() };
    // Viewers can't move a file; owners and editors can; everyone sees where it is.
    assert!(failed(ask(&mut bo, move_to("Mine"))).contains("owners and editors"));
    done(ask(&mut ann, move_to("Marketing/2026")));
    done(ask(&mut cy, move_to(" Marketing / 2026 ")));
    assert_eq!(folders(&mut bo), vec!["Marketing", "Marketing/2026"]);
    let (files, _) = browse(&mut bo);
    assert_eq!((files[0].folder.as_str(), files[0].role, files[0].sealed), ("Marketing/2026", Role::Viewer, false));
    assert!(failed(ask(&mut ann, move_to("../up"))).contains("can't be a folder name"));
    // Someone who isn't in the file can't move it.
    let (mut dee, _) = account(addr, token("u4", "dee@example.com", "Dee"));
    assert!(failed(ask(&mut dee, move_to("Elsewhere"))).contains("aren't in this file"));
    assert!(folders(&mut dee).is_empty());

    // Empty folders are their maker's.
    done(ask(&mut ann, AccountReq::CreateFolder { path: "Drafts/Old".into() }));
    done(ask(&mut ann, AccountReq::CreateFolder { path: "Drafts/Old".into() }));
    assert!(failed(ask(&mut ann, AccountReq::CreateFolder { path: " / ".into() })).contains("name"));
    assert_eq!(folders(&mut ann), vec!["Drafts", "Drafts/Old", "Marketing", "Marketing/2026"]);
    assert_eq!(folders(&mut bo), vec!["Marketing", "Marketing/2026"]);

    // Renaming moves what you may edit: Bo (a viewer) moves nothing, Ann moves the file.
    let rename = |from: &str, to: &str| AccountReq::RenameFolder { from: from.into(), to: to.into() };
    assert!(failed(ask(&mut bo, rename("Marketing", "Sales"))).contains("nothing in it"));
    assert!(failed(ask(&mut ann, rename("Marketing", "Marketing/Inner"))).contains("inside itself"));
    done(ask(&mut ann, rename("Marketing", "Sales")));
    assert_eq!(folders(&mut bo), vec!["Sales", "Sales/2026"]);
    done(ask(&mut ann, rename("Drafts", "Archive")));
    assert_eq!(folders(&mut ann), vec!["Archive", "Archive/Old", "Sales", "Sales/2026"]);

    // Removing: only a folder with no file you're in.
    assert!(failed(ask(&mut ann, AccountReq::RemoveFolder { path: "Sales".into() })).contains("isn't empty"));
    done(ask(&mut ann, AccountReq::RemoveFolder { path: "Archive".into() }));
    assert!(failed(ask(&mut ann, AccountReq::RemoveFolder { path: "Archive".into() })).contains("no folder"));
    assert_eq!(folders(&mut ann), vec!["Sales", "Sales/2026"]);

    // Kept across a restart.
    done(ask(&mut ann, AccountReq::CreateFolder { path: "Kept".into() }));
    drop((ann, bo, cy, dee));
    server.stop();
    let mut server = start(&cfg);
    let (mut ann, _) = account(server.addr(), token("u1", "ann@example.com", "Ann"));
    assert_eq!(folders(&mut ann), vec!["Kept", "Sales", "Sales/2026"]);
    let (files, _) = browse(&mut ann);
    assert_eq!(files[0].folder, "Sales/2026");
    server.stop();
}

#[test]
fn listings_say_when_you_last_opened_a_file() {
    let dir = TempDir::new("folders-recents");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let (mut ann, mut bo, _cy, file) = team(addr);
    let (files, _) = browse(&mut bo);
    assert_eq!(files[0].opened, None);
    // Bo opens it: his listing says when; Ann's doesn't (she hasn't).
    let (_conn, access) = join(addr, Some(token("u2", "bo@example.com", "Bo")), &file, "");
    assert!(access.is_ok());
    let (files, _) = browse(&mut bo);
    assert!(files[0].opened.is_some_and(|t| t > 0));
    assert_eq!(browse(&mut ann).0[0].opened, None);
    // The old listing stays as it was.
    assert!(matches!(ask(&mut bo, AccountReq::Files), AccountReply::Files(ref f) if f.len() == 1));
    // Kept on disk (restarts keep it).
    let text = std::fs::read_to_string(dir.path().join("recents.json")).unwrap();
    assert!(text.contains(&file));
    // Taken off the server: their recents and folders go.
    let (mut bo, me) = account(addr, token("u2", "bo@example.com", "Bo"));
    done(ask(&mut bo, AccountReq::CreateFolder { path: "Bo's".into() }));
    assert!(std::fs::read_to_string(dir.path().join("folders.json")).unwrap().contains(&me.account));
    drop(bo);
    let e = figcraft_collab_net::Endpoint::plain(addr.to_string());
    let req = figcraft_collab::message::Admin::RemovePerson { account: me.account.clone(), force: false };
    let limits = figcraft_collab_net::NetLimits::default();
    let r =
        figcraft_collab_net::manage::request(&e, &crate::test_util::key(dir.path()), vec![req], &limits, std::time::Duration::from_secs(10)).unwrap();
    assert!(matches!(r[0], figcraft_collab::message::AdminReply::PersonRemoved { .. }), "{r:?}");
    assert!(!std::fs::read_to_string(dir.path().join("recents.json")).unwrap().contains(&me.account));
    assert!(!std::fs::read_to_string(dir.path().join("folders.json")).unwrap().contains(&me.account));
    server.stop();
}

#[test]
fn previews_of_plain_files() {
    let dir = TempDir::new("folders-thumbs");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let (mut ann, mut bo, mut cy, file) = team(addr);
    let set = |image: Vec<u8>| AccountReq::SetThumbnail { file: file.clone(), image };
    let get = AccountReq::GetThumbnail { file: file.clone() };
    assert_eq!(ask(&mut bo, get.clone()), AccountReply::Thumbnail { image: Vec::new(), set: 0 });
    assert!(failed(ask(&mut bo, set(png()))).contains("owners and editors"));
    assert!(failed(ask(&mut cy, set(b"GIF89a not a png".to_vec()))).contains("PNG"));
    assert!(failed(ask(&mut cy, set(Vec::new()))).contains("at most"));
    let mut huge = png();
    huge.resize(MAX_THUMBNAIL + 1, 0);
    assert!(failed(ask(&mut cy, set(huge))).contains("at most"));
    done(ask(&mut cy, set(png())));
    let AccountReply::Thumbnail { image, set: when } = ask(&mut bo, get.clone()) else { panic!() };
    assert_eq!(image, png());
    assert!(when > 0);
    let (files, _) = browse(&mut ann);
    assert_eq!(files[0].thumbnail, Some(when));
    let (mut dee, _) = account(addr, token("u4", "dee@example.com", "Dee"));
    assert!(failed(ask(&mut dee, get)).contains("aren't in this file"));
    assert_eq!(std::fs::read(dir.path().join("files").join(&file).join("thumbnail.bin")).unwrap(), png());
    server.stop();
}

fn ex(s: &mut Session, cmd: &str, p: Value) -> Value {
    s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"))
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

const CANARY: &str = "CANARY-THUMB-FOLDER-6b1";

/// An app signed in publishes a sealed file: its preview goes to the server sealed (by itself,
/// after the publish), the server's disk never holds the picture or the canary, the owner's app
/// opens it, an app without the key gets no picture; folders and recents show in its listing.
#[test]
fn previews_of_sealed_files_are_sealed_by_the_app() {
    let dir = TempDir::new("folders-sealed");
    let mut cfg = accounts_config(dir.path(), "accounts");
    cfg.e2e.mode = "optional".into();
    let mut server = start(&cfg);
    let url = format!("ws://{}/", server.addr());
    let mut ann = session("Ann");
    ex(&mut ann, "account.signIn", json!({"server": url, "token": "u1|ann@example.com|Ann"}));
    let id = ex(&mut ann, "shape.rectangle", json!({"x": 0, "y": 0, "width": 80, "height": 50, "fill": "#e04040"}))["id"].as_u64().unwrap();
    ex(&mut ann, "node.set", json!({"ids": [id], "props": {"name": CANARY}}));
    ex(&mut ann, "collab.publish", json!({"server": url, "name": CANARY, "sealed": true}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    let file = ann.live().published.clone().unwrap().file;
    let thumb = dir.path().join("files").join(&file).join("thumbnail.bin");
    // The app sends the preview by itself (in the background).
    pump(&mut [&mut ann], "the sealed preview", |_| thumb.exists());
    let stored = std::fs::read(&thumb).unwrap();
    assert!(!stored.starts_with(b"\x89PNG"), "sealed, not a PNG");
    let shown = ex(&mut ann, "account.thumbnail", json!({"server": url, "file": file}));
    assert_eq!(shown["sealed"], true);
    let picture = base64::engine::general_purpose::STANDARD.decode(shown["data"].as_str().unwrap()).unwrap();
    assert!(picture.starts_with(b"\x89PNG\r\n\x1a\n"));
    // Sending one now works too.
    let sent = ex(&mut ann, "account.uploadThumbnail", json!({}));
    assert_eq!(sent["file"], file.as_str());

    // Bo, invited, has no key yet: no picture for him.
    ex(&mut ann, "collab.invite", json!({"email": "bo@example.com", "role": "viewer"}));
    let mut bo = session("Bo");
    ex(&mut bo, "account.signIn", json!({"server": url, "token": "u2|bo@example.com|Bo"}));
    let theirs = ex(&mut bo, "account.thumbnail", json!({"server": url, "file": file}));
    assert_eq!((theirs["sealed"].as_bool(), theirs["data"].is_null()), (Some(true), true));
    assert!(bo.execute("account.uploadThumbnail", &json!({"server": url, "file": file})).is_err(), "viewers don't set previews");

    // Folders and recents in the app's listing.
    ex(&mut ann, "account.createFolder", json!({"server": url, "path": "Clients/Acme"}));
    ex(&mut ann, "account.moveFile", json!({"server": url, "file": file, "folder": "Clients/Acme"}));
    let list = ex(&mut ann, "account.browse", json!({"server": url}));
    assert_eq!(list["folders"], json!(["Clients", "Clients/Acme"]));
    let f = &list["files"][0];
    assert_eq!((f["folder"].as_str(), f["sealed"].as_bool(), f["name"].as_str()), (Some("Clients/Acme"), Some(true), Some(CANARY)));
    assert!(f["thumbnail"].as_u64().is_some() && f["opened"].as_u64().is_some(), "{f}");
    assert_eq!(list["recent"], json!([file]));
    ex(&mut ann, "account.renameFolder", json!({"server": url, "from": "Clients", "to": "Customers"}));
    assert_eq!(ex(&mut ann, "account.folders", json!({"server": url}))["folders"], json!(["Customers", "Customers/Acme"]));
    assert!(ann.execute("account.removeFolder", &json!({"server": url, "path": "Customers"})).is_err());
    let bo_list = ex(&mut bo, "account.browse", json!({"server": url}));
    assert_eq!(bo_list["files"][0]["name"], "Encrypted file");
    assert_eq!(bo_list["files"][0]["folder"], "Customers/Acme");

    drop((ann, bo));
    server.stop();
    // The canary: neither the name nor the picture is on the server's disk.
    for (path, bytes) in all_bytes(dir.path()) {
        assert!(!bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()), "{path} has the canary in the clear");
        assert!(!bytes.windows(picture.len()).any(|w| w == picture.as_slice()), "{path} has the preview in the clear");
    }
}

/// A plain file published by an app signed in gets its preview by itself: a PNG on the server.
#[test]
fn previews_of_plain_files_from_the_app() {
    let dir = TempDir::new("folders-plain-app");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let url = format!("ws://{}/", server.addr());
    let mut ann = session("Ann");
    ex(&mut ann, "account.signIn", json!({"server": url, "token": "u1|ann@example.com|Ann"}));
    ex(&mut ann, "shape.rectangle", json!({"x": 0, "y": 0, "width": 60, "height": 60}));
    ex(&mut ann, "collab.publish", json!({"server": url, "name": "Board"}));
    pump(&mut [&mut ann], "Ann's publish", |s| live(s[0]) && s[0].live().published.is_some());
    let file = ann.live().published.clone().unwrap().file;
    let thumb = dir.path().join("files").join(&file).join("thumbnail.bin");
    pump(&mut [&mut ann], "the preview", |_| thumb.exists());
    assert!(std::fs::read(&thumb).unwrap().starts_with(b"\x89PNG\r\n\x1a\n"));
    let shown = ex(&mut ann, "account.thumbnail", json!({"server": url, "file": file}));
    assert_eq!(shown["sealed"], false);
    assert!(shown["data"].as_str().is_some_and(|d| !d.is_empty()));
    drop(ann);
    server.stop();
}
