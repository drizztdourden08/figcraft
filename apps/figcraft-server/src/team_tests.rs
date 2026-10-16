//! Team access end to end over loopback (`docs/server-accounts.md` › *Team access*): on a server
//! where everyone is in every file (the default), people an admin let in see, open and edit every
//! file without invites, folders are everyone's, sealed files' keys go to everyone's devices and
//! taking someone off the server starts a new epoch everywhere; admins keep the allow-list and
//! make admins from the app; people's pictures are fetched from their provider's address, kept
//! small and served to anyone signed in; and the app makes new files straight on the server, in a
//! folder or on the default server, and saves files there.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use figcraft_auth::SignIn;
use figcraft_collab::message::{AccountReply, AccountReq, Admin, AdminReply, ClientMsg, Manage, PROTOCOL, Role, ServerMsg};
use figcraft_engine::Session;
use serde_json::{Value, json};

use crate::accounts_tests::{account, accounts_config, ask, join, signed, snapshot, start, team_config, token};
use crate::store::keyrings::KeyringFile;
use crate::store::members::EVERYONE;
use crate::test_util::{Raw, TempDir, live, pump, same, session};

fn ex(s: &mut Session, cmd: &str, p: Value) -> Value {
    s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"))
}

/// A managing connection signed in as `sign`, an admin (no key).
fn admin_conn(addr: SocketAddr, sign: SignIn) -> Raw {
    let (mut raw, me) = signed(addr, sign);
    assert!(me.unwrap().admin);
    raw.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(raw.next(), ServerMsg::Admin(r) if *r == AdminReply::Ready));
    raw
}

fn admin(raw: &mut Raw, req: Admin) -> AdminReply {
    raw.send(&ClientMsg::Admin(req));
    match raw.next() {
        ServerMsg::Admin(r) => *r,
        other => panic!("{other:?}"),
    }
}

fn failed(r: AccountReply) -> String {
    match r {
        AccountReply::Failed { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn keyring(dir: &Path, file: &str) -> KeyringFile {
    serde_json::from_slice(&std::fs::read(dir.join("files").join(file).join("keyring.json")).unwrap()).unwrap()
}

/// Ann publishes; Bo, never invited, sees the file in his lists as an editor, joins it with edit
/// access and moves it into a folder Ann made; per-file invites and member lists say the server
/// gives everyone access. On a server whose files have members, Bo sees nothing.
#[test]
fn everyone_on_the_server_sees_opens_and_edits_every_file() {
    let dir = TempDir::new("team-everyone");
    let mut server = start(&team_config(dir.path(), "accounts"));
    let addr = server.addr();
    let (mut a, _) = account(addr, token("u1", "ann@example.com", "Ann"));
    let (mut b, bo) = account(addr, token("u2", "bo@example.com", "Bo"));
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    // Ann owns it; Bo is an editor of it without being invited.
    let AccountReply::Files(mine) = ask(&mut a, AccountReq::Files) else { panic!() };
    assert_eq!(mine[0].role, Role::Owner);
    let AccountReply::Files(his) = ask(&mut b, AccountReq::Files) else { panic!() };
    assert_eq!((his.len(), his[0].info.id.as_str(), his[0].role), (1, file.id.as_str(), Role::Editor));
    let (_, access) = join(addr, Some(token("u2", "bo@example.com", "Bo")), &file.id, "");
    assert_eq!(access.unwrap(), figcraft_collab::message::Access::Edit);
    // Folders are everyone's: an empty one Ann made shows for Bo, and he moves the file there.
    assert_eq!(ask(&mut a, AccountReq::CreateFolder { path: "Team/Q3".into() }), AccountReply::Done);
    let AccountReply::Folders(folders) = ask(&mut b, AccountReq::Folders) else { panic!() };
    assert_eq!(folders, vec!["Team".to_string(), "Team/Q3".to_string()]);
    assert_eq!(ask(&mut b, AccountReq::MoveFile { file: file.id.clone(), folder: "Team/Q3".into() }), AccountReply::Done);
    let AccountReply::Browse { files, .. } = ask(&mut a, AccountReq::Browse) else { panic!() };
    assert_eq!(files[0].folder, "Team/Q3");
    // Per-file people don't apply here.
    for req in [
        AccountReq::Members { file: file.id.clone() },
        AccountReq::Invite { file: file.id.clone(), email: "cy@example.com".into(), role: Role::Editor },
        AccountReq::SetRole { file: file.id.clone(), account: bo.account.clone(), role: Role::Viewer },
        AccountReq::RemoveMember { file: file.id.clone(), account: bo.account.clone() },
        AccountReq::Leave { file: file.id.clone() },
    ] {
        assert_eq!(failed(ask(&mut a, req)), EVERYONE);
    }
    // Owner-only things stay the owner's.
    assert!(failed(ask(&mut b, AccountReq::RemoveFile { file: file.id.clone() })).contains("owners"));
    // Who is on the server, by name; how files are shared there.
    let AccountReply::Team { file_access, people } = ask(&mut b, AccountReq::Team) else { panic!() };
    assert_eq!(file_access, "everyone");
    let names: Vec<&str> = people.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["Ann", "Bo"]);
    assert!(people.iter().all(|p| p.email.is_none()), "only admins are told emails");
    server.stop();

    // A server whose files have their own members: Bo sees nothing until he is invited.
    let dir = TempDir::new("team-members");
    let mut server = start(&accounts_config(dir.path(), "accounts"));
    let addr = server.addr();
    let (mut a, _) = account(addr, token("u1", "ann@example.com", "Ann"));
    let (mut b, _) = account(addr, token("u2", "bo@example.com", "Bo"));
    let AccountReply::Published { file } = ask(&mut a, AccountReq::Publish { name: "Plan".into(), snapshot: snapshot("Plan") }) else { panic!() };
    let AccountReply::Files(his) = ask(&mut b, AccountReq::Files) else { panic!() };
    assert!(his.is_empty());
    assert!(join(addr, Some(token("u2", "bo@example.com", "Bo")), &file.id, "").1.is_err());
    let AccountReply::Team { file_access, .. } = ask(&mut b, AccountReq::Team) else { panic!() };
    assert_eq!(file_access, "members");
    server.stop();
}

/// An admin adds people from the app: once the list has someone, only listed emails (and
/// admins) sign in; taking an email off ends its person's sessions; emails in the settings stay.
/// Admins make others admins (the settings' admins stay admins).
#[test]
fn admins_keep_the_allow_list_and_make_admins() {
    let dir = TempDir::new("team-allow");
    let mut server = start(&team_config(dir.path(), "accounts"));
    let addr = server.addr();
    let mut boss = admin_conn(addr, token("b", "boss@example.com", "Boss"));
    // Nobody listed: anyone the provider vouches for.
    let AdminReply::Allowed(list) = admin(&mut boss, Admin::Allowed) else { panic!() };
    assert!(list.open);
    assert!(list.emails.iter().any(|e| e.email == "boss@example.com" && e.admin && e.settings));
    assert!(signed(addr, token("u9", "zed@example.com", "Zed")).1.is_ok());
    // Ann is added: now only she (and admins) get in.
    assert_eq!(admin(&mut boss, Admin::AllowEmail { email: " Ann@Example.com ".into(), admin: false }), AdminReply::Done);
    assert!(matches!(admin(&mut boss, Admin::AllowEmail { email: "nonsense".into(), admin: false }), AdminReply::Failed { .. }));
    let AdminReply::Allowed(list) = admin(&mut boss, Admin::Allowed) else { panic!() };
    assert!(!list.open);
    assert!(list.emails.iter().any(|e| e.email == "ann@example.com" && !e.admin && !e.settings));
    let (_, ann) = signed(addr, token("u1", "ann@example.com", "Ann"));
    let ann = ann.unwrap();
    let refused = signed(addr, token("u2", "bo@example.com", "Bo")).1.unwrap_err();
    assert!(refused.contains("ask one of its admins"), "{refused}");
    assert!(signed(addr, token("u9", "zed@example.com", "Zed")).1.is_err(), "people who signed in before are narrowed too");
    assert!(signed(addr, token("b", "boss@example.com", "Boss")).1.unwrap().admin);
    // The list is kept in the data directory.
    let kept = std::fs::read_to_string(dir.path().join("accounts").join("allowed.json")).unwrap();
    assert!(kept.contains("ann@example.com"));

    // Ann made an admin: she manages the server from the app.
    assert_eq!(admin(&mut boss, Admin::SetAdmin { account: ann.account.clone(), admin: true }), AdminReply::Done);
    let mut a = admin_conn(addr, SignIn::Session { token: ann.session.clone() });
    assert_eq!(admin(&mut a, Admin::AllowEmail { email: "bo@example.com".into(), admin: false }), AdminReply::Done);
    assert!(signed(addr, token("u2", "bo@example.com", "Bo")).1.is_ok());
    // The settings' admins stay admins; their emails stay listed.
    let AdminReply::People(people) = admin(&mut a, Admin::People) else { panic!() };
    let boss_account = people.iter().find(|p| p.name == "Boss").unwrap().account.clone();
    assert!(
        matches!(admin(&mut a, Admin::SetAdmin { account: boss_account, admin: false }), AdminReply::Failed { reason } if reason.contains("server.toml"))
    );
    assert!(
        matches!(admin(&mut a, Admin::DisallowEmail { email: "boss@example.com".into() }), AdminReply::Failed { reason } if reason.contains("server.toml"))
    );
    // Not an admin any more: back to a person.
    assert_eq!(admin(&mut boss, Admin::SetAdmin { account: ann.account.clone(), admin: false }), AdminReply::Done);
    assert!(!signed(addr, SignIn::Session { token: ann.session.clone() }).1.unwrap().admin);
    // Bo taken off the list: his sessions end and he can't sign in again.
    let (_, bo) = signed(addr, token("u2", "bo@example.com", "Bo"));
    let bo = bo.unwrap();
    assert_eq!(admin(&mut boss, Admin::DisallowEmail { email: "bo@example.com".into() }), AdminReply::Done);
    assert!(signed(addr, SignIn::Session { token: bo.session }).1.is_err());
    assert!(signed(addr, token("u2", "bo@example.com", "Bo")).1.is_err());
    // People who aren't admins can't.
    let (mut plain, _) = signed(addr, token("u1", "ann@example.com", "Ann"));
    plain.send(&ClientMsg::Manage(Manage { protocol: PROTOCOL, key: String::new(), client_version: "t".into() }));
    assert!(matches!(plain.next(), ServerMsg::Refused { .. }));
    server.stop();
}

/// A tiny web server for pictures: `/a.png` a PNG, `/big.png` a PNG too large to keep,
/// `/page.html` not a picture. Counts the requests.
fn picture_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
            let (kind, body) = match path.as_str() {
                "/a.png" => {
                    png.extend_from_slice(b"tiny picture");
                    ("image/png", png)
                }
                "/big.png" => {
                    png.resize(300 << 10, 7);
                    ("image/png", png)
                }
                _ => ("text/html", b"<html>not a picture</html>".to_vec()),
            };
            let head = format!("HTTP/1.1 200 OK\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        }
    });
    (addr, hits)
}

/// Ann's picture is fetched when she signs in, kept in `avatars/`, served to Bo, and not fetched
/// again the same day; a picture too large or that isn't one isn't kept. The app gets it as base64.
#[test]
fn pictures_are_fetched_kept_small_and_served() {
    let (web, hits) = picture_server();
    let dir = TempDir::new("team-avatars");
    let mut server = start(&team_config(dir.path(), "accounts"));
    let addr = server.addr();
    let pic = format!("http://{web}/a.png");
    let (_, ann) = signed(addr, SignIn::Token { provider: "fake".into(), token: format!("u1|ann@example.com|Ann|{pic}") });
    let ann = ann.unwrap();
    let kept = dir.path().join("avatars").join(format!("{}.png", ann.account));
    assert!(kept.is_file(), "kept in the data directory");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // Bo gets it.
    let (mut b, _) = account(addr, token("u2", "bo@example.com", "Bo"));
    let AccountReply::Avatar { image, mime } = ask(&mut b, AccountReq::Avatar { account: ann.account.clone() }) else { panic!() };
    assert_eq!(mime, "image/png");
    assert!(image.ends_with(b"tiny picture"));
    let AccountReply::Team { people, .. } = ask(&mut b, AccountReq::Team) else { panic!() };
    assert!(people.iter().any(|p| p.account == ann.account && p.avatar));
    assert!(people.iter().any(|p| p.name == "Bo" && !p.avatar));
    // No picture: empty. Nobody by that id (or a path): empty.
    let AccountReply::Avatar { image, .. } = ask(&mut b, AccountReq::Avatar { account: "../accounts/people".into() }) else { panic!() };
    assert!(image.is_empty());
    // Signing in again the same day doesn't fetch it again.
    signed(addr, SignIn::Token { provider: "fake".into(), token: format!("u1|ann@example.com|Ann|{pic}") }).1.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // A new address is fetched; one too large, or not a picture, isn't kept (the copy there stays).
    for bad in ["big.png", "page.html"] {
        let tok = format!("u1|ann@example.com|Ann|http://{web}/{bad}");
        signed(addr, SignIn::Token { provider: "fake".into(), token: tok }).1.unwrap();
        let AccountReply::Avatar { image, .. } = ask(&mut b, AccountReq::Avatar { account: ann.account.clone() }) else { panic!() };
        assert!(image.ends_with(b"tiny picture"), "{bad}: the copy kept stays");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    // An address that isn't https (or this machine) isn't fetched at all.
    signed(addr, SignIn::Token { provider: "fake".into(), token: "u1|ann@example.com|Ann|http://169.254.169.254/x.png".into() }).1.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 3);

    // The app: base64 data and its type; none for someone without a picture.
    let url = format!("ws://{addr}/");
    let mut s = session("Bo");
    ex(&mut s, "account.signIn", json!({"server": url, "token": "u2|bo@example.com|Bo"}));
    let r = ex(&mut s, "account.avatar", json!({"server": url, "account": ann.account}));
    assert_eq!(r["mime"], "image/png");
    assert!(r["data"].as_str().is_some_and(|d| d.len() > 10), "{r}");
    let people = ex(&mut s, "account.people", json!({"server": url}));
    assert_eq!(people["fileAccess"], "everyone");
    let bo = people["people"].as_array().unwrap().iter().find(|p| p["name"] == "Bo").unwrap().clone();
    let none = ex(&mut s, "account.avatar", json!({"server": url, "account": bo["account"]}));
    assert!(none["data"].is_null() && none["mime"].is_null(), "{none}");
    server.stop();
}

/// A sealed file where everyone is in every file: Ann's app wraps its key for Bo's and Cy's
/// devices without inviting them; Bo joins and reads it. An admin takes Bo off the server: his
/// copies go, the file needs a new epoch, and Cy (an editor, not the owner) starts it.
#[test]
fn sealed_keys_go_to_everyone_and_removing_a_person_rotates_them() {
    let dir = TempDir::new("team-sealed");
    let mut cfg = team_config(dir.path(), "accounts");
    cfg.e2e.mode = "required".into();
    let mut server = start(&cfg);
    let addr = server.addr();
    let url = format!("ws://{addr}/");
    let signed_in = |name: &str, tok: &str| {
        let mut s = session(name);
        ex(&mut s, "account.signIn", json!({"server": url, "token": tok}));
        s
    };
    let mut ann = signed_in("Ann", "u1|ann@example.com|Ann");
    let mut bo = signed_in("Bo", "u2|bo@example.com|Bo");
    let mut cy = signed_in("Cy", "u3|cy@example.com|Cy");
    let bo_device = ex(&mut bo, "account.devices", json!({"server": url}))["device"].as_str().unwrap().to_string();
    let cy_device = ex(&mut cy, "account.devices", json!({"server": url}))["device"].as_str().unwrap().to_string();
    ex(&mut ann, "shape.rectangle", json!({"x": 0, "y": 0, "width": 40, "height": 30}));
    ex(&mut ann, "collab.publish", json!({"server": url, "name": "Roadmap"}));
    pump(&mut [&mut ann], "Ann's sealed publish", |s| live(s[0]) && s[0].live().published.is_some());
    assert_eq!(ann.live_summary()["sealed"], true);
    let p = ann.live().published.clone().unwrap();
    let bare = p.edit.split_once('#').unwrap().0.to_string();
    // Ann's app wraps for everyone's devices (nobody was invited).
    ex(&mut ann, "account.syncKeys", json!({"server": url}));
    let ring = keyring(dir.path(), &p.file);
    assert!(ring.epochs[&0].contains_key(&bo_device) && ring.epochs[&0].contains_key(&cy_device), "{ring:?}");
    ex(&mut bo, "collab.join", json!({"link": bare}));
    ex(&mut cy, "collab.join", json!({"link": bare}));
    pump(&mut [&mut ann, &mut bo, &mut cy], "Bo and Cy in", |s| {
        live(s[1]) && live(s[2]) && same(s[0].doc().unwrap(), s[1].doc().unwrap()) && same(s[0].doc().unwrap(), s[2].doc().unwrap())
    });
    assert_eq!(bo.live_summary()["access"], "edit");
    // Signatures: everyone's devices sign.
    let (mut raw, _) = account(addr, token("u3", "cy@example.com", "Cy"));
    let AccountReply::EditorKeys { editors, .. } = ask(&mut raw, AccountReq::EditorKeys { file: p.file.clone() }) else { panic!() };
    assert!(editors.iter().any(|e| e.device == bo_device) && editors.iter().any(|e| e.device == cy_device));

    // Bo is taken off the server.
    let people = ex(&mut cy, "account.people", json!({"server": url}));
    let bo_account = people["people"].as_array().unwrap().iter().find(|x| x["name"] == "Bo").unwrap()["account"].as_str().unwrap().to_string();
    let mut boss = admin_conn(addr, token("b", "boss@example.com", "Boss"));
    assert!(matches!(admin(&mut boss, Admin::RemovePerson { account: bo_account, force: false }), AdminReply::PersonRemoved { .. }));
    let ring = keyring(dir.path(), &p.file);
    assert!(ring.rotate, "a new epoch is needed");
    assert!(!ring.epochs.values().any(|w| w.contains_key(&bo_device)), "Bo's copies are gone");
    pump(&mut [&mut ann, &mut bo, &mut cy], "Bo out", |s| !s[1].live().status.active());
    // Cy, an editor, starts it (any editor may here).
    let r = ex(&mut cy, "account.syncKeys", json!({"server": url}));
    assert_eq!(r["rotated"], json!([p.file]), "{r}");
    let ring = keyring(dir.path(), &p.file);
    assert_eq!(ring.epochs.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
    assert!(!ring.rotate);
    assert!(!ring.epochs[&1].contains_key(&bo_device));
    drop((ann, bo, cy));
    server.stop();
}

/// The app makes a blank file straight on the server in a folder; with a default server the + tab
/// (`file.new`) makes it on its root; Save says a server file is saved there, puts an untitled
/// file on the default server, and saves a file with a path on this computer to that path.
#[test]
fn new_files_on_the_server_and_saving_there() {
    let dir = TempDir::new("team-newfile");
    let mut server = start(&team_config(dir.path(), "accounts"));
    let url = format!("ws://{}/", server.addr());
    let mut ann = session("Ann");
    ex(&mut ann, "account.signIn", json!({"server": url, "token": "u1|ann@example.com|Ann"}));
    // In a folder.
    let tabs = ann.docs.len();
    let r = ex(&mut ann, "account.newFile", json!({"server": url, "folder": "Team/Q3", "name": "Plan"}));
    assert_eq!(r["folder"], "Team/Q3");
    assert_eq!(ann.docs.len(), tabs + 1, "opened in a new tab");
    pump(&mut [&mut ann], "the new file on the server", |s| live(s[0]) && s[0].live().published.is_some());
    let plan = ann.live().published.clone().unwrap().file;
    let mut browse = Value::Null;
    // The move goes in the background; its answer arrives through polling.
    pump(&mut [&mut ann], "the file in its folder", |s| !s[0].waiting_for("account.moveFile"));
    let (cmd, moved) = ann.take_background_done().unwrap();
    assert_eq!(cmd, "account.moveFile");
    assert_eq!(moved.unwrap()["folder"], "Team/Q3");
    for _ in 0..200 {
        browse = ex(&mut ann, "account.browse", json!({"server": url}));
        if browse["files"].as_array().unwrap().iter().any(|f| f["file"] == plan.as_str() && f["folder"] == "Team/Q3") {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let f = browse["files"].as_array().unwrap().iter().find(|f| f["file"] == plan.as_str()).cloned().unwrap();
    assert_eq!((f["name"].as_str(), f["folder"].as_str(), f["role"].as_str()), (Some("Plan"), Some("Team/Q3"), Some("owner")), "{browse}");
    // Save: it is on the server already.
    ex(&mut ann, "shape.rectangle", json!({"x": 0, "y": 0, "width": 10, "height": 10}));
    let saved = ex(&mut ann, "file.save", json!({}));
    assert_eq!(
        (saved["where"].as_str(), saved["server"].as_str(), saved["file"].as_str()),
        (Some("server"), Some(url.as_str()), Some(plan.as_str()))
    );
    pump(&mut [&mut ann], "the edit confirmed", |s| s[0].live().client().is_some_and(|c| c.pending() == 0));
    assert_eq!(ex(&mut ann, "file.save", json!({}))["synced"], true);

    // A default server: the + tab makes the file there, on its root.
    ex(&mut ann, "servers.add", json!({"url": url, "name": "Team"}));
    let set = ex(&mut ann, "servers.setDefault", json!({"server": url}));
    assert_eq!(set["default"], url.as_str());
    assert!(ann.execute("servers.setDefault", &json!({"server": "ws://elsewhere.test/"})).is_err(), "only a server in the list");
    let r = ex(&mut ann, "file.new", json!({}));
    assert_eq!((r["server"].as_str(), r["serverName"].as_str(), r["folder"].as_str()), (Some(url.as_str()), Some("Team"), Some("")));
    assert_eq!(ann.docs.len(), tabs + 2);
    pump(&mut [&mut ann], "the + tab's file on the server", |s| live(s[0]) && s[0].live().published.is_some());
    let untitled = ann.live().published.clone().unwrap();
    assert_eq!(untitled.name, "Untitled");
    // `local` keeps it here; Save puts an untitled one on the default server.
    let r = ex(&mut ann, "file.new", json!({"local": true}));
    assert!(r["server"].is_null(), "{r}");
    assert_eq!(ann.live().status, figcraft_engine::live::Status::Off);
    let saved = ex(&mut ann, "file.save", json!({}));
    assert_eq!((saved["where"].as_str(), saved["publishing"].as_bool()), (Some("server"), Some(true)), "{saved}");
    pump(&mut [&mut ann], "the untitled file saved to the server", |s| live(s[0]) && s[0].live().published.is_some());
    // A file with a path here saves to it; Save locally makes a copy here.
    let local = dir.path().join("local.figcraft");
    ex(&mut ann, "file.new", json!({"local": true}));
    ex(&mut ann, "file.saveLocally", json!({"path": local.to_string_lossy()}));
    ex(&mut ann, "shape.rectangle", json!({"x": 0, "y": 0, "width": 10, "height": 10}));
    let saved = ex(&mut ann, "file.save", json!({}));
    assert_eq!(saved["path"].as_str(), Some(local.to_string_lossy().as_ref()), "{saved}");
    // Everything Ann made is on the server.
    let browse = ex(&mut ann, "account.browse", json!({"server": url}));
    assert_eq!(browse["files"].as_array().unwrap().len(), 3, "{browse}");
    // Forgetting the default: new files stay here.
    ex(&mut ann, "servers.setDefault", json!({"server": null}));
    assert!(ex(&mut ann, "file.new", json!({}))["server"].is_null());

    // Run in the background (as the browser app runs it): one new tab, one file, whatever runs
    // again when the server's answers arrive.
    let mut bo = session("Bo");
    ex(&mut bo, "account.signIn", json!({"server": url, "token": "u2|bo@example.com|Bo"}));
    let tabs = bo.docs.len();
    let first = bo.start_background("account.newFile", json!({"server": url, "name": "Sketch"})).unwrap();
    assert!(first.is_none(), "it waits for the server: {first:?}");
    assert_eq!(bo.docs.len(), tabs, "nothing made before the answers");
    pump(&mut [&mut bo], "the background new file", |s| !s[0].waiting_for("account.newFile"));
    let (cmd, r) = bo.take_background_done().unwrap();
    assert_eq!(cmd, "account.newFile");
    let r = r.unwrap();
    assert_eq!(r["server"], url.as_str());
    assert_eq!(bo.docs.len(), tabs + 1);
    // A background run leaves the tab in front as it was: the UI brings `index` forward.
    bo.active = r["index"].as_u64().unwrap() as usize;
    pump(&mut [&mut bo], "Bo's file on the server", |s| live(s[0]) && s[0].live().published.is_some());
    let browse = ex(&mut bo, "account.browse", json!({"server": url}));
    assert_eq!(browse["files"].as_array().unwrap().iter().filter(|f| f["name"] == "Sketch").count(), 1, "{browse}");
    drop((ann, bo));
    server.stop();
}
