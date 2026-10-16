//! The servers you use, checking a cached sign-in, the admin commands and a
//! sign-in the server ended, against a scripted link: the list survives a restart (old preferences
//! list their server for online sharing), addresses are checked, the list is ordered and online
//! sharing follows its first server, `account.check` keeps a sign-in the server still takes (and one it
//! can't be asked about) and forgets one it doesn't, admin requests go out signed in with the
//! session and only for admins, removing someone who is the last owner of files asks first, a
//! session the server signed out is forgotten (the app asks to sign in again), the people of a
//! joined member link's file are its server's, and no result carries a session token.

use std::sync::{Arc, Mutex};

use figcraft_collab::message::{Admin, AdminReply, ClientMsg, FileInfo, Member, OwnerlessFile, PersonInfo, Role};
use serde_json::{Value, json};

use crate::accounts::{SIGNED_OUT, SignedIn};
use crate::live::{Access, Event, HostOptions, LiveLink, Me, NetReply, NetRequest, Presence, SessionInfo, SignIn, SignInReply};
use crate::{Prefs, Session};

const SERVER: &str = "wss://acc.example/";
const OTHER: &str = "ws://127.0.0.1:47900/";
const TOKEN: &str = "SessionSecretSessionSecret";

/// What the scripted server says and what it was asked.
#[derive(Default)]
struct Wire {
    /// Every request, as sent.
    asked: Vec<NetRequest>,
    /// The server can't be reached.
    offline: bool,
    /// It no longer takes the session token.
    ended: bool,
    /// What `RemovePerson` without `force` answers: the last owner of a file.
    last_owner: bool,
    joined: Vec<String>,
    events: Vec<(u64, Event)>,
}

struct Link(Arc<Mutex<Wire>>);

fn me(name: &str) -> Me {
    Me { account: "a1".into(), name: name.into(), email: Some("ann@example.com".into()), admin: true, session: String::new(), expires: 99 }
}

impl LiveLink for Link {
    fn host(&mut self, _: u64, _: HostOptions) -> Result<SessionInfo, String> {
        Err("not in this test".into())
    }
    fn join(&mut self, _: u64, link: &str, _: &str) -> Result<(), String> {
        self.0.lock().unwrap().joined.push(link.to_string());
        Ok(())
    }
    fn leave(&mut self, _: u64) {}
    fn presence(&mut self, _: u64, _: &Presence) {}
    fn send(&mut self, _: u64, _: ClientMsg) {}
    fn poll(&mut self) -> Vec<(u64, Event)> {
        std::mem::take(&mut self.0.lock().unwrap().events)
    }
    fn accounts(&mut self, req: NetRequest) -> NetReply {
        let mut w = self.0.lock().unwrap();
        w.asked.push(req.clone());
        if w.offline {
            return req.failure()("no answer from the server (timed out)".into());
        }
        match req {
            NetRequest::SignIn { req: SignIn::Session { token }, .. } if token == TOKEN && !w.ended => {
                NetReply::SignIn(Ok(SignInReply::SignedIn(me("Ann Again"))))
            }
            NetRequest::SignIn { req: SignIn::Session { .. }, .. } => {
                NetReply::SignIn(Ok(SignInReply::Refused { reason: "that session ended".into() }))
            }
            NetRequest::Admin { .. } if w.ended => {
                NetReply::Admin(Err("your sign-in to this server ended (that session ended): sign in again".into()))
            }
            NetRequest::Admin { req, .. } => NetReply::Admin(Ok(match req {
                Admin::People => AdminReply::People(vec![PersonInfo {
                    account: "b2".into(),
                    provider: "corp".into(),
                    email: Some("bob@example.com".into()),
                    name: "Bob".into(),
                    created: 1,
                    seen: 2,
                    sessions: 1,
                    admin: false,
                    owned: 1,
                }]),
                Admin::Files => {
                    AdminReply::Files(vec![FileInfo { id: "f1".into(), name: "Plan".into(), created: 1, updated: 2, seq: 3, bytes: 4, people: 0 }])
                }
                Admin::FileMembers { .. } => AdminReply::FileMembers {
                    members: vec![Member { account: "b2".into(), name: "Bob".into(), email: None, role: Role::Owner }],
                    invited: Vec::new(),
                },
                Admin::RemovePerson { force: false, .. } if w.last_owner => {
                    AdminReply::LastOwner { files: vec![OwnerlessFile { id: "f1".into(), name: "Plan".into() }] }
                }
                Admin::RemovePerson { force, .. } => AdminReply::PersonRemoved {
                    orphaned: if force { vec![OwnerlessFile { id: "f1".into(), name: "Plan".into() }] } else { Vec::new() },
                },
                Admin::EndSessions { .. } | Admin::SetFileRole { .. } | Admin::AddFileMember { .. } => AdminReply::Done,
                _ => AdminReply::Failed { reason: "no such file".into() },
            })),
            other => other.failure()("not in this test".into()),
        }
    }
}

fn session() -> (Session, Arc<Mutex<Wire>>) {
    let wire = Arc::new(Mutex::new(Wire::default()));
    let mut s = Session::new();
    // No servers until a test adds them.
    s.prefs.servers = Some(Vec::new());
    s.live.install(Box::new(Link(wire.clone())));
    (s, wire)
}

fn signed_in(s: &mut Session, server: &str, admin: bool) {
    s.prefs.accounts.push(SignedIn {
        server: server.into(),
        account: "a1".into(),
        name: "Ann".into(),
        email: Some("ann@example.com".into()),
        admin,
        session: TOKEN.into(),
        expires: 9,
    });
}

fn run(s: &mut Session, cmd: &str, p: Value) -> Value {
    let v = s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    assert!(!v.to_string().contains(TOKEN), "{cmd} showed the session token");
    v
}

fn err(s: &mut Session, cmd: &str, p: Value) -> String {
    s.execute(cmd, &p).err().unwrap_or_else(|| panic!("{cmd} should fail")).to_string()
}

#[test]
fn old_preferences_list_their_sharing_server_and_the_list_is_kept() {
    // Preferences from before the list: the server for online sharing is the list.
    let old: Prefs = serde_json::from_value(json!({"publish_server": SERVER})).unwrap();
    assert_eq!(old.servers, None);
    let (mut s, _) = session();
    s.prefs = old;
    assert_eq!(s.servers(), vec![crate::servers::SavedServer { name: "acc.example".into(), url: SERVER.into() }]);
    assert_eq!(s.home_server(), SERVER);
    run(&mut s, "servers.add", json!({"url": OTHER, "name": "Laptop"}));
    let saved: Prefs = serde_json::from_value(serde_json::to_value(&s.prefs).unwrap()).unwrap();
    assert_eq!(saved.servers.as_ref().map(Vec::len), Some(2));
    assert_eq!(saved.servers.unwrap()[1].name, "Laptop");
    // Removing every server is kept as such (it doesn't come back from the old setting).
    run(&mut s, "servers.remove", json!({"url": SERVER}));
    run(&mut s, "servers.remove", json!({"url": OTHER}));
    let saved: Prefs = serde_json::from_value(serde_json::to_value(&s.prefs).unwrap()).unwrap();
    assert_eq!(saved.servers, Some(Vec::new()));
    assert_eq!(saved.publish_server, "", "online sharing follows the list");
    s.prefs = saved;
    assert!(s.servers().is_empty() && s.home_server().is_empty());
    assert!(err(&mut s, "account.files", json!({})).contains("no server"));
}

#[test]
fn servers_are_added_checked_moved_and_removed() {
    let (mut s, _) = session();
    s.prefs.publish_server = String::new();
    assert!(run(&mut s, "servers.list", json!({}))["servers"].as_array().unwrap().is_empty());
    for bad in ["https://acc.example/", "wss://acc.example/?key=k", "acc example", "ws://"] {
        assert!(err(&mut s, "servers.add", json!({"url": bad})).contains("ws://host:port/"), "{bad}");
    }
    let v = run(&mut s, "servers.add", json!({"url": "WSS://Acc.Example"}));
    assert_eq!(v["added"], SERVER);
    assert_eq!(s.servers()[0].name, "acc.example", "named by its host unless given a name");
    assert_eq!(s.prefs.publish_server, SERVER, "join codes are asked of the first server");
    run(&mut s, "servers.add", json!({"url": OTHER, "name": "Laptop"}));
    run(&mut s, "servers.add", json!({"url": OTHER, "name": "Desk"}));
    assert_eq!(s.servers().len(), 2, "the same address is renamed, not kept twice");
    assert_eq!(s.servers()[1].name, "Desk");
    let v = run(&mut s, "servers.move", json!({"url": OTHER, "to": 0}));
    assert_eq!(v["servers"][0]["url"], OTHER);
    assert_eq!(s.home_server(), OTHER);
    assert_eq!(s.prefs.publish_server, OTHER);
    assert!(err(&mut s, "servers.move", json!({"url": "wss://nowhere.example/", "to": 0})).contains("isn't in the list"));
    assert_eq!(run(&mut s, "servers.remove", json!({"url": OTHER}))["removed"], true);
    assert_eq!(s.home_server(), SERVER);
    assert_eq!(run(&mut s, "servers.remove", json!({"url": OTHER}))["removed"], false);
    for i in 0..30 {
        let _ = s.execute("servers.add", &json!({"url": format!("wss://s{i}.example/")}));
    }
    assert_eq!(s.servers().len(), crate::servers::MAX_SERVERS);
}

#[test]
fn a_cached_sign_in_is_checked_kept_or_forgotten() {
    let (mut s, wire) = session();
    run(&mut s, "servers.add", json!({"url": SERVER}));
    let v = run(&mut s, "account.check", json!({}));
    assert_eq!((v["signedIn"].clone(), v["server"].clone()), (json!(false), json!(SERVER)));
    assert!(wire.lock().unwrap().asked.is_empty(), "nothing to ask without a sign-in");
    signed_in(&mut s, SERVER, false);
    let v = run(&mut s, "account.check", json!({}));
    assert_eq!(v["signedIn"], true);
    assert_eq!(v["account"]["name"], "Ann Again", "what the server says now is kept");
    assert_eq!(s.signed_in(SERVER).unwrap().session, TOKEN, "the session token stays");
    assert!(matches!(&wire.lock().unwrap().asked[0], NetRequest::SignIn { req: SignIn::Session { token }, .. } if token == TOKEN));
    // Offline: the sign-in stays for when the server answers.
    wire.lock().unwrap().offline = true;
    let v = run(&mut s, "account.check", json!({}));
    assert_eq!((v["signedIn"].clone(), v["offline"].clone()), (json!(false), json!(true)));
    assert!(s.signed_in(SERVER).is_some());
    // The server no longer takes it: forgotten.
    let mut w = wire.lock().unwrap();
    (w.offline, w.ended) = (false, true);
    drop(w);
    let v = run(&mut s, "account.check", json!({}));
    assert_eq!(v["signedIn"], false);
    assert!(v["reason"].as_str().unwrap().contains("ended"));
    assert!(s.signed_in(SERVER).is_none());
    assert!(s.live.unsaved);
}

#[test]
fn admins_list_people_and_files_and_manage_them() {
    let (mut s, wire) = session();
    run(&mut s, "servers.add", json!({"url": SERVER}));
    assert!(err(&mut s, "admin.people", json!({})).contains("sign in first"));
    signed_in(&mut s, SERVER, false);
    assert!(err(&mut s, "admin.people", json!({})).contains("aren't an admin"));
    assert!(wire.lock().unwrap().asked.is_empty(), "nothing goes out for someone who isn't an admin");
    s.prefs.accounts[0].admin = true;
    let v = run(&mut s, "admin.people", json!({}));
    assert_eq!(v["people"][0]["email"], "bob@example.com");
    assert_eq!(v["people"][0]["owned"], 1);
    assert!(
        matches!(&wire.lock().unwrap().asked[0], NetRequest::Admin { session, server, req: Admin::People } if session == TOKEN && server == SERVER)
    );
    assert_eq!(run(&mut s, "admin.files", json!({}))["files"][0]["name"], "Plan");
    assert_eq!(run(&mut s, "admin.fileMembers", json!({"file": "f1"}))["members"][0]["role"], "owner");
    assert_eq!(run(&mut s, "admin.setFileRole", json!({"file": "f1", "account": "a1", "role": "owner"}))["role"], "owner");
    assert!(err(&mut s, "admin.setFileRole", json!({"file": "f1", "account": "a1", "role": "boss"})).contains("owner, editor or viewer"));
    assert_eq!(run(&mut s, "admin.addFileMember", json!({"file": "f1", "email": "cy@example.com"}))["role"], "editor");
    assert_eq!(run(&mut s, "admin.endSessions", json!({"account": "b2"}))["ended"], true);
    // The last owner of a file: nothing is done until the admin says so.
    wire.lock().unwrap().last_owner = true;
    let v = run(&mut s, "admin.removePerson", json!({"account": "b2"}));
    assert_eq!((v["removed"].clone(), v["lastOwner"][0]["file"].clone()), (json!(false), json!("f1")));
    let v = run(&mut s, "admin.removePerson", json!({"account": "b2", "force": true}));
    assert_eq!((v["removed"].clone(), v["orphaned"][0]["name"].clone()), (json!(true), json!("Plan")));
    // The server's own refusal is the error.
    assert!(err(&mut s, "admin.status", json!({})).contains("no such file"));
    // A session the server ended: forgotten, and the app asks to sign in again.
    wire.lock().unwrap().ended = true;
    s.ui_requests.clear();
    assert!(err(&mut s, "admin.people", json!({})).contains("sign-in to this server ended"));
    assert!(s.signed_in(SERVER).is_none());
    assert!(s.ui_requests.iter().any(|u| u.kind == "account.signedOut" && u.data["server"] == SERVER));
}

fn welcome(link: &str) -> Event {
    Event::Welcome {
        info: SessionInfo {
            role: crate::live::Role::Guest,
            me: 1,
            name: "Ann".into(),
            color: "#0D99FF".into(),
            file_name: "Plan".into(),
            pages: Vec::new(),
            link: link.into(),
            url: String::new(),
            address: String::new(),
            network: true,
            access: Access::Edit,
        },
        peers: Vec::new(),
    }
}

#[test]
fn a_joined_member_link_is_its_servers_file_and_a_server_sign_out_is_forgotten() {
    let (mut s, wire) = session();
    signed_in(&mut s, SERVER, false);
    let link = format!("figcraft://join?server={SERVER}&file=f1");
    let id = run(&mut s, "collab.join", json!({"link": link}))["session"].as_u64().unwrap();
    assert_eq!(wire.lock().unwrap().joined, vec![link.clone()]);
    wire.lock().unwrap().events.push((id, welcome(&link)));
    s.live_poll();
    assert_eq!(s.people_file(), Some((SERVER.to_string(), "f1".to_string())));
    // An admin ended the session: the copy stays, the sign-in goes, nothing retries.
    let reason = format!("{SIGNED_OUT}. Your copy stays open");
    wire.lock().unwrap().events.push((id, Event::Ended { reason: reason.clone() }));
    s.live_poll();
    assert!(s.signed_in(SERVER).is_none());
    assert_eq!(s.accounts.last, Some(Err(reason)));
    assert!(s.ui_requests.iter().any(|u| u.kind == "account.signedOut"));
    assert!(s.people_file().is_none());
}

#[test]
fn a_join_refused_for_an_ended_sign_in_forgets_it() {
    let (mut s, wire) = session();
    signed_in(&mut s, SERVER, false);
    signed_in(&mut s, OTHER, false);
    let id = run(&mut s, "collab.join", json!({"link": format!("figcraft://join?server={SERVER}&file=f1")}))["session"].as_u64().unwrap();
    let reason = "The host refused: your sign-in to this server ended (expired): sign in again".to_string();
    wire.lock().unwrap().events.push((id, Event::Status(crate::live::Status::Failed { reason })));
    s.live_poll();
    assert!(s.signed_in(SERVER).is_none());
    assert!(s.signed_in(OTHER).is_some(), "only that server's sign-in goes");
    // Any other end of a session keeps it.
    let id = run(&mut s, "collab.join", json!({"link": format!("figcraft://join?server={OTHER}&file=f2")}))["session"].as_u64().unwrap();
    wire.lock().unwrap().events.push((id, Event::Ended { reason: "The host ended the session".into() }));
    s.live_poll();
    assert!(s.signed_in(OTHER).is_some());
}

#[test]
fn folders_and_pictures_say_they_arent_there_yet() {
    let (mut s, _) = session();
    run(&mut s, "servers.add", json!({"url": SERVER}));
    assert!(err(&mut s, "account.folders", json!({})).contains("signed in"));
    signed_in(&mut s, SERVER, false);
    for (cmd, p) in [
        ("account.folders", json!({})),
        ("account.createFolder", json!({"path": "Work"})),
        ("account.renameFolder", json!({"path": "Work", "to": "Old"})),
        ("account.removeFolder", json!({"path": "Work"})),
        ("account.moveFile", json!({"file": "f1", "folder": "Work"})),
        ("account.thumbnail", json!({"file": "f1"})),
    ] {
        assert!(err(&mut s, cmd, p).contains(crate::folders::NO_FOLDERS), "{cmd}");
    }
    assert!(err(&mut s, "account.moveFile", json!({"file": "f1"})).contains("folder"));
}
