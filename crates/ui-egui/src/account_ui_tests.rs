//! A server with accounts on the home screen, against a scripted link: its page offers the
//! server's ways in (a token field for a token provider, a button per provider with a page or a
//! code), signing in shows your files there, a file's people show under it and owners invite by
//! email, the server's admin tools show for admins, Sign out lives there too, and Preferences ▸
//! Servers adds the server the page is for. No session token reaches what the UI shows.

use std::sync::{Arc, Mutex};

use figcraft_engine::figcraft_auth::{AuthMode, ProviderInfo, ServerAbout};
use figcraft_engine::figcraft_collab::message::{AccountReply, AccountReq, Admin, AdminReply, ClientMsg, FileEntry, FileInfo, Member, MyFile, Role};
use figcraft_engine::live::{
    Event as LiveEvent, Flow, HostOptions, LiveLink, Me, NetReply, NetRequest, Presence, ServerInfo, SessionInfo, SignIn, SignInReply,
};

use crate::live_tests::{Harness, has_text, text_center};

const SERVER: &str = "ws://127.0.0.1:47910/";
const TOKEN: &str = "SessionSecretSessionSecret";

#[derive(Default)]
struct Wire {
    asked: Vec<NetRequest>,
}

struct Link(Arc<Mutex<Wire>>);

fn info() -> ServerInfo {
    ServerInfo {
        auth: AuthMode::Accounts,
        providers: vec![
            ProviderInfo { id: "tokens".into(), label: "Access token".into(), flows: vec![Flow::Token { label: "Access token".into() }] },
            ProviderInfo { id: "sso".into(), label: "Example SSO".into(), flows: vec![Flow::Device] },
        ],
        ..ServerInfo::default()
    }
}

impl LiveLink for Link {
    fn host(&mut self, _: u64, _: HostOptions) -> Result<SessionInfo, String> {
        Err("not in this test".into())
    }
    fn join(&mut self, _: u64, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn leave(&mut self, _: u64) {}
    fn presence(&mut self, _: u64, _: &Presence) {}
    fn send(&mut self, _: u64, _: ClientMsg) {}
    fn poll(&mut self) -> Vec<(u64, LiveEvent)> {
        Vec::new()
    }
    fn accounts(&mut self, req: NetRequest) -> NetReply {
        self.0.lock().unwrap().asked.push(req.clone());
        let file = FileInfo { id: "f1".into(), name: "Plan".into(), created: 1, updated: 1_791_800_000, seq: 1, bytes: 1, people: 0 };
        match req {
            NetRequest::Info { .. } => NetReply::Info(Ok(ServerAbout { name: String::new(), info: info(), version: "1".into() })),
            NetRequest::SignIn { req: SignIn::Token { token, .. }, .. } if token == "ann" => NetReply::SignIn(Ok(SignInReply::SignedIn(Me {
                account: "a1".into(),
                name: "Ann".into(),
                email: Some("ann@example.com".into()),
                admin: true,
                session: TOKEN.into(),
                expires: 9,
            }))),
            NetRequest::SignIn { req: SignIn::Session { .. }, .. } => NetReply::SignIn(Ok(SignInReply::SignedIn(Me {
                account: "a1".into(),
                name: "Ann".into(),
                email: Some("ann@example.com".into()),
                admin: true,
                ..Me::default()
            }))),
            NetRequest::SignIn { .. } => NetReply::SignIn(Ok(SignInReply::Refused { reason: "no".into() })),
            NetRequest::Account { req: AccountReq::Files, .. } => {
                NetReply::Account(Ok(AccountReply::Files(vec![MyFile { info: file, role: Role::Owner }])))
            }
            NetRequest::Account { req: AccountReq::Browse, .. } => NetReply::Account(Ok(AccountReply::Browse {
                files: vec![FileEntry { info: file, role: Role::Owner, folder: String::new(), sealed: false, thumbnail: None, opened: Some(5) }],
                folders: vec!["Work".into()],
            })),
            NetRequest::Account { req: AccountReq::Members { .. }, .. } => NetReply::Account(Ok(AccountReply::Members {
                members: vec![
                    Member { account: "a1".into(), name: "Ann".into(), email: None, role: Role::Owner },
                    Member { account: "b2".into(), name: "Bob".into(), email: None, role: Role::Editor },
                ],
                invited: Vec::new(),
            })),
            NetRequest::Account { .. } => NetReply::Account(Ok(AccountReply::Done)),
            NetRequest::Admin { req: Admin::People, .. } => NetReply::Admin(Ok(AdminReply::People(Vec::new()))),
            other => other.failure()("not in this test".into()),
        }
    }
}

fn harness() -> (Harness, Arc<Mutex<Wire>>) {
    let (mut h, _) = Harness::new();
    let wire = Arc::new(Mutex::new(Wire::default()));
    h.app.session.live.install(Box::new(Link(wire.clone())));
    h.app.session.prefs.servers = Some(Vec::new());
    h.app.ui.home = true;
    h.frames(2);
    (h, wire)
}

fn click(h: &mut Harness, text: &str) -> Vec<egui::Shape> {
    let shapes = h.frames(2);
    h.click(text_center(&shapes, text));
    h.frames(4)
}

#[test]
fn a_servers_page_signs_in_lists_your_files_and_their_people() {
    let (mut h, wire) = harness();
    // Preferences ▸ Servers adds it; the home screen has its page.
    h.app.ui.preferences = true;
    click(&mut h, "Servers");
    h.app.ui.account.new_name = "Team".into();
    h.app.ui.account.new_url = SERVER.into();
    let shapes = click(&mut h, "Add");
    assert!(has_text(&shapes, "Team") && has_text(&shapes, "127.0.0.1:47910"));
    h.app.ui.preferences = false;
    let shapes = click(&mut h, "Team");
    // Not signed in: the server's ways in, under its name (never its address).
    for t in ["Sign in to Team", "Access token", "Sign in with Example SSO"] {
        assert!(has_text(&shapes, t), "the page shows {t:?}");
    }
    assert!(!has_text(&shapes, "127.0.0.1:47910"));
    assert!(wire.lock().unwrap().asked.iter().any(|r| matches!(r, NetRequest::Info { .. })));
    // A token signs in; the files there show as cards, and the tabs (Admin for an admin).
    h.app.ui.account.token = "ann".into();
    let shapes = h.frames(1);
    let sign_in = crate::live_tests::texts(&shapes).into_iter().filter(|t| t.0 == "Sign in").map(|t| t.1).next().unwrap();
    h.click(sign_in);
    let shapes = h.frames(6);
    for t in [
        "Signed in as Ann (ann@example.com)",
        "Sign out",
        "Files",
        "People",
        "Settings",
        "Admin",
        "New design file",
        "Recent",
        "All files",
        "Plan",
        "Folders",
        "Work",
    ] {
        assert!(has_text(&shapes, t), "signed in, the page shows {t:?}");
    }
    // Signed in with a token, not a password: no Account tab.
    assert!(!has_text(&shapes, "Account"));
    assert!(!format!("{:?}", crate::account_ui::inspect(&h.app)).contains(TOKEN));
    // The People tab: everyone in your files, by name, without invites.
    click(&mut h, "People");
    let shapes = h.frames(6);
    for t in ["Ann (you)", "Bob", "In 1 of your files"] {
        assert!(has_text(&shapes, t), "the people show {t:?}");
    }
    assert!(!has_text(&shapes, "Invite"));
    assert!(wire.lock().unwrap().asked.iter().any(|r| matches!(r, NetRequest::Account { req: AccountReq::Members { file }, .. } if file == "f1")));
    // Settings: this server for new files.
    let shapes = click(&mut h, "Settings");
    assert!(has_text(&shapes, "Use this server for new files") && has_text(&shapes, "Open this server's home when FigCraft starts"));
    // The Admin tab: one page of sections.
    let shapes = click(&mut h, "Admin");
    for t in ["People on this server", "Invite people", "Sessions"] {
        assert!(has_text(&shapes, t), "the admin tab shows {t:?}");
    }
    // Signed in with a password: the Account tab, with the password.
    h.app.session.prefs.accounts[0].password = true;
    let shapes = click(&mut h, "Account");
    assert!(has_text(&shapes, "Change password") && has_text(&shapes, "Current password"));
    // Sign out: back to the ways in.
    let shapes = click(&mut h, "Sign out");
    assert!(h.app.session.signed_in(SERVER).is_none());
    assert!(has_text(&shapes, "Access token"));
}
