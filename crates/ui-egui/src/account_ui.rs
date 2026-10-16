//! Remote servers in the window, on top of the files on this computer: Preferences ▸ Servers (add,
//! remove and order them), the home screen's page for each server (signing in there, your files
//! on it with their people, putting an open file there, the files you shared there from this
//! computer, and an admin's tools), the Sign in window (a device code to type when you aren't on
//! the server's page, or a server that signed you out), and the People part of the Share popover
//! for a file on a server with accounts.
//!
//! Everything acts through the engine's commands (`servers.*`, `account.*`, `collab.publish`,
//! `collab.share`);
//! the ones that ask a server run in the background, so the window never waits. Session tokens
//! never reach the UI.

use std::collections::BTreeMap;

use egui::{Context, CornerRadius, Rect, RichText, Sense, Ui, pos2, vec2};
use figcraft_engine::accounts::Pending;
use figcraft_engine::servers::{SavedServer, host};
use serde_json::{Value, json};

use crate::FigApp;
use crate::a11y;
use crate::i18n::{tr, trf};
use crate::icons::Icon;
use crate::theme::{ACCENT, Tokens, regular, semibold};
use crate::widgets;

const SIGN_IN: &str = "account.signIn";
const INFO: &str = "account.info";
const POLL: &str = "account.signInPoll";
const SIGN_OUT: &str = "account.signOut";
const CHECK: &str = "account.check";
const FILES: &str = "account.browse";
const THUMBNAIL: &str = "account.thumbnail";
const FOLDER_CHANGES: [&str; 4] = ["account.createFolder", "account.renameFolder", "account.removeFolder", "account.moveFile"];
const DEVICES: &str = "account.devices";
const DEVICE_CHANGES: [&str; 3] = ["account.revokeDevice", "account.recoveryKey", "account.recover"];
const AVATAR: &str = "account.avatar";
const PEOPLE: &str = "account.people";
const NEW_FILE: &str = "account.newFile";

/// Roles in the order the pickers show them (ids and labels).
pub(crate) const ROLES: [&str; 3] = ["editor", "viewer", "owner"];

/// A role's label.
pub(crate) fn role_label(role: &str) -> &'static str {
    match role {
        "owner" => tr("Owner"),
        "viewer" => tr("Viewer"),
        _ => tr("Editor"),
    }
}

/// What the window knows of one server this run.
#[derive(Default)]
pub struct ServerState {
    /// What it accepts (`account.info`), asked once a run.
    pub info: Option<Value>,
    info_asked: bool,
    /// Your cached sign-in was checked (`account.check`), and what it said.
    pub checked: bool,
    pub check: Option<Value>,
    /// Your files there (`account.files`).
    pub files: Option<Value>,
    /// You were signed in there when its page last drew (a change loads the files again), and as
    /// whom (another account: what was shown of the last one goes).
    was_signed_in: Option<bool>,
    who: Option<String>,
    /// The frame its page last drew in: shown again after a gap, the files are asked for again
    /// (the cards stay until the answer).
    drawn: Option<u64>,
    /// The files changed from here (a new file): asked for again when the page shows.
    pub files_stale: bool,
    /// Your devices there (`account.devices`), asked once a run; a recovery key just made (shown
    /// this once).
    pub devices: Option<Value>,
    devices_asked: bool,
    pub recovery_key: Option<String>,
    /// The recovery key just shown was saved somewhere (its confirmation is ticked).
    pub recovery_saved: bool,
    /// Everyone on the server (`account.people`), asked once a visit.
    pub team: Option<Value>,
    team_asked: bool,
    /// The page's tab, and the folder the Files tab is in (`""`: the top).
    pub tab: ServerTab,
    pub folder: String,
    /// The pictures of your files there: by file, the time of the picture asked for and its
    /// texture (`None`: none to show).
    pub pictures: BTreeMap<String, (u64, Option<egui::TextureHandle>)>,
}

/// UI-only state of servers and accounts.
#[derive(Default)]
pub struct AccountUi {
    pub servers: BTreeMap<String, ServerState>,
    /// When the device code was last asked about (UI clock).
    last_poll: f64,
    /// The Sign in window, for this server (and why it shows: a server that signed you out).
    pub window: Option<(String, Option<String>)>,
    /// Preferences ▸ Servers: the name and address of a server being added.
    pub new_name: String,
    pub new_url: String,
    /// People's pictures by (server, account): `None` once asked when there is none (their
    /// initials show).
    pub avatars: BTreeMap<(String, String), Option<egui::TextureHandle>>,
    /// A folder being made, and one being renamed (its path and the name typed).
    pub new_folder: Option<String>,
    pub rename_folder: Option<(String, String)>,
    /// A password being changed (current, new), a safety number shown (account, number), and an
    /// account being made (email, name) with the username and password above.
    pub change: (String, String),
    pub safety: Option<(String, String)>,
    pub sign_up: Option<(String, String)>,
    /// A token being typed to sign in, a username and password, and a recovery key.
    pub token: String,
    pub username: String,
    pub password: String,
    pub recovery_typed: String,
}

impl AccountUi {
    fn of(&mut self, server: &str) -> &mut ServerState {
        self.servers.entry(server.to_string()).or_default()
    }
}

/// The servers the home screen has a page for: yours ([`figcraft_engine::Session::servers`]),
/// then those of files you shared online from here that aren't in your list.
pub fn home_servers(app: &FigApp) -> Vec<SavedServer> {
    let mut list = app.session.servers();
    for f in &app.session.prefs.online_files {
        if !list.iter().any(|s| figcraft_engine::online::same_server(&s.url, &f.server)) {
            let url = figcraft_engine::accounts::server_key(&f.server);
            list.push(SavedServer { name: host(&url).to_string(), url });
        }
    }
    // A server nobody named (the browser build's, one added by its address) goes by the name it
    // gives itself.
    for sv in &mut list {
        let own = app
            .ui
            .account
            .servers
            .get(&sv.url)
            .and_then(|st| st.info.as_ref())
            .and_then(|i| i["name"].as_str())
            .map(str::trim)
            .filter(|n| !n.is_empty());
        if let Some(own) = own.filter(|_| sv.name == host(&sv.url)) {
            sv.name = own.to_string();
        }
    }
    list
}

/// What `server` accepts, asked once (in the background) when something needs it.
pub fn info(app: &mut FigApp, ctx: &Context, server: &str) -> Option<Value> {
    let st = app.ui.account.of(server);
    if st.info.is_some() || st.info_asked {
        return st.info.clone();
    }
    if !app.session.waiting_for(INFO) {
        app.ui.account.of(server).info_asked = true;
        let at = server.to_string();
        app.run_background(
            ctx,
            INFO,
            json!({"server": server}),
            Box::new(move |app, _, v| {
                app.ui.account.of(&at).info = Some(v);
            }),
        );
    }
    None
}

/// `info` is of a server where people sign in (and files have members).
pub fn has_accounts(info: &Value) -> bool {
    info["accounts"] == true
}

/// Each frame, in the main window: ask about a device code every `interval` seconds; close the
/// Sign in window once it has done its job.
pub fn tick(app: &mut FigApp, ctx: &Context) {
    if app.windows.current != 0 {
        return;
    }
    if let Some(Pending::Device { interval, .. }) = app.session.accounts.pending.clone() {
        let every = f64::from(interval.clamp(1, 60));
        let now = ctx.input(|i| i.time);
        if !app.session.waiting_for(POLL) && now - app.ui.account.last_poll >= every {
            app.ui.account.last_poll = now;
            app.run_background(ctx, POLL, json!({}), Box::new(|_, _, _| {}));
        }
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(every));
    }
    if app.ui.account.window.as_ref().is_some_and(|(server, _)| app.session.signed_in(server).is_some()) {
        app.ui.account.window = None;
    }
}

/// Your files on `server` as last listed (`account.browse`), if they were.
pub(crate) fn server_files(app: &mut FigApp, server: &str) -> Option<Value> {
    app.ui.account.of(&figcraft_engine::accounts::server_key(server)).files.clone()
}

/// Ask for your files on `server` again (in the background; what was listed stays meanwhile).
pub(crate) fn refresh_files(app: &mut FigApp, ctx: &Context, server: &str) {
    load_files(app, ctx, &figcraft_engine::accounts::server_key(server));
}

fn load_files(app: &mut FigApp, ctx: &Context, server: &str) {
    let at = server.to_string();
    app.run_background(
        ctx,
        FILES,
        json!({"server": server}),
        Box::new(move |app, _, v| {
            app.ui.account.of(&at).files = Some(v);
        }),
    );
}

/// What a server's page needs: your cached sign-in checked once (silently), then your files, and
/// again when you sign in.
fn ensure(app: &mut FigApp, ctx: &Context, server: &str) {
    let who = app.session.signed_in(server).map(|m| m.account.clone());
    let signed = who.is_some();
    let frame = ctx.cumulative_frame_nr();
    let st = app.ui.account.of(server);
    // Signed in as someone else than when the page last drew (or not any more): nothing of theirs
    // stays.
    let changed = st.who != who;
    st.who = who;
    let (checked, was) = (st.checked, if changed { Some(false) } else { st.was_signed_in });
    st.was_signed_in = Some(signed);
    let back = st.drawn.replace(frame).is_some_and(|d| d.saturating_add(1) < frame);
    if back {
        // Who is on the server is asked again too.
        st.team_asked = false;
    }
    if signed && checked && (back || st.files_stale) && !app.session.waiting_for(FILES) {
        app.ui.account.of(server).files_stale = false;
        load_files(app, ctx, server);
    }
    if changed {
        app.ui.admin = None;
    }
    let st = app.ui.account.of(server);
    if !signed || changed {
        st.recovery_key = None;
        st.files = None;
        st.team = None;
        st.team_asked = false;
        st.devices = None;
        st.devices_asked = false;
    }
    if signed && !checked && !app.session.waiting_for(CHECK) {
        app.ui.account.of(server).checked = true;
        let at = server.to_string();
        app.run_background(
            ctx,
            CHECK,
            json!({"server": server}),
            Box::new(move |app, ctx, v| {
                let ok = v["signedIn"] == true;
                app.ui.account.of(&at).check = Some(v);
                if ok {
                    load_files(app, ctx, &at);
                }
            }),
        );
    } else if signed && checked && was == Some(false) {
        // Signed in just now.
        load_files(app, ctx, server);
    }
}

/// What a UI request about signing in asks for: the code to type (`account.code`) shows on the
/// server's page, else in the Sign in window; a server that signed you out asks you to sign in
/// again (`account.signedOut`).
pub fn request(app: &mut FigApp, kind: &str, data: &Value) {
    let server = data["server"].as_str().map(str::to_string);
    match kind {
        "account.signedOut" => {
            let server = server.unwrap_or_else(|| app.session.home_server());
            let st = app.ui.account.of(&server);
            st.files = None;
            st.checked = false;
            app.ui.account.window = Some((server, data["reason"].as_str().map(str::to_string)));
        }
        "account.code" => {
            let server = match &app.session.accounts.pending {
                Some(Pending::Device { server, .. } | Pending::Browser { server, .. }) => server.clone(),
                None => app.session.home_server(),
            };
            let on_its_page = app.ui.home && shown_server(app).is_some_and(|s| s.url == server);
            if !on_its_page && app.ui.account.window.is_none() {
                app.ui.account.window = Some((server, None));
            }
        }
        _ => {}
    }
}

/// The server whose page the home screen shows, if it shows one.
pub fn shown_server(app: &FigApp) -> Option<SavedServer> {
    match app.ui.home_view.section {
        crate::home::Section::Server(i) => home_servers(app).into_iter().nth(i),
        _ => None,
    }
}

/// Signing in to `server`: who you are there and Sign out; or the sign-in on its way (finish it in
/// the browser, or the code to type and where); or a way in per provider (a button for one with a
/// page or a code, a field for one that takes a token), with why the last try failed.
pub fn sign_in_block(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    if let Some(me) = app.session.signed_in(server).cloned() {
        let who = match &me.email {
            Some(email) if !email.is_empty() => trf("Signed in as {name} ({email})", &[("name", &me.name), ("email", email)]),
            _ => trf("Signed in as {name}", &[("name", &me.name)]),
        };
        ui.horizontal(|ui| {
            widgets::label(ui, &who, t.text);
            if widgets::button(ui, tr("Sign out"), false, !app.session.waiting_for(SIGN_OUT)).clicked() {
                app.run_background(&ctx, SIGN_OUT, json!({"server": server}), Box::new(|app, _, _| app.toast(tr("Signed out"))));
            }
        });
        return;
    }
    match app.session.accounts.pending.clone() {
        Some(Pending::Browser { server: s, url }) if s == server => {
            widgets::label(ui, tr("Finish signing in in your browser."), t.text);
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Open the page again"), false, true).clicked() {
                    app.services.open_url(&url);
                }
                if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                    app.run("account.cancelSignIn", json!({}));
                }
            });
            return;
        }
        Some(Pending::Device { server: s, user_code, verification_uri, .. }) if s == server => {
            widgets::label(ui, &trf("Enter this code at {address}", &[("address", &verification_uri)]), t.text);
            ui.label(RichText::new(&user_code).font(egui::FontId::monospace(22.0)).color(t.text));
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Copy code"), true, true).clicked() {
                    app.services.clipboard_set_text(&user_code);
                    app.toast(tr("Code copied"));
                }
                if widgets::button(ui, tr("Open the page"), false, verification_uri.starts_with("http")).clicked() {
                    app.services.open_url(&verification_uri);
                }
                if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                    app.cancel_background(POLL);
                    app.run("account.cancelSignIn", json!({}));
                }
            });
            widgets::label(ui, tr("Waiting for the code to be entered…"), t.text_secondary);
            return;
        }
        _ => {}
    }
    let busy = app.session.waiting_for(SIGN_IN);
    let Some(info) = info(app, &ctx, server) else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    if !has_accounts(&info) {
        widgets::label(ui, tr("This server has no accounts: its files are shared with links and codes."), t.text_secondary);
        return;
    }
    let providers = info["providers"].as_array().cloned().unwrap_or_default();
    let mut start: Option<Value> = None;
    let has = |p: &Value, f: &str| p["flows"].as_array().is_some_and(|l| l.iter().any(|x| x == f));
    // The browser build has no loopback page to come back to: it sends the page to the provider
    // (when the server lets it come back here), else a code typed on another device.
    let web = cfg!(target_arch = "wasm32");
    let sso_flows: &[&str] = if web { &["redirect", "device"] } else { &["browser", "device"] };
    let sso_flow = |p: &Value| sso_flows.iter().copied().find(|f| has(p, f));
    // A username and password (basic sign-in).
    for p in providers.iter().filter(|p| has(p, "password")) {
        let id = p["id"].as_str().unwrap_or_default();
        let user = widgets::text_input(ui, egui::Id::new(("account_user", id)), &mut app.ui.account.username, 240.0, tr("Username"));
        a11y::text(&user, tr("Username"), &app.ui.account.username);
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.ui.account.password)
                .password(true)
                .hint_text(tr("Password"))
                .desired_width(240.0)
                .id(egui::Id::new(("account_password", id))),
        );
        a11y::text(&field, tr("Password"), "");
        let filled = !app.ui.account.username.trim().is_empty() && !app.ui.account.password.is_empty();
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (widgets::button(ui, if busy { tr("Signing in…") } else { tr("Sign in") }, true, filled && !busy).clicked() || enter) && filled {
            let (user, pass) = (app.ui.account.username.trim().to_string(), std::mem::take(&mut app.ui.account.password));
            start = Some(json!({"server": server, "provider": id, "flow": "password", "username": user, "password": pass}));
        }
    }
    // Making an account, where the server lets people do it themselves.
    if let Some(p) = providers.iter().find(|p| has(p, "signUp")) {
        let id = p["id"].as_str().unwrap_or_default().to_string();
        match app.ui.account.sign_up.take() {
            None => {
                if ui.link(tr("No account yet? Make one")).clicked() {
                    app.ui.account.sign_up = Some(Default::default());
                }
            }
            Some((mut email, mut name)) => {
                let mut keep = true;
                widgets::label(ui, tr("Make an account with the username and password above."), t.text_secondary);
                let r = widgets::text_input(ui, egui::Id::new(("signup_email", &id)), &mut email, 240.0, tr("Email (optional)"));
                a11y::text(&r, tr("Email"), &email);
                let r = widgets::text_input(ui, egui::Id::new(("signup_name", &id)), &mut name, 240.0, tr("Your name (optional)"));
                a11y::text(&r, tr("Name"), &name);
                let filled = !app.ui.account.username.trim().is_empty() && app.ui.account.password.chars().count() >= 10;
                ui.horizontal(|ui| {
                    if widgets::button(ui, tr("Make account"), true, filled && !busy).clicked() {
                        let params = json!({
                            "server": server, "provider": id, "username": app.ui.account.username.trim(),
                            "password": std::mem::take(&mut app.ui.account.password), "email": email.trim(), "name": name.trim(),
                        });
                        app.run_background(&ctx, "account.signUp", params, Box::new(|_, _, _| {}));
                        keep = false;
                    }
                    if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                        keep = false;
                    }
                });
                if keep {
                    app.ui.account.sign_up = Some((email, name));
                }
            }
        }
    }
    // A token the person has.
    for p in providers.iter().filter(|p| sso_flow(p).is_none() && !has(p, "password") && has(p, "token")) {
        let (id, label) = (p["id"].as_str().unwrap_or_default(), p["label"].as_str().unwrap_or_default());
        ui.horizontal(|ui| {
            let field = ui.add(
                egui::TextEdit::singleline(&mut app.ui.account.token)
                    .password(true)
                    .hint_text(label)
                    .desired_width(180.0)
                    .id(egui::Id::new(("account_token", id))),
            );
            a11y::text(&field, label, "");
            let filled = !app.ui.account.token.trim().is_empty();
            let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (widgets::button(ui, if busy { tr("Signing in…") } else { tr("Sign in") }, true, filled && !busy).clicked() || enter) && filled {
                start = Some(json!({"server": server, "provider": id, "token": app.ui.account.token.trim()}));
            }
        });
    }
    // Single sign-on: one button per provider.
    for p in &providers {
        let Some(flow) = sso_flow(p) else { continue };
        let (id, label) = (p["id"].as_str().unwrap_or_default(), p["label"].as_str().unwrap_or_default());
        if sso_button(ui, t, &trf("Sign in with {provider}", &[("provider", &label)]), !busy).clicked() {
            start = Some(json!({"server": server, "provider": id, "flow": flow}));
        }
    }
    if providers.is_empty() {
        widgets::label(ui, tr("This server offers no way to sign in right now."), t.text_secondary);
    }
    if let Some(params) = start {
        app.ui.account.token.clear();
        app.ui.account.password.clear();
        app.session.accounts.last = None;
        app.run_background(&ctx, SIGN_IN, params, Box::new(|_, _, _| {}));
    }
    if web && providers.iter().any(|p| sso_flow(p) == Some("device")) {
        widgets::label(ui, tr("In the browser you sign in with a code you enter on another device."), t.text_secondary);
    }
    if let Some(Err(why)) = &app.session.accounts.last {
        widgets::label(ui, why, t.danger);
    }
}

/// The browser build a server with accounts hosts, while you aren't signed in there: the whole
/// window is its sign-in (the server's name and its ways in), and nothing else shows. True while
/// it shows. A cached sign-in is checked with the server once (the app shows meanwhile); one the
/// server no longer takes brings this back, as signing out does. A server without accounts (or
/// none) has no gate.
pub fn gate(app: &mut FigApp, ui: &mut Ui) -> bool {
    let Some(server) = app.session.servers().first().map(|s| s.url.clone()) else { return false };
    let ctx = ui.ctx().clone();
    let known = info(app, &ctx, &server);
    if known.as_ref().is_some_and(|i| !has_accounts(i)) {
        return false;
    }
    if app.session.signed_in(&server).is_some() {
        // Checked once; your files come with it.
        ensure(app, &ctx, &server);
        return false;
    }
    let t = Tokens::get(&ctx);
    let name = server_name(app, &server);
    egui::CentralPanel::default().frame(egui::Frame::NONE.fill(t.canvas)).show(ui, |ui| {
        let area = ui.max_rect();
        let w = 400.0_f32.min(area.width() - 32.0);
        let left = area.center().x - w / 2.0;
        ui.scope_builder(egui::UiBuilder::new().max_rect(Rect::from_min_size(pos2(left, area.min.y + 80.0), vec2(w, area.height() - 120.0))), |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                egui::Frame::NONE
                    .fill(t.panel)
                    .stroke(egui::Stroke::new(1.0, t.border))
                    .corner_radius(CornerRadius::same(12))
                    .inner_margin(egui::Margin::same(28))
                    .show(ui, |ui| {
                        ui.set_width(w - 56.0);
                        ui.spacing_mut().item_spacing.y = 10.0;
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(vec2(28.0, 28.0), Sense::hover());
                            crate::icons::paint(ui.painter(), r, Icon::Logo, ACCENT);
                            ui.label(RichText::new("FigCraft").font(semibold(15.0)).color(t.text));
                        });
                        ui.add_space(6.0);
                        ui.label(RichText::new(&name).font(semibold(20.0)).color(t.text));
                        if known.is_none() && app.session.waiting_for(INFO) {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new().size(14.0));
                                widgets::label(ui, &trf("Connecting to {server}…", &[("server", &name)]), t.text_secondary);
                            });
                            return;
                        }
                        if known.is_none() {
                            widgets::label(ui, &trf("Couldn't reach {server}.", &[("server", &name)]), t.danger);
                            if widgets::button(ui, tr("Try again"), true, true).clicked() {
                                app.ui.account.of(&server).info_asked = false;
                            }
                            return;
                        }
                        widgets::label(ui, tr("Sign in to continue: your files and your team are on this server."), t.text_secondary);
                        ui.add_space(4.0);
                        sign_in_block(app, ui, &t, &server);
                    });
            });
        });
    });
    true
}

/// A single sign-on button: a light surface, rounded, a plain key drawn in code (never a provider's
/// logo) and "Sign in with …".
fn sso_button(ui: &mut Ui, t: &Tokens, label: &str, enabled: bool) -> egui::Response {
    let font = egui::FontId::proportional(13.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), egui::Color32::BLACK);
    let size = vec2((galley.size().x + 64.0).max(240.0), 36.0);
    let (rect, resp) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    a11y::button(&resp, label);
    let hot = enabled && resp.hovered();
    let fill = if hot { egui::Color32::from_gray(242) } else { egui::Color32::WHITE };
    let ink = egui::Color32::from_gray(if enabled { 31 } else { 140 });
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(18), fill);
    p.rect_stroke(rect, CornerRadius::same(18), egui::Stroke::new(1.0, egui::Color32::from_gray(200)), egui::StrokeKind::Inside);
    crate::icons::paint(p, Rect::from_center_size(pos2(rect.min.x + 22.0, rect.center().y), vec2(16.0, 16.0)), Icon::Lock, ink);
    p.text(rect.center() + vec2(10.0, 0.0), egui::Align2::CENTER_CENTER, label, font, ink);
    if resp.has_focus() {
        p.rect_stroke(rect, CornerRadius::same(18), egui::Stroke::new(2.0, t.focus), egui::StrokeKind::Outside);
    }
    resp
}

/// Preferences ▸ Servers: the remote servers you use (name and address), in order: add, move up,
/// remove. Nothing else about servers is set here.
pub fn servers_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    widgets::label(
        ui,
        tr(
            "Servers you use, on top of the files on this computer. Each has its page on the home screen, where you sign in and find your files there.",
        ),
        t.text_secondary,
    );
    ui.add_space(4.0);
    let servers = app.session.servers();
    if servers.is_empty() {
        widgets::label(ui, tr("No servers yet."), t.text_secondary);
    }
    let mut act: Option<(&str, Value)> = None;
    for (i, sv) in servers.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_width(250.0);
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&sv.name).font(regular(12.0)).color(t.text));
                    widgets::label(ui, host(&sv.url), t.text_secondary);
                });
            });
            if i == 0 {
                // The first one has nowhere to move up to: its row lines up with the others.
                ui.allocate_exact_size(vec2(24.0, 24.0), Sense::hover());
            } else if widgets::icon_button(ui, Icon::ChevronUp, tr("Move up")) {
                act = Some(("servers.move", json!({"url": sv.url, "to": i - 1})));
            }
            if widgets::button(ui, tr("Remove"), false, true).on_hover_text(tr("Your sign-in there and the files on it stay")).clicked() {
                act = Some(("servers.remove", json!({"url": sv.url})));
            }
        });
    }
    if let Some((cmd, params)) = act {
        app.run(cmd, params);
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let name = widgets::text_input(ui, egui::Id::new("pref_server_name"), &mut app.ui.account.new_name, 110.0, tr("Name"));
        a11y::text(&name, tr("Server name"), &app.ui.account.new_name);
        let url = widgets::text_input(ui, egui::Id::new("pref_server_url"), &mut app.ui.account.new_url, 200.0, "wss://host/");
        a11y::text(&url, tr("Server address"), &app.ui.account.new_url);
        let filled = !app.ui.account.new_url.trim().is_empty();
        let enter = url.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (widgets::button(ui, tr("Add"), true, filled).clicked() || enter) && filled {
            let params = json!({"name": app.ui.account.new_name.trim(), "url": app.ui.account.new_url.trim()});
            if app.run("servers.add", params).is_some() {
                app.ui.account.new_name.clear();
                app.ui.account.new_url.clear();
            }
        }
    });
    widgets::label(ui, tr("Join codes typed without a link are asked of the first server."), t.text_secondary);
}

/// The Sign in window: signing in to a server that asked when its page isn't showing (a code to
/// type, or a server that signed you out); it closes once you are signed in.
pub fn sign_in_window(app: &mut FigApp, ctx: &Context) {
    let Some((server, why)) = app.ui.account.window.clone() else { return };
    let t = Tokens::get(ctx);
    let mut open = true;
    crate::dialogs::window(tr("Sign in"), ctx).id(egui::Id::new("account_sign_in")).open(&mut open).show(ctx, |ui| {
        ui.set_width(320.0);
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        ui.label(RichText::new(trf("Sign in to {server}", &[("server", &server_name(app, &server))])).font(semibold(13.0)).color(t.text));
        // The same reason is the last sign-in's outcome, which the block below shows.
        let shown_below = matches!(&app.session.accounts.last, Some(Err(last)) if Some(last) == why.as_ref());
        if let Some(why) = why.as_ref().filter(|_| !shown_below) {
            widgets::label(ui, why, t.danger);
        }
        ui.add_space(4.0);
        sign_in_block(app, ui, &t, &server);
    });
    if !open {
        app.ui.account.window = None;
    }
}

/// A heading inside a server's page.
fn subheading(ui: &mut Ui, t: &Tokens, text: &str) {
    ui.add_space(14.0);
    ui.label(RichText::new(text).font(semibold(12.0)).color(t.text_secondary));
    ui.add_space(4.0);
}

/// Widest a section of a server's page gets.
pub(crate) const SECTION_WIDTH: f32 = 720.0;

/// One section of a server's page: a card with a heading, one sentence saying what it does, and
/// `body`.
pub(crate) fn section(ui: &mut Ui, t: &Tokens, title: &str, about: &str, body: impl FnOnce(&mut Ui)) {
    ui.add_space(4.0);
    egui::Frame::NONE
        .fill(t.panel)
        .stroke(egui::Stroke::new(1.0, t.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width().min(SECTION_WIDTH));
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.label(RichText::new(title).font(semibold(13.0)).color(t.text));
            widgets::label(ui, about, t.text_secondary);
            ui.add_space(4.0);
            body(ui);
        });
    ui.add_space(8.0);
}

/// A setting that is on or off: its title and what it does, and a switch at the right. True when
/// it was switched.
fn switch_row(ui: &mut Ui, t: &Tokens, on: bool, title: &str, about: &str, enabled: bool) -> bool {
    let w = ui.available_width();
    let galley = ui.painter().layout(about.to_string(), regular(11.0), t.text_secondary, (w - 64.0).max(80.0));
    let h = (galley.size().y + 24.0).max(40.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), if enabled { Sense::click() } else { Sense::hover() });
    a11y::checkbox(&resp, title, on);
    if resp.hovered() && enabled {
        ui.painter().rect_filled(rect.expand2(vec2(6.0, 2.0)), CornerRadius::same(6), t.hover);
    }
    let p = ui.painter();
    p.text(rect.min + vec2(0.0, 4.0), egui::Align2::LEFT_TOP, title, semibold(12.0), if enabled { t.text } else { t.text_secondary });
    p.galley(rect.min + vec2(0.0, 22.0), galley, t.text_secondary);
    // The switch: a pill with a knob, the accent when on.
    let track = Rect::from_center_size(pos2(rect.max.x - 18.0, rect.min.y + 14.0), vec2(32.0, 18.0));
    let fill = if on && enabled {
        ACCENT
    } else if on {
        t.border_strong
    } else {
        t.pressed
    };
    p.rect_filled(track, CornerRadius::same(9), fill);
    let knob = if on { track.max.x - 9.0 } else { track.min.x + 9.0 };
    p.circle_filled(pos2(knob, track.center().y), 7.0, egui::Color32::WHITE);
    if resp.has_focus() {
        p.rect_stroke(track, CornerRadius::same(9), egui::Stroke::new(2.0, t.focus), egui::StrokeKind::Outside);
    }
    resp.clicked()
}

/// The tabs of a server's page (with accounts, signed in).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerTab {
    #[default]
    Files,
    People,
    /// Signed in with a username and password: your password, devices and recovery.
    Account,
    Settings,
    Admin,
}

impl ServerTab {
    fn label(self) -> &'static str {
        match self {
            ServerTab::Files => tr("Files"),
            ServerTab::People => tr("People"),
            ServerTab::Account => tr("Account"),
            ServerTab::Settings => tr("Settings"),
            ServerTab::Admin => tr("Admin"),
        }
    }
}

/// The name people know `server` by: the one it was given in Preferences ▸ Servers, else its host.
/// What the window shows of a server (never its address, outside Preferences ▸ Servers).
pub fn server_name(app: &FigApp, server: &str) -> String {
    let key = figcraft_engine::accounts::server_key(server);
    home_servers(app).into_iter().find(|s| s.url == key).map_or_else(|| host(&key).to_string(), |s| s.name)
}

/// The home screen's page for `server`, in `main`. A server with accounts: signing in, then tabs:
/// Files (your files there as cards, in folders when the server keeps them, a new file, and
/// putting an open file there), People (who you work with there), Account (signed in with a
/// password: your password, devices and recovery), Settings (this server and new files; devices
/// and recovery for a single sign-on) and Admin (for admins). Any server: the files you shared
/// there from this computer.
pub fn page(app: &mut FigApp, ui: &mut Ui, main: Rect, t: &Tokens, server: &SavedServer) {
    let ctx = ui.ctx().clone();
    ui.painter().text(main.min, egui::Align2::LEFT_TOP, &server.name, semibold(18.0), t.text);
    let info = info(app, &ctx, &server.url);
    let accounts = info.as_ref().is_some_and(has_accounts);
    // A server that also takes files with links and codes (or one that can't say).
    let links = info.as_ref().is_none_or(|i| i["links"] != false);
    let width = if accounts { main.width() } else { main.width().min(720.0) };
    let body = Rect::from_min_max(pos2(main.min.x, main.min.y + 40.0), pos2(main.min.x + width, main.max.y));
    if accounts {
        ensure(app, &ctx, &server.url);
    }
    ui.scope_builder(egui::UiBuilder::new().max_rect(body).layout(egui::Layout::top_down(egui::Align::Min)), |ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        ui.spacing_mut().item_spacing.y = 6.0;
        egui::ScrollArea::vertical().id_salt(("server_page", &server.url)).auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            if accounts {
                account_part(app, ui, t, &server.url, links);
            } else {
                crate::online::list(app, ui, t, &server.url);
                put_here(app, ui, t, &server.url, false);
            }
        });
    });
}

/// You signed in to `server` with a username and password (its Account tab shows).
fn password_sign_in(app: &FigApp, server: &str) -> bool {
    app.session.signed_in(server).is_some_and(|m| m.password)
}

/// The server keeps sealed (end-to-end encrypted) files: devices and recovery keys matter there.
fn sealing(app: &mut FigApp, server: &str) -> bool {
    app.ui.account.of(server).info.as_ref().is_some_and(|i| i["e2e"].as_str().is_some_and(|m| m != "off"))
}

/// A server with accounts: the sign-in, or (signed in) who you are and the tabs.
fn account_part(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str, links: bool) {
    let name = server_name(app, server);
    if app.session.signed_in(server).is_none() {
        let offline =
            app.ui.account.of(server).check.as_ref().filter(|c| c["offline"] == true).map(|c| c["reason"].as_str().unwrap_or_default().to_string());
        if offline.is_some() {
            widgets::label(ui, &trf("Couldn't reach {server}.", &[("server", &name)]), t.danger);
        }
        egui::Frame::NONE
            .fill(t.panel)
            .stroke(egui::Stroke::new(1.0, t.border))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(520.0));
                ui.spacing_mut().item_spacing.y = 8.0;
                ui.label(RichText::new(trf("Sign in to {server}", &[("server", &name)])).font(semibold(13.0)).color(t.text));
                widgets::label(ui, tr("Your files on the server show here once you are signed in."), t.text_secondary);
                sign_in_block(app, ui, t, server);
            });
        return;
    }
    // Behind the browser build's sign-in screen, you are always signed in here: Sign out is
    // under Settings.
    if !app.ui.login_gate {
        sign_in_block(app, ui, t, server);
    }
    let admin = app.session.signed_in(server).is_some_and(|m| m.admin);
    let tabs: Vec<ServerTab> = [ServerTab::Files, ServerTab::People]
        .into_iter()
        .chain(password_sign_in(app, server).then_some(ServerTab::Account))
        .chain([ServerTab::Settings])
        .chain(admin.then_some(ServerTab::Admin))
        .collect();
    let mut tab = app.ui.account.of(server).tab;
    if !tabs.contains(&tab) {
        tab = ServerTab::Files;
    }
    ui.add_space(6.0);
    crate::dialogs::tab_strip(ui, t, &tabs, ServerTab::label, &mut tab);
    app.ui.account.of(server).tab = tab;
    ui.add_space(6.0);
    match tab {
        ServerTab::Files => {
            files_tab(app, ui, t, server);
            if let Some(session) = app.ui.live.home_join {
                crate::live::join_status(app, ui, t, session);
            }
            put_here(app, ui, t, server, true);
            if links && crate::online::has_files(app, server) {
                subheading(ui, t, tr("Shared from this computer"));
                ui.scope(|ui| {
                    ui.set_max_width(720.0);
                    crate::online::list(app, ui, t, server);
                });
            }
        }
        ServerTab::People => people_tab(app, ui, t, server),
        ServerTab::Account => account_tab(app, ui, t, server),
        ServerTab::Settings => settings_tab(app, ui, t, server),
        ServerTab::Admin => crate::admin_ui::tools(app, ui, t, server),
    }
}

/// Signed in with a username and password: change it, the devices you use here, and recovering
/// your account on a new device.
fn account_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    section(ui, t, tr("Change password"), tr("Choose a new password for signing in here. Your other devices stay signed in."), |ui| {
        change_password(app, ui, t, server);
    });
    device_sections(app, ui, t, server);
}

/// Connected devices and Recover your account, where the server keeps encrypted files: on the
/// Account tab, or on Settings for a single sign-on.
fn device_sections(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    if !sealing(app, server) {
        return;
    }
    section(
        ui,
        t,
        tr("Connected devices"),
        tr("The devices that open your encrypted files on this server. Revoke one you no longer use or have lost: its keys stop working."),
        |ui| connected_devices(app, ui, t, server),
    );
    section(
        ui,
        t,
        tr("Recover your account"),
        tr("A recovery key lets a new device into your encrypted files when none of your other devices is at hand."),
        |ui| recover_account(app, ui, t, server),
    );
}

/// This server and new files: the + tab and Save put new files here; the home screen opens on
/// this server's page (desktop). For a single sign-on, the devices and recovery too.
fn settings_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let name = server_name(app, server);
    let key = figcraft_engine::accounts::server_key(server);
    let in_list = app.session.servers().iter().any(|s| s.url == key);
    section(ui, t, tr("This server"), tr("How FigCraft uses this server on this computer."), |ui| {
        let default = app.session.prefs.default_server.as_deref() == Some(key.as_str());
        let about = trf("The + tab and Save put new files at the top of {server}, instead of on this computer.", &[("server", &name)]);
        if switch_row(ui, t, default, tr("Use this server for new files"), &about, in_list) {
            app.run("servers.setDefault", json!({"server": if default { Value::Null } else { json!(key) }}));
        }
        if !cfg!(target_arch = "wasm32") {
            ui.add_space(4.0);
            let start = app.session.start_home_server().as_deref() == Some(key.as_str());
            let about = trf("FigCraft opens on the home page of {server} instead of your recent files.", &[("server", &name)]);
            if switch_row(ui, t, start, tr("Open this server's home when FigCraft starts"), &about, in_list) {
                app.run("servers.setStartHome", json!({"server": if start { Value::Null } else { json!(key) }}));
            }
        }
        if !in_list {
            widgets::label(ui, tr("Add this server in Preferences ▸ Servers to use these."), t.text_secondary);
        }
    });
    // Signed in another way than a password: devices and recovery live here.
    if !password_sign_in(app, server) {
        device_sections(app, ui, t, server);
    }
    // Behind the browser build's sign-in screen: who you are, and signing out back to it.
    if app.ui.login_gate
        && let Some(me) = app.session.signed_in(server).cloned()
    {
        let who = trf("Signed in as {name}", &[("name", &person_name(&me.name, me.email.as_deref()))]);
        section(ui, t, tr("Signing in"), &who, |ui| {
            if widgets::button(ui, tr("Sign out"), false, !app.session.waiting_for(SIGN_OUT)).clicked() {
                let ctx = ui.ctx().clone();
                app.run_background(&ctx, SIGN_OUT, json!({"server": server}), Box::new(|app, _, _| app.toast(tr("Signed out"))));
            }
        });
    }
}

/// Your files on `server` as cards, like the home screen's own (`account.browse`): the recent
/// ones first, then the folder you are in (with the way back up), its folders and its files, with
/// their pictures (`account.thumbnail`) or a plain placeholder. A new folder, renaming and removing
/// one, and moving a file into one, from the folders' and cards' menus.
fn files_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    let st = app.ui.account.of(server);
    let (browse, here) = (st.files.clone(), st.folder.clone());
    let busy = FOLDER_CHANGES.iter().any(|c| app.session.waiting_for(c));
    ui.horizontal(|ui| {
        if widgets::button(ui, tr("Refresh"), false, !app.session.waiting_for(FILES)).clicked() {
            load_files(app, &ctx, server);
        }
        if widgets::button(ui, tr("New folder…"), false, !busy).clicked() {
            app.ui.account.new_folder = Some(String::new());
        }
        if app.session.waiting_for(FILES) || app.session.waiting_for(CHECK) {
            widgets::label(ui, tr("Loading your files…"), t.text_secondary);
        }
    });
    if let Some(mut name) = app.ui.account.new_folder.take() {
        let mut keep = true;
        ui.horizontal(|ui| {
            let resp = widgets::text_input(ui, egui::Id::new(("new_folder", server)), &mut name, 220.0, tr("Folder name"));
            a11y::text(&resp, tr("Folder name"), &name);
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let filled = !name.trim().is_empty() && !name.contains('/');
            if (widgets::button(ui, tr("Make folder"), true, filled).clicked() || enter) && filled {
                let path = if here.is_empty() { name.trim().to_string() } else { format!("{here}/{}", name.trim()) };
                folder_change(app, &ctx, server, "account.createFolder", json!({"server": server, "path": path}));
                keep = false;
            }
            if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                keep = false;
            }
        });
        if keep {
            app.ui.account.new_folder = Some(name);
        }
    }
    let list = browse.as_ref().and_then(|f| f["files"].as_array().cloned()).unwrap_or_default();
    let all: Vec<String> = browse
        .as_ref()
        .and_then(|v| v["folders"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|f| f.as_str().map(str::to_string))
        .collect();
    let folder_of = |f: &Value| f["folder"].as_str().unwrap_or_default().trim_matches('/').to_string();
    let mut open = None;
    // The folder you are in, and the way back up.
    ui.horizontal(|ui| {
        if ui.link(tr("All files")).clicked() {
            app.ui.account.of(server).folder.clear();
        }
        let mut path = String::new();
        for part in here.split('/').filter(|p| !p.is_empty()) {
            path = if path.is_empty() { part.to_string() } else { format!("{path}/{part}") };
            widgets::label(ui, "›", t.text_tertiary);
            if ui.link(part).clicked() {
                app.ui.account.of(server).folder = path.clone();
            }
        }
    });
    // A new file here: at the top, or in the folder you are in.
    ui.add_space(6.0);
    let about = if here.is_empty() { tr("Start from a blank canvas") } else { tr("Start from a blank canvas in this folder") };
    if crate::home::action_card(ui, t, Icon::Plus, tr("New design file"), about) && !app.session.waiting_for(NEW_FILE) {
        new_file(app, &ctx, NEW_FILE, json!({"server": server, "folder": here, "name": tr("Untitled")}));
        // It shows in the list once it is there.
        app.ui.account.of(server).files_stale = true;
    }
    if browse.is_some() && list.is_empty() && all.is_empty() {
        widgets::label(ui, tr("No files here yet: make one, or put an open file here."), t.text_secondary);
        return;
    }
    if here.is_empty() {
        // The server's order: what you opened or changed last first.
        let ids: Vec<String> = browse
            .as_ref()
            .and_then(|v| v["recent"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|f| f.as_str().map(str::to_string))
            .collect();
        let (columns, _) = crate::home_recents::grid_columns(ui.available_width() - 16.0);
        let recent: Vec<Value> = ids.iter().filter_map(|id| list.iter().find(|f| f["file"] == id.as_str()).cloned()).take(columns.max(1)).collect();
        if !recent.is_empty() {
            subheading(ui, t, tr("Recent"));
            if let Some(id) = cards(app, ui, t, server, &recent, "recent", &all) {
                open = Some(id);
            }
        }
    }
    // Folders in this one.
    let inside: Vec<String> = all.iter().filter(|f| f.rsplit_once('/').map_or("", |(p, _)| p) == here.as_str() && !f.is_empty()).cloned().collect();
    if !inside.is_empty() {
        subheading(ui, t, tr("Folders"));
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(12.0, 12.0);
            for f in &inside {
                let name = f.rsplit('/').next().unwrap_or(f);
                // A folder tile: a mark and its name, lit on hover.
                let (rect, _) = ui.allocate_exact_size(vec2(220.0, 48.0), Sense::hover());
                let resp = ui.interact(rect, ui.id().with(("server_folder", f)), Sense::click());
                a11y::button(&resp, name);
                let p = ui.painter();
                p.rect_filled(rect, CornerRadius::same(8), if resp.hovered() { t.hover } else { t.panel });
                p.rect_stroke(
                    rect,
                    CornerRadius::same(8),
                    egui::Stroke::new(1.0, if resp.hovered() { t.border_strong } else { t.border }),
                    egui::StrokeKind::Inside,
                );
                crate::icons::paint(p, Rect::from_center_size(pos2(rect.min.x + 22.0, rect.center().y), vec2(18.0, 18.0)), Icon::Group, t.icon);
                let shown = widgets::elide_font(ui, name, rect.width() - 56.0, semibold(12.0));
                ui.painter().text(pos2(rect.min.x + 42.0, rect.center().y), egui::Align2::LEFT_CENTER, shown, semibold(12.0), t.text);
                if resp.clicked() {
                    app.ui.account.of(server).folder = f.clone();
                }
                crate::right::context_popup(&resp).show(|ui| {
                    if crate::right::menu_item(ui, tr("Rename…"), "") {
                        app.ui.account.rename_folder = Some((f.clone(), name.to_string()));
                        ui.close();
                    }
                    if crate::right::menu_item(ui, tr("Remove folder"), "") {
                        folder_change(app, &ctx, server, "account.removeFolder", json!({"server": server, "path": f}));
                        ui.close();
                    }
                });
            }
        });
        if let Some((from, mut name)) = app.ui.account.rename_folder.take() {
            let mut keep = true;
            ui.horizontal(|ui| {
                let resp = widgets::text_input(ui, egui::Id::new(("rename_folder", server)), &mut name, 220.0, tr("Folder name"));
                a11y::text(&resp, tr("Folder name"), &name);
                let filled = !name.trim().is_empty() && !name.contains('/');
                if widgets::button(ui, tr("Rename"), true, filled).clicked() && filled {
                    let to = match from.rsplit_once('/') {
                        Some((parent, _)) => format!("{parent}/{}", name.trim()),
                        None => name.trim().to_string(),
                    };
                    folder_change(app, &ctx, server, "account.renameFolder", json!({"server": server, "from": from, "to": to}));
                    keep = false;
                }
                if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                    keep = false;
                }
            });
            if keep {
                app.ui.account.rename_folder = Some((from, name));
            }
        }
    }
    let shown: Vec<Value> = list.iter().filter(|f| folder_of(f) == here).cloned().collect();
    subheading(ui, t, if here.is_empty() { tr("All files") } else { tr("In this folder") });
    if shown.is_empty() {
        widgets::label(ui, tr("No files in this folder."), t.text_secondary);
    }
    if let Some(id) = cards(app, ui, t, server, &shown, "all", &all) {
        open = Some(id);
    }
    if let Some(file) = open {
        open_file(app, server, &file);
    }
}

/// A new file (`cmd`: `account.newFile`, or `file.new`, which makes it on the server for new
/// files when one is set), asked in the background (registering this device may ask the server
/// first): its tab comes to the front once it is there.
pub(crate) fn new_file(app: &mut FigApp, ctx: &Context, cmd: &str, params: Value) {
    app.run_background(
        ctx,
        cmd,
        params,
        Box::new(|app, _, v| {
            if let Some(i) = v["index"].as_u64() {
                app.run("doc.switch", json!({"index": i}));
            }
            app.ui.home = false;
        }),
    );
}

/// Make, rename or remove a folder, or move a file: then the files again.
fn folder_change(app: &mut FigApp, ctx: &Context, server: &str, cmd: &str, params: Value) {
    let at = server.to_string();
    app.run_background(ctx, cmd, params, Box::new(move |app, ctx, _| load_files(app, ctx, &at)));
}

/// The picture of `file` on `server`, once it has been asked for (one at a time, in the
/// background); `None` while there is none to show.
fn picture(app: &mut FigApp, ctx: &Context, server: &str, file: &Value) -> Option<egui::TextureHandle> {
    let id = file["file"].as_str().unwrap_or_default().to_string();
    let set = file["thumbnail"].as_u64()?;
    let st = app.ui.account.of(server);
    if let Some((at, texture)) = st.pictures.get(&id) {
        // Kept until the server has a newer one.
        if *at >= set {
            return texture.clone();
        }
    }
    if app.session.waiting_for(THUMBNAIL) {
        return st.pictures.get(&id).and_then(|(_, t)| t.clone());
    }
    let (at, key) = (server.to_string(), id.clone());
    app.run_background(
        ctx,
        THUMBNAIL,
        json!({"server": server, "file": id}),
        Box::new(move |app, ctx, v| {
            let texture = v["data"].as_str().and_then(|b| {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD.decode(b).ok()?;
                let image = image::load_from_memory(&bytes).ok()?.thumbnail(720, 405).to_rgba8();
                let size = [image.width() as usize, image.height() as usize];
                let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
                Some(ctx.load_texture(format!("server-thumb-{at}-{key}"), color, egui::TextureOptions::LINEAR))
            });
            app.ui.account.of(&at).pictures.insert(key, (set, texture));
        }),
    );
    // Asked: not again for this version, whatever comes back.
    app.ui.account.of(server).pictures.entry(file["file"].as_str().unwrap_or_default().to_string()).or_insert((set, None));
    None
}

/// `files` as cards in as many columns as fit (the home screen's cards), with their menus (open,
/// people, move to one of `folders`); the file chosen, if any.
fn cards(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str, files: &[Value], salt: &str, folders: &[String]) -> Option<String> {
    let ctx = ui.ctx().clone();
    // Clear of the scroll bar.
    let (columns, card_w) = crate::home_recents::grid_columns(ui.available_width() - 16.0);
    let (picture_h, card_h) = crate::home_recents::card_heights(card_w);
    let now = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut chosen = None;
    for row in files.chunks(columns.max(1)) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = crate::home_recents::GAP;
            for f in row {
                let (id, name) = (f["file"].as_str().unwrap_or_default(), f["name"].as_str().unwrap_or_default());
                let (rect, _) = ui.allocate_exact_size(vec2(card_w, card_h), Sense::hover());
                let resp = ui.interact(rect, ui.id().with(("server_card", salt, id)), Sense::click());
                a11y::button(&resp, name);
                let mut detail = format!(
                    "{} · {}",
                    role_label(f["role"].as_str().unwrap_or_default()),
                    crate::home_recents::edited(now, f["updated"].as_u64().unwrap_or(0))
                );
                let sealed = f["sealed"] == true;
                if sealed {
                    detail = format!("{} · {detail}", tr("Encrypted"));
                }
                let lead = |ui: &Ui, at: egui::Pos2| {
                    let icon = if sealed { Icon::Lock } else { Icon::Online };
                    crate::icons::paint(ui.painter(), Rect::from_center_size(at, vec2(16.0, 16.0)), icon, ACCENT);
                };
                let shown = if ui.is_rect_visible(rect) { picture(app, &ctx, server, f) } else { None };
                let picture = match shown {
                    Some(texture) => crate::home_recents::CardPicture::Image { page: None, texture: Some(texture), alpha: 1.0 },
                    None => crate::home_recents::CardPicture::Glyph(Icon::Page),
                };
                crate::home_recents::file_card(ui, t, rect, picture_h, &resp, false, picture, &lead, name, &detail);
                if resp.clicked() {
                    chosen = Some(id.to_string());
                }
                crate::right::context_popup(&resp).show(|ui| {
                    if crate::right::menu_item(ui, tr("Open"), "") {
                        chosen = Some(id.to_string());
                        ui.close();
                    }
                    let current = f["folder"].as_str().unwrap_or_default().trim_matches('/').to_string();
                    let mut moved = None;
                    if !current.is_empty() && crate::right::menu_item(ui, tr("Move to All files"), "") {
                        moved = Some(String::new());
                    }
                    for folder in folders.iter().filter(|x| **x != current) {
                        if crate::right::menu_item(ui, &trf("Move to {folder}", &[("folder", folder)]), "") {
                            moved = Some(folder.clone());
                        }
                    }
                    if let Some(folder) = moved {
                        folder_change(app, &ctx, server, "account.moveFile", json!({"server": server, "file": id, "folder": folder}));
                        ui.close();
                    }
                });
            }
        });
        ui.add_space(crate::home_recents::GAP / 2.0);
    }
    chosen
}

/// Changing your password, on a server where you sign in with one.
fn change_password(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    let (old, new) = &mut app.ui.account.change;
    let a = ui.add(
        egui::TextEdit::singleline(old).password(true).hint_text(tr("Current password")).desired_width(240.0).id(egui::Id::new(("pw_old", server))),
    );
    a11y::text(&a, tr("Current password"), "");
    let b = ui
        .add(egui::TextEdit::singleline(new).password(true).hint_text(tr("New password")).desired_width(240.0).id(egui::Id::new(("pw_new", server))));
    a11y::text(&b, tr("New password"), "");
    let ready = !old.is_empty() && new.chars().count() >= 10;
    widgets::label(ui, tr("At least 10 characters, not your username."), t.text_secondary);
    if widgets::button(ui, tr("Change password"), true, ready && !app.session.waiting_for("account.changePassword")).clicked() {
        let (old, new) = std::mem::take(&mut app.ui.account.change);
        app.run_background(
            &ctx,
            "account.changePassword",
            json!({"server": server, "old": old, "new": new}),
            Box::new(|app, _, _| app.toast(tr("Password changed"))),
        );
    }
}

/// People whose devices changed on `server` since this app last saw them (`account.status` ›
/// `keyChanges`): a gentle note each, with their safety number to compare.
fn key_changes(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let Ok(status) = app.session.execute("account.status", &json!({})) else { return };
    let key = figcraft_engine::accounts::server_key(server);
    let changes: Vec<Value> =
        status["keyChanges"].as_array().cloned().unwrap_or_default().into_iter().filter(|c| c["server"] == key.as_str()).collect();
    if changes.is_empty() {
        return;
    }
    let ctx = ui.ctx().clone();
    // Their names, from the people you have seen in your files.
    let names: BTreeMap<String, String> = app
        .ui
        .account
        .servers
        .get(server)
        .and_then(|st| st.team.as_ref())
        .and_then(|v| v["people"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| Some((m["account"].as_str()?.to_string(), person_name(m["name"].as_str()?, m["email"].as_str()))))
        .collect();
    for c in changes {
        let account = c["account"].as_str().unwrap_or_default().to_string();
        let name = names.get(&account).cloned().unwrap_or_else(|| tr("Someone").to_string());
        egui::Frame::NONE.fill(t.field).corner_radius(CornerRadius::same(6)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
            ui.set_max_width(720.0);
            widgets::label(
                ui,
                &trf("{name}'s devices changed. If you didn't expect it, compare their safety number with them.", &[("name", &name)]),
                t.text,
            );
            let shown = app.ui.account.safety.as_ref().filter(|(a, _)| *a == account).map(|(_, n)| n.clone());
            match shown {
                Some(number) => {
                    ui.label(RichText::new(&number).font(egui::FontId::monospace(16.0)).color(t.text));
                }
                None => {
                    if widgets::button(ui, tr("Show safety number"), false, true).clicked() {
                        let who = account.clone();
                        app.run_background(
                            &ctx,
                            "account.safetyNumber",
                            json!({"server": server, "account": account}),
                            Box::new(move |app, _, v| {
                                app.ui.account.safety = Some((who, v["safetyNumber"].as_str().unwrap_or_default().to_string()));
                            }),
                        );
                    }
                }
            }
        });
    }
}

/// How a person shows: their name, never an email (a name that is an email, or none, shows the
/// part of the email before the @, in words).
pub(crate) fn person_name(name: &str, email: Option<&str>) -> String {
    let name = name.trim();
    if !name.is_empty() && !name.contains('@') {
        return name.to_string();
    }
    let from = if name.contains('@') { name } else { email.unwrap_or_default() };
    let local = from.split('@').next().unwrap_or_default();
    let words: Vec<String> = local
        .split(['.', '_', '-', '+'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
        })
        .collect();
    if words.is_empty() { tr("Someone").to_string() } else { words.join(" ") }
}

/// A person's colour: the same every time for the same account.
pub(crate) fn person_color(account: &str) -> egui::Color32 {
    let h = account.bytes().fold(0usize, |h, b| h.wrapping_mul(31).wrapping_add(usize::from(b)));
    crate::live::people(h)
}

/// A person's picture in a circle of radius `r` at `center` (`account.avatar`, asked once when the
/// server keeps one), else their initials in their colour.
pub(crate) fn person_avatar(app: &mut FigApp, ui: &Ui, server: &str, account: &str, name: &str, center: egui::Pos2, r: f32) {
    let key = (server.to_string(), account.to_string());
    if !app.ui.account.avatars.contains_key(&key) && !app.session.waiting_for(AVATAR) && has_picture(app, server, account) {
        app.ui.account.avatars.insert(key.clone(), None);
        let at = key.clone();
        app.run_background(
            ui.ctx(),
            AVATAR,
            json!({"server": server, "account": account}),
            Box::new(move |app, ctx, v| {
                let texture = v["data"].as_str().and_then(|b| {
                    use base64::Engine as _;
                    let bytes = base64::engine::general_purpose::STANDARD.decode(b).ok()?;
                    let image = image::load_from_memory(&bytes).ok()?.thumbnail(96, 96).to_rgba8();
                    let size = [image.width() as usize, image.height() as usize];
                    let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
                    Some(ctx.load_texture(format!("avatar-{}-{}", at.0, at.1), color, egui::TextureOptions::LINEAR))
                });
                app.ui.account.avatars.insert(at, texture);
            }),
        );
    }
    let rect = Rect::from_center_size(center, vec2(2.0 * r, 2.0 * r));
    match app.ui.account.avatars.get(&key).cloned().flatten() {
        Some(texture) => {
            egui::Image::from_texture(&texture).corner_radius(CornerRadius::same(r.min(127.0) as u8)).paint_at(ui, rect);
        }
        None => crate::live::avatar(ui.painter(), center, r, name, person_color(account)),
    }
}

/// Everyone on `server` (`account.people`), asked once a visit of its page: what the People tab
/// shows and where pictures are known to be.
pub(crate) fn team(app: &mut FigApp, ctx: &Context, server: &str) -> Option<Value> {
    let st = app.ui.account.of(server);
    if st.team.is_none() && !st.team_asked && !app.session.waiting_for(PEOPLE) {
        st.team_asked = true;
        let at = server.to_string();
        app.run_background(
            ctx,
            PEOPLE,
            json!({"server": server}),
            Box::new(move |app, _, v| {
                app.ui.account.of(&at).team = Some(v);
            }),
        );
    }
    app.ui.account.of(server).team.clone()
}

/// The server keeps a picture of `account` (`account.people` says so).
fn has_picture(app: &mut FigApp, server: &str, account: &str) -> bool {
    app.ui
        .account
        .of(server)
        .team
        .as_ref()
        .and_then(|v| v["people"].as_array()?.iter().find(|p| p["account"] == account).cloned())
        .is_some_and(|p| p["avatar"] == true)
}

/// Everyone on `server`, each with their picture or initials and their name (never an email as a
/// name; an admin sees emails as a small second line), admins marked.
fn people_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    key_changes(app, ui, t, server);
    let v = team(app, &ctx, server);
    let loading = app.session.waiting_for(PEOPLE);
    let me = app.session.signed_in(server).map(|m| m.account.clone()).unwrap_or_default();
    let mut list: Vec<Value> = v.as_ref().and_then(|v| v["people"].as_array().cloned()).unwrap_or_default();
    // You first, then by name.
    list.sort_by_key(|p| (p["account"] != me.as_str(), p["name"].as_str().unwrap_or_default().to_lowercase()));
    ui.horizontal(|ui| {
        let note = match v.as_ref().map(|v| v["fileAccess"] == "everyone") {
            Some(true) => tr("Everyone here is in every file on this server."),
            Some(false) => tr("Each file has its own people."),
            None => "",
        };
        widgets::label(ui, &format!("{} {note}", crate::i18n::trn("{n} people on this server.", list.len(), &[])), t.text_secondary);
        if loading {
            ui.add(egui::Spinner::new().size(12.0));
        } else if ui.link(tr("Refresh")).clicked() {
            let st = app.ui.account.of(server);
            st.team = None;
            st.team_asked = false;
        }
    });
    if v.is_none() && !loading {
        return;
    }
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(12.0, 12.0);
        for p in &list {
            let account = p["account"].as_str().unwrap_or_default().to_string();
            let name = person_name(p["name"].as_str().unwrap_or_default(), None);
            let (rect, resp) = ui.allocate_exact_size(vec2(240.0, 60.0), Sense::hover());
            let shown = if account == me { trf("{name} (you)", &[("name", &name)]) } else { name.clone() };
            let email = p["email"].as_str().unwrap_or_default().to_string();
            let detail = match (p["admin"] == true, email.is_empty()) {
                (true, true) => tr("Admin").to_string(),
                (true, false) => format!("{} · {email}", tr("Admin")),
                (false, _) => email,
            };
            a11y::status(&resp, &shown, &detail);
            let painter = ui.painter();
            painter.rect_filled(rect, CornerRadius::same(8), t.panel);
            painter.rect_stroke(rect, CornerRadius::same(8), egui::Stroke::new(1.0, t.border), egui::StrokeKind::Inside);
            person_avatar(app, ui, server, &account, &name, pos2(rect.min.x + 30.0, rect.center().y), 18.0);
            let w = rect.width() - 70.0;
            let dy = if detail.is_empty() { 0.0 } else { 8.0 };
            let line = widgets::elide_font(ui, &shown, w, semibold(12.0));
            ui.painter().text(pos2(rect.min.x + 58.0, rect.center().y - dy), egui::Align2::LEFT_CENTER, line, semibold(12.0), t.text);
            if !detail.is_empty() {
                let d = widgets::elide_font(ui, &detail, w, regular(10.5));
                ui.painter().text(pos2(rect.min.x + 58.0, rect.center().y + 9.0), egui::Align2::LEFT_CENTER, d, regular(10.5), t.text_secondary);
            }
        }
    });
}

/// Your devices on `server` (for end-to-end encrypted files): this one marked, the others and
/// your recovery key, each revocable.
fn connected_devices(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    let st = app.ui.account.of(server);
    let (list, asked) = (st.devices.clone(), st.devices_asked);
    if list.is_none() && !asked && !app.session.waiting_for(DEVICES) {
        app.ui.account.of(server).devices_asked = true;
        load_devices(app, &ctx, server);
    }
    let Some(v) = list else {
        if app.session.waiting_for(DEVICES) {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(12.0));
                widgets::label(ui, tr("Asking the server…"), t.text_secondary);
            });
        } else if asked {
            // It failed (the reason was shown): ask again on request.
            ui.horizontal(|ui| {
                widgets::label(ui, tr("Your devices couldn't be listed."), t.text_secondary);
                if widgets::button(ui, tr("Try again"), false, true).clicked() {
                    app.ui.account.of(server).devices_asked = false;
                }
            });
        }
        return;
    };
    if v["keyStore"] == "preferences" {
        widgets::label(
            ui,
            tr("This computer has no keychain FigCraft can use: this device's key is kept with your preferences, which is less safe."),
            t.warning,
        );
    }
    let busy = DEVICE_CHANGES.iter().any(|c| app.session.waiting_for(c));
    let mut revoke = None;
    if v["devices"].as_array().is_none_or(Vec::is_empty) {
        widgets::label(ui, tr("No devices yet: this one is added when it first opens an encrypted file."), t.text_secondary);
    }
    for d in v["devices"].as_array().cloned().unwrap_or_default() {
        let id = d["id"].as_str().unwrap_or_default().to_string();
        let recovery = d["recovery"] == true;
        let name = if recovery { tr("Recovery key").to_string() } else { d["name"].as_str().unwrap_or_default().to_string() };
        let seen = figcraft_engine::live::utc_date(d["seen"].as_u64().unwrap_or(0));
        let day = seen.get(..10).unwrap_or(&seen).to_string();
        let this = d["thisDevice"] == true;
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
            crate::icons::paint(ui.painter(), r.shrink(2.0), if recovery { Icon::Lock } else { Icon::Online }, if this { ACCENT } else { t.icon });
            ui.scope(|ui| {
                ui.set_width(280.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&name).font(regular(12.0)).color(t.text));
                    if this {
                        ui.label(RichText::new(tr("This device")).font(semibold(10.0)).color(ACCENT));
                    }
                });
            });
            ui.scope(|ui| {
                ui.set_width(150.0);
                widgets::label(ui, &trf("Last used {date}", &[("date", &day)]), t.text_secondary);
            });
            if widgets::button(ui, tr("Revoke"), false, !busy)
                .on_hover_text(tr("Takes this device off your account: its keys stop working"))
                .clicked()
            {
                revoke = Some(id.clone());
            }
        });
    }
    if let Some(device) = revoke {
        let at = server.to_string();
        app.run_background(
            &ctx,
            "account.revokeDevice",
            json!({"server": server, "device": device}),
            Box::new(move |app, ctx, _| {
                app.toast(tr("Device revoked"));
                load_devices(app, ctx, &at);
            }),
        );
    }
}

/// Making a recovery key (shown once, with Copy and a confirmation), and using one on a device
/// that has no access yet.
fn recover_account(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    let busy = DEVICE_CHANGES.iter().any(|c| app.session.waiting_for(c));
    // A recovery key just made: shown this once.
    if let Some(key) = app.ui.account.of(server).recovery_key.clone() {
        egui::Frame::NONE.fill(t.field).corner_radius(CornerRadius::same(6)).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 8.0;
            widgets::label(ui, tr("Your recovery key. Write it down or keep it in a password manager: it is shown only this once."), t.text);
            ui.horizontal(|ui| {
                ui.label(RichText::new(&key).font(egui::FontId::monospace(14.0)).color(t.text));
                if widgets::button(ui, tr("Copy"), false, true).clicked() {
                    app.services.clipboard_set_text(&key);
                    app.toast(tr("Recovery key copied"));
                }
            });
            let saved = app.ui.account.of(server).recovery_saved;
            if widgets::checkbox(ui, saved, tr("I saved my recovery key somewhere safe")) {
                app.ui.account.of(server).recovery_saved = !saved;
            }
            if widgets::button(ui, tr("Done"), true, saved).clicked() {
                let st = app.ui.account.of(server);
                st.recovery_key = None;
                st.recovery_saved = false;
            }
        });
        return;
    }
    ui.label(RichText::new(tr("Make a recovery key")).font(semibold(12.0)).color(t.text));
    widgets::label(ui, tr("Make one now, while this device opens your files, and keep it somewhere safe."), t.text_secondary);
    if widgets::button(ui, tr("Make a recovery key"), false, !busy).clicked() {
        let at = server.to_string();
        app.run_background(
            &ctx,
            "account.recoveryKey",
            json!({"server": server}),
            Box::new(move |app, ctx, v| {
                match v["recoveryKey"].as_str().filter(|_| v["created"] == true) {
                    Some(key) => app.ui.account.of(&at).recovery_key = Some(key.to_string()),
                    None => app.toast(tr("You have a recovery key already")),
                }
                load_devices(app, ctx, &at);
            }),
        );
    }
    ui.add_space(8.0);
    ui.label(RichText::new(tr("Use a recovery key")).font(semibold(12.0)).color(t.text));
    widgets::label(ui, tr("On a new device: enter your recovery key to open your encrypted files here."), t.text_secondary);
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.ui.account.recovery_typed)
                .password(true)
                .hint_text(tr("Recovery key"))
                .desired_width(240.0)
                .id(egui::Id::new(("recovery_key", server))),
        );
        a11y::text(&field, tr("Recovery key"), "");
        let filled = !app.ui.account.recovery_typed.trim().is_empty();
        if widgets::button(ui, tr("Use a recovery key"), false, filled && !busy).clicked() {
            let key = std::mem::take(&mut app.ui.account.recovery_typed);
            app.run_background(
                &ctx,
                "account.recover",
                json!({"server": server, "recoveryKey": key.trim()}),
                Box::new(|app, _, v| {
                    let n = v["files"].as_array().map_or(0, Vec::len);
                    app.toast(crate::i18n::trn("This device opens {n} encrypted files now", n, &[]));
                }),
            );
        }
    });
}

fn load_devices(app: &mut FigApp, ctx: &Context, server: &str) {
    let at = server.to_string();
    app.run_background(
        ctx,
        DEVICES,
        json!({"server": server}),
        Box::new(move |app, _, v| {
            app.ui.account.of(&at).devices = Some(v);
        }),
    );
}

/// Open your file `file` on `server` (its member link), or bring its tab to the front.
fn open_file(app: &mut FigApp, server: &str, file: &str) {
    let open = app.session.live.iter().find(|l| l.account_file().is_some_and(|(s, f)| s == server && f == file)).and_then(|l| l.doc_uid);
    if let Some(i) = open.and_then(|uid| app.session.docs.iter().position(|d| d.uid == uid)) {
        app.run("doc.switch", json!({"index": i}));
        app.ui.home = false;
        return;
    }
    let link = format!("figcraft://join?server={server}&file={file}");
    if let Some(j) = app.run("collab.join", json!({"link": link})) {
        app.ui.live.home_join = j["session"].as_u64();
        app.ui.live.home_join_link = Some(link);
    }
}

/// Put an open file on `server`: one row per open file that isn't on a server or shared yet. On
/// a server with accounts it is published as yours (only people you invite get in); else it is
/// shared there with a join code.
fn put_here(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str, accounts: bool) {
    let local: Vec<(usize, String)> = app
        .session
        .docs
        .iter()
        .enumerate()
        .filter(|(_, d)| app.session.live.iter().all(|l| l.doc_uid != Some(d.uid)))
        .map(|(i, d)| (i, d.doc.name.clone()))
        .collect();
    if local.is_empty() || (accounts && app.session.signed_in(server).is_none()) {
        return;
    }
    subheading(ui, t, tr("Put an open file here"));
    let mut put = None;
    for (i, name) in &local {
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_width(300.0);
                widgets::label(ui, name, t.text);
            });
            let hint = if accounts { tr("Only people you invite get in") } else { tr("Shared with a join code") };
            if widgets::button(ui, tr("Put here"), false, true).on_hover_text(hint).clicked() {
                put = Some(*i);
            }
        });
    }
    if let Some(i) = put {
        app.run("doc.switch", json!({"index": i}));
        let done = if accounts {
            app.run("collab.publish", json!({"server": server}))
        } else {
            app.run("collab.share", json!({"via": "online", "server": server}))
        };
        if done.is_some() {
            app.ui.home = false;
        }
    }
}

/// What `ui.inspect` says about servers and accounts (never a token).
pub fn inspect(app: &FigApp) -> Value {
    let pending = match &app.session.accounts.pending {
        Some(Pending::Browser { server, .. }) => json!({"server": server, "flow": "browser"}),
        Some(Pending::Device { server, user_code, .. }) => json!({"server": server, "flow": "device", "userCode": user_code}),
        None => Value::Null,
    };
    let servers: Vec<Value> = home_servers(app)
        .iter()
        .map(|s| {
            let st = app.ui.account.servers.get(&s.url);
            json!({
                "name": s.name,
                "url": s.url,
                "signedIn": app.session.signed_in(&s.url).is_some(),
                "accounts": st.and_then(|x| x.info.as_ref()).map(has_accounts),
                "files": st.and_then(|x| x.files.as_ref()).map(|f| f["files"].as_array().map_or(0, Vec::len)),
            })
        })
        .collect();
    json!({
        "servers": servers,
        "pending": pending,
        "signInWindow": app.ui.account.window.as_ref().map(|(s, _)| s.clone()),
    })
}
