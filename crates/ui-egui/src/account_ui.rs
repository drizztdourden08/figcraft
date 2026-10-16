//! Remote servers in the window, on top of the files on this computer: Preferences ▸ Servers (add,
//! remove and order them), the home screen's page for each server (signing in there, your files
//! on it with their people, putting an open file there, the files you shared there from this
//! computer, and an admin's tools), the Sign in window (a device code to type when you aren't on
//! the server's page, or a server that signed you out), and the People part of the Share popover
//! for a file on a server with accounts.
//!
//! Everything acts through the engine's commands (`servers.*`, `account.*`, `collab.members`,
//! `collab.invite`, `collab.setRole`, `collab.removeMember`, `collab.publish`, `collab.share`);
//! the ones that ask a server run in the background, so the window never waits. Session tokens
//! never reach the UI.

use std::collections::BTreeMap;

use egui::{Context, CornerRadius, Rect, RichText, Sense, Ui, pos2, vec2};
use figcraft_engine::accounts::Pending;
use figcraft_engine::servers::{SavedServer, host};
use serde_json::{Value, json};

use crate::FigApp;
use crate::a11y;
use crate::home::{FileRow, file_row};
use crate::i18n::{tr, trf};
use crate::icons::Icon;
use crate::theme::{ACCENT, Tokens, regular, semibold};
use crate::widgets;

const SIGN_IN: &str = "account.signIn";
const INFO: &str = "account.info";
const POLL: &str = "account.signInPoll";
const SIGN_OUT: &str = "account.signOut";
const CHECK: &str = "account.check";
const FILES: &str = "account.files";
const MEMBERS: &str = "collab.members";
const DEVICES: &str = "account.devices";
const FOLDERS: &str = "account.folders";
const DEVICE_CHANGES: [&str; 3] = ["account.revokeDevice", "account.recoveryKey", "account.recover"];
const PEOPLE_CHANGE: [&str; 3] = ["collab.invite", "collab.setRole", "collab.removeMember"];

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
    /// You were signed in there when its page last drew (a change loads the files again).
    was_signed_in: Option<bool>,
    /// The file whose people show on the page, and them (`collab.members {file}`; null until
    /// they arrive).
    pub people: Option<(String, Value)>,
    /// Your devices there (`account.devices`), asked once a run; a recovery key just made (shown
    /// this once).
    pub devices: Option<Value>,
    devices_asked: bool,
    pub recovery_key: Option<String>,
    /// The page's tab, and the folder the Files tab is in (`""`: the top).
    pub tab: ServerTab,
    pub folder: String,
    /// The folders there (`account.folders`; none while the server keeps no folders), asked once a
    /// run.
    pub folders: Option<Value>,
    folders_asked: bool,
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
    /// The Share popover's people of the file in front: (server, file) and `collab.members`.
    pub popover_people: Option<((String, String), Value)>,
    /// The frame the popover's People part last drew in (it asks again when it shows after a gap).
    people_drawn: Option<u64>,
    /// The member whose role is being changed (their account), and the invite being written.
    pub role_edit: Option<String>,
    pub invite_email: String,
    pub invite_role: usize,
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
    let signed = app.session.signed_in(server).is_some();
    let st = app.ui.account.of(server);
    let (checked, was) = (st.checked, st.was_signed_in);
    st.was_signed_in = Some(signed);
    if !signed {
        st.files = None;
        st.people = None;
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
    // The browser build has no loopback page to come back to: a code typed on another device.
    let web = cfg!(target_arch = "wasm32");
    let sso_flow = |p: &Value| if web { has(p, "device").then_some("device") } else { ["browser", "device"].into_iter().find(|f| has(p, f)) };
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
    if cfg!(target_arch = "wasm32") {
        widgets::label(ui, tr("In the browser you sign in with a code you enter on another device."), t.text_secondary);
    }
    if let Some(Err(why)) = &app.session.accounts.last {
        widgets::label(ui, why, t.danger);
    }
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

/// The tabs of a server's page (with accounts, signed in).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerTab {
    #[default]
    Files,
    People,
    Devices,
    Admin,
}

impl ServerTab {
    fn label(self) -> &'static str {
        match self {
            ServerTab::Files => tr("Files"),
            ServerTab::People => tr("People"),
            ServerTab::Devices => tr("Devices"),
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
/// Files (your files there as cards, in folders when the server keeps them, and putting an open
/// file there), People (who is in each of your files), Devices (for sealed files) and Admin (for
/// admins). Any server: the files you shared there from this computer.
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
    sign_in_block(app, ui, t, server);
    let sealing = app.ui.account.of(server).info.as_ref().is_some_and(|i| i["e2e"].as_str().is_some_and(|m| m != "off"));
    let admin = app.session.signed_in(server).is_some_and(|m| m.admin);
    let tabs: Vec<ServerTab> = [ServerTab::Files, ServerTab::People]
        .into_iter()
        .chain(sealing.then_some(ServerTab::Devices))
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
        ServerTab::Devices => devices(app, ui, t, server),
        ServerTab::Admin => {
            ui.scope(|ui| {
                ui.set_max_width(900.0);
                crate::admin_ui::tools(app, ui, t, server);
            });
        }
    }
}

/// Your files on `server` as cards, like the home screen's own: the recent ones first, then the
/// folder you are in (with its path to go back up) and its folders and files. Folders and pictures
/// show once the server keeps them (`account.folders`, `account.thumbnail`).
fn files_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    let st = app.ui.account.of(server);
    let (files, folders, folders_asked, here) = (st.files.clone(), st.folders.clone(), st.folders_asked, st.folder.clone());
    // Whether the server keeps folders: asked once (it says so when it doesn't).
    if !folders_asked && !app.session.waiting_for(FOLDERS) {
        app.ui.account.of(server).folders_asked = true;
        let at = server.to_string();
        app.run_background(
            &ctx,
            FOLDERS,
            json!({"server": server}),
            Box::new(move |app, _, v| {
                app.ui.account.of(&at).folders = Some(v);
            }),
        );
    }
    ui.horizontal(|ui| {
        if widgets::button(ui, tr("Refresh"), false, !app.session.waiting_for(FILES)).clicked() {
            load_files(app, &ctx, server);
        }
        if app.session.waiting_for(FILES) || app.session.waiting_for(CHECK) {
            widgets::label(ui, tr("Loading your files…"), t.text_secondary);
        }
    });
    let list = files.as_ref().and_then(|f| f["files"].as_array().cloned()).unwrap_or_default();
    if files.is_some() && list.is_empty() {
        widgets::label(ui, tr("No files here yet. Put an open file here, or open one someone invited you to."), t.text_secondary);
        return;
    }
    let folder_of = |f: &Value| f["folder"].as_str().unwrap_or_default().trim_matches('/').to_string();
    let mut open = None;
    // The folder you are in, and the way back up.
    let all: Vec<String> = folders
        .as_ref()
        .and_then(|v| v["folders"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|f| f.as_str().map(str::to_string))
        .collect();
    if folders.is_some() {
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
    }
    if here.is_empty() && !list.is_empty() {
        subheading(ui, t, tr("Recent"));
        let mut recent = list.clone();
        recent.sort_by_key(|f| std::cmp::Reverse(f["updated"].as_u64().unwrap_or(0)));
        let (columns, _) = crate::home_recents::grid_columns(ui.available_width() - 16.0);
        recent.truncate(columns.max(1));
        if let Some(id) = cards(app, ui, t, server, &recent, "recent") {
            open = Some(id);
        }
    }
    // Folders in this one.
    let inside: Vec<String> = all
        .iter()
        .filter(|f| {
            let parent = f.rsplit_once('/').map_or("", |(p, _)| p);
            parent == here.as_str() && !f.is_empty()
        })
        .cloned()
        .collect();
    if !inside.is_empty() {
        subheading(ui, t, tr("Folders"));
        ui.horizontal_wrapped(|ui| {
            for f in &inside {
                let name = f.rsplit('/').next().unwrap_or(f);
                let resp = widgets::button(ui, name, false, true);
                if resp.clicked() {
                    app.ui.account.of(server).folder = f.clone();
                }
            }
        });
    }
    let shown: Vec<Value> = list.iter().filter(|f| folder_of(f) == here).cloned().collect();
    subheading(ui, t, if here.is_empty() { tr("All files") } else { tr("In this folder") });
    if let Some(id) = cards(app, ui, t, server, &shown, "all") {
        open = Some(id);
    }
    if let Some(file) = open {
        open_file(app, server, &file);
    }
}

/// `files` as cards in as many columns as fit (the home screen's cards); the file chosen, if any.
fn cards(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str, files: &[Value], salt: &str) -> Option<String> {
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
                if f["sealed"] == true {
                    detail = format!("{} · {detail}", tr("Encrypted"));
                }
                let sealed = f["sealed"] == true;
                let lead = |ui: &Ui, at: egui::Pos2| {
                    let icon = if sealed { Icon::Lock } else { Icon::Online };
                    crate::icons::paint(ui.painter(), Rect::from_center_size(at, vec2(16.0, 16.0)), icon, ACCENT);
                };
                let picture = crate::home_recents::CardPicture::Glyph(Icon::Page);
                crate::home_recents::file_card(ui, t, rect, picture_h, &resp, false, picture, &lead, name, &detail);
                if resp.clicked() {
                    chosen = Some(id.to_string());
                }
                crate::right::context_popup(&resp).show(|ui| {
                    if crate::right::menu_item(ui, tr("Open"), "") {
                        chosen = Some(id.to_string());
                        ui.close();
                    }
                    if crate::right::menu_item(ui, tr("People…"), "") {
                        let st = app.ui.account.of(server);
                        st.tab = ServerTab::People;
                        st.people = Some((id.to_string(), Value::Null));
                        ui.close();
                    }
                });
            }
        });
        ui.add_space(crate::home_recents::GAP / 2.0);
    }
    chosen
}

/// Who is in each of your files on `server`: a row per file; its people open under it.
fn people_tab(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let files = app.ui.account.of(server).files.clone();
    let list = files.as_ref().and_then(|f| f["files"].as_array().cloned()).unwrap_or_default();
    if list.is_empty() {
        widgets::label(ui, tr("No files here yet. Put an open file here, or open one someone invited you to."), t.text_secondary);
        return;
    }
    ui.scope(|ui| {
        ui.set_max_width(720.0);
        for f in &list {
            let (id, name) = (f["file"].as_str().unwrap_or_default(), f["name"].as_str().unwrap_or_default());
            let open = app.ui.account.of(server).people.as_ref().is_some_and(|(f, _)| f == id);
            let detail = role_label(f["role"].as_str().unwrap_or_default());
            let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 36.0), Sense::hover());
            let resp = ui.interact(r, ui.id().with(("people_file", id)), Sense::click());
            a11y::button(&resp, name);
            let row = FileRow { mark: Some((Icon::LiveShared, ACCENT)), name, ink: t.text, detail, detail_size: 11.0, detail_ink: t.text_secondary };
            file_row(ui, t, r, &resp, &row);
            if resp.clicked() {
                app.ui.account.of(server).people = if open { None } else { Some((id.to_string(), Value::Null)) };
                app.ui.account.role_edit = None;
            }
            if open {
                ui.indent(("people_of", id), |ui| people_block(app, ui, t, (server, id), false));
            }
        }
    });
}

/// Your devices on `server` (for end-to-end encrypted files): this one, the others and your
/// recovery key, each revocable; making a recovery key (shown once), and using one on a device
/// that has no access yet.
fn devices(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    let ctx = ui.ctx().clone();
    // Only a server that keeps sealed files has devices.
    let sealing = app.ui.account.of(server).info.as_ref().is_some_and(|i| i["e2e"].as_str().is_some_and(|m| m != "off"));
    if !sealing {
        return;
    }
    let st = app.ui.account.of(server);
    let (list, asked) = (st.devices.clone(), st.devices_asked);
    if list.is_none() && !asked && !app.session.waiting_for(DEVICES) {
        app.ui.account.of(server).devices_asked = true;
        load_devices(app, &ctx, server);
    }
    let Some(v) = list else {
        if app.session.waiting_for(DEVICES) {
            widgets::label(ui, tr("Asking the server…"), t.text_secondary);
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
    for d in v["devices"].as_array().cloned().unwrap_or_default() {
        let id = d["id"].as_str().unwrap_or_default().to_string();
        let name = if d["recovery"] == true { tr("Recovery key").to_string() } else { d["name"].as_str().unwrap_or_default().to_string() };
        let seen = figcraft_engine::live::utc_date(d["seen"].as_u64().unwrap_or(0));
        let day = seen.get(..10).unwrap_or(&seen).to_string();
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_width(300.0);
                let label = if d["thisDevice"] == true { trf("{name} (this device)", &[("name", &name)]) } else { name.clone() };
                widgets::label(ui, &label, t.text);
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
    // A recovery key just made: shown this once.
    if let Some(key) = app.ui.account.of(server).recovery_key.clone() {
        egui::Frame::NONE.fill(t.field).corner_radius(CornerRadius::same(6)).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            widgets::label(ui, tr("Your recovery key. Write it down or keep it in a password manager: it is shown only this once."), t.text);
            ui.label(RichText::new(&key).font(egui::FontId::monospace(14.0)).color(t.text));
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Copy"), false, true).clicked() {
                    app.services.clipboard_set_text(&key);
                    app.toast(tr("Recovery key copied"));
                }
                if widgets::button(ui, tr("I saved it"), true, true).clicked() {
                    app.ui.account.of(server).recovery_key = None;
                }
            });
        });
        return;
    }
    let hint = tr("Lets a new device into your encrypted files when no other device is at hand");
    if widgets::button(ui, tr("Make a recovery key"), false, !busy).on_hover_text(hint).clicked() {
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
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut app.ui.account.recovery_typed)
                .password(true)
                .hint_text(tr("Recovery key"))
                .desired_width(220.0)
                .id(egui::Id::new(("recovery_key", server))),
        );
        a11y::text(&field, tr("Recovery key"), "");
        let filled = !app.ui.account.recovery_typed.trim().is_empty();
        let hint = tr("On a device without access to your encrypted files");
        if widgets::button(ui, tr("Use a recovery key"), false, filled && !busy).on_hover_text(hint).clicked() {
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

/// The people of `file` (server, id): members and their roles, invites; owners change roles,
/// remove people and invite by email. `front`: the file in front (the Share popover); else one
/// named on a server's page.
pub fn people_block(app: &mut FigApp, ui: &mut Ui, t: &Tokens, (server, file): (&str, &str), front: bool) {
    let ctx = ui.ctx().clone();
    let key = (server.to_string(), file.to_string());
    let params = if front { json!({}) } else { json!({"server": server, "file": file}) };
    let shown = if front {
        app.ui.account.popover_people.as_ref().filter(|(k, _)| *k == key).map(|(_, v)| v.clone())
    } else {
        app.ui.account.of(server).people.as_ref().filter(|(f, v)| f == file && !v.is_null()).map(|(_, v)| v.clone())
    };
    if shown.is_none() && !app.session.waiting_for(MEMBERS) {
        load_people(app, &ctx, key.clone(), params.clone(), front);
    }
    let Some(v) = shown else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    let me = app.session.signed_in(server).map(|m| m.account.clone()).unwrap_or_default();
    let members = v["members"].as_array().cloned().unwrap_or_default();
    let owner = members.iter().any(|m| m["account"] == me.as_str() && m["role"] == "owner");
    let busy = PEOPLE_CHANGE.iter().any(|c| app.session.waiting_for(c));
    let mut change: Option<(&str, Value)> = None;
    let with = |mut v: Value| {
        if let (Some(o), Some(p)) = (v.as_object_mut(), params.as_object()) {
            o.extend(p.clone());
        }
        v
    };
    for m in &members {
        let account = m["account"].as_str().unwrap_or_default().to_string();
        let role = m["role"].as_str().unwrap_or("editor");
        let name = m["name"].as_str().unwrap_or_default();
        let shown = if account == me { trf("{name} (you)", &[("name", &name)]) } else { name.to_string() };
        let editing = app.ui.account.role_edit.as_deref() == Some(account.as_str());
        ui.horizontal(|ui| {
            let w = (ui.available_width() - 74.0).min(320.0);
            let line = widgets::elide(ui, &shown, w);
            let r = ui.allocate_exact_size(vec2(w, 22.0), Sense::hover()).0;
            ui.painter().text(pos2(r.min.x, r.center().y), egui::Align2::LEFT_CENTER, line, regular(11.0), t.text);
            if let Some(email) = m["email"].as_str() {
                ui.interact(r, ui.id().with(("member", &account)), Sense::hover()).on_hover_text(email);
            }
            if owner && account != me {
                if widgets::button(ui, role_label(role), false, !busy).on_hover_text(tr("Change role or remove")).clicked() {
                    app.ui.account.role_edit = if editing { None } else { Some(account.clone()) };
                }
            } else {
                widgets::label(ui, role_label(role), t.text_secondary);
            }
        });
        if editing {
            ui.horizontal(|ui| {
                let labels: Vec<&str> = ROLES.iter().map(|r| role_label(r)).collect();
                let at = ROLES.iter().position(|r| *r == role).unwrap_or(0);
                if let Some(i) = widgets::segmented_text(ui, &labels, at)
                    && i != at
                {
                    change = Some(("collab.setRole", with(json!({"account": account, "role": ROLES.get(i).copied().unwrap_or("editor")}))));
                }
                if widgets::button(ui, tr("Remove"), false, true).on_hover_text(tr("Takes them out of the file at once")).clicked() {
                    change = Some(("collab.removeMember", with(json!({"account": account}))));
                }
            });
        }
    }
    for i in v["invited"].as_array().cloned().unwrap_or_default() {
        let email = i["email"].as_str().unwrap_or_default().to_string();
        ui.horizontal(|ui| {
            let line = trf("{email} · invited", &[("email", &email)]);
            widgets::label(ui, &widgets::elide(ui, &line, (ui.available_width() - 80.0).min(320.0)), t.text_secondary);
            if owner && widgets::button(ui, tr("Take back"), false, !busy).clicked() {
                change = Some(("collab.removeMember", with(json!({"email": email}))));
            }
        });
    }
    if owner {
        ui.horizontal(|ui| {
            let resp = widgets::text_input(ui, egui::Id::new(("people_invite", file)), &mut app.ui.account.invite_email, 196.0, tr("Email"));
            a11y::text(&resp, tr("Invite by email"), &app.ui.account.invite_email);
            let filled = app.ui.account.invite_email.contains('@');
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (widgets::button(ui, tr("Invite"), true, filled && !busy).clicked() || enter) && filled {
                let role = ROLES.get(app.ui.account.invite_role).copied().unwrap_or("editor");
                change = Some(("collab.invite", with(json!({"email": app.ui.account.invite_email.trim(), "role": role}))));
            }
        });
        ui.scope(|ui| {
            ui.set_max_width(300.0);
            let labels: Vec<&str> = ROLES.iter().map(|r| role_label(r)).collect();
            if let Some(i) = widgets::segmented_text(ui, &labels, app.ui.account.invite_role) {
                app.ui.account.invite_role = i;
            }
        });
    }
    if let Some((cmd, p)) = change {
        let invite = cmd == "collab.invite";
        app.ui.account.role_edit = None;
        app.run_background(
            &ctx,
            cmd,
            p,
            Box::new(move |app, ctx, _| {
                if invite {
                    app.ui.account.invite_email.clear();
                    app.toast(tr("Invited"));
                }
                load_people(app, ctx, key, params, front);
            }),
        );
    }
}

fn load_people(app: &mut FigApp, ctx: &Context, key: (String, String), params: Value, front: bool) {
    app.run_background(
        ctx,
        MEMBERS,
        params,
        Box::new(move |app, _, v| {
            if front {
                app.ui.account.popover_people = Some((key, v));
            } else if let Some(st) = app.ui.account.servers.get_mut(&key.0)
                && st.people.as_ref().is_some_and(|(f, _)| *f == key.1)
            {
                st.people = Some((key.1, v));
            }
        }),
    );
}

/// The Share popover's People: for the file in front on a server where you are signed in, who is
/// in it (asked again when the popover shows after a gap). Nothing for other files.
pub fn people_section(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    let Some((server, file)) = app.session.people_file() else { return };
    let frame = ui.ctx().cumulative_frame_nr();
    if app.ui.account.people_drawn.replace(frame).is_none_or(|d| d.saturating_add(1) < frame) {
        app.ui.account.popover_people = None;
    }
    ui.separator();
    ui.label(RichText::new(tr("People")).font(semibold(12.0)).color(t.text));
    people_block(app, ui, t, (&server, &file), true);
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
        "people": app.ui.account.popover_people.as_ref().map(|(_, v)| v["members"].as_array().map_or(0, Vec::len)),
    })
}
