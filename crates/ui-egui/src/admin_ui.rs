//! A server's admin tools, on its page of the home screen (for admins signed in there): the people who
//! signed in there (end their sessions, take them off the server), the files and who is in them
//! (change roles, add someone by email: how a file whose owner left gets one) and the server's
//! status. Everything runs through the engine's `admin.*` commands in the background.
//!
//! Taking someone off the server who is the last owner of files asks first: make someone else
//! owner of those files, or remove them anyway; files left without an owner are listed so each
//! can be given one.

use egui::{Context, RichText, Ui};
use serde_json::{Value, json};

use crate::FigApp;
use crate::a11y;
use crate::account_ui::{ROLES, role_label};
use crate::dialogs::tab_strip;
use crate::i18n::{tr, trf, trn};
use crate::theme::{Tokens, semibold};
use crate::widgets;

const PEOPLE: &str = "admin.people";
const FILES: &str = "admin.files";
const MEMBERS: &str = "admin.fileMembers";
const STATUS: &str = "admin.status";
const CHANGES: [&str; 7] = [
    "admin.endSessions",
    "admin.removePerson",
    "admin.setFileRole",
    "admin.addFileMember",
    "admin.createUser",
    "admin.resetPassword",
    "admin.removeUser",
];
const USERS: &str = "admin.users";

/// The window's tabs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminTab {
    #[default]
    People,
    Users,
    Files,
    Status,
}

impl AdminTab {
    fn label(self) -> &'static str {
        match self {
            AdminTab::People => tr("People"),
            AdminTab::Users => tr("Usernames"),
            AdminTab::Files => tr("Ownership"),
            AdminTab::Status => tr("Status"),
        }
    }
}

/// A person the server wouldn't remove (account, name): the last owner of these files (id, name).
pub type LastOwner = (String, String, Vec<(String, String)>);

/// The Server admin window's state (open when `Some` in [`crate::UiState`]).
#[derive(Default)]
pub struct AdminWindow {
    pub server: String,
    pub tab: AdminTab,
    pub people: Option<Value>,
    pub files: Option<Value>,
    pub status: Option<Value>,
    /// The file whose members show, and them.
    pub file: Option<String>,
    pub members: Option<Value>,
    /// Remove… was chosen for this person (account, name): its confirmation shows.
    pub confirm: Option<(String, String)>,
    /// The server refused to remove this person (account, name): they are the last owner of these
    /// files (id, name).
    pub last_owner: Option<LastOwner>,
    /// Files left without an owner (id, name).
    pub orphaned: Vec<(String, String)>,
    /// A member whose role is being changed (their account).
    pub role_edit: Option<String>,
    /// Add someone to the file: their email and role.
    pub add_email: String,
    pub add_role: usize,
    /// Usernames (`admin.users`), a user being added (username, email, name), and a password the
    /// server just made (username, password: shown this once).
    pub users: Option<Value>,
    pub new_user: (String, String, String),
    pub made: Option<(String, String)>,
}

impl AdminWindow {
    pub fn new(server: String) -> Self {
        Self { server, ..Self::default() }
    }
}

fn files_of(v: &Value) -> Vec<(String, String)> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|f| (f["file"].as_str().unwrap_or_default().to_string(), f["name"].as_str().unwrap_or_default().to_string()))
        .collect()
}

/// Run admin command `cmd` with `params` on the window's server; then `done`.
fn ask(app: &mut FigApp, ctx: &Context, cmd: &str, mut params: Value, done: crate::Done) {
    if let Some(w) = app.ui.admin.as_ref() {
        params["server"] = json!(w.server);
    }
    app.run_background(ctx, cmd, params, done);
}

fn with(app: &mut FigApp, f: impl FnOnce(&mut AdminWindow)) {
    if let Some(w) = app.ui.admin.as_mut() {
        f(w);
    }
}

fn load(app: &mut FigApp, ctx: &Context, cmd: &'static str) {
    let params = match (cmd, app.ui.admin.as_ref().and_then(|w| w.file.clone())) {
        (MEMBERS, Some(file)) => json!({"file": file}),
        (MEMBERS, None) => return,
        _ => json!({}),
    };
    ask(
        app,
        ctx,
        cmd,
        params,
        Box::new(move |app, _, v| {
            with(app, |w| match cmd {
                PEOPLE => w.people = Some(v),
                FILES => w.files = Some(v),
                STATUS => w.status = Some(v),
                _ => w.members = Some(v),
            })
        }),
    );
}

/// A server's admin tools, on its page of the home screen (for admins signed in there): tabs for
/// its people, its files and its status.
pub fn tools(app: &mut FigApp, ui: &mut Ui, t: &Tokens, server: &str) {
    if app.ui.admin.as_ref().is_none_or(|w| w.server != server) {
        app.ui.admin = Some(AdminWindow::new(server.to_string()));
    }
    // Usernames only where people sign in with a username and password.
    let basic =
        app.ui.account.servers.get(server).and_then(|st| st.info.as_ref()).is_some_and(|i| i["access"].as_str().is_some_and(|a| a.contains("basic")));
    let tabs: Vec<AdminTab> =
        [AdminTab::People].into_iter().chain(basic.then_some(AdminTab::Users)).chain([AdminTab::Files, AdminTab::Status]).collect();
    let mut tab = app.ui.admin.as_ref().map(|w| w.tab).unwrap_or_default();
    if !tabs.contains(&tab) {
        tab = AdminTab::People;
    }
    tab_strip(ui, t, &tabs, AdminTab::label, &mut tab);
    with(app, |w| w.tab = tab);
    ui.add_space(4.0);
    match tab {
        AdminTab::People => people(app, ui, t),
        AdminTab::Users => users(app, ui, t),
        AdminTab::Files => files(app, ui, t),
        AdminTab::Status => status(app, ui, t),
    }
}

/// People who sign in with a username and password: add one (the server makes the password, shown
/// once with Copy), give one a new temporary password, take one's password away.
fn users(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    let ctx = ui.ctx().clone();
    let Some(w) = app.ui.admin.as_ref() else { return };
    let (users, made) = (w.users.clone(), w.made.clone());
    if users.is_none() && !app.session.waiting_for(USERS) {
        ask(app, &ctx, USERS, json!({}), Box::new(|app, _, v| with(app, |w| w.users = Some(v))));
    }
    if let Some((username, password)) = made {
        egui::Frame::NONE.fill(t.field).corner_radius(egui::CornerRadius::same(6)).inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            widgets::label(
                ui,
                &trf(
                    "The password for {username}, shown only this once: give it to them. They choose their own when they first sign in.",
                    &[("username", &username)],
                ),
                t.text,
            );
            ui.label(RichText::new(&password).font(egui::FontId::monospace(14.0)).color(t.text));
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Copy"), false, true).clicked() {
                    app.services.clipboard_set_text(&password);
                    app.toast(tr("Password copied"));
                }
                if widgets::button(ui, tr("Done"), true, true).clicked() {
                    with(app, |w| w.made = None);
                }
            });
        });
    }
    let busy = busy(app);
    let shown = |app: &mut FigApp, v: Value| {
        let username = v["username"].as_str().unwrap_or_default().to_string();
        let password = v["password"].as_str().map(str::to_string);
        with(app, |w| {
            w.users = None;
            w.made = password.map(|p| (username, p));
        });
    };
    for u in users.as_ref().and_then(|v| v["users"].as_array().cloned()).unwrap_or_default() {
        let username = u["username"].as_str().unwrap_or_default().to_string();
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_width(300.0);
                let mut line = username.clone();
                if let Some(e) = u["email"].as_str() {
                    line = format!("{line} · {e}");
                }
                widgets::label(ui, &line, t.text);
                if u["temporary"] == true {
                    widgets::label(ui, tr("temporary password"), t.text_secondary);
                }
            });
            if widgets::button(ui, tr("Reset password"), false, !busy)
                .on_hover_text(tr("A new temporary password, shown once; their sessions end"))
                .clicked()
            {
                ask(app, &ctx, "admin.resetPassword", json!({"username": username}), Box::new(move |app, _, v| shown(app, v)));
            }
            if widgets::button(ui, tr("Remove"), false, !busy)
                .on_hover_text(tr("They can't sign in with it any more; their account and files stay"))
                .clicked()
            {
                ask(app, &ctx, "admin.removeUser", json!({"username": username}), Box::new(|app, _, _| with(app, |w| w.users = None)));
            }
        });
    }
    ui.add_space(6.0);
    let Some(w) = app.ui.admin.as_mut() else { return };
    let mut add = None;
    ui.horizontal(|ui| {
        let (user, email, name) = &mut w.new_user;
        let r = widgets::text_input(ui, egui::Id::new("admin_new_username"), user, 140.0, tr("Username"));
        a11y::text(&r, tr("Username"), user);
        let r = widgets::text_input(ui, egui::Id::new("admin_new_email"), email, 180.0, tr("Email (optional)"));
        a11y::text(&r, tr("Email"), email);
        let r = widgets::text_input(ui, egui::Id::new("admin_new_name"), name, 140.0, tr("Name (optional)"));
        a11y::text(&r, tr("Name"), name);
        if widgets::button(ui, tr("Add user"), true, !user.trim().is_empty() && !busy).clicked() {
            add = Some(json!({"username": user.trim(), "email": email.trim(), "name": name.trim()}));
        }
    });
    if let Some(params) = add {
        w.new_user = Default::default();
        ask(app, &ctx, "admin.createUser", params, Box::new(move |app, _, v| shown(app, v)));
    }
}

fn busy(app: &FigApp) -> bool {
    CHANGES.iter().any(|c| app.session.waiting_for(c))
}

fn people(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    let ctx = ui.ctx().clone();
    let Some(w) = app.ui.admin.as_ref() else { return };
    let (people, confirm, last_owner, orphaned) = (w.people.clone(), w.confirm.clone(), w.last_owner.clone(), w.orphaned.clone());
    if people.is_none() && !app.session.waiting_for(PEOPLE) {
        load(app, &ctx, PEOPLE);
    }
    orphans(app, ui, t, &orphaned);
    let Some(people) = people else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    let list = people["people"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        widgets::label(ui, tr("Nobody has signed in here yet."), t.text_secondary);
    }
    let me = app.session.signed_in(&app.ui.admin.as_ref().map(|w| w.server.clone()).unwrap_or_default()).map(|m| m.account.clone());
    let busy = busy(app);
    for p in &list {
        let account = p["account"].as_str().unwrap_or_default().to_string();
        let name = p["name"].as_str().unwrap_or_default().to_string();
        let email = p["email"].as_str().unwrap_or_default();
        let sessions = p["sessions"].as_u64().unwrap_or(0) as usize;
        let owned = p["owned"].as_u64().unwrap_or(0) as usize;
        let you = me.as_deref() == Some(account.as_str());
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(300.0);
                let title = if you { trf("{name} (you)", &[("name", &name)]) } else { name.clone() };
                let admin = if p["admin"] == true { format!(" · {}", tr("Admin")) } else { String::new() };
                ui.label(RichText::new(format!("{title}{admin}")).font(semibold(11.0)).color(t.text));
                let detail = format!("{email} · {} · {}", trn("{n} sessions", sessions, &[]), trn("owns {n} files", owned, &[]));
                widgets::label(ui, detail.trim_start_matches(" · "), t.text_secondary);
            });
            if widgets::button(ui, tr("End sessions"), false, !busy && sessions > 0)
                .on_hover_text(tr("Signs them out everywhere; their account and files stay"))
                .clicked()
            {
                let said = trf("{name} was signed out everywhere", &[("name", &name)]);
                ask(
                    app,
                    &ctx,
                    "admin.endSessions",
                    json!({"account": account}),
                    Box::new(move |app, ctx, _| {
                        app.toast(said);
                        with(app, |w| w.people = None);
                        load(app, ctx, PEOPLE);
                    }),
                );
            }
            if !you && widgets::button(ui, tr("Remove…"), false, !busy).clicked() {
                with(app, |w| {
                    w.confirm = Some((account.clone(), name.clone()));
                    w.last_owner = None;
                });
            }
        });
        if confirm.as_ref().is_some_and(|(a, _)| *a == account) {
            confirm_remove(app, ui, t, &account, &name, last_owner.as_ref().filter(|(a, ..)| *a == account).map(|(_, _, f)| f.clone()));
        }
        ui.separator();
    }
}

/// Removing `account` from the server: the question; when they are the last owner of `files`,
/// what to do about those files.
fn confirm_remove(app: &mut FigApp, ui: &mut Ui, t: &Tokens, account: &str, name: &str, files: Option<Vec<(String, String)>>) {
    let ctx = ui.ctx().clone();
    let remove = |app: &mut FigApp, force: bool| {
        let (account, name) = (account.to_string(), name.to_string());
        ask(
            app,
            &ctx,
            "admin.removePerson",
            json!({"account": account, "force": force}),
            Box::new(move |app, ctx, v| {
                if v["removed"] == true {
                    let orphaned = files_of(&v["orphaned"]);
                    app.toast(trf("{name} was removed from the server", &[("name", &name)]));
                    with(app, |w| {
                        w.confirm = None;
                        w.last_owner = None;
                        w.people = None;
                        w.files = None;
                        w.orphaned.extend(orphaned);
                    });
                    load(app, ctx, PEOPLE);
                } else {
                    let files = files_of(&v["lastOwner"]);
                    with(app, |w| w.last_owner = Some((account, name, files)));
                }
            }),
        );
    };
    match files {
        None => {
            widgets::label(
                ui,
                &trf("Remove {name} from the server? Their sessions end, they leave every file and their account is forgotten.", &[("name", &name)]),
                t.danger,
            );
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Remove"), true, !busy(app)).clicked() {
                    remove(app, false);
                }
                if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                    with(app, |w| w.confirm = None);
                }
            });
        }
        Some(files) => {
            let names: Vec<&str> = files.iter().map(|(_, n)| n.as_str()).collect();
            widgets::label(
                ui,
                &trf(
                    "{name} is the last owner of: {files}. Make someone else owner of these files first, or remove them anyway and the files are left without an owner.",
                    &[("name", &name), ("files", &names.join(", "))],
                ),
                t.danger,
            );
            ui.horizontal(|ui| {
                if widgets::button(ui, tr("Make someone else owner"), true, true).clicked()
                    && let Some((file, _)) = files.first()
                {
                    let file = file.clone();
                    with(app, |w| {
                        w.tab = AdminTab::Files;
                        w.file = Some(file);
                        w.members = None;
                        w.add_role = 2;
                    });
                }
                if widgets::button(ui, tr("Remove anyway"), false, !busy(app)).clicked() {
                    remove(app, true);
                }
                if widgets::button(ui, tr("Cancel"), false, true).clicked() {
                    with(app, |w| {
                        w.confirm = None;
                        w.last_owner = None;
                    });
                }
            });
        }
    }
}

/// Files left without an owner: give each one.
fn orphans(app: &mut FigApp, ui: &mut Ui, t: &Tokens, orphaned: &[(String, String)]) {
    for (file, name) in orphaned {
        ui.horizontal(|ui| {
            widgets::label(ui, &trf("{file} has no owner now.", &[("file", name)]), t.warning);
            if widgets::button(ui, tr("Give it an owner"), false, true).clicked() {
                let file = file.clone();
                with(app, |w| {
                    w.tab = AdminTab::Files;
                    w.file = Some(file);
                    w.members = None;
                    w.add_role = 2;
                });
            }
        });
    }
}

fn files(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    let ctx = ui.ctx().clone();
    let Some(w) = app.ui.admin.as_ref() else { return };
    let (files, selected) = (w.files.clone(), w.file.clone());
    if files.is_none() && !app.session.waiting_for(FILES) {
        load(app, &ctx, FILES);
    }
    let Some(files) = files else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    let list = files["files"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        widgets::label(ui, tr("No files are kept here yet."), t.text_secondary);
    }
    for f in &list {
        let id = f["file"].as_str().unwrap_or_default().to_string();
        let name = f["name"].as_str().unwrap_or_default();
        let updated = figcraft_engine::live::utc_date(f["updated"].as_u64().unwrap_or(0));
        let people = f["people"].as_u64().unwrap_or(0) as usize;
        let open = selected.as_deref() == Some(id.as_str());
        let line = format!("{name} · {} · {}", updated.get(..10).unwrap_or(&updated), trn("{n} people in it now", people, &[]));
        if ui.selectable_label(open, line).clicked() {
            with(app, |w| {
                w.file = if open { None } else { Some(id.clone()) };
                w.members = None;
                w.role_edit = None;
            });
        }
        if open {
            ui.indent(("admin_members", &id), |ui| members(app, ui, t, &id));
        }
    }
    // A file that isn't listed (yet): its members still show when it was picked from elsewhere.
    if let Some(file) = selected.filter(|f| !list.iter().any(|x| x["file"] == f.as_str())) {
        members(app, ui, t, &file);
    }
}

/// Who is in `file`: change a member's role, add someone by email (an owner, for a file without
/// one).
fn members(app: &mut FigApp, ui: &mut Ui, t: &Tokens, file: &str) {
    let ctx = ui.ctx().clone();
    let Some(w) = app.ui.admin.as_ref() else { return };
    let (members, role_edit) = (w.members.clone(), w.role_edit.clone());
    if members.is_none() && !app.session.waiting_for(MEMBERS) {
        load(app, &ctx, MEMBERS);
    }
    let Some(v) = members else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    let list = v["members"].as_array().cloned().unwrap_or_default();
    if !list.iter().any(|m| m["role"] == "owner") {
        widgets::label(ui, tr("This file has no owner: make a member owner, or add someone as owner."), t.warning);
    }
    let busy = busy(app);
    let mut change: Option<(&str, Value)> = None;
    for m in &list {
        let account = m["account"].as_str().unwrap_or_default().to_string();
        let role = m["role"].as_str().unwrap_or("editor");
        let who = match m["email"].as_str() {
            Some(e) => format!("{} · {e}", m["name"].as_str().unwrap_or_default()),
            None => m["name"].as_str().unwrap_or_default().to_string(),
        };
        ui.horizontal(|ui| {
            ui.scope(|ui| {
                ui.set_width(300.0);
                widgets::label(ui, &who, t.text);
            });
            if widgets::button(ui, role_label(role), false, !busy).on_hover_text(tr("Change role")).clicked() {
                with(app, |w| w.role_edit = if role_edit.as_deref() == Some(account.as_str()) { None } else { Some(account.clone()) });
            }
        });
        if role_edit.as_deref() == Some(account.as_str()) {
            let labels: Vec<&str> = ROLES.iter().map(|r| role_label(r)).collect();
            let at = ROLES.iter().position(|r| *r == role).unwrap_or(0);
            if let Some(i) = widgets::segmented_text(ui, &labels, at)
                && i != at
            {
                change = Some(("admin.setFileRole", json!({"file": file, "account": account, "role": ROLES.get(i).copied().unwrap_or("editor")})));
            }
        }
    }
    for i in v["invited"].as_array().cloned().unwrap_or_default() {
        let line = trf(
            "{email} · invited as {role}",
            &[("email", &i["email"].as_str().unwrap_or_default()), ("role", &role_label(i["role"].as_str().unwrap_or_default()))],
        );
        widgets::label(ui, &line, t.text_secondary);
    }
    let Some(w) = app.ui.admin.as_mut() else { return };
    ui.horizontal(|ui| {
        let resp = widgets::text_input(ui, egui::Id::new("admin_add_email"), &mut w.add_email, 180.0, tr("Email"));
        a11y::text(&resp, tr("Add someone by email"), &w.add_email);
        let labels: Vec<&str> = ROLES.iter().map(|r| role_label(r)).collect();
        ui.scope(|ui| {
            ui.set_max_width(240.0);
            if let Some(i) = widgets::segmented_text(ui, &labels, w.add_role) {
                w.add_role = i;
            }
        });
        let filled = w.add_email.contains('@');
        if widgets::button(ui, tr("Add"), true, filled && !busy).clicked() && filled {
            let role = ROLES.get(w.add_role).copied().unwrap_or("editor");
            change = Some(("admin.addFileMember", json!({"file": file, "email": w.add_email.trim(), "role": role})));
        }
    });
    if let Some((cmd, params)) = change {
        let added = cmd == "admin.addFileMember";
        let owner = params["role"] == "owner";
        let file = file.to_string();
        ask(
            app,
            &ctx,
            cmd,
            params,
            Box::new(move |app, ctx, _| {
                with(app, |w| {
                    if added {
                        w.add_email.clear();
                    }
                    w.role_edit = None;
                    w.members = None;
                    // A file that has an owner now is no longer one to recover.
                    if owner {
                        w.orphaned.retain(|(f, _)| *f != file);
                    }
                });
                load(app, ctx, MEMBERS);
            }),
        );
    }
}

fn status(app: &mut FigApp, ui: &mut Ui, t: &Tokens) {
    let ctx = ui.ctx().clone();
    let Some(status) = app.ui.admin.as_ref().map(|w| w.status.clone()) else { return };
    if status.is_none() && !app.session.waiting_for(STATUS) {
        load(app, &ctx, STATUS);
    }
    let Some(s) = status else {
        widgets::label(ui, tr("Asking the server…"), t.text_secondary);
        return;
    };
    let providers: Vec<&str> = s["providers"].as_array().into_iter().flatten().filter_map(|p| p["label"].as_str()).collect();
    let free = s["freeBytes"].as_u64().map_or_else(|| tr("unknown").to_string(), |b| format!("{:.1} GB", b as f64 / 1e9));
    let rows: [(&str, String); 7] = [
        (tr("Version"), s["version"].as_str().unwrap_or_default().to_string()),
        (tr("Who gets in"), s["auth"].as_str().unwrap_or_default().to_string()),
        (tr("Sign-ins"), providers.join(", ")),
        (tr("End-to-end encryption"), s["e2e"].as_str().unwrap_or_default().to_string()),
        (tr("People"), s["people"].to_string()),
        (tr("Sessions"), s["sessions"].to_string()),
        (tr("Files"), s["files"].to_string()),
    ];
    for (k, v) in rows.iter().chain(std::iter::once(&(tr("Free space"), free.clone()))) {
        ui.horizontal(|ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            ui.scope(|ui| {
                ui.set_width(170.0);
                widgets::label(ui, k, t.text_secondary);
            });
            widgets::label(ui, v, t.text);
        });
    }
    if widgets::button(ui, tr("Refresh"), false, !app.session.waiting_for(STATUS)).clicked() {
        with(app, |w| w.status = None);
    }
}
