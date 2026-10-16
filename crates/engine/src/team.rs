//! Working with a team on a server with accounts (milestone M9; `docs/server-accounts.md` ›
//! *Team access*): who is on the server and their pictures, new files made straight on the
//! server, and where File ▸ Save puts a file.
//!
//! - `account.people` lists everyone on the server by name (an admin also sees emails) and says
//!   how files are shared there: `fileAccess` `"everyone"` (everyone on the server is in every
//!   file: per-file invites don't apply, admins add people to the server) or `"members"`.
//! - `account.avatar` gives someone's picture as the server keeps it (base64 `data`, `mime`), or
//!   null: the UI draws their initials then.
//! - `account.newFile` makes a blank file on the server as you (in `folder`, sealed when the
//!   server requires it or `sealed` says so) and opens it in a tab. With a default server
//!   (`servers.setDefault`, [`Prefs::default_server`](crate::Prefs)), `file.new` (the + tab, File ▸
//!   New) does the same on its root.
//! - **Saving.** `file.save` on a file whose session is on a server says it is saved there: edits
//!   go to the server as they are made, so it sends what is left now and answers with how many
//!   batches the server hasn't confirmed yet (`pending`; 0: everything is there). An untitled file
//!   (no path on this computer) with a default server set goes to that server's root. A file with
//!   a path on this computer, not on a server, is saved to that path as before (moving it to a
//!   server is publishing it). `file.saveLocally` is Save as: a copy on this computer.

use base64::Engine as _;
use figcraft_collab::message::{AccountReply, AccountReq, TeamMember};
use serde_json::{Value, json};

use crate::cmd::CommandSpec;
use crate::live::{Role, Status};
use crate::params::{get, req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

fn other() -> EngineError {
    EngineError::Other("the server answered something else".into())
}

fn member_json(m: &TeamMember) -> Value {
    json!({"account": m.account, "name": m.name, "admin": m.admin, "avatar": m.avatar, "email": m.email})
}

impl Session {
    /// A file made with `account.newFile {folder}` was published to `server` as `file`: it goes
    /// into the folder (in the background).
    pub(crate) fn team_after_publish(&mut self, server: &str, file: &str, folder: &str) {
        if folder.trim().is_empty() || self.signed_in(server).is_none() {
            return;
        }
        let server = crate::accounts::server_key(server);
        if let Err(e) = self.start_background("account.moveFile", json!({"server": server, "file": file, "folder": folder})) {
            log::info!("new file: not moved to {folder:?} on {server}: {e}");
        }
    }

    /// The server the active file's session is on, with the file there, when that session is a
    /// server's (a file you published or opened from a server; not one this app hosts).
    fn on_server(&self) -> Option<(String, Option<String>)> {
        let live = self.live();
        let there = matches!(live.status, Status::Live | Status::Reconnecting { .. } | Status::Connecting);
        if !there || live.role() == Some(Role::Host) {
            return None;
        }
        let server = live.account_server();
        let file = live.account_file().map(|(_, f)| f);
        let a_server = live.published.is_some() || live.hosting.is_some() || (!server.is_empty() && self.signed_in(&server).is_some());
        (a_server && !server.is_empty()).then_some((server, file))
    }

    fn server_name(&self, server: &str) -> String {
        self.servers().into_iter().find(|sv| sv.url == server).map_or_else(|| crate::servers::host(server).to_string(), |sv| sv.name)
    }
}

/// A blank document in a new tab (`file.new`), named `name`.
pub(crate) fn blank(s: &mut Session, name: Option<String>) -> usize {
    use figcraft_doc::{Document, NodeKind};
    let mut doc = Document::new(name.unwrap_or_else(|| "Untitled".into()));
    // A property of the page from here on: a later change of theme leaves it alone.
    let background = s.new_page_background();
    for page in doc.pages.clone() {
        if let Some(NodeKind::Page { background: b, .. }) = doc.node_mut(page).map(|n| &mut n.kind) {
            *b = background;
        }
    }
    s.docs.push(crate::DocState::new(doc, None));
    s.active = s.docs.len() - 1;
    s.active
}

/// Make a blank file on `server` as you and open it (see the module docs), for command `cmd`.
pub(crate) fn new_on_server(s: &mut Session, cmd: &str, server: &str, p: &Value) -> Result<Value> {
    if s.signed_in(server).is_none() {
        return Err(bad(cmd, format!("you aren't signed in to {}: sign in first", crate::servers::host(server))));
    }
    let sealed = match get(p, "sealed") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_bool().ok_or_else(|| bad(cmd, "`sealed` must be true or false"))?),
    };
    let folder = string(p, "folder").map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
    // This device first (a sealed file's first session signs with it): every server request comes
    // before the new tab, so a command run again in the background makes one file.
    if sealed != Some(false) {
        match s.device_id(cmd, server) {
            Err(EngineError::Waiting) => return Err(EngineError::Waiting),
            Err(e) => log::info!("devices: not registered with {server} before the new file: {e}"),
            Ok(_) => {}
        }
    }
    let index = blank(s, string(p, "name").map(|n| n.trim().to_string()).filter(|n| !n.is_empty()));
    let mut opts = json!({});
    if let Some(n) = string(p, "name") {
        opts["name"] = json!(n);
    }
    if let Some(b) = sealed {
        opts["sealed"] = json!(b);
    }
    let id = crate::live::publish_with(s, cmd, server, &opts, false, false)?;
    if let Some(live) = s.live_mut().filter(|l| l.id == id) {
        live.folder = folder.clone();
    }
    Ok(json!({
        "index": index,
        "server": server,
        "serverName": s.server_name(server),
        "folder": folder.unwrap_or_default(),
        "status": s.live().status.id(),
    }))
}

fn new_file(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.newFile";
    let server = s.account_server(CMD, p)?;
    new_on_server(s, CMD, &server, p)
}

/// `file.new`: on the default server's root when one is set (and you are signed in there), else
/// on this computer (`local: true` always).
pub(crate) fn file_new(s: &mut Session, p: &Value) -> Result<Value> {
    let local = get(p, "local").and_then(Value::as_bool).unwrap_or(false);
    if !local && let Some(server) = s.default_server() {
        let mut opts = json!({});
        if let Some(n) = string(p, "name") {
            opts["name"] = json!(n);
        }
        return new_on_server(s, "file.new", &server, &opts);
    }
    let index = blank(s, string(p, "name"));
    Ok(json!({"index": index}))
}

/// `file.save` for a file on a server, or an untitled one when a default server is set: what it
/// did, or `None` (save on this computer as before).
pub(crate) fn save_to_server(s: &mut Session) -> Result<Option<Value>> {
    if let Some((server, file)) = s.on_server() {
        // What is left goes now; the server confirms it in the background.
        s.live_sync();
        let pending = s.live().client().map_or(0, figcraft_collab::Client::pending);
        let i = crate::branches::file_tab(s);
        if let Some(ds) = s.docs.get_mut(i) {
            ds.mark_saved();
        }
        return Ok(Some(json!({
            "saved": true,
            "where": "server",
            "server": server,
            "serverName": s.server_name(&server),
            "file": file,
            "pending": pending,
            "synced": pending == 0,
        })));
    }
    let untitled = s.docs.get(crate::branches::file_tab(s)).ok_or(EngineError::NoDocument)?.path.is_none();
    let Some(server) = s.default_server().filter(|_| untitled) else { return Ok(None) };
    crate::live::start_publish(s, "file.save", &server, &json!({}), false)?;
    Ok(Some(json!({
        "saved": true,
        "where": "server",
        "server": server,
        "serverName": s.server_name(&server),
        "publishing": true,
        "status": s.live().status.id(),
    })))
}

fn people(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.people";
    let server = s.account_server(CMD, p)?;
    match s.account_request(CMD, &server, AccountReq::Team)? {
        AccountReply::Team { file_access, people } => {
            Ok(json!({"server": server, "fileAccess": file_access, "people": people.iter().map(member_json).collect::<Vec<_>>()}))
        }
        _ => Err(other()),
    }
}

fn avatar(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.avatar";
    let server = s.account_server(CMD, p)?;
    let account = req_string(CMD, p, "account")?;
    match s.account_request(CMD, &server, AccountReq::Avatar { account: account.clone() })? {
        AccountReply::Avatar { image, mime } => {
            // Only pictures that are what they say.
            let ok = (mime == "image/png" && image.starts_with(b"\x89PNG\r\n\x1a\n")) || (mime == "image/jpeg" && image.starts_with(b"\xff\xd8\xff"));
            let data = ok.then(|| base64::engine::general_purpose::STANDARD.encode(&image));
            Ok(json!({"server": server, "account": account, "data": data, "mime": if ok { Value::from(mime) } else { Value::Null }}))
        }
        _ => Err(other()),
    }
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "account.people",
            "People on server",
            "{server?} → {server, fileAccess: everyone (everyone on the server is in every file: per-file invites don't apply, admins add people to the server) | members (each file has its own members), people: [{account, name (show this, never the email), admin, avatar (the server keeps a picture: `account.avatar`), email (admins only, else null)}]}: everyone who signed in there",
            false,
            people
        ),
        spec!(
            "account.avatar",
            "Person's picture",
            "{server?, account} → {server, account, data (base64 PNG or JPEG, or null: none — draw their initials), mime (image/png | image/jpeg | null)}: someone's picture as the server keeps it (from their identity provider, refreshed at most daily)",
            false,
            avatar
        ),
        spec!(
            "account.newFile",
            "New file on server",
            "{server? (default: the first server), folder? (\"Marketing/2026\"; default the top), name? (default Untitled), sealed? (default: sealed when the server requires it)} → {index (its tab), server, serverName, folder, status}: makes a blank file on the server as you and opens it in a new tab (it moves into `folder` once it is there)",
            false,
            new_file
        ),
    ]
}
