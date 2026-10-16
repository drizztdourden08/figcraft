//! Your files on a server with accounts as a file browser shows them (milestone M9;
//! `docs/server-accounts.md`): folders, recent files and previews, and basic accounts' passwords.
//!
//! - `account.browse` lists your files on a server with their folder, role, whether they are
//!   sealed, when their preview was set and when you last opened them (the server notes it when
//!   you join), with the folders you see and your recent files (newest first).
//! - `account.createFolder`, `account.renameFolder`, `account.removeFolder` and `account.moveFile`
//!   change folders (a file has one folder, the same for everyone in it; owners and editors move
//!   it).
//! - `account.thumbnail` gives a file's preview as base64 PNG `data` (a sealed file's opened with
//!   the key kept on this computer). Previews are sent by the app itself: after publishing to a
//!   server you are signed in to, and every [`THUMB_EVERY`] for a file you edit there when it
//!   changed (`account.uploadThumbnail` sends one now). A sealed file's preview is sealed with
//!   its key for slot `Meta { what: "thumbnail" }` before it leaves.
//! - `account.signUp` and `account.changePassword`: basic accounts (usernames and passwords the
//!   server keeps). A password is sent only over TLS or to this machine and never returned.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use figcraft_collab::message::{AccountReply, AccountReq, FileEntry, MAX_THUMBNAIL, Secret};
use figcraft_collab::sealed::Sealed;
use figcraft_collab_seal::{Slot, open, parse_ring_fragment, seal};
use figcraft_doc::Document;
use serde_json::{Value, json};

use crate::accounts::{server_key, server_of};
use crate::cmd::CommandSpec;
use crate::file_keys::link_file;
use crate::live::{Access, SignIn, SignInReply};
use crate::params::{req_string, string};
use crate::{EngineError, Result, Session, bad, spec};

/// How often the previews of the files you edit on servers are sent again (when they changed).
pub const THUMB_EVERY: Duration = Duration::from_secs(120);
/// Longest side of a preview, in pixels.
pub const THUMB_SIDE: f64 = 256.0;
/// Previews remembered as sent (the oldest go first).
const MAX_SENT: usize = 64;
/// Recent files listed.
const MAX_RECENT: usize = 20;

fn thumbnail_slot() -> Slot {
    Slot::Meta { what: "thumbnail".into() }
}

/// The previews this app sent, and when it looks again.
#[derive(Clone, Default)]
pub struct Thumbs {
    /// `(server, file)` and the document the preview was made of.
    sent: Vec<(String, String, Arc<Document>)>,
    next: Option<web_time::Instant>,
}

impl std::fmt::Debug for Thumbs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Thumbs").field("sent", &self.sent.len()).finish_non_exhaustive()
    }
}

/// A small PNG of `doc`'s first page (at most [`THUMB_SIDE`] on its longest side and
/// [`MAX_THUMBNAIL`] bytes), or `None` when it has nothing to show.
pub fn preview_png(doc: &Document) -> Option<Vec<u8>> {
    let page = doc.first_page()?;
    let b = doc.page_content_bounds(page)?;
    for side in [THUMB_SIDE, THUMB_SIDE / 2.0] {
        let scale = (side / b.width().max(b.height()).max(1.0)).min(2.0);
        if !scale.is_finite() || scale <= 0.0 {
            return None;
        }
        let view = figcraft_render::View {
            origin: (b.x0, b.y0),
            scale,
            width: (b.width() * scale).ceil().clamp(1.0, side) as u32,
            height: (b.height() * scale).ceil().clamp(1.0, side) as u32,
        };
        let pix = figcraft_render::render_view(doc, page, &view, &Default::default())?;
        let png = figcraft_render::encode_png(&pix).ok()?;
        if png.len() <= MAX_THUMBNAIL {
            return Some(png);
        }
    }
    None
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn entry_json(s: &Session, server: &str, f: &FileEntry) -> Value {
    let (name, _) = s.listed_name(server, &f.info.id, &f.info.name, None);
    json!({
        "file": f.info.id,
        "name": name,
        "folder": f.folder,
        "sealed": f.sealed,
        "role": f.role.id(),
        "people": f.info.people,
        "updated": f.info.updated,
        "thumbnail": f.thumbnail,
        "opened": f.opened,
    })
}

impl Session {
    /// The server and file a live session is on, when you may edit it there and are signed in.
    fn editing_on_server(&self, live: &crate::live::Live) -> Option<(String, String)> {
        if let Some(p) = &live.published {
            let server = if live.server.trim().is_empty() { server_of(&p.edit)? } else { live.server.clone() };
            return Some((server_key(&server), p.file.clone()));
        }
        let info = live.info.as_ref().filter(|i| i.access == Access::Edit)?;
        Some((server_key(&server_of(&info.link)?), link_file(&info.link)?.to_string()))
    }

    /// The document of the session on `file` at `server`, else the one in front.
    fn doc_for(&self, server: &str, file: &str) -> Option<Arc<Document>> {
        let live = self.live.sessions().find(|l| self.editing_on_server(l).is_some_and(|(s, f)| s == server && f == file));
        let uid = live.and_then(|l| l.doc_uid);
        match uid {
            Some(uid) => self.docs.iter().find(|d| d.uid == uid).map(|d| d.doc.clone()),
            None => self.ds().ok().map(|d| d.doc.clone()),
        }
    }

    /// Send the preview of `file` at `server` now, made of `doc`: sealed with the file's key when
    /// one is kept here.
    fn send_thumbnail(&mut self, cmd: &str, server: &str, file: &str, doc: Arc<Document>) -> Result<usize> {
        let png = preview_png(&doc).ok_or_else(|| bad(cmd, "the file has nothing to show yet"))?;
        let image = match self.file_key(server, file) {
            Some(key) => {
                let ring = parse_ring_fragment(key).map_err(|e| EngineError::Other(e.to_string()))?;
                let k = ring.current().ok_or_else(|| EngineError::Other("the file's key is missing".into()))?;
                seal(k, file, &thumbnail_slot(), &png).map_err(|e| EngineError::Other(e.to_string()))?.into_bytes()
            }
            None => png,
        };
        let bytes = image.len();
        self.account_request(cmd, server, AccountReq::SetThumbnail { file: file.to_string(), image })?;
        let t = &mut self.accounts.thumbs;
        t.sent.retain(|(s, f, _)| !(s == server && f == file));
        t.sent.insert(0, (server.to_string(), file.to_string(), doc));
        t.sent.truncate(MAX_SENT);
        Ok(bytes)
    }

    /// A file was published to `server`: its preview goes there too, when you are signed in (in
    /// the background).
    pub(crate) fn thumbs_after_publish(&mut self, server: &str, file: &str) {
        if self.signed_in(server).is_none() || self.waiting_for("account.uploadThumbnail") {
            return;
        }
        if let Err(e) = self.start_background("account.uploadThumbnail", json!({"server": server_key(server), "file": file})) {
            log::info!("previews: not sent to {server}: {e}");
        }
    }

    /// Now and then, send the preview of a file you edit on a server you are signed in to, when it
    /// changed since it was last sent (one at a time, in the background).
    pub(crate) fn thumbs_tick(&mut self) {
        if self.prefs.accounts.is_empty() || !self.live.available() || self.waiting_for("account.uploadThumbnail") {
            return;
        }
        let now = web_time::Instant::now();
        match self.accounts.thumbs.next {
            None => {
                self.accounts.thumbs.next = Some(now + THUMB_EVERY);
                return;
            }
            Some(t) if now < t => return,
            Some(_) => self.accounts.thumbs.next = Some(now + THUMB_EVERY),
        }
        let due = self.live.sessions().filter_map(|l| self.editing_on_server(l)).find(|(server, file)| {
            self.signed_in(server).is_some()
                && self
                    .doc_for(server, file)
                    .is_some_and(|doc| !self.accounts.thumbs.sent.iter().any(|(s, f, d)| s == server && f == file && Arc::ptr_eq(d, &doc)))
        });
        if let Some((server, file)) = due
            && let Err(e) = self.start_background("account.uploadThumbnail", json!({"server": server, "file": file}))
        {
            log::info!("previews: not sent to {server}: {e}");
        }
    }
}

fn browse(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.browse";
    let server = s.account_server(CMD, p)?;
    match s.account_request(CMD, &server, AccountReq::Browse)? {
        AccountReply::Browse { files, folders } => {
            let mut recent: Vec<&FileEntry> = files.iter().filter(|f| f.opened.is_some()).collect();
            recent.sort_by_key(|f| std::cmp::Reverse(f.opened));
            let recent: Vec<&str> = recent.iter().take(MAX_RECENT).map(|f| f.info.id.as_str()).collect();
            let list: Vec<Value> = files.iter().map(|f| entry_json(s, &server, f)).collect();
            Ok(json!({"server": server, "folders": folders, "files": list, "recent": recent}))
        }
        _ => Err(EngineError::Other("the server answered something else".into())),
    }
}

fn folders(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.folders";
    let server = s.account_server(CMD, p)?;
    match s.account_request(CMD, &server, AccountReq::Folders)? {
        AccountReply::Folders(list) => Ok(json!({"server": server, "folders": list})),
        _ => Err(EngineError::Other("the server answered something else".into())),
    }
}

fn create_folder(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.createFolder";
    let server = s.account_server(CMD, p)?;
    let path = req_string(CMD, p, "path")?;
    s.account_request(CMD, &server, AccountReq::CreateFolder { path: path.clone() })?;
    Ok(json!({"server": server, "created": path}))
}

fn rename_folder(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.renameFolder";
    let server = s.account_server(CMD, p)?;
    let (from, to) = (req_string(CMD, p, "from")?, req_string(CMD, p, "to")?);
    s.account_request(CMD, &server, AccountReq::RenameFolder { from: from.clone(), to: to.clone() })?;
    Ok(json!({"server": server, "from": from, "to": to}))
}

fn remove_folder(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.removeFolder";
    let server = s.account_server(CMD, p)?;
    let path = req_string(CMD, p, "path")?;
    s.account_request(CMD, &server, AccountReq::RemoveFolder { path: path.clone() })?;
    Ok(json!({"server": server, "removed": path}))
}

fn move_file(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.moveFile";
    let server = s.account_server(CMD, p)?;
    let file = req_string(CMD, p, "file")?;
    let folder = string(p, "folder").unwrap_or_default();
    s.account_request(CMD, &server, AccountReq::MoveFile { file: file.clone(), folder: folder.clone() })?;
    Ok(json!({"server": server, "file": file, "folder": folder}))
}

fn thumbnail(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.thumbnail";
    let server = s.account_server(CMD, p)?;
    let file = req_string(CMD, p, "file")?;
    let (image, set) = match s.account_request(CMD, &server, AccountReq::GetThumbnail { file: file.clone() })? {
        AccountReply::Thumbnail { image, set } => (image, set),
        _ => return Err(EngineError::Other("the server answered something else".into())),
    };
    if image.is_empty() {
        return Ok(json!({"server": server, "file": file, "data": Value::Null, "set": Value::Null}));
    }
    if image.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok(json!({"server": server, "file": file, "data": b64(&image), "set": set, "sealed": false}));
    }
    // A sealed preview: opened with the key kept here (none, or it doesn't open: no picture).
    let opened = s.file_key(&server, &file).and_then(|k| parse_ring_fragment(k).ok()).and_then(|ring| {
        let sealed = Sealed::from_bytes(image).ok()?;
        open(&ring, &file, &thumbnail_slot(), &sealed).ok().filter(|png| png.starts_with(b"\x89PNG\r\n\x1a\n"))
    });
    Ok(json!({"server": server, "file": file, "data": opened.as_deref().map(b64), "set": set, "sealed": true}))
}

fn upload_thumbnail(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.uploadThumbnail";
    let (server, file) = match string(p, "file") {
        Some(file) => (s.account_server(CMD, p)?, file),
        None => {
            let live = s.live();
            s.editing_on_server(live).ok_or_else(|| bad(CMD, "the file in front isn't on a server you may edit it on: give `server` and `file`"))?
        }
    };
    let doc = s.doc_for(&server, &file).ok_or_else(|| bad(CMD, "no file is open"))?;
    let bytes = s.send_thumbnail(CMD, &server, &file, doc)?;
    Ok(json!({"server": server, "file": file, "bytes": bytes}))
}

fn sign_up(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.signUp";
    let server = s.account_server(CMD, p)?;
    let info = s.server_about(&server)?.info;
    let provider = match string(p, "provider") {
        Some(id) => info.providers.iter().find(|x| x.id == id),
        None => info.providers.iter().find(|x| x.flows.contains(&crate::live::Flow::SignUp)),
    };
    let provider = provider
        .filter(|x| x.flows.contains(&crate::live::Flow::SignUp))
        .ok_or_else(|| bad(CMD, "this server doesn't let people make their own account: ask an admin for one"))?;
    let req = SignIn::SignUp {
        provider: provider.id.clone(),
        username: req_string(CMD, p, "username")?,
        password: req_string(CMD, p, "password")?,
        email: string(p, "email").filter(|e| !e.trim().is_empty()),
        name: string(p, "name").unwrap_or_default(),
    };
    match s.sign_in_step(&server, req)? {
        SignInReply::SignedIn(me) => Ok(json!({"status": "signedIn", "account": s.keep_sign_in_with(&server, me, true)})),
        SignInReply::Refused { reason } => Err(EngineError::Other(reason)),
        _ => Err(EngineError::Other("the server didn't make the account".into())),
    }
}

fn change_password(s: &mut Session, p: &Value) -> Result<Value> {
    const CMD: &str = "account.changePassword";
    let server = s.account_server(CMD, p)?;
    let old = req_string(CMD, p, "old")?;
    let new = req_string(CMD, p, "new")?;
    s.account_request(CMD, &server, AccountReq::ChangePassword { old: Secret(old), new: Secret(new) })?;
    Ok(json!({"server": server, "changed": true}))
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "account.browse",
            "Browse server files",
            "{server?} → {server, folders: [path (\"Marketing/2026\")], files: [{file, name, folder (\"\": at the top), sealed, role: owner | editor | viewer, people, updated, thumbnail (when its preview was set, or null: `account.thumbnail`), opened (when you last opened it, or null)}], recent: [file ids, last opened first]}: your files on a server with accounts, as a file browser shows them",
            false,
            browse
        ),
        spec!("account.folders", "Server folders", "{server?} → {server, folders: [path]}: the folders you see on the server", false, folders),
        spec!(
            "account.createFolder",
            "New server folder",
            "{server?, path (names joined by /: \"Marketing/2026\")} → {server, created}: an empty folder of yours (others see it once a file they're in is in it)",
            false,
            create_folder
        ),
        spec!(
            "account.renameFolder",
            "Rename server folder",
            "{server?, from, to} → {server, from, to}: the files in it (and below) you may edit move, and your empty folders",
            false,
            rename_folder
        ),
        spec!(
            "account.removeFolder",
            "Remove server folder",
            "{server?, path} → {server, removed}: removes a folder of yours that holds no file you're in",
            false,
            remove_folder
        ),
        spec!(
            "account.moveFile",
            "Move server file",
            "{server?, file, folder? (default \"\": the top)} → {server, file, folder}: owners and editors put a file in a folder (the same folder for everyone in it)",
            false,
            move_file
        ),
        spec!(
            "account.thumbnail",
            "Server file preview",
            "{server?, file} → {server, file, data (base64 PNG, or null: no preview, or a sealed one this computer has no key for), set (when it was set), sealed}",
            false,
            thumbnail
        ),
        spec!(
            "account.uploadThumbnail",
            "Send file preview",
            "{server?, file? (default: the file in front, on its server)} → {server, file, bytes}: renders the file's first page small and keeps it on the server as its preview (sealed with the file's key for a sealed file); the app does it by itself after publishing and every two minutes for files you edit there",
            false,
            upload_thumbnail
        ),
        spec!(
            "account.signUp",
            "Make server account",
            "{server?, provider?, username, password, email?, name?} → {status: signedIn, account}: makes an account with a username and password on a server that lets people sign up, and signs in (the password is sent only over wss:// or to this machine, never returned)",
            false,
            sign_up
        ),
        spec!(
            "account.changePassword",
            "Change server password",
            "{server?, old, new} → {server, changed}: changes your password on a server where you sign in with a username and password (10 to 256 characters, not your username)",
            false,
            change_password
        ),
    ]
}
