//! Folders, recent files and previews on a server with accounts (`docs/server-accounts.md`).
//!
//! - **Folders.** A file has one folder (`meta.json`'s `folder`, `"Marketing/2026"`: names joined
//!   by `/`), the same for everyone in it; its owners and editors move it. A folder exists while
//!   a file is in it (or below), and a person sees the folders of the files they're in, with their
//!   parents. An empty folder someone made is theirs (`folders.json`): others see it once a file
//!   they're in is put there. Renaming a folder moves the files in it that you may edit, and your
//!   own folders; a folder you remove must hold no file you're in. Folder names are plain text on
//!   the server, also for sealed files.
//! - **Recent files.** When someone signed in opens a file, the server notes when
//!   (`recents.json`, the newest [`MAX_RECENTS_EACH`] per person); listings say when you last
//!   opened each file.
//! - **Previews.** Owners and editors keep a small PNG of a file (`thumbnail.bin`, at most
//!   [`MAX_THUMBNAIL`] bytes); for a sealed file it is the PNG sealed for slot
//!   `Meta { what: "thumbnail" }`, kept as it comes (the server checks only that it is a sealed
//!   value). Everyone in the file may read it.

use figcraft_auth::Person;
use figcraft_collab::message::{AccountReply, AccountReq, FileEntry, MAX_THUMBNAIL, Role};
use figcraft_collab::sealed::Sealed;
use figcraft_collab_net::hub::{AccountHandled, OpenFile};
use serde::{Deserialize, Serialize};

use super::{Store, now, write_json};
use crate::disk;

/// Empty folders people made, at the data directory's root.
pub const FOLDERS: &str = "folders.json";
/// When people last opened files, at the data directory's root.
pub const RECENTS: &str = "recents.json";
/// A file's preview, in its folder.
pub const THUMBNAIL: &str = "thumbnail.bin";

/// Most folders one person makes, and all together.
pub const MAX_FOLDERS_EACH: usize = 1_000;
pub const MAX_FOLDERS: usize = 50_000;
/// Recent files kept per person, and all together (the lists stay well under the 16 MiB a list
/// at the root may take).
pub const MAX_RECENTS_EACH: usize = 100;
pub const MAX_RECENTS: usize = 50_000;
/// A folder path: at most this many names, each at most [`MAX_NAME`] characters, all together at
/// most [`MAX_PATH`].
pub const MAX_DEPTH: usize = 8;
pub const MAX_NAME: usize = 64;
pub const MAX_PATH: usize = 256;
/// An opening is written again only when it moved this much (seconds).
const OPENED_EVERY: u64 = 60;

/// An empty folder someone made (`folders.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRec {
    pub account: String,
    pub path: String,
}

/// When someone last opened a file (`recents.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recent {
    pub account: String,
    pub file: String,
    pub at: u64,
}

/// A folder path as kept: its names trimmed and joined by `/` (empty names dropped); `""` is the
/// top. Why not, when it can't be one.
pub fn folder_path(s: &str) -> Result<String, String> {
    let names: Vec<&str> = s.split('/').map(str::trim).filter(|n| !n.is_empty()).collect();
    if names.len() > MAX_DEPTH {
        return Err(format!("folders go at most {MAX_DEPTH} deep"));
    }
    for n in &names {
        if n.chars().count() > MAX_NAME {
            return Err(format!("a folder name has at most {MAX_NAME} characters"));
        }
        if *n == "." || *n == ".." || n.chars().any(|c| c.is_control() || c == '\\') {
            return Err(format!("{n:?} can't be a folder name"));
        }
    }
    let path = names.join("/");
    if path.chars().count() > MAX_PATH {
        return Err(format!("a folder path has at most {MAX_PATH} characters"));
    }
    Ok(path)
}

/// `path` is `folder` or inside it.
pub fn within(path: &str, folder: &str) -> bool {
    !folder.is_empty() && (path == folder || path.strip_prefix(folder).is_some_and(|rest| rest.starts_with('/')))
}

/// `path` and every folder above it (`"a/b"`: `"a"`, `"a/b"`).
fn with_parents(path: &str, out: &mut Vec<String>) {
    let mut at = String::new();
    for name in path.split('/').filter(|n| !n.is_empty()) {
        if !at.is_empty() {
            at.push('/');
        }
        at.push_str(name);
        out.push(at.clone());
    }
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const NOT_IN: &str = "you aren't in this file: ask its owner to invite you";
const EDITORS_ONLY: &str = "only the file's owners and editors can do that";

impl Store {
    /// `who`'s role in `file` (an admin counts as an owner).
    fn role_or_admin(&mut self, file: &str, who: &Person) -> Result<Role, String> {
        match self.role_of(file, who)? {
            Some(r) => Ok(r),
            None if who.admin => Ok(Role::Owner),
            None => Err(NOT_IN.into()),
        }
    }

    fn editor(&mut self, file: &str, who: &Person) -> Result<(), String> {
        match self.role_or_admin(file, who)? {
            Role::Owner | Role::Editor => Ok(()),
            Role::Viewer => Err(EDITORS_ONLY.into()),
        }
    }

    /// The files `who` is in, with their roles (invites to their email taken first).
    fn files_of(&mut self, who: &Person) -> Vec<(String, Role)> {
        for id in self.file_ids() {
            let _ = self.role_of(&id, who);
        }
        self.file_ids().into_iter().filter_map(|id| Some((id.clone(), self.people(&id)?.role(&who.account)?))).collect()
    }

    /// The folders `who` sees (sorted).
    fn folders_of(&mut self, who: &Person) -> Vec<String> {
        let mut out = Vec::new();
        for (id, _) in self.files_of(who) {
            if let Some(e) = self.files.get(&id) {
                with_parents(&e.meta.folder, &mut out);
            }
        }
        for f in self.folders.iter().filter(|f| f.account == who.account) {
            with_parents(&f.path, &mut out);
        }
        out.sort();
        out.dedup();
        out
    }

    fn save_folders(&self) -> Result<(), String> {
        write_json(&self.root.join(FOLDERS), &self.folders).map_err(|e| format!("couldn't save the folders: {e}"))
    }

    fn save_recents(&self) -> Result<(), String> {
        write_json(&self.root.join(RECENTS), &self.recents).map_err(|e| format!("couldn't save the recent files: {e}"))
    }

    fn create_folder(&mut self, who: &Person, path: &str) -> Result<(), String> {
        let path = folder_path(path)?;
        if path.is_empty() {
            return Err("give the folder a name".into());
        }
        if self.folders.iter().any(|f| f.account == who.account && f.path == path) {
            return Ok(());
        }
        if self.folders.iter().filter(|f| f.account == who.account).count() >= MAX_FOLDERS_EACH || self.folders.len() >= MAX_FOLDERS {
            return Err(format!("one person makes at most {MAX_FOLDERS_EACH} folders here"));
        }
        self.folders.push(FolderRec { account: who.account.clone(), path });
        self.save_folders()
    }

    fn rename_folder(&mut self, who: &Person, from: &str, to: &str) -> Result<(), String> {
        let (from, to) = (folder_path(from)?, folder_path(to)?);
        if from.is_empty() || to.is_empty() {
            return Err("give both folders a name".into());
        }
        if within(&to, &from) {
            return Err("a folder can't go inside itself".into());
        }
        let moved = |path: &str| format!("{to}{}", path.get(from.len()..).unwrap_or_default());
        let mut changed = 0usize;
        for (id, role) in self.files_of(who) {
            let Some(e) = self.files.get_mut(&id) else { continue };
            if !within(&e.meta.folder, &from) {
                continue;
            }
            if role == Role::Viewer {
                continue;
            }
            let new = moved(&e.meta.folder);
            folder_path(&new)?;
            e.meta.folder = new;
            self.save_meta(&id)?;
            changed += 1;
        }
        let mut mine = false;
        for f in self.folders.iter_mut().filter(|f| f.account == who.account && within(&f.path, &from)) {
            f.path = moved(&f.path);
            mine = true;
        }
        if mine {
            self.folders.sort_by(|a, b| (&a.account, &a.path).cmp(&(&b.account, &b.path)));
            self.folders.dedup();
            self.save_folders()?;
        }
        if changed == 0 && !mine {
            return Err("you have no folder by that name, or nothing in it you may move".into());
        }
        Ok(())
    }

    fn remove_folder(&mut self, who: &Person, path: &str) -> Result<(), String> {
        let path = folder_path(path)?;
        if path.is_empty() {
            return Err("the top can't be removed".into());
        }
        let full = self.files_of(who).iter().any(|(id, _)| self.files.get(id).is_some_and(|e| within(&e.meta.folder, &path)));
        if full {
            return Err("the folder isn't empty: move its files out first".into());
        }
        let before = self.folders.len();
        self.folders.retain(|f| !(f.account == who.account && within(&f.path, &path)));
        if self.folders.len() == before {
            return Err("you have no folder by that name".into());
        }
        self.save_folders()
    }

    fn move_file(&mut self, who: &Person, file: &str, folder: &str) -> Result<(), String> {
        let folder = folder_path(folder)?;
        self.editor(file, who)?;
        let entry = self.entry(file)?;
        if entry.meta.folder == folder {
            return Ok(());
        }
        entry.meta.folder = folder;
        self.save_meta(file)?;
        log::info!("event=file_moved file={file} account={}", who.account);
        Ok(())
    }

    /// Someone signed in opened `file`: note it (written at most once a minute per file and
    /// person).
    pub(crate) fn opened_by(&mut self, file: &str, account: &str) {
        let t = now();
        match self.recents.iter().position(|r| r.account == account && r.file == file) {
            Some(i) => {
                let Some(r) = self.recents.get_mut(i) else { return };
                if t.saturating_sub(r.at) < OPENED_EVERY {
                    return;
                }
                r.at = t;
            }
            None => {
                self.recents.push(Recent { account: account.to_string(), file: file.to_string(), at: t });
                // A person keeps their newest few; everyone together a bounded list.
                let mine: Vec<u64> = self.recents.iter().filter(|r| r.account == account).map(|r| r.at).collect();
                if mine.len() > MAX_RECENTS_EACH {
                    let mut sorted = mine;
                    sorted.sort_unstable();
                    let cut = sorted.get(sorted.len() - MAX_RECENTS_EACH).copied().unwrap_or(0);
                    self.recents.retain(|r| r.account != account || r.at >= cut);
                }
                if self.recents.len() > MAX_RECENTS {
                    self.recents.sort_by_key(|r| std::cmp::Reverse(r.at));
                    self.recents.truncate(MAX_RECENTS);
                }
            }
        }
        if let Err(e) = self.save_recents() {
            log::warn!("{e}");
        }
    }

    /// Forget the folders and recent files of someone taken off the server.
    pub(crate) fn forget_folders_of(&mut self, account: &str) {
        let (f, r) = (self.folders.len(), self.recents.len());
        self.folders.retain(|x| x.account != account);
        self.recents.retain(|x| x.account != account);
        if self.folders.len() != f
            && let Err(e) = self.save_folders()
        {
            log::warn!("{e}");
        }
        if self.recents.len() != r
            && let Err(e) = self.save_recents()
        {
            log::warn!("{e}");
        }
    }

    fn browse(&mut self, who: &Person, open: &dyn Fn(&str) -> Option<OpenFile>) -> AccountReply {
        let mine = self.files_of(who);
        let files = mine
            .into_iter()
            .filter_map(|(id, role)| {
                let e = self.files.get(&id)?;
                let opened = self.recents.iter().find(|r| r.account == who.account && r.file == id).map(|r| r.at);
                Some(FileEntry {
                    folder: e.meta.folder.clone(),
                    sealed: e.meta.sealed,
                    thumbnail: e.meta.thumbnail,
                    info: self.file_info(&id, open)?,
                    role,
                    opened,
                })
            })
            .collect();
        AccountReply::Browse { files, folders: self.folders_of(who) }
    }

    fn set_thumbnail(&mut self, who: &Person, file: &str, image: Vec<u8>) -> Result<(), String> {
        self.editor(file, who)?;
        if image.is_empty() || image.len() > MAX_THUMBNAIL {
            return Err(format!("a preview is a PNG of at most {} KiB", MAX_THUMBNAIL >> 10));
        }
        let sealed = self.entry(file)?.meta.sealed;
        if sealed {
            // Kept as it came: only that it is a sealed value is checked.
            Sealed::from_bytes(image.clone()).map_err(|_| "this file is end-to-end encrypted: its preview must be sealed".to_string())?;
        } else if !image.starts_with(PNG) {
            return Err("a preview is a PNG".into());
        }
        let path = self.dir(file).join(THUMBNAIL);
        disk::write_atomic(&path, &image).map_err(|e| format!("couldn't keep the preview: {e}"))?;
        self.entry(file)?.meta.thumbnail = Some(now());
        self.save_meta(file)
    }

    fn get_thumbnail(&mut self, who: &Person, file: &str) -> Result<AccountReply, String> {
        self.role_or_admin(file, who)?;
        let Some(set) = self.entry(file)?.meta.thumbnail else { return Ok(AccountReply::Thumbnail { image: Vec::new(), set: 0 }) };
        let image = disk::read_capped(&self.dir(file).join(THUMBNAIL), MAX_THUMBNAIL as u64)?;
        Ok(AccountReply::Thumbnail { image, set })
    }

    /// The folder, recent-file and preview requests of an account connection.
    pub(crate) fn folder_request(&mut self, who: &Person, req: AccountReq, open: &dyn Fn(&str) -> Option<OpenFile>) -> AccountHandled {
        let failed = |reason: String| AccountHandled::from(AccountReply::Failed { reason });
        let done = |r: Result<(), String>| r.map_or_else(failed, |()| AccountReply::Done.into());
        match req {
            AccountReq::Folders => AccountReply::Folders(self.folders_of(who)).into(),
            AccountReq::CreateFolder { path } => done(self.create_folder(who, &path)),
            AccountReq::RenameFolder { from, to } => done(self.rename_folder(who, &from, &to)),
            AccountReq::RemoveFolder { path } => done(self.remove_folder(who, &path)),
            AccountReq::MoveFile { file, folder } => done(self.move_file(who, &file, &folder)),
            AccountReq::Browse => self.browse(who, open).into(),
            AccountReq::SetThumbnail { file, image } => done(self.set_thumbnail(who, &file, image)),
            AccountReq::GetThumbnail { file } => self.get_thumbnail(who, &file).map_or_else(failed, Into::into),
            _ => failed("that isn't a request about folders".into()),
        }
    }
}
