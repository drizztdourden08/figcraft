//! Folders and pictures of your files on a server with accounts (milestone M9): the home screen's
//! Files tab of a server shows your files there as cards in folders.
//!
//! The commands are defined now so the app can be built against them; the server requests they
//! need are being added to the protocol. Until a server (and this build) has them, each command
//! says so, and the app shows your files without folders and with plain pictures.

use serde_json::Value;

use crate::cmd::CommandSpec;
use crate::params::req_string;
use crate::{Result, Session, bad, spec};

/// What a server that keeps no folders or pictures (yet) says.
pub const NO_FOLDERS: &str = "folders and file pictures aren't available on this server yet";

/// The command, checked: you are signed in on its server. Every command answers that folders
/// aren't available until the protocol has them.
fn unavailable(s: &Session, cmd: &str, p: &Value, needs: &[&str]) -> Result<Value> {
    for key in needs {
        req_string(cmd, p, key)?;
    }
    let server = s.account_server(cmd, p)?;
    if s.signed_in(&server).is_none() {
        return Err(bad(cmd, "you aren't signed in to this server: `account.signIn` first"));
    }
    Err(bad(cmd, NO_FOLDERS))
}

pub fn specs() -> Vec<CommandSpec> {
    vec![
        spec!(
            "account.folders",
            "Your folders on server",
            "{server?} → {server, folders: [path]}: the folders your files are in on a server with accounts (`account.files` gives each file's `folder`)",
            false,
            |s, p| unavailable(s, "account.folders", p, &[])
        ),
        spec!("account.createFolder", "New folder on server", "{path, server?} → {server, path}: makes a folder", false, |s, p| unavailable(
            s,
            "account.createFolder",
            p,
            &["path"]
        )),
        spec!(
            "account.renameFolder",
            "Rename folder on server",
            "{path, to, server?} → {server, path}: renames a folder (its files go with it)",
            false,
            |s, p| unavailable(s, "account.renameFolder", p, &["path", "to"])
        ),
        spec!("account.removeFolder", "Remove folder on server", "{path, server?} → {server, removed}: removes an empty folder", false, |s, p| {
            unavailable(s, "account.removeFolder", p, &["path"])
        }),
        spec!(
            "account.moveFile",
            "Move file to folder",
            "{file, folder (\"\": the top), server?} → {server, file, folder}: puts a file of yours in a folder",
            false,
            |s, p| unavailable(s, "account.moveFile", p, &["file", "folder"])
        ),
        spec!(
            "account.thumbnail",
            "File picture",
            "{file, server?} → {server, file, png (base64)}: the picture of a file of yours (a sealed file's is opened with its key)",
            false,
            |s, p| unavailable(s, "account.thumbnail", p, &["file"])
        ),
    ]
}
