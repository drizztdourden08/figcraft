//! The editors of a sealed file on a server with accounts, as the server lists them
//! (`AccountReq::EditorKeys`): what a session checks the signatures of the batches it receives
//! against, and whether this device is one of them (it signs only then). See
//! `docs/accounts-and-e2e.md` › *Editor signatures*.
//!
//! The list is fetched before the session connects ([`MemberEditors::load`]: an answer also says
//! the server reads signed batches, so an app never sends them to one that can't), again when the
//! app learns that people or roles changed ([`MemberEditors::reload`]), and once for a device the
//! list doesn't know before its batch is refused ([`EditorKeys::refresh`]: an editor added a
//! moment ago). Each answer goes to the app too ([`Event::Editors`]), which notices when someone's
//! devices changed (their safety number).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use figcraft_collab::message::EditorDevice;
use figcraft_collab_seal::{DeviceKeys, EditorKeys};
use figcraft_engine::live::Event;

use crate::inbox::Inbox;

/// What the server says of a sealed file's editors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditorList {
    /// Batches numbered above this must be signed (`None`: not yet).
    pub signed_from: Option<u64>,
    pub editors: Vec<EditorDevice>,
}

/// Asks the server for a file's editors (the file id).
pub type FetchEditors = Box<dyn Fn(&str) -> Result<EditorList, String> + Send + Sync>;

#[derive(Default)]
struct State {
    file: String,
    signed_from: Option<u64>,
    devices: BTreeSet<[u8; 32]>,
    /// Devices fetched again for once already.
    tried: BTreeSet<[u8; 32]>,
    inbox: Option<Inbox>,
}

/// One session's editors on a server with accounts, and this device's keys (see the module docs).
pub struct MemberEditors {
    /// The server, as [`Endpoint::url`](crate::Endpoint::url) has it.
    pub server: String,
    device: Arc<DeviceKeys>,
    fetch: FetchEditors,
    state: Mutex<State>,
}

impl std::fmt::Debug for MemberEditors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberEditors").field("server", &self.server).finish_non_exhaustive()
    }
}

impl MemberEditors {
    pub fn new(server: String, device: Arc<DeviceKeys>, fetch: FetchEditors) -> MemberEditors {
        MemberEditors { server, device, fetch, state: Mutex::default() }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// This device's keys.
    pub fn device(&self) -> Arc<DeviceKeys> {
        self.device.clone()
    }

    /// Fetch `file`'s editors (answers go to the app through `inbox`): whether this device is one
    /// of them (it signs its batches then). An error: the server can't say (one older than signed
    /// batches, or not reachable), and the session goes on unsigned as before.
    pub fn load(&self, file: &str, inbox: Inbox) -> Result<bool, String> {
        {
            let mut s = self.state();
            s.file = file.to_string();
            s.inbox = Some(inbox);
        }
        self.reload()?;
        let me = self.device.public().map_err(|e| e.to_string())?.signing;
        Ok(self.state().devices.contains(&me))
    }

    /// Fetch the list again (people or roles changed).
    pub fn reload(&self) -> Result<(), String> {
        let file = self.state().file.clone();
        if file.is_empty() {
            return Err("no file yet".into());
        }
        let list = (self.fetch)(&file)?;
        let inbox = {
            let mut s = self.state();
            s.signed_from = list.signed_from;
            s.devices = list.editors.iter().map(|e| e.public.signing).collect();
            s.inbox.clone()
        };
        if let Some(inbox) = inbox {
            inbox.push(Event::Editors { server: self.server.clone(), file, editors: list.editors });
        }
        Ok(())
    }
}

impl EditorKeys for MemberEditors {
    fn required(&self) -> bool {
        self.state().signed_from.is_some()
    }

    fn required_at(&self, seq: u64) -> bool {
        self.state().signed_from.is_some_and(|from| seq > from)
    }

    fn is_editor(&self, device: &[u8; 32]) -> bool {
        self.state().devices.contains(device)
    }

    fn refresh(&self, device: &[u8; 32]) -> bool {
        if !self.state().tried.insert(*device) {
            return false;
        }
        match self.reload() {
            Ok(()) => true,
            Err(e) => {
                log::warn!("live session: the file's editors couldn't be fetched again: {e}");
                false
            }
        }
    }
}
