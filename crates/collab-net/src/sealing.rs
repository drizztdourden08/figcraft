//! The sealing layer of a sealed (end-to-end encrypted) file's session, shared by the native guest
//! and the browser driver: what the engine's sync client sends is sealed on its way out, and what
//! the server sends is opened into the plain messages the client reads. The engine never sees a
//! sealed message (see `docs/accounts-and-e2e.md` › *Sealed sessions*).
//!
//! - Out: `Changes` → `SealedChanges` (each change sealed for the file id), `Presence` →
//!   `SealedPresence` (for this client's id, once the welcome said it), a chat `Signal` →
//!   `SealedSignal`; a spotlight stays plain (the server relays it), everything else as it is.
//! - In: `SealedWelcome`, `SealedChanges` and `SealedReject` → `Welcome`, `Changes` and `Reject`;
//!   `SealedPresence` and `SealedSignal` → `Presence` and `Signal` with the sender's id.
//!
//! **A change that doesn't open is skipped, the same way on every app.** The server orders every
//! batch and sends everyone the same sealed bytes; opening is deterministic (the same keyring, file
//! id and slot either open a value or don't), so every app drops exactly the same changes from the
//! same batch and applies the rest in the same order: their copies stay the same. A welcome whose
//! document opens to nothing means the key is wrong, and the join fails with that.
//!
//! Without a key a sealed welcome ends the join ("join it with its whole link"), and the other
//! sealed messages are dropped; with one, a plain welcome or plain changes end it (a server
//! that hands out a sealed file's contents unencrypted isn't trusted with them), and plain
//! presence and chat are dropped.

use figcraft_collab::Change;
use figcraft_collab::message::{AcceptedOf, CatchUpOf, ClientMsg, ServerMsg, Signal};
use figcraft_collab::sealed::SealedChange;
use figcraft_collab_seal::{FileKey, Keyring, open_change, open_presence, open_signal, seal_change, seal_presence, seal_signal};

use crate::invite::Invite;

/// A sealed file joined without its key (a link without `#k=…`, or a join code).
pub const NEEDS_KEY: &str =
    "This file is end-to-end encrypted: join it with its whole link, including the key after #k= (join codes can't carry the key)";

/// The link's key opens nothing in the file.
pub const WRONG_KEY: &str = "The link's key doesn't open this file (it is for another file, or the link was cut): ask for the link again";

/// The link has a key, but the server sent the file in the clear.
pub const NOT_SEALED: &str =
    "This link is for an end-to-end encrypted file, but the server sent the file unencrypted: it wasn't opened (ask whoever shared it)";

/// The keys of a sealed file's session: its id and keyring.
pub(crate) struct Seal<'a> {
    file: &'a str,
    key: &'a FileKey,
    ring: Keyring,
}

impl<'a> Seal<'a> {
    /// The session behind `invite` is sealed (its link has a key).
    pub(crate) fn of(invite: &'a Invite) -> Option<Seal<'a>> {
        let key = invite.key.as_ref()?;
        Some(Seal { file: &invite.file, key, ring: Keyring::from(key.clone()) })
    }

    fn open_all(&self, changes: &[SealedChange]) -> Vec<Change> {
        changes.iter().filter_map(|c| open_change(&self.ring, self.file, c).ok()).collect()
    }

    fn open_accepted(&self, a: AcceptedOf<SealedChange>) -> AcceptedOf<Change> {
        AcceptedOf { seq: a.seq, author: a.author, batch_id: a.batch_id, changes: self.open_all(&a.changes) }
    }

    /// Seal what the sync client (or the engine) sends; `me`: this client's id, once welcomed.
    /// `None`: nothing to send (presence before the welcome). Errors: a change that can't be
    /// sealed (the session can't go on without it).
    pub(crate) fn seal(&self, me: Option<u32>, msg: ClientMsg) -> Result<Option<ClientMsg>, String> {
        let failed = |e: figcraft_collab_seal::SealError| format!("Couldn't encrypt a change for the server: {e}");
        Ok(Some(match msg {
            ClientMsg::Changes { base_seq, batch_id, changes } => {
                let changes = changes.iter().map(|c| seal_change(self.key, self.file, c)).collect::<Result<Vec<_>, _>>().map_err(failed)?;
                ClientMsg::SealedChanges { base_seq, batch_id, changes }
            }
            ClientMsg::Presence(p) => match me {
                Some(me) => ClientMsg::SealedPresence(seal_presence(self.key, self.file, me, &p).map_err(failed)?),
                None => return Ok(None),
            },
            ClientMsg::Signal(s) if s.kind != Signal::SPOTLIGHT => match me {
                Some(me) => ClientMsg::SealedSignal(seal_signal(self.key, self.file, me, &s).map_err(failed)?),
                None => return Ok(None),
            },
            other => other,
        }))
    }

    /// Open what the server sent. `Ok(None)`: drop it; `Err`: the join can't go on (why, as shown).
    pub(crate) fn open(&self, msg: ServerMsg) -> Result<Option<ServerMsg>, String> {
        Ok(Some(match msg {
            ServerMsg::SealedWelcome { session, client_id, seq, catch_up, processed, peers, access } => {
                let catch_up = match catch_up {
                    CatchUpOf::Snapshot(s) => {
                        let opened = self.open_all(&s);
                        if opened.is_empty() && !s.is_empty() {
                            return Err(WRONG_KEY.into());
                        }
                        CatchUpOf::Snapshot(opened)
                    }
                    CatchUpOf::Delta(d) => CatchUpOf::Delta(d.into_iter().map(|a| self.open_accepted(a)).collect()),
                };
                ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
            }
            ServerMsg::SealedChanges(a) => ServerMsg::Changes(self.open_accepted(a)),
            ServerMsg::SealedReject { batch_id, reason, fixes } => ServerMsg::Reject { batch_id, reason, fixes: self.open_all(&fixes) },
            ServerMsg::SealedPresence { client_id, blob } => match open_presence(&self.ring, self.file, client_id, &blob) {
                Ok(presence) => ServerMsg::Presence { client_id, presence },
                Err(_) => return Ok(None),
            },
            ServerMsg::SealedSignal { client_id, blob } => match open_signal(&self.ring, self.file, client_id, &blob) {
                Ok(signal) => ServerMsg::Signal { client_id, signal },
                Err(_) => return Ok(None),
            },
            // The file's contents in the clear: not from this file's server as it should be.
            ServerMsg::Welcome { .. } => return Err(NOT_SEALED.into()),
            ServerMsg::Changes(_) => return Err("The server sent unencrypted changes to an end-to-end encrypted file: left it".into()),
            // A refusal of something sent plain carries no contents worth taking.
            ServerMsg::Reject { batch_id, reason, .. } => ServerMsg::Reject { batch_id, reason, fixes: Vec::new() },
            // Presence and chat are sealed in a sealed file; spotlights and the server's own
            // signals stay plain.
            ServerMsg::Presence { .. } => return Ok(None),
            ServerMsg::Signal { signal, .. } if signal.kind == Signal::CHAT => return Ok(None),
            other => other,
        }))
    }
}

/// What the server sent, for a session joined without a key: a sealed file can't be opened.
pub(crate) fn unsealed(msg: ServerMsg) -> Result<Option<ServerMsg>, String> {
    match msg {
        ServerMsg::SealedWelcome { .. } => Err(NEEDS_KEY.into()),
        ServerMsg::SealedChanges(_) | ServerMsg::SealedReject { .. } | ServerMsg::SealedPresence { .. } | ServerMsg::SealedSignal { .. } => Ok(None),
        other => Ok(Some(other)),
    }
}

/// What the server sent to the session behind `invite`, opened (see the module docs).
pub(crate) fn incoming(invite: &Invite, msg: ServerMsg) -> Result<Option<ServerMsg>, String> {
    match Seal::of(invite) {
        Some(seal) => seal.open(msg),
        None => unsealed(msg),
    }
}

/// What the session behind `invite` sends, sealed when its file is (`me`: this client's id, once
/// welcomed).
pub(crate) fn outgoing(invite: &Invite, me: Option<u32>, msg: ClientMsg) -> Result<Option<ClientMsg>, String> {
    match Seal::of(invite) {
        Some(seal) => seal.seal(me, msg),
        None => Ok(Some(msg)),
    }
}
