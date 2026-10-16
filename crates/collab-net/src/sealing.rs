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
//!
//! **Editor signatures** (step 10, [`SealingKeys`]): with a device key, every batch sent ends with
//! the device's signature ([`sign_batch`]); every batch that arrives (live or in a catch-up) has
//! its signature checked against the editors this app knows ([`check_batch`]) before it opens. A
//! signature that doesn't hold, an unsigned batch where editors must sign, or a device that isn't
//! an editor's ends the session (the apps' lists of editors may differ for a moment, so skipping
//! such a batch could leave copies different). The opened changes then go to the sync client,
//! which checks their values with the sealed rules (`Client::join_sealed`).

use std::sync::Arc;

use figcraft_collab::Change;
use figcraft_collab::message::{AcceptedOf, CatchUpOf, ClientMsg, LibraryReply, LibraryReq, ServerMsg, Signal};
use figcraft_collab::sealed::{Sealed, SealedChange};
use figcraft_collab_seal::{
    AnyEditor, DeviceKeys, EditorKeys, FileKey, Keyring, SealError, Slot, check_batch, open, open_change, open_presence, open_signal, seal,
    seal_change, seal_presence, seal_signal, sign_batch,
};
pub use figcraft_engine::devices::NEW_EPOCH;

use crate::invite::Invite;

/// The keys a sealed session signs its batches with and checks others' against (from
/// [`GuestConfig::sealing`](crate::join::GuestConfig::sealing)). Without a signer batches go
/// unsigned; without editors any signature that holds is taken, and unsigned batches too
/// ([`AnyEditor`]).
#[derive(Clone, Default)]
pub struct SealingKeys {
    /// This device's keys: every batch sent is signed with them.
    pub signer: Option<Arc<DeviceKeys>>,
    /// Who may edit the file, by device: what the batches that arrive are checked against.
    pub editors: Option<Arc<dyn EditorKeys>>,
}

impl std::fmt::Debug for SealingKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingKeys").field("signer", &self.signer.is_some()).field("editors", &self.editors.is_some()).finish()
    }
}

/// A sealed file joined without its key (a link without `#k=…`, or a join code).
pub const NEEDS_KEY: &str =
    "This file is end-to-end encrypted: join it with its whole link, including the key after #k= (join codes can't carry the key)";

/// The link's key opens nothing in the file.
pub const WRONG_KEY: &str = "The link's key doesn't open this file (it is for another file, or the link was cut): ask for the link again";

/// The link has a key, but the server sent the file in the clear.
pub const NOT_SEALED: &str =
    "This link is for an end-to-end encrypted file, but the server sent the file unencrypted: it wasn't opened (ask whoever shared it)";

/// The keys of a sealed file's session: its id, the key new writes are sealed with (the newest
/// epoch) and every epoch held (what opens).
pub(crate) struct Seal<'a> {
    file: &'a str,
    key: FileKey,
    ring: Keyring,
    keys: &'a SealingKeys,
}

impl<'a> Seal<'a> {
    /// The session behind `invite` is sealed (its link has a key). Read again for every message:
    /// the app may add a newer epoch while the session runs.
    pub(crate) fn of(invite: &'a Invite, keys: &'a SealingKeys) -> Option<Seal<'a>> {
        let ring = invite.key.as_ref()?.ring();
        let key = ring.current()?.clone();
        Some(Seal { file: &invite.file, key, ring, keys })
    }

    /// The changes that open. One sealed with an epoch newer than every key held means the file's
    /// key moved on (someone was taken out): the session ends with [`NEW_EPOCH`] and the app
    /// fetches the new key and joins again, rather than skip what everyone else opens.
    fn open_all(&self, changes: &[SealedChange]) -> Result<Vec<Change>, String> {
        let newest = self.key.epoch();
        let mut out = Vec::with_capacity(changes.len());
        for c in changes {
            match open_change(&self.ring, self.file, c) {
                Ok(c) => out.push(c),
                Err(SealError::UnknownEpoch(e)) if e > newest => return Err(NEW_EPOCH.into()),
                Err(_) => {}
            }
        }
        Ok(out)
    }

    /// Check a batch's signature, then open it. `Err`: the session can't go on.
    fn open_accepted(&self, a: AcceptedOf<SealedChange>) -> Result<AcceptedOf<Change>, String> {
        let editors: &dyn EditorKeys = self.keys.editors.as_deref().unwrap_or(&AnyEditor);
        let body = check_batch(editors, self.file, a.batch_id, &a.changes).map_err(|e| {
            log::warn!("live session: sealed batch {} from client {} refused: {e:?}", a.seq, a.author);
            e.to_string()
        })?;
        Ok(AcceptedOf { seq: a.seq, author: a.author, batch_id: a.batch_id, changes: self.open_all(body)? })
    }

    /// Seal what the sync client (or the engine) sends; `me`: this client's id, once welcomed.
    /// `None`: nothing to send (presence before the welcome). Errors: a change that can't be
    /// sealed (the session can't go on without it).
    pub(crate) fn seal(&self, me: Option<u32>, msg: ClientMsg) -> Result<Option<ClientMsg>, String> {
        let failed = |e: figcraft_collab_seal::SealError| format!("Couldn't encrypt a change for the server: {e}");
        Ok(Some(match msg {
            ClientMsg::Changes { base_seq, batch_id, changes } => {
                let mut changes = changes.iter().map(|c| seal_change(&self.key, self.file, c)).collect::<Result<Vec<_>, _>>().map_err(failed)?;
                if let Some(device) = &self.keys.signer {
                    let signature = sign_batch(device, self.file, self.key.epoch(), base_seq, batch_id, &changes).map_err(failed)?;
                    changes.push(signature);
                }
                ClientMsg::SealedChanges { base_seq, batch_id, changes }
            }
            ClientMsg::Presence(p) => match me {
                Some(me) => ClientMsg::SealedPresence(seal_presence(&self.key, self.file, me, &p).map_err(failed)?),
                None => return Ok(None),
            },
            ClientMsg::Signal(s) if s.kind != Signal::SPOTLIGHT => match me {
                Some(me) => ClientMsg::SealedSignal(seal_signal(&self.key, self.file, me, &s).map_err(failed)?),
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
                        let opened = self.open_all(&s)?;
                        if opened.is_empty() && !s.is_empty() {
                            return Err(WRONG_KEY.into());
                        }
                        CatchUpOf::Snapshot(opened)
                    }
                    CatchUpOf::Delta(d) => CatchUpOf::Delta(d.into_iter().map(|a| self.open_accepted(a)).collect::<Result<_, _>>()?),
                };
                ServerMsg::Welcome { session, client_id, seq, catch_up, processed, peers, access }
            }
            ServerMsg::SealedChanges(a) => ServerMsg::Changes(self.open_accepted(a)?),
            ServerMsg::SealedReject { batch_id, reason, fixes } => ServerMsg::Reject { batch_id, reason, fixes: self.open_all(&fixes)? },
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

/// The slot a sealed file's team library archive is sealed for.
fn library_slot() -> Slot {
    Slot::Meta { what: "library".into() }
}

/// The team library of a sealed file doesn't open with the link's key.
pub const LIBRARY_WONT_OPEN: &str = "This file's team library is end-to-end encrypted and doesn't open with the link's key (or the server sent it unencrypted): ask for the link again";

/// A library request about the file behind `invite`: a sealed file's archive is sealed for its
/// [`Slot::Meta`] `"library"` on the way out, with the newest key held (the server keeps it as it
/// comes and checks nothing in it; the apps check what they open).
pub(crate) fn library_out(invite: &Invite, req: LibraryReq) -> Result<LibraryReq, String> {
    let ring = invite.key.as_ref().map(|k| k.ring());
    match (req, ring.as_ref().and_then(Keyring::current)) {
        (LibraryReq::Publish { archive }, Some(key)) => {
            let sealed = seal(key, &invite.file, &library_slot(), &archive).map_err(|e| format!("Couldn't encrypt the team library: {e}"))?;
            Ok(LibraryReq::Publish { archive: sealed.into_bytes() })
        }
        (req, _) => Ok(req),
    }
}

/// The server's answer to a library request about the file behind `invite`: a sealed file's
/// archive opened with any epoch held (one that doesn't open, or came unencrypted, is refused).
pub(crate) fn library_in(invite: &Invite, reply: LibraryReply) -> Result<LibraryReply, String> {
    match (reply, invite.key.as_ref()) {
        (LibraryReply::Library { version, archive }, Some(keys)) => {
            let sealed = Sealed::from_bytes(archive).map_err(|_| LIBRARY_WONT_OPEN.to_string())?;
            let archive = open(&keys.ring(), &invite.file, &library_slot(), &sealed).map_err(|_| LIBRARY_WONT_OPEN.to_string())?;
            Ok(LibraryReply::Library { version, archive })
        }
        (reply, _) => Ok(reply),
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

/// What the server sent to the session behind `invite`, opened and checked with `keys` (see the
/// module docs).
pub(crate) fn incoming(invite: &Invite, keys: &SealingKeys, msg: ServerMsg) -> Result<Option<ServerMsg>, String> {
    match Seal::of(invite, keys) {
        Some(seal) => seal.open(msg),
        None => unsealed(msg),
    }
}

/// What the session behind `invite` sends, sealed (and signed, with a signer in `keys`) when its
/// file is (`me`: this client's id, once welcomed).
pub(crate) fn outgoing(invite: &Invite, keys: &SealingKeys, me: Option<u32>, msg: ClientMsg) -> Result<Option<ClientMsg>, String> {
    match Seal::of(invite, keys) {
        Some(seal) => seal.seal(me, msg),
        None => Ok(Some(msg)),
    }
}
