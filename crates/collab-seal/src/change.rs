//! Changes, presence and signals with their contents sealed.

use figcraft_collab::{Change, DocProp, Entry, Json, Presence, Prop, Signal};
use figcraft_doc::{NodeId, NodeKind};
use serde::{Deserialize, Serialize};

use crate::SealError;
use crate::keys::{FileKey, Keyring, entry_id};
use crate::seal::{Sealed, Slot, open, put_str, seal};

/// A document-level entry as the server of a sealed file sees it: the kind of entry, and its key
/// with names (style, collection and variable ids, image hashes) replaced by their
/// [`entry_id`]. Comment and dev snapshot keys are numbers and stay as they are.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKey {
    Style(String),
    Comment(u64),
    Collection(String),
    Variable(String),
    DevSnapshot(NodeId),
    Image(String),
}

impl EntryKey {
    /// A tag byte, then the entry id (u32 LE length and text) or number (u64 LE).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            EntryKey::Style(id) => {
                out.push(1);
                put_str(out, id);
            }
            EntryKey::Comment(n) => {
                out.push(2);
                out.extend_from_slice(&n.to_le_bytes());
            }
            EntryKey::Collection(id) => {
                out.push(3);
                put_str(out, id);
            }
            EntryKey::Variable(id) => {
                out.push(4);
                put_str(out, id);
            }
            EntryKey::DevSnapshot(id) => {
                out.push(5);
                out.extend_from_slice(&id.0.to_le_bytes());
            }
            EntryKey::Image(id) => {
                out.push(6);
                put_str(out, id);
            }
        }
    }

    /// Whether the key is a hashed name (then the [`SealedEntry`] carries the sealed name).
    fn named(&self) -> bool {
        !matches!(self, EntryKey::Comment(_) | EntryKey::DevSnapshot(_))
    }

    /// The entry with this key and `name` (for the named kinds).
    fn entry(&self, name: Option<String>) -> Result<Entry, SealError> {
        Ok(match (self, name) {
            (EntryKey::Style(_), Some(n)) => Entry::Style(n),
            (EntryKey::Collection(_), Some(n)) => Entry::Collection(n),
            (EntryKey::Variable(_), Some(n)) => Entry::Variable(n),
            (EntryKey::Image(_), Some(n)) => Entry::Image(n),
            (EntryKey::Comment(n), None) => Entry::Comment(*n),
            (EntryKey::DevSnapshot(id), None) => Entry::DevSnapshot(*id),
            _ => return Err(SealError::Invalid("entry name doesn't match its kind".into())),
        })
    }
}

/// A document-level entry in a [`SealedChange`]: its [`EntryKey`] (what the server keys it by),
/// and for named entries the name itself, sealed (slot [`Slot::EntryName`]), so that a removal
/// opens without the reader having to know the name already.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealedEntry {
    pub key: EntryKey,
    pub name: Option<Sealed>,
}

/// A [`Change`] on a sealed file: what the server needs stays plain (ids, the node kind's tag,
/// the tree: parent and position, property names, entry keys), every other value is [`Sealed`]
/// with the JSON of the original value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SealedChange {
    /// A new node. `kind_tag` is the kind's type name (`"frame"`, `"text"`, `"page"`…:
    /// [`node_kind_tag`]), all the server learns of the kind; the whole kind (a text's contents, a
    /// vector's paths, a page's background and flows…) is `kind`, sealed for slot
    /// `Node { id, prop: Prop::Kind }`. `props` never holds `Kind`, `Parent` or `Position`.
    Create {
        id: NodeId,
        kind_tag: String,
        kind: Sealed,
        parent: Option<NodeId>,
        position: String,
        props: Vec<(Prop, Sealed)>,
    },
    /// Field property `prop` (any but `Kind`, `Parent` and `Position`) of node `id` is now `value`.
    Set {
        id: NodeId,
        prop: Prop,
        value: Sealed,
    },
    /// The node's kind is now `value` (sealed for `Prop::Kind`), whose tag is `kind_tag`, so the
    /// server can still refuse a node becoming or ceasing to be a page.
    SetKind {
        id: NodeId,
        kind_tag: String,
        value: Sealed,
    },
    /// `Prop::Parent` or `Prop::Position` of node `id`: the tree is structure, so it stays plain.
    SetTree {
        id: NodeId,
        prop: Prop,
        value: Json,
    },
    Delete {
        id: NodeId,
    },
    SetDoc {
        prop: DocProp,
        value: Sealed,
    },
    Put {
        entry: SealedEntry,
        value: Sealed,
    },
    Remove {
        entry: SealedEntry,
    },
}

impl SealedChange {
    /// The node this change is about, if any.
    pub fn node(&self) -> Option<NodeId> {
        match self {
            SealedChange::Create { id, .. }
            | SealedChange::Set { id, .. }
            | SealedChange::SetKind { id, .. }
            | SealedChange::SetTree { id, .. }
            | SealedChange::Delete { id } => Some(*id),
            _ => None,
        }
    }
}

/// The type name of a node kind's JSON (`{"type": "frame", …}` → `"frame"`).
pub fn kind_tag(kind: &Json) -> Option<String> {
    kind.0.get("type").and_then(|t| t.as_str()).map(str::to_string)
}

/// The tag of `kind`: its serde type name, the same as [`kind_tag`] of its JSON.
pub fn node_kind_tag(kind: &NodeKind) -> &'static str {
    match kind {
        NodeKind::Page { .. } => "page",
        NodeKind::Frame => "frame",
        NodeKind::Group => "group",
        NodeKind::Section { .. } => "section",
        NodeKind::Rectangle => "rectangle",
        NodeKind::Ellipse { .. } => "ellipse",
        NodeKind::Polygon { .. } => "polygon",
        NodeKind::Star { .. } => "star",
        NodeKind::Line => "line",
        NodeKind::Vector { .. } => "vector",
        NodeKind::Text(_) => "text",
        NodeKind::BooleanOp { .. } => "booleanOp",
        NodeKind::Component { .. } => "component",
        NodeKind::ComponentSet { .. } => "componentSet",
        NodeKind::Instance { .. } => "instance",
        NodeKind::Slice => "slice",
    }
}

/// Whether a kind tag is a page's ([`Node::is_page`](figcraft_doc::Node::is_page)).
pub fn is_page_tag(tag: &str) -> bool {
    tag == "page"
}

/// Whether nodes of a kind tag hold layers ([`NodeKind::is_container`]).
pub fn is_container_tag(tag: &str) -> bool {
    matches!(tag, "page" | "frame" | "group" | "section" | "booleanOp" | "component" | "componentSet" | "instance")
}

/// The tree properties, which stay plain.
fn is_tree(prop: Prop) -> bool {
    matches!(prop, Prop::Parent | Prop::Position)
}

fn seal_json(key: &FileKey, file: &str, slot: &Slot, value: &Json) -> Result<Sealed, SealError> {
    let bytes = serde_json::to_vec(&value.0).map_err(|e| SealError::Invalid(e.to_string()))?;
    seal(key, file, slot, &bytes)
}

fn open_json(keyring: &Keyring, file: &str, slot: &Slot, sealed: &Sealed) -> Result<Json, SealError> {
    let bytes = open(keyring, file, slot, sealed)?;
    // serde_json caps nesting depth, so hostile input can't overflow the stack.
    serde_json::from_slice(&bytes).map(Json).map_err(|e| SealError::Invalid(e.to_string()))
}

fn seal_entry(key: &FileKey, file: &str, entry: &Entry) -> Result<SealedEntry, SealError> {
    let (k, name) = match entry {
        Entry::Style(n) => (EntryKey::Style(entry_id(key, n)?), Some(n)),
        Entry::Collection(n) => (EntryKey::Collection(entry_id(key, n)?), Some(n)),
        Entry::Variable(n) => (EntryKey::Variable(entry_id(key, n)?), Some(n)),
        Entry::Image(n) => (EntryKey::Image(entry_id(key, n)?), Some(n)),
        Entry::Comment(n) => (EntryKey::Comment(*n), None),
        Entry::DevSnapshot(id) => (EntryKey::DevSnapshot(*id), None),
    };
    let name = match name {
        Some(n) => Some(seal(key, file, &Slot::EntryName(k.clone()), n.as_bytes())?),
        None => None,
    };
    Ok(SealedEntry { key: k, name })
}

fn open_entry(keyring: &Keyring, file: &str, entry: &SealedEntry) -> Result<Entry, SealError> {
    let name = match (&entry.name, entry.key.named()) {
        (Some(sealed), true) => {
            let bytes = open(keyring, file, &Slot::EntryName(entry.key.clone()), sealed)?;
            let name = String::from_utf8(bytes).map_err(|_| SealError::Invalid("entry name isn't UTF-8".into()))?;
            // The name must hash to the key the server stores it under (the names secret is the
            // same in every epoch, so the sealing epoch's key will do).
            let key = keyring.get(sealed.epoch()).ok_or(SealError::UnknownEpoch(sealed.epoch()))?;
            let id = entry_id(key, &name)?;
            let expected = match &entry.key {
                EntryKey::Style(i) | EntryKey::Collection(i) | EntryKey::Variable(i) | EntryKey::Image(i) => i,
                EntryKey::Comment(_) | EntryKey::DevSnapshot(_) => return Err(SealError::Invalid("unnamed entry".into())),
            };
            if &id != expected {
                return Err(SealError::Invalid("entry name doesn't match its id".into()));
            }
            Some(name)
        }
        (None, false) => None,
        _ => return Err(SealError::Invalid("entry name doesn't match its kind".into())),
    };
    entry.key.entry(name)
}

/// Seal `change` for `file` with `key` (the keyring's current key).
pub fn seal_change(key: &FileKey, file: &str, change: &Change) -> Result<SealedChange, SealError> {
    Ok(match change {
        Change::Create { id, kind, parent, position, props } => {
            let tag = kind_tag(kind).ok_or_else(|| SealError::Invalid("node kind without a type".into()))?;
            let sealed_kind = seal_json(key, file, &Slot::Node { id: *id, prop: Prop::Kind }, kind)?;
            let props = props
                .iter()
                .map(|(p, v)| {
                    if *p == Prop::Kind || is_tree(*p) {
                        return Err(SealError::Invalid(format!("{p:?} isn't a created node's property")));
                    }
                    Ok((*p, seal_json(key, file, &Slot::Node { id: *id, prop: *p }, v)?))
                })
                .collect::<Result<Vec<_>, SealError>>()?;
            SealedChange::Create { id: *id, kind_tag: tag, kind: sealed_kind, parent: *parent, position: position.clone(), props }
        }
        Change::Set { id, prop: Prop::Kind, value } => {
            let tag = kind_tag(value).ok_or_else(|| SealError::Invalid("node kind without a type".into()))?;
            SealedChange::SetKind { id: *id, kind_tag: tag, value: seal_json(key, file, &Slot::Node { id: *id, prop: Prop::Kind }, value)? }
        }
        Change::Set { id, prop, value } if is_tree(*prop) => SealedChange::SetTree { id: *id, prop: *prop, value: value.clone() },
        Change::Set { id, prop, value } => {
            SealedChange::Set { id: *id, prop: *prop, value: seal_json(key, file, &Slot::Node { id: *id, prop: *prop }, value)? }
        }
        Change::Delete { id } => SealedChange::Delete { id: *id },
        Change::SetDoc { prop, value } => SealedChange::SetDoc { prop: *prop, value: seal_json(key, file, &Slot::Doc { prop: *prop }, value)? },
        Change::Put { entry, value } => {
            let entry = seal_entry(key, file, entry)?;
            let value = seal_json(key, file, &Slot::Entry(entry.key.clone()), value)?;
            SealedChange::Put { entry, value }
        }
        Change::Remove { entry } => SealedChange::Remove { entry: seal_entry(key, file, entry)? },
    })
}

/// Open a sealed change of `file`. Fails when any value doesn't open for its slot, or when the
/// plain parts contradict the sealed ones (a kind's type name, an entry name's id): apps skip such
/// a change, all the same way.
pub fn open_change(keyring: &Keyring, file: &str, sealed: &SealedChange) -> Result<Change, SealError> {
    Ok(match sealed {
        SealedChange::Create { id, kind_tag: tag, kind, parent, position, props } => {
            let k = open_json(keyring, file, &Slot::Node { id: *id, prop: Prop::Kind }, kind)?;
            if kind_tag(&k).as_deref() != Some(tag.as_str()) {
                return Err(SealError::Invalid("node kind doesn't match its tag".into()));
            }
            let props = props
                .iter()
                .map(|(p, v)| {
                    if *p == Prop::Kind || is_tree(*p) {
                        return Err(SealError::Invalid(format!("{p:?} isn't a created node's property")));
                    }
                    Ok((*p, open_json(keyring, file, &Slot::Node { id: *id, prop: *p }, v)?))
                })
                .collect::<Result<Vec<_>, SealError>>()?;
            Change::Create { id: *id, kind: k, parent: *parent, position: position.clone(), props }
        }
        SealedChange::Set { id, prop, value } => {
            if *prop == Prop::Kind || is_tree(*prop) {
                return Err(SealError::Invalid(format!("{prop:?} isn't sealed with Set")));
            }
            Change::Set { id: *id, prop: *prop, value: open_json(keyring, file, &Slot::Node { id: *id, prop: *prop }, value)? }
        }
        SealedChange::SetKind { id, kind_tag: tag, value } => {
            let value = open_json(keyring, file, &Slot::Node { id: *id, prop: Prop::Kind }, value)?;
            if kind_tag(&value).as_deref() != Some(tag.as_str()) {
                return Err(SealError::Invalid("node kind doesn't match its tag".into()));
            }
            Change::Set { id: *id, prop: Prop::Kind, value }
        }
        SealedChange::SetTree { id, prop, value } => {
            if !is_tree(*prop) {
                return Err(SealError::Invalid(format!("{prop:?} isn't a tree property")));
            }
            Change::Set { id: *id, prop: *prop, value: value.clone() }
        }
        SealedChange::Delete { id } => Change::Delete { id: *id },
        SealedChange::SetDoc { prop, value } => Change::SetDoc { prop: *prop, value: open_json(keyring, file, &Slot::Doc { prop: *prop }, value)? },
        SealedChange::Put { entry, value } => {
            let value = open_json(keyring, file, &Slot::Entry(entry.key.clone()), value)?;
            Change::Put { entry: open_entry(keyring, file, entry)?, value }
        }
        SealedChange::Remove { entry } => Change::Remove { entry: open_entry(keyring, file, entry)? },
    })
}

/// Seal session client `client`'s presence (slot [`Slot::Presence`], the presence subkey).
pub fn seal_presence(key: &FileKey, file: &str, client: u32, presence: &Presence) -> Result<Sealed, SealError> {
    let bytes = serde_json::to_vec(presence).map_err(|e| SealError::Invalid(e.to_string()))?;
    seal(key, file, &Slot::Presence { client }, &bytes)
}

pub fn open_presence(keyring: &Keyring, file: &str, client: u32, sealed: &Sealed) -> Result<Presence, SealError> {
    let bytes = open(keyring, file, &Slot::Presence { client }, sealed)?;
    serde_json::from_slice(&bytes).map_err(|e| SealError::Invalid(e.to_string()))
}

/// Seal a signal from session client `client` (cursor chat; a spotlight stays plain, as the
/// design says, so the server can relay "follow me").
pub fn seal_signal(key: &FileKey, file: &str, client: u32, signal: &Signal) -> Result<Sealed, SealError> {
    let bytes = serde_json::to_vec(signal).map_err(|e| SealError::Invalid(e.to_string()))?;
    seal(key, file, &Slot::Signal { client }, &bytes)
}

/// Open a signal and make it safe to show ([`Signal::clean`]); an unknown or malformed one fails.
pub fn open_signal(keyring: &Keyring, file: &str, client: u32, sealed: &Sealed) -> Result<Signal, SealError> {
    let bytes = open(keyring, file, &Slot::Signal { client }, sealed)?;
    let signal: Signal = serde_json::from_slice(&bytes).map_err(|e| SealError::Invalid(e.to_string()))?;
    signal.clean().ok_or_else(|| SealError::Invalid("unknown or malformed signal".into()))
}
