//! The data of sealed (end-to-end encrypted) files, as the session server sees it: [`Sealed`]
//! values (their shape only), [`SealedChange`]s with their structure plain, entry keys and node
//! kind tags. No cryptography: sealing and opening live in `figcraft-collab-seal`, which re-exports
//! these types; they are here so the session messages and the session server for sealed files
//! ([`OpaqueReplica`](crate::OpaqueReplica)) can carry them. See `docs/accounts-and-e2e.md` ›
//! *Sealed files*.

use figcraft_doc::{NodeId, NodeKind};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::change::{DocProp, Json, Prop};

/// Largest plaintext a [`Sealed`] value holds: padded with its length prefix, it fills 64 MiB.
pub const MAX_PLAINTEXT: usize = (1 << 26) - 4;
/// Epoch (4) and nonce (24) in front of the ciphertext.
pub const SEALED_HEADER: usize = 4 + 24;
/// The Poly1305 tag after it.
pub const SEALED_TAG: usize = 16;
/// The smallest padded plaintext.
pub const MIN_PADDED: usize = 64;

/// The padded size of an `n`-byte plaintext: its 4-byte length prefix and the plaintext, rounded
/// up to 64 B, 256 B, 1 KiB, then the next power of two (`None` above [`MAX_PLAINTEXT`]).
pub fn padded_len(n: usize) -> Option<usize> {
    if n > MAX_PLAINTEXT {
        return None;
    }
    let framed = n + 4;
    Some(match framed {
        0..=64 => 64,
        65..=256 => 256,
        257..=1024 => 1024,
        _ => framed.next_power_of_two(),
    })
}

/// A sealed value: `epoch (u32 LE) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, XChaCha20-Poly1305 over
/// the padded plaintext (see [`padded_len`]). Its length always says the padded size, so a server
/// can check it and nothing else: [`Sealed::from_bytes`] (and deserializing) accepts only lengths a
/// real sealed value has.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SealedBytes", into = "SealedBytes")]
pub struct Sealed(Vec<u8>);

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealed(epoch {}, {} bytes)", self.epoch(), self.0.len())
    }
}

/// Serde form of [`Sealed`]: bytes, or base64url in JSON.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SealedBytes(#[serde(with = "bin")] Vec<u8>);

impl TryFrom<SealedBytes> for Sealed {
    type Error = Error;
    fn try_from(b: SealedBytes) -> Result<Sealed, Error> {
        Sealed::from_bytes(b.0)
    }
}

impl From<Sealed> for SealedBytes {
    fn from(s: Sealed) -> SealedBytes {
        SealedBytes(s.0)
    }
}

impl Sealed {
    /// Check the shape of untrusted bytes (length only: whether they open is for whoever holds the
    /// key).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Sealed, Error> {
        let malformed = || Error::Decode("malformed sealed value".into());
        let padded = bytes.len().checked_sub(SEALED_HEADER + SEALED_TAG).ok_or_else(malformed)?;
        if !(MIN_PADDED..=MAX_PLAINTEXT + 4).contains(&padded) || padded_len(padded.saturating_sub(4)) != Some(padded) {
            return Err(malformed());
        }
        Ok(Sealed(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The epoch of the key it was sealed with.
    pub fn epoch(&self) -> u32 {
        let mut e = [0u8; 4];
        if let Some(b) = self.0.get(..4) {
            e.copy_from_slice(b);
        }
        u32::from_le_bytes(e)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a sealed file's name looks like in [`FileInfo::name`](crate::message::FileInfo::name)
/// and the other listings: this prefix, then the sealed name (slot `Meta { what: "name" }`) as
/// unpadded base64url. Apps that know sealed files open it; older ones show it as it is.
pub const SEALED_NAME_PREFIX: &str = "sealed:";

/// A sealed file name as listings carry it ([`SEALED_NAME_PREFIX`]).
pub fn sealed_name_text(name: &Sealed) -> String {
    use base64::Engine as _;
    format!("{SEALED_NAME_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(name.as_bytes()))
}

/// The sealed name in a listing's file name (`None`: a plain name).
pub fn parse_sealed_name(text: &str) -> Option<Sealed> {
    use base64::Engine as _;
    let b64 = text.strip_prefix(SEALED_NAME_PREFIX)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).ok()?;
    Sealed::from_bytes(bytes).ok()
}

/// The bytes of a [`Wrapped`] file key's ciphertext: a 68-byte file key and its 16-byte tag.
pub const WRAPPED_CIPHERTEXT: usize = 84;

/// A device's public keys, registered with a server under its owner's account
/// (`docs/accounts-and-e2e.md` › *Keys*): the data only (`figcraft-collab-seal` makes and uses
/// them).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DevicePublic {
    /// X25519 public key: file keys are wrapped to it.
    #[serde(with = "bin")]
    pub agreement: [u8; 32],
    /// Ed25519 public key: checks the device's signatures.
    #[serde(with = "bin")]
    pub signing: [u8; 32],
}

/// A file key wrapped to one device: RFC 9180 HPKE base mode, DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, ChaCha20-Poly1305, `info` = `"figcraft file key v1"`, associated data = the file
/// id; the plaintext is the 68-byte file key, so the ciphertext is [`WRAPPED_CIPHERTEXT`] bytes.
/// Wrapping and unwrapping live in `figcraft-collab-seal`; servers keep these as they come
/// (`keyring.json`) and can't open them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Wrapped {
    /// The encapsulated (ephemeral X25519 public) key.
    #[serde(with = "bin")]
    pub enc: [u8; 32],
    #[serde(with = "bin")]
    pub ciphertext: Vec<u8>,
}

impl Wrapped {
    /// `enc (32) ‖ ciphertext (84)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ciphertext.len());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Wrapped, Error> {
        let malformed = || Error::Decode("malformed wrapped key".into());
        if bytes.len() != 32 + WRAPPED_CIPHERTEXT {
            return Err(malformed());
        }
        let enc: [u8; 32] = bytes.get(..32).and_then(|b| b.try_into().ok()).ok_or_else(malformed)?;
        let ciphertext = bytes.get(32..).ok_or_else(malformed)?.to_vec();
        Ok(Wrapped { enc, ciphertext })
    }

    /// Its shape is a wrapped file key's (whether it opens is for the device it was wrapped to).
    pub fn well_formed(&self) -> bool {
        self.ciphertext.len() == WRAPPED_CIPHERTEXT
    }
}

/// A document-level entry as the server of a sealed file sees it: the kind of entry, and its key
/// with names (style, collection and variable ids, image hashes) replaced by their entry ids
/// (`figcraft_collab_seal::entry_id`). Comment and dev snapshot keys are numbers and stay as they
/// are.
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
    /// The key as it is bound into a sealed value's associated data: a tag byte, then the entry id
    /// (u32 LE length and text) or number (u64 LE).
    pub fn encode(&self, out: &mut Vec<u8>) {
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
    pub fn named(&self) -> bool {
        !matches!(self, EntryKey::Comment(_) | EntryKey::DevSnapshot(_))
    }

    /// The client id space the entry's key lies in, where the server can still tell: comment ids
    /// ([`Entry::id_space`](crate::Entry::id_space)). Hashed names have none; dev snapshots and
    /// images aren't checked (as on plain files).
    pub fn id_space(&self) -> Option<u32> {
        match self {
            EntryKey::Comment(id) => Some(figcraft_doc::ids::space_of(*id)),
            _ => None,
        }
    }

    /// The ordered list of the document the entry is in (dev snapshots and images aren't).
    pub fn list(&self) -> Option<DocProp> {
        match self {
            EntryKey::Style(_) => Some(DocProp::Styles),
            EntryKey::Comment(_) => Some(DocProp::Comments),
            EntryKey::Collection(_) => Some(DocProp::Collections),
            EntryKey::Variable(_) => Some(DocProp::Variables),
            EntryKey::DevSnapshot(_) | EntryKey::Image(_) => None,
        }
    }

    /// What the entry is, for messages ("comment thread 7").
    pub fn describe(&self) -> String {
        match self {
            EntryKey::Style(_) => "style".into(),
            EntryKey::Comment(id) => format!("comment thread {id}"),
            EntryKey::Collection(_) => "variable collection".into(),
            EntryKey::Variable(_) => "variable".into(),
            EntryKey::DevSnapshot(id) => format!("ready-for-dev snapshot of {id}"),
            EntryKey::Image(_) => "image".into(),
        }
    }
}

/// A document-level entry in a [`SealedChange`]: its [`EntryKey`] (what the server keys it by),
/// and for named entries the name itself, sealed (slot `EntryName`), so that a removal opens
/// without the reader having to know the name already.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealedEntry {
    pub key: EntryKey,
    pub name: Option<Sealed>,
}

/// A [`Change`](crate::Change) on a sealed file: what the server needs stays plain (ids, the node
/// kind's tag, the tree: parent and position, property names, entry keys), every other value is
/// [`Sealed`] with the JSON of the original value.
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

    /// About how many bytes the change takes in memory.
    pub fn weight(&self) -> usize {
        let entry = |e: &SealedEntry| 48 + e.name.as_ref().map_or(0, Sealed::len);
        match self {
            SealedChange::Create { kind_tag, kind, position, props, .. } => {
                props.iter().map(|(_, v)| 16 + v.len()).fold(64 + kind_tag.len() + kind.len() + position.len(), usize::saturating_add)
            }
            SealedChange::Set { value, .. } | SealedChange::SetDoc { value, .. } => 32 + value.len(),
            SealedChange::SetKind { kind_tag, value, .. } => 32 + kind_tag.len() + value.len(),
            SealedChange::SetTree { value, .. } => 32 + value.0.to_string().len(),
            SealedChange::Delete { .. } => 16,
            SealedChange::Put { entry: e, value } => entry(e).saturating_add(value.len()),
            SealedChange::Remove { entry: e } => entry(e),
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

/// Every kind tag there is.
pub const KIND_TAGS: &[&str] = &[
    "page",
    "frame",
    "group",
    "section",
    "rectangle",
    "ellipse",
    "polygon",
    "star",
    "line",
    "vector",
    "text",
    "booleanOp",
    "component",
    "componentSet",
    "instance",
    "slice",
];

/// Whether a kind tag is a page's ([`Node::is_page`](figcraft_doc::Node::is_page)).
pub fn is_page_tag(tag: &str) -> bool {
    tag == "page"
}

/// Whether nodes of a kind tag hold layers ([`NodeKind::is_container`]).
pub fn is_container_tag(tag: &str) -> bool {
    matches!(tag, "page" | "frame" | "group" | "section" | "booleanOp" | "component" | "componentSet" | "instance")
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Serde for byte strings: raw bytes in binary formats (postcard), unpadded base64url text in
/// human-readable ones (JSON).
pub mod bin {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserializer, Serializer, de};

    pub fn serialize<T: AsRef<[u8]>, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() { s.serialize_str(&URL_SAFE_NO_PAD.encode(v.as_ref())) } else { s.serialize_bytes(v.as_ref()) }
    }

    pub fn deserialize<'de, T: TryFrom<Vec<u8>>, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        struct Bytes;
        impl<'de> de::Visitor<'de> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes or base64url text")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                URL_SAFE_NO_PAD.decode(v).map_err(E::custom)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        let bytes = if d.is_human_readable() { d.deserialize_str(Bytes)? } else { d.deserialize_byte_buf(Bytes)? };
        let len = bytes.len();
        T::try_from(bytes).map_err(|_| de::Error::invalid_length(len, &"the expected number of bytes"))
    }
}
