//! The value rules every app applies to a sealed file's batches ([`Mode::Sealed`]), and their
//! version.
//!
//! On a plain file the session server checks every value ([`Replica::apply`] in
//! [`Mode::Strict`]) and refuses a batch that breaks a rule. On a sealed file it can't read the
//! values, so each app checks them after opening a batch, and all of them must come to the same
//! document. The rules are therefore a pure function of the batch and the document before it, the
//! same in every app speaking one rules version ([`SEALED_RULES`]); a server refuses a sealed
//! file's hello from an app with another version.
//!
//! **Rules version 1** (`rules1`), one change at a time, in batch order:
//!
//! 1. A node property (in a `Create` or a `Set`) whose value doesn't read as the property's type,
//!    or breaks a value rule — width and height finite, at least 0 and at most [`MAX_COORD`]; every
//!    transform coefficient finite and within ±[`MAX_COORD`]; opacity finite and in 0..=1 — takes
//!    the value a new rectangle has, whatever the node's kind ([`fallback`]: opacity 1, size 0, no
//!    transform…). Not "keep the old value": the server keeps only the latest sealed value of each
//!    property, so an app that joins later (from a snapshot) sees the bad value without the
//!    history, and must come to the same document as an app that saw the batch; and not the
//!    node's own kind's defaults, since its kind may change after the bad value was written.
//! 2. A node kind (in a `Create` or a `Set` of `kind`) that doesn't read becomes the plain kind of
//!    its type name (a polygon with 3 sides, an empty text, a union…; the type name itself was
//!    checked against the plain tag the server saw when the change was opened).
//! 3. A document property that doesn't read takes a new document's value; an entry (style,
//!    variable, comment, image…) whose value doesn't read is removed.
//! 4. Anything else that can't apply (a node that doesn't exist or already does, a page with a
//!    parent, a layer inside a layer that can't hold layers, a bad position key…) is skipped. The
//!    server already refuses those batches by their visible structure, so an honest server never
//!    sends them.
//!
//! Every change applies on its own: a batch is no longer all-or-nothing, and nothing fails the
//! session. One difference is known: an entry whose value doesn't read is removed, and if it is
//! put again later it goes to the end of its list in the apps that saw it removed, where an app
//! that joins later finds it where it first was (the same entries, in another order until the
//! list's order is next set). What was reset or skipped is counted ([`Applied::defaulted`],
//! [`Applied::skipped`]) and the sync client says how many, never what (`Notice::Checked`).
//!
//! [`Replica::apply`]: crate::Replica::apply
//! [`Mode::Strict`]: crate::Mode::Strict
//! [`Mode::Sealed`]: crate::Mode::Sealed
//! [`Applied::defaulted`]: crate::Applied::defaulted
//! [`Applied::skipped`]: crate::Applied::skipped

use figcraft_doc::{BoolOp, Node, NodeKind, TextData, VectorNetwork};

use crate::change::Prop;
use crate::replica::MAX_COORD;

/// The version of the sealed-file value rules this build applies (see the module docs). Apps
/// announce it in their hello ([`crate::message::client_version`], the word `rules1`); a server
/// takes a sealed file's hello only from apps with the same version, so no two copies of a file
/// are checked with different rules.
pub const SEALED_RULES: u32 = 1;

/// Whether `v` is a finite coordinate within ±[`MAX_COORD`].
pub(crate) fn coord_ok(v: f64) -> bool {
    v.is_finite() && v.abs() <= MAX_COORD
}

/// Whether field `prop` of `n` keeps the value rules (the ones [`Replica::check`] makes on a
/// server): sizes, transforms, opacity. Other properties have no value rule beyond their type.
///
/// [`Replica::check`]: crate::Replica
pub(crate) fn value_ok(prop: Prop, n: &Node) -> bool {
    match prop {
        Prop::Width => coord_ok(n.width) && n.width >= 0.0,
        Prop::Height => coord_ok(n.height) && n.height >= 0.0,
        Prop::Transform => n.transform.as_coeffs().into_iter().all(coord_ok),
        Prop::Opacity => n.opacity.is_finite() && (0.0..=1.0).contains(&n.opacity),
        _ => true,
    }
}

/// Write field `prop` of `node` from `value` under the rules: when it doesn't read or breaks a
/// value rule the property takes [`fallback`]'s value. Returns whether it did.
pub(crate) fn set_checked(node: &mut Node, prop: Prop, value: &crate::Json) -> bool {
    if prop.set(node, value).is_ok() && value_ok(prop, node) {
        return false;
    }
    if let Ok(v) = prop.get(&fallback()) {
        let _ = prop.set(node, &v);
    }
    true
}

/// Where a value that doesn't read or breaks a rule comes from: a new rectangle's properties,
/// whatever the node's kind. Not the node's own kind's defaults: its kind may have changed since
/// the bad value was written, and an app that joins later sees the value with the node's current
/// kind, so a kind's defaults would differ between them.
pub(crate) fn fallback() -> Node {
    Node::new(figcraft_doc::NodeId(0), NodeKind::Rectangle, "", 0.0, 0.0)
}

/// The plain kind of type name `tag` (what a kind that doesn't read becomes).
pub(crate) fn default_kind(tag: &str) -> Option<NodeKind> {
    if let Ok(k) = serde_json::from_value::<NodeKind>(serde_json::json!({ "type": tag })) {
        return Some(k);
    }
    Some(match tag {
        "polygon" => NodeKind::Polygon { count: 3 },
        "star" => NodeKind::Star { count: 5, inner_ratio: 0.382 },
        "vector" => NodeKind::Vector { network: VectorNetwork::default() },
        "text" => NodeKind::Text(TextData::default()),
        "booleanOp" => NodeKind::BooleanOp { op: BoolOp::default() },
        // An instance of nothing (as one whose main component was deleted).
        "instance" => NodeKind::Instance { component: figcraft_doc::NodeId(0), props: Default::default() },
        _ => return None,
    })
}

/// Read a node kind under the rules: as it is, or the plain kind of its type name (then `true`).
pub(crate) fn read_kind(kind: &crate::Json) -> Result<(NodeKind, bool), crate::Error> {
    match kind.read::<NodeKind>("kind") {
        Ok(k) => Ok((k, false)),
        Err(e) => crate::sealed::kind_tag(kind).as_deref().and_then(default_kind).map(|k| (k, true)).ok_or(e),
    }
}
