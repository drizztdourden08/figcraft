//! The synced state of a sealed file as its session server keeps it: the tree in the clear (ids,
//! kind tags, parents, positions) and every value sealed. Batches are checked for structure only
//! (the rules of [`Replica::apply`](crate::Replica::apply) that need no values); value rules (size,
//! transform, opacity…) are every app's to check when it opens a batch.

use std::collections::BTreeSet;

use figcraft_doc::NodeId;
use figcraft_doc::ids::space_of;
use imbl::{OrdMap, OrdSet};

use crate::Error;
use crate::change::{DocProp, Prop};
use crate::frac;
use crate::sealed::{EntryKey, KIND_TAGS, Sealed, SealedChange, SealedEntry, is_container_tag, is_page_tag, split_signature};

/// A node: its kind's tag and sealed kind, its place in the tree and its sealed properties.
#[derive(Clone, Debug, PartialEq)]
struct Node {
    kind_tag: String,
    kind: Sealed,
    parent: Option<NodeId>,
    position: String,
    props: OrdMap<Prop, Sealed>,
    children: OrdSet<NodeId>,
    /// The kind it was created with (tag and sealed kind), once its kind changed to another tag.
    /// A new node's properties start from its kind's defaults and only written ones are kept here,
    /// so a snapshot creates it with that kind, then sets the current one: an app that joins later
    /// starts from the same defaults as the apps that saw it created.
    born: Option<(String, Sealed)>,
}

/// A document-level entry: its key and sealed name, its value (`None`: removed after the last
/// whole list of its kind was set, so a snapshot removes it from that list too), when it was
/// added (a counter: lists append new entries) and whether that was after the last order of its
/// list was set.
#[derive(Clone, Debug, PartialEq)]
struct Slot {
    entry: SealedEntry,
    value: Option<Sealed>,
    added: u64,
    late: bool,
}

/// One copy of a sealed file's state, as the server keeps it. Cloning is cheap (persistent maps).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OpaqueReplica {
    nodes: OrdMap<NodeId, Node>,
    doc: OrdMap<DocProp, Sealed>,
    entries: OrdMap<EntryKey, Slot>,
    /// The next [`Slot::added`].
    counter: u64,
}

/// The whole-list and order properties of the keyed lists, by list.
const LISTS: [(DocProp, DocProp); 4] = [
    (DocProp::Styles, DocProp::StyleOrder),
    (DocProp::Comments, DocProp::CommentOrder),
    (DocProp::Collections, DocProp::CollectionOrder),
    (DocProp::Variables, DocProp::VariableOrder),
];

/// The list (by its whole-list property) a property is the whole of (`Ok`) or the order of
/// (`Err`).
fn list_of(prop: DocProp) -> Option<Result<DocProp, DocProp>> {
    LISTS.iter().find_map(|(whole, order)| {
        if prop == *whole {
            Some(Ok(*whole))
        } else if prop == *order {
            Some(Err(*whole))
        } else {
            None
        }
    })
}

fn is_tree(prop: Prop) -> bool {
    matches!(prop, Prop::Parent | Prop::Position)
}

fn known_tag(tag: &str) -> Result<(), Error> {
    if KIND_TAGS.contains(&tag) { Ok(()) } else { Err(Error::Invalid(format!("unknown layer kind {tag:?}"))) }
}

fn check_entry(entry: &SealedEntry) -> Result<(), Error> {
    if entry.key.named() != entry.name.is_some() {
        return Err(Error::Invalid("entry name doesn't match its kind".into()));
    }
    Ok(())
}

impl OpaqueReplica {
    /// Rebuild a state from a [`snapshot`](Self::snapshot) (or any batch that builds a file: it
    /// must hold a page).
    pub fn from_snapshot(changes: &[SealedChange]) -> Result<OpaqueReplica, Error> {
        let mut r = OpaqueReplica::default();
        r.apply(changes)?;
        Ok(r)
    }

    /// Whether node `id` exists.
    pub fn contains(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// How many nodes there are.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// A node's kind tag.
    pub fn kind_tag(&self, id: NodeId) -> Option<&str> {
        self.nodes.get(&id).map(|n| n.kind_tag.as_str())
    }

    /// A node's parent (`None`: no such node; `Some(None)`: a page).
    pub fn parent(&self, id: NodeId) -> Option<Option<NodeId>> {
        self.nodes.get(&id).map(|n| n.parent)
    }

    /// Whether entry `key` is there.
    pub fn has_entry(&self, key: &EntryKey) -> bool {
        self.entries.get(key).is_some_and(|s| s.value.is_some())
    }

    /// The highest client id space the ids it can see use (layers, comments, dev snapshots).
    pub fn highest_id_space(&self) -> u32 {
        let nodes = self.nodes.keys().map(|id| id.0);
        let entries = self.entries.keys().filter_map(|k| match k {
            EntryKey::Comment(n) => Some(*n),
            EntryKey::DevSnapshot(id) => Some(id.0),
            _ => None,
        });
        nodes.chain(entries).map(space_of).max().unwrap_or(0)
    }

    /// The roots (pages) and every node's children, ordered by `(position, id)`.
    fn sorted(&self, ids: impl Iterator<Item = NodeId>) -> Vec<NodeId> {
        let mut v: Vec<(&str, NodeId)> = ids.filter_map(|id| self.nodes.get(&id).map(|n| (n.position.as_str(), id))).collect();
        v.sort();
        v.into_iter().map(|(_, id)| id).collect()
    }

    /// `id` and everything inside it, parents before children.
    fn subtree(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            let Some(node) = self.nodes.get(&n) else { continue };
            out.push(n);
            let mut kids = self.sorted(node.children.iter().copied());
            kids.reverse();
            stack.extend(kids);
        }
        out
    }

    /// The changes that make node `id` as it is: its creation with the kind it was created with,
    /// then its current kind when that changed (see [`Node::born`]).
    fn create_of(&self, id: NodeId) -> Vec<SealedChange> {
        let Some(n) = self.nodes.get(&id) else { return Vec::new() };
        let (tag, kind) = n.born.as_ref().map_or((&n.kind_tag, &n.kind), |(t, k)| (t, k));
        let mut out = vec![SealedChange::Create {
            id,
            kind_tag: tag.clone(),
            kind: kind.clone(),
            parent: n.parent,
            position: n.position.clone(),
            props: n.props.iter().map(|(p, v)| (*p, v.clone())).collect(),
        }];
        if n.born.is_some() {
            out.push(SealedChange::SetKind { id, kind_tag: n.kind_tag.clone(), value: n.kind.clone() });
        }
        out
    }

    /// The whole state as changes that build it from nothing: every node (pages, then each tree
    /// parents first, children in order), the document-level properties, then each list as its
    /// readers would rebuild it (the whole list if one was set, the entries added before its order
    /// was set, the order, the entries added since, and removals of entries of the whole list),
    /// then the other entries.
    pub fn snapshot(&self) -> Vec<SealedChange> {
        let mut out = Vec::with_capacity(self.nodes.len() + self.doc.len() + self.entries.len());
        let roots = self.sorted(self.nodes.iter().filter(|(_, n)| n.parent.is_none()).map(|(id, _)| *id));
        for r in roots {
            out.extend(self.subtree(r).into_iter().flat_map(|id| self.create_of(id)));
        }
        for (prop, value) in &self.doc {
            if list_of(*prop).is_none() {
                out.push(SealedChange::SetDoc { prop: *prop, value: value.clone() });
            }
        }
        let put = |s: &Slot| s.value.as_ref().map(|v| SealedChange::Put { entry: s.entry.clone(), value: v.clone() });
        for (whole, order) in LISTS {
            let mut slots: Vec<&Slot> = self.entries.values().filter(|s| s.entry.key.list() == Some(whole)).collect();
            slots.sort_by_key(|s| s.added);
            if let Some(v) = self.doc.get(&whole) {
                out.push(SealedChange::SetDoc { prop: whole, value: v.clone() });
            }
            out.extend(slots.iter().filter(|s| !s.late).filter_map(|s| put(s)));
            if let Some(v) = self.doc.get(&order) {
                out.push(SealedChange::SetDoc { prop: order, value: v.clone() });
            }
            out.extend(slots.iter().filter(|s| s.late).filter_map(|s| put(s)));
            out.extend(slots.iter().filter(|s| s.value.is_none()).map(|s| SealedChange::Remove { entry: s.entry.clone() }));
        }
        out.extend(self.entries.values().filter(|s| s.entry.key.list().is_none()).filter_map(put));
        out
    }

    /// Apply a batch with the server's structural checks: nodes exist (or don't, to be created),
    /// pages and only pages have no parent, no node becomes or stops being a page, only containers
    /// hold layers, positions are valid fractional keys, no layer goes inside itself, a deletion
    /// takes the subtree, the file keeps a page; property names and entry names fit their changes;
    /// a batch's signature ([`SealedChange::Signature`]) is its last change and its only one (the
    /// apps check what it signs). Stops at the first problem (the state is then left partly
    /// changed: apply to a clone). The nodes deleted.
    pub fn apply(&mut self, changes: &[SealedChange]) -> Result<Vec<NodeId>, Error> {
        let mut deleted = Vec::new();
        let mut touched: BTreeSet<NodeId> = BTreeSet::new();
        let (changes, _signature) = split_signature(changes)?;
        for c in changes {
            self.apply_one(c, &mut deleted, &mut touched)?;
        }
        if !self.nodes.values().any(|n| n.parent.is_none() && is_page_tag(&n.kind_tag)) {
            return Err(Error::Invalid("a file needs at least one page".into()));
        }
        for id in touched {
            if let Some(n) = self.nodes.get(&id)
                && !n.children.is_empty()
                && !is_container_tag(&n.kind_tag)
            {
                return Err(Error::Invalid(format!("{id} can't contain layers")));
            }
        }
        Ok(deleted)
    }

    fn node_mut(&mut self, id: NodeId) -> Result<&mut Node, Error> {
        self.nodes.get_mut(&id).ok_or(Error::Unknown(id))
    }

    fn apply_one(&mut self, c: &SealedChange, deleted: &mut Vec<NodeId>, touched: &mut BTreeSet<NodeId>) -> Result<(), Error> {
        match c {
            SealedChange::Create { id, kind_tag, kind, parent, position, props } => {
                frac::validate(position).map_err(|e| Error::Invalid(e.to_string()))?;
                if self.nodes.contains_key(id) {
                    return Err(Error::Invalid(format!("node {id} already exists")));
                }
                known_tag(kind_tag)?;
                let mut map = OrdMap::new();
                for (p, v) in props {
                    if *p == Prop::Kind || is_tree(*p) {
                        return Err(Error::Invalid(format!("{p:?} isn't a created node's property")));
                    }
                    map.insert(*p, v.clone());
                }
                match (is_page_tag(kind_tag), parent) {
                    (true, None) => {}
                    (false, Some(p)) => {
                        self.node_mut(*p)?.children.insert(*id);
                        touched.insert(*p);
                    }
                    _ => return Err(Error::Invalid("pages, and only pages, have no parent".into())),
                }
                let node = Node {
                    kind_tag: kind_tag.clone(),
                    kind: kind.clone(),
                    parent: *parent,
                    position: position.clone(),
                    props: map,
                    children: OrdSet::new(),
                    born: None,
                };
                self.nodes.insert(*id, node);
            }
            SealedChange::Set { id, prop, value } => {
                if *prop == Prop::Kind || is_tree(*prop) {
                    return Err(Error::Invalid(format!("{prop:?} isn't set with a sealed value")));
                }
                self.node_mut(*id)?.props.insert(*prop, value.clone());
            }
            SealedChange::SetKind { id, kind_tag, value } => {
                known_tag(kind_tag)?;
                let node = self.node_mut(*id)?;
                if is_page_tag(&node.kind_tag) != is_page_tag(kind_tag) {
                    return Err(Error::Invalid("a node can't become or stop being a page".into()));
                }
                if node.born.is_none() && node.kind_tag != *kind_tag {
                    node.born = Some((node.kind_tag.clone(), node.kind.clone()));
                }
                node.kind_tag = kind_tag.clone();
                node.kind = value.clone();
                touched.insert(*id);
            }
            SealedChange::SetTree { id, prop: Prop::Parent, value } => {
                let parent: Option<NodeId> = value.read("parent")?;
                let node = self.nodes.get(id).ok_or(Error::Unknown(*id))?;
                let (page, old) = (is_page_tag(&node.kind_tag), node.parent);
                match (page, parent) {
                    (true, None) => {}
                    (false, Some(p)) => {
                        if !self.nodes.contains_key(&p) {
                            return Err(Error::Unknown(p));
                        }
                        // The new parent mustn't be the node or inside it.
                        let mut up = Some(p);
                        while let Some(a) = up {
                            if a == *id {
                                return Err(Error::Invalid(format!("{id} can't go inside itself")));
                            }
                            up = self.nodes.get(&a).and_then(|n| n.parent);
                        }
                        if let Some(o) = old
                            && let Some(n) = self.nodes.get_mut(&o)
                        {
                            n.children.remove(id);
                        }
                        self.node_mut(p)?.children.insert(*id);
                        self.node_mut(*id)?.parent = Some(p);
                        touched.insert(p);
                    }
                    _ => return Err(Error::Invalid("pages, and only pages, have no parent".into())),
                }
            }
            SealedChange::SetTree { id, prop: Prop::Position, value } => {
                let key: String = value.read("position")?;
                frac::validate(&key).map_err(|e| Error::Invalid(e.to_string()))?;
                self.node_mut(*id)?.position = key;
            }
            SealedChange::SetTree { prop, .. } => return Err(Error::Invalid(format!("{prop:?} isn't a tree property"))),
            SealedChange::Delete { id } => {
                let Some(parent) = self.nodes.get(id).map(|n| n.parent) else { return Ok(()) };
                let gone = self.subtree(*id);
                for g in &gone {
                    self.nodes.remove(g);
                }
                if let Some(p) = parent
                    && let Some(n) = self.nodes.get_mut(&p)
                {
                    n.children.remove(id);
                }
                deleted.extend(gone);
            }
            SealedChange::SetDoc { prop, value } => {
                self.doc.insert(*prop, value.clone());
                match list_of(*prop) {
                    // A whole list replaces every entry of it.
                    Some(Ok(whole)) => {
                        let keys: Vec<EntryKey> = self.entries.keys().filter(|k| k.list() == Some(whole)).cloned().collect();
                        for k in keys {
                            self.entries.remove(&k);
                        }
                    }
                    // Its order: the entries there now are ordered by it.
                    Some(Err(whole)) => {
                        let keys: Vec<EntryKey> =
                            self.entries.iter().filter(|(k, s)| k.list() == Some(whole) && s.late).map(|(k, _)| k.clone()).collect();
                        for k in keys {
                            if let Some(s) = self.entries.get_mut(&k) {
                                s.late = false;
                            }
                        }
                    }
                    None => {}
                }
            }
            SealedChange::Put { entry, value } => {
                check_entry(entry)?;
                match self.entries.get_mut(&entry.key) {
                    Some(s) if s.value.is_some() => {
                        s.entry = entry.clone();
                        s.value = Some(value.clone());
                    }
                    _ => {
                        let added = self.counter;
                        self.counter += 1;
                        self.entries.insert(entry.key.clone(), Slot { entry: entry.clone(), value: Some(value.clone()), added, late: true });
                    }
                }
            }
            // Changes nothing (taken off the batch in `apply`).
            SealedChange::Signature(_) => {}
            SealedChange::Remove { entry } => {
                check_entry(entry)?;
                let in_whole = entry.key.list().is_some_and(|w| self.doc.contains_key(&w));
                if in_whole {
                    // A removal of an entry it never saw takes the next counter too, so the
                    // removals keep their order when a snapshot is rebuilt.
                    let added = match self.entries.get(&entry.key) {
                        Some(s) => s.added,
                        None => {
                            self.counter += 1;
                            self.counter - 1
                        }
                    };
                    self.entries.insert(entry.key.clone(), Slot { entry: entry.clone(), value: None, added, late: true });
                } else {
                    self.entries.remove(&entry.key);
                }
            }
        }
        Ok(())
    }

    /// The current sealed values of what a refused batch touched, so a client can roll its copy
    /// back: nodes that don't exist are deleted, deleted subtrees come back whole, a node's kind,
    /// place and properties get their current values (a property never written since the node was
    /// made has nothing to send), document-level data likewise.
    pub fn fixes(&self, changes: &[SealedChange]) -> Vec<SealedChange> {
        let mut out: Vec<SealedChange> = Vec::new();
        let push = |c: SealedChange, out: &mut Vec<SealedChange>| {
            if !out.contains(&c) {
                out.push(c);
            }
        };
        for c in changes.iter().filter(|c| !matches!(c, SealedChange::Signature(_))) {
            if let Some(id) = c.node()
                && !self.nodes.contains_key(&id)
            {
                push(SealedChange::Delete { id }, &mut out);
                continue;
            }
            match c {
                SealedChange::Create { id, .. } | SealedChange::SetKind { id, .. } | SealedChange::SetTree { id, .. } => {
                    if let Some(n) = self.nodes.get(id) {
                        push(SealedChange::SetKind { id: *id, kind_tag: n.kind_tag.clone(), value: n.kind.clone() }, &mut out);
                        if let Ok(v) = crate::Json::of(&n.parent) {
                            push(SealedChange::SetTree { id: *id, prop: Prop::Parent, value: v }, &mut out);
                        }
                        if let Ok(v) = crate::Json::of(&n.position) {
                            push(SealedChange::SetTree { id: *id, prop: Prop::Position, value: v }, &mut out);
                        }
                        if matches!(c, SealedChange::Create { .. }) {
                            for (p, v) in &n.props {
                                push(SealedChange::Set { id: *id, prop: *p, value: v.clone() }, &mut out);
                            }
                        }
                    }
                }
                SealedChange::Set { id, prop, .. } => {
                    if let Some(v) = self.nodes.get(id).and_then(|n| n.props.get(prop)) {
                        push(SealedChange::Set { id: *id, prop: *prop, value: v.clone() }, &mut out);
                    }
                }
                SealedChange::Delete { id } => {
                    for d in self.subtree(*id) {
                        for c in self.create_of(d) {
                            push(c, &mut out);
                        }
                    }
                }
                SealedChange::SetDoc { prop, .. } => {
                    if let Some(v) = self.doc.get(prop) {
                        push(SealedChange::SetDoc { prop: *prop, value: v.clone() }, &mut out);
                    }
                }
                SealedChange::Put { entry, .. } | SealedChange::Remove { entry } => match self.entries.get(&entry.key) {
                    Some(Slot { entry: e, value: Some(v), .. }) => push(SealedChange::Put { entry: e.clone(), value: v.clone() }, &mut out),
                    Some(Slot { entry: e, value: None, .. }) => push(SealedChange::Remove { entry: e.clone() }, &mut out),
                    None => push(SealedChange::Remove { entry: entry.clone() }, &mut out),
                },
                SealedChange::Signature(_) => {}
            }
        }
        out
    }
}
