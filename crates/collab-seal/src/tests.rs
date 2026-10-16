use figcraft_collab::{Change, DocProp, Entry, Json, Presence, Prop, Signal};
use figcraft_doc::NodeId;
use serde_json::json;

use crate::keys::hkdf;
use crate::*;

const FILE: &str = "f-1234";

fn fixed_key() -> FileKey {
    let mut key = [0u8; 32];
    let mut names = [0u8; 32];
    for i in 0..32u8 {
        key[usize::from(i)] = i;
        names[usize::from(i)] = 32 + i;
    }
    FileKey::from_parts(7, key, names)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A small deterministic generator for junk inputs.
struct Junk(u64);
impl Junk {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % (max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn all_slots() -> Vec<Slot> {
    vec![
        Slot::Node { id: NodeId(42), prop: Prop::Fills },
        Slot::Node { id: NodeId(42), prop: Prop::Kind },
        Slot::Doc { prop: DocProp::Name },
        Slot::Entry(EntryKey::Style("abc".into())),
        Slot::Entry(EntryKey::Comment(9)),
        Slot::Entry(EntryKey::Collection("abc".into())),
        Slot::Entry(EntryKey::Variable("abc".into())),
        Slot::Entry(EntryKey::DevSnapshot(NodeId(3))),
        Slot::Entry(EntryKey::Image("abc".into())),
        Slot::EntryName(EntryKey::Style("abc".into())),
        Slot::Presence { client: 2 },
        Slot::Signal { client: 2 },
        Slot::Meta { what: "name".into() },
    ]
}

// --- key derivation -------------------------------------------------------------------------

#[test]
fn hkdf_matches_rfc5869_case_3() {
    // RFC 5869 A.3: SHA-256, IKM = 22 × 0x0b, no salt, no info (first 32 bytes of the OKM).
    let okm = hkdf(&[0x0b; 22], b"").unwrap();
    assert_eq!(hex(okm.as_slice()), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d");
}

#[test]
fn subkey_vectors() {
    let k = fixed_key();
    assert_eq!(hex(k.value_key().unwrap().as_slice()), VALUE_VECTOR);
    assert_eq!(hex(k.entry_key().unwrap().as_slice()), ENTRY_VECTOR);
    assert_eq!(hex(k.presence_key().unwrap().as_slice()), PRESENCE_VECTOR);
    assert_eq!(hex(k.meta_key().unwrap().as_slice()), META_VECTOR);
    assert_eq!(entry_id(&k, "S:1:2").unwrap(), ENTRY_ID_VECTOR);
    // The subkeys are distinct.
    let all = [VALUE_VECTOR, ENTRY_VECTOR, PRESENCE_VECTOR, META_VECTOR];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

// Test vectors for fixed_key() (checked against an independent HKDF/HMAC implementation).
const VALUE_VECTOR: &str = "2b544f0ca0f6ef3c23b7950dd855c0d78c055419789aaf77bad5122980b7b738";
const ENTRY_VECTOR: &str = "43897c1300c8d2b63f87963cf105635d2cfe455f35d5fb5ea6e30b7fd317c51d";
const PRESENCE_VECTOR: &str = "1cf63ae03d3af687bad1cb56ea1fe93be720f43da284765a69454e7a438284f6";
const META_VECTOR: &str = "bc0194cfc3cf3637d27f0d311fd363ddfe4772cb19869eae52088ae15afb5bbc";
const ENTRY_ID_VECTOR: &str = "S1gpLaCAp2Er-v5mrvJTePuJJJdqJ9DYpQgtdYZyf4o";

#[test]
fn file_key_bytes_round_trip_and_rotation() {
    let k = FileKey::generate().unwrap();
    assert_eq!(k.epoch(), 0);
    let bytes = k.to_bytes();
    assert_eq!(bytes.len(), 68);
    assert_eq!(FileKey::from_bytes(&bytes).unwrap(), k);
    assert!(FileKey::from_bytes(&bytes[..67]).is_err());
    let next = k.rotate().unwrap();
    assert_eq!(next.epoch(), 1);
    assert_ne!(next, k);
    assert_eq!(next.entry_key().unwrap(), k.entry_key().unwrap(), "names secret carries over");
    assert_ne!(next.value_key().unwrap(), k.value_key().unwrap());
    let last = FileKey::from_parts(u32::MAX, [1; 32], [2; 32]);
    assert!(last.rotate().is_err());
}

#[test]
fn debug_prints_no_secrets() {
    let k = fixed_key();
    let shown = format!("{k:?} {:?}", Keyring::from(k.clone()));
    assert!(shown.contains("epoch: 7"));
    assert!(!shown.contains("15, 16") && !shown.contains("0f10"));
    let d = DeviceKeys::from_secret_bytes(&[5; 64]).unwrap();
    assert!(!format!("{d:?}").contains("5, 5, 5"));
    let r = RecoveryKey::generate().unwrap();
    assert_eq!(format!("{r:?}"), "RecoveryKey(..)");
}

// --- seal and open ------------------------------------------------------------------------

#[test]
fn every_slot_round_trips() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    for slot in all_slots() {
        for msg in [&b""[..], b"x", &[7u8; 300], &[0u8; 5000]] {
            let s = seal(&k, FILE, &slot, msg).unwrap();
            assert_eq!(s.epoch(), 7);
            assert_eq!(open(&ring, FILE, &slot, &s).unwrap(), msg, "{slot:?}");
        }
    }
}

#[test]
fn nonces_are_fresh() {
    let k = fixed_key();
    let slot = Slot::Doc { prop: DocProp::Name };
    assert_ne!(seal(&k, FILE, &slot, b"same").unwrap(), seal(&k, FILE, &slot, b"same").unwrap());
}

#[test]
fn wrong_slot_file_or_key_fails() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let slots = all_slots();
    for (i, a) in slots.iter().enumerate() {
        let s = seal(&k, FILE, a, b"secret").unwrap();
        for (j, b) in slots.iter().enumerate() {
            if i != j {
                assert_eq!(open(&ring, FILE, b, &s), Err(SealError::Open), "{a:?} opened as {b:?}");
            }
        }
        assert_eq!(open(&ring, "f-1235", a, &s), Err(SealError::Open));
    }
    let slot = Slot::Node { id: NodeId(1), prop: Prop::Name };
    let s = seal(&k, FILE, &slot, b"secret").unwrap();
    // An epoch the keyring doesn't have.
    let other = Keyring::from(k.rotate().unwrap());
    assert_eq!(open(&other, FILE, &slot, &s), Err(SealError::UnknownEpoch(7)));
    // Another key under the same epoch number.
    let impostor = Keyring::from(FileKey::from_parts(7, [9; 32], [9; 32]));
    assert_eq!(open(&impostor, FILE, &slot, &s), Err(SealError::Open));
    // Old epochs still open from a keyring that has them.
    let mut both = Keyring::from(k.rotate().unwrap());
    both.insert(k.clone());
    assert_eq!(both.current().unwrap().epoch(), 8);
    assert_eq!(open(&both, FILE, &slot, &s).unwrap(), b"secret");
}

#[test]
fn tampering_and_truncation_fail() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let slot = Slot::Doc { prop: DocProp::Name };
    let s = seal(&k, FILE, &slot, b"a file name").unwrap();
    let bytes = s.as_bytes().to_vec();
    for i in 0..bytes.len() {
        let mut t = bytes.clone();
        t[i] ^= 0x01;
        let t = Sealed::from_bytes(t).unwrap();
        assert!(open(&ring, FILE, &slot, &t).is_err(), "flip at {i} opened");
    }
    for n in 0..bytes.len() {
        assert!(Sealed::from_bytes(bytes[..n].to_vec()).is_err(), "truncated to {n}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Sealed::from_bytes(longer).is_err());
}

#[test]
fn padding_buckets() {
    let cases =
        [(0, 64), (60, 64), (61, 256), (252, 256), (253, 1024), (1020, 1024), (1021, 2048), (2044, 2048), (2045, 4096), (MAX_PLAINTEXT, 1 << 26)];
    for (n, padded) in cases {
        assert_eq!(padded_len(n), Some(padded), "{n}");
    }
    assert_eq!(padded_len(MAX_PLAINTEXT + 1), None);
    let k = fixed_key();
    let slot = Slot::Meta { what: "name".into() };
    for (n, padded) in cases.iter().take(9) {
        let s = seal(&k, FILE, &slot, &vec![1u8; *n]).unwrap();
        assert_eq!(s.len(), 4 + 24 + padded + 16, "{n}");
    }
}

#[test]
fn non_canonical_padding_fails() {
    // Seal hand-made padded plaintexts through the same cipher: a wrong length prefix or non-zero
    // padding must not open even though the AEAD accepts it.
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let slot = Slot::Meta { what: "name".into() };
    let good = seal(&k, FILE, &slot, b"hi").unwrap();
    let mut ad = b"figcraft sealed v1".to_vec();
    ad.extend_from_slice(&(FILE.len() as u32).to_le_bytes());
    ad.extend_from_slice(FILE.as_bytes());
    ad.extend_from_slice(&7u32.to_le_bytes());
    slot.encode(&mut ad).unwrap();
    let cipher = XChaCha20Poly1305::new_from_slice(k.meta_key().unwrap().as_slice()).unwrap();
    let nonce = [3u8; 24];
    let build = |padded: &[u8]| {
        let ct = cipher.encrypt(&XNonce::from(nonce), Payload { msg: padded, aad: &ad }).unwrap();
        let mut b = 7u32.to_le_bytes().to_vec();
        b.extend_from_slice(&nonce);
        b.extend_from_slice(&ct);
        Sealed::from_bytes(b).unwrap()
    };
    let mut p = vec![0u8; 64];
    p[..4].copy_from_slice(&2u32.to_le_bytes());
    p[4..6].copy_from_slice(b"hi");
    assert_eq!(open(&ring, FILE, &slot, &build(&p)).unwrap(), b"hi");
    assert_eq!(open(&ring, FILE, &slot, &good).unwrap(), b"hi");
    let mut dirty = p.clone();
    dirty[63] = 1;
    assert!(open(&ring, FILE, &slot, &build(&dirty)).is_err());
    let mut long = p.clone();
    long[..4].copy_from_slice(&61u32.to_le_bytes());
    assert!(open(&ring, FILE, &slot, &build(&long)).is_err());
    let mut huge = p.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(open(&ring, FILE, &slot, &build(&huge)).is_err());
    let mut wasteful = vec![0u8; 256];
    wasteful[..4].copy_from_slice(&2u32.to_le_bytes());
    assert!(open(&ring, FILE, &slot, &build(&wasteful)).is_err(), "a too-large bucket is not canonical");
}

// --- entry ids ----------------------------------------------------------------------------

#[test]
fn entry_ids_are_stable_and_opaque() {
    let k = fixed_key();
    let id = entry_id(&k, "S:1:2").unwrap();
    assert_eq!(id.len(), 43);
    assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert!(!id.contains("S:1"));
    assert_eq!(entry_id(&k, "S:1:2").unwrap(), id);
    assert_eq!(entry_id(&k.rotate().unwrap(), "S:1:2").unwrap(), id, "stable across epochs");
    assert_ne!(entry_id(&k, "S:1:3").unwrap(), id);
    let other_file = FileKey::generate().unwrap();
    assert_ne!(entry_id(&other_file, "S:1:2").unwrap(), id);
}

// --- changes ------------------------------------------------------------------------------

fn sample_changes() -> Vec<Change> {
    let named = [
        Entry::Style("S:1:2".into()),
        Entry::Comment(77),
        Entry::Collection("VC:1:1".into()),
        Entry::Variable("V:1:9".into()),
        Entry::DevSnapshot(NodeId(5)),
        Entry::Image("deadbeef".into()),
    ];
    let mut out = vec![
        Change::Create {
            id: NodeId(10),
            kind: Json(json!({"type": "text", "content": "top secret"})),
            parent: Some(NodeId(1)),
            position: "a5".into(),
            props: vec![(Prop::Name, Json(json!("Title"))), (Prop::Opacity, Json(json!(0.5)))],
        },
        Change::Create { id: NodeId(1), kind: Json(json!({"type": "page"})), parent: None, position: "a0".into(), props: vec![] },
        Change::Set { id: NodeId(10), prop: Prop::Name, value: Json(json!("Renamed")) },
        Change::Set { id: NodeId(10), prop: Prop::Kind, value: Json(json!({"type": "frame"})) },
        Change::Set { id: NodeId(10), prop: Prop::Parent, value: Json(json!(1)) },
        Change::Set { id: NodeId(10), prop: Prop::Position, value: Json(json!("a7")) },
        Change::Delete { id: NodeId(10) },
        Change::SetDoc { prop: DocProp::Name, value: Json(json!("My file")) },
    ];
    for e in named {
        out.push(Change::Put { entry: e.clone(), value: Json(json!({"some": "value", "n": [1, 2, 3]})) });
        out.push(Change::Remove { entry: e });
    }
    out
}

#[test]
fn changes_round_trip() {
    let k0 = fixed_key();
    let k1 = k0.rotate().unwrap();
    let mut ring = Keyring::from(k0.clone());
    ring.insert(k1.clone());
    for key in [&k0, &k1] {
        for c in sample_changes() {
            let s = seal_change(key, FILE, &c).unwrap();
            assert_eq!(open_change(&ring, FILE, &s).unwrap(), c);
            // Both wire forms carry it.
            let bin = postcard::to_allocvec(&s).unwrap();
            assert_eq!(postcard::from_bytes::<SealedChange>(&bin).unwrap(), s);
            let text = serde_json::to_string(&s).unwrap();
            assert!(!text.contains("secret") && !text.contains("Renamed") && !text.contains("S:1:2"), "{text}");
            assert_eq!(serde_json::from_str::<SealedChange>(&text).unwrap(), s);
            // Another file id can't open it (unless nothing in it is sealed).
            let plain = matches!(
                &s,
                SealedChange::Delete { .. }
                    | SealedChange::SetTree { .. }
                    | SealedChange::Remove { entry: SealedEntry { key: EntryKey::Comment(_) | EntryKey::DevSnapshot(_), .. } }
            );
            assert_eq!(open_change(&ring, "f-other", &s).is_ok(), plain, "{s:?}");
        }
    }
}

#[test]
fn plain_parts_must_match_sealed_ones() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let create = sample_changes().remove(0);
    let SealedChange::Create { id, kind_tag, kind, parent, position, props } = seal_change(&k, FILE, &create).unwrap() else { panic!() };
    assert_eq!(kind_tag, "text");
    let lie = SealedChange::Create { id, kind_tag: "frame".into(), kind: kind.clone(), parent, position: position.clone(), props: props.clone() };
    assert!(open_change(&ring, FILE, &lie).is_err());
    // Moving a value to another node fails.
    let moved = SealedChange::Create { id: NodeId(11), kind_tag: "text".into(), kind: kind.clone(), parent, position: position.clone(), props };
    assert!(open_change(&ring, FILE, &moved).is_err());
    // Created nodes' props hold no kind or tree properties.
    let tree_prop = vec![(Prop::Parent, kind.clone())];
    assert!(open_change(&ring, FILE, &SealedChange::Create { id, kind_tag: "text".into(), kind, parent, position, props: tree_prop }).is_err());
    let bad = Change::Create {
        id: NodeId(3),
        kind: Json(json!({"type": "frame"})),
        parent: None,
        position: "a0".into(),
        props: vec![(Prop::Position, Json(json!("a1")))],
    };
    assert!(seal_change(&k, FILE, &bad).is_err());

    let kind = seal_change(&k, FILE, &Change::Set { id: NodeId(1), prop: Prop::Kind, value: Json(json!({"type": "frame"})) }).unwrap();
    let SealedChange::SetKind { id, kind_tag, value } = kind else { panic!() };
    assert_eq!(kind_tag, "frame");
    assert!(open_change(&ring, FILE, &SealedChange::SetKind { id, kind_tag: "page".into(), value: value.clone() }).is_err());
    // A kind can't come in through Set, nor a tree property through Set or SetTree's opposite.
    assert!(open_change(&ring, FILE, &SealedChange::Set { id, prop: Prop::Kind, value: value.clone() }).is_err());
    assert!(open_change(&ring, FILE, &SealedChange::Set { id, prop: Prop::Parent, value }).is_err());
    assert!(open_change(&ring, FILE, &SealedChange::SetTree { id, prop: Prop::Name, value: Json(json!("x")) }).is_err());
    let tree = seal_change(&k, FILE, &Change::Set { id: NodeId(1), prop: Prop::Position, value: Json(json!("a3")) }).unwrap();
    assert_eq!(tree, SealedChange::SetTree { id: NodeId(1), prop: Prop::Position, value: Json(json!("a3")) });

    // An entry's sealed name must hash to its key.
    let a = seal_change(&k, FILE, &Change::Remove { entry: Entry::Style("S:1:1".into()) }).unwrap();
    let b = seal_change(&k, FILE, &Change::Remove { entry: Entry::Style("S:1:2".into()) }).unwrap();
    let (SealedChange::Remove { entry: ea }, SealedChange::Remove { entry: eb }) = (a, b) else { panic!() };
    let swapped = SealedEntry { key: ea.key.clone(), name: eb.name.clone() };
    assert!(open_change(&ring, FILE, &SealedChange::Remove { entry: swapped }).is_err());
    let unnamed = SealedEntry { key: ea.key.clone(), name: None };
    assert!(open_change(&ring, FILE, &SealedChange::Remove { entry: unnamed }).is_err());
    let named_comment = SealedEntry { key: EntryKey::Comment(1), name: ea.name.clone() };
    assert!(open_change(&ring, FILE, &SealedChange::Remove { entry: named_comment }).is_err());
    // A kind without a type name can't be sealed.
    assert!(seal_change(&k, FILE, &Change::Set { id: NodeId(1), prop: Prop::Kind, value: Json(json!(3)) }).is_err());
}

#[test]
fn kind_tags_match_the_json_and_the_doc_rules() {
    use figcraft_doc::{BoolOp, NodeKind};
    let page: NodeKind = serde_json::from_value(json!({"type": "page"})).unwrap();
    let kinds = vec![
        page,
        NodeKind::Frame,
        NodeKind::Group,
        NodeKind::Section { contents_hidden: false },
        NodeKind::Rectangle,
        NodeKind::Ellipse { start: 0.0, sweep: 1.0, inner: 0.0 },
        NodeKind::Polygon { count: 3 },
        NodeKind::Star { count: 5, inner_ratio: 0.4 },
        NodeKind::Line,
        NodeKind::Vector { network: Default::default() },
        NodeKind::Text(Default::default()),
        NodeKind::BooleanOp { op: BoolOp::default() },
        NodeKind::Component { description: String::new(), props: Default::default() },
        NodeKind::ComponentSet { description: String::new() },
        NodeKind::Instance { component: NodeId(1), props: Default::default() },
        NodeKind::Slice,
    ];
    for k in kinds {
        let tag = node_kind_tag(&k);
        assert_eq!(kind_tag(&Json::of(&k).unwrap()).as_deref(), Some(tag));
        assert_eq!(is_container_tag(tag), k.is_container(), "{tag}");
        assert_eq!(is_page_tag(tag), matches!(k, NodeKind::Page { .. }), "{tag}");
    }
}

#[test]
fn presence_and_signals_round_trip() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let p = Presence { cursor: Some((NodeId(1), 3.0, 4.5)), selection: Some(vec![NodeId(2)]), viewport: None, editing_text: None };
    let s = seal_presence(&k, FILE, 4, &p).unwrap();
    assert_eq!(open_presence(&ring, FILE, 4, &s).unwrap(), p);
    assert!(open_presence(&ring, FILE, 5, &s).is_err());
    let chat = Signal::chat("hello\u{7}there");
    let s = seal_signal(&k, FILE, 4, &chat).unwrap();
    assert_eq!(open_signal(&ring, FILE, 4, &s).unwrap().text, "hello there");
    assert!(open_signal(&ring, FILE, 5, &s).is_err());
    assert!(open_presence(&ring, FILE, 4, &s).is_err(), "signal and presence slots differ");
    let unknown = seal_signal(&k, FILE, 4, &Signal { kind: "nope".into(), text: String::new() }).unwrap();
    assert!(open_signal(&ring, FILE, 4, &unknown).is_err());
}

// --- devices ------------------------------------------------------------------------------

#[test]
fn wrap_and_unwrap() {
    let alice = DeviceKeys::generate().unwrap();
    let bob = DeviceKeys::generate().unwrap();
    let key = FileKey::generate().unwrap().rotate().unwrap();
    let w = wrap(&key, FILE, &alice.public().unwrap()).unwrap();
    assert_eq!(w.ciphertext.len(), 84);
    assert_eq!(unwrap(&alice, FILE, &w).unwrap(), key);
    assert_eq!(unwrap(&bob, FILE, &w), Err(SealError::Open));
    assert_eq!(unwrap(&alice, "f-other", &w), Err(SealError::Open));
    let mut t = w.clone();
    t.ciphertext[3] ^= 1;
    assert!(unwrap(&alice, FILE, &t).is_err());
    let mut t = w.clone();
    t.enc[0] ^= 1;
    assert!(unwrap(&alice, FILE, &t).is_err());
    // Byte and serde forms.
    assert_eq!(Wrapped::from_bytes(&w.to_bytes()).unwrap(), w);
    let text = serde_json::to_string(&w).unwrap();
    assert_eq!(serde_json::from_str::<Wrapped>(&text).unwrap(), w);
    assert_eq!(postcard::from_bytes::<Wrapped>(&postcard::to_allocvec(&w).unwrap()).unwrap(), w);
    // Two wraps of one key differ (fresh ephemeral keys).
    assert_ne!(wrap(&key, FILE, &alice.public().unwrap()).unwrap(), w);
}

#[test]
fn device_keys_store_and_sign() {
    let d = DeviceKeys::generate().unwrap();
    let again = DeviceKeys::from_secret_bytes(&d.to_secret_bytes()).unwrap();
    assert_eq!(again.public().unwrap(), d.public().unwrap());
    let public = d.public().unwrap();
    let text = serde_json::to_string(&public).unwrap();
    assert_eq!(serde_json::from_str::<DevicePublic>(&text).unwrap(), public);
    assert!(serde_json::from_str::<DevicePublic>(r#"{"agreement":"AAAA","signing":"AAAA"}"#).is_err());

    let sig = d.sign(b"batch 1");
    assert!(verify(&public, b"batch 1", &sig));
    assert!(!verify(&public, b"batch 2", &sig));
    assert!(!verify(&DeviceKeys::generate().unwrap().public().unwrap(), b"batch 1", &sig));
    assert!(!verify(&public, b"batch 1", &sig[..63]));
    let mut bad = sig;
    bad[10] ^= 1;
    assert!(!verify(&public, b"batch 1", &bad));
}

#[test]
fn ed25519_rfc8032_test_1() {
    // RFC 8032 7.1 TEST 1: empty message.
    let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let mut secret = vec![1u8; 32];
    for i in 0..32 {
        secret.push(u8::from_str_radix(&seed[2 * i..2 * i + 2], 16).unwrap());
    }
    let d = DeviceKeys::from_secret_bytes(&secret).unwrap();
    assert_eq!(hex(&d.public().unwrap().signing), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(
        hex(&d.sign(b"")),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

// --- links and recovery -------------------------------------------------------------------

#[test]
fn link_keys() {
    let k = FileKey::generate().unwrap().rotate().unwrap();
    let frag = link_fragment(&k);
    assert!(frag.starts_with("k="));
    assert_eq!(frag.len(), 2 + 91);
    assert_eq!(parse_link_fragment(&frag).unwrap(), k);
    assert_eq!(parse_link_fragment(&format!("#{frag}")).unwrap(), k);
    assert_eq!(parse_link_fragment(&format!("#v=1&{frag}&x=2")).unwrap(), k);
    let longer = format!("{frag}A");
    for bad in ["", "#", "k=", "#k=abc", "#x=1", &frag[..frag.len() - 1], &longer] {
        assert!(parse_link_fragment(bad).is_err(), "{bad}");
    }
}

#[test]
fn recovery_keys() {
    let r = RecoveryKey::generate().unwrap();
    let shown = r.to_display();
    assert_eq!(shown.len(), 55 + 10);
    assert_eq!(shown.split('-').count(), 11);
    assert!(shown.split('-').all(|g| g.len() == 5));
    assert_eq!(RecoveryKey::parse(&shown).unwrap(), r);
    let sloppy = shown.to_lowercase().replace('-', " ").replace('o', "0").replace('i', "1").replace('b', "8");
    assert_eq!(RecoveryKey::parse(&sloppy).unwrap(), r);
    // A typo is caught by the checksum (or the format).
    let mut typo: Vec<char> = shown.chars().collect();
    typo[3] = if typo[3] == 'A' { 'C' } else { 'A' };
    assert!(RecoveryKey::parse(&typo.into_iter().collect::<String>()).is_err());
    assert!(RecoveryKey::parse(&shown[..shown.len() - 1]).is_err());

    let copy = r.seal(b"account 1", b"keyring bytes").unwrap();
    assert_eq!(r.open(b"account 1", &copy).unwrap().as_slice(), b"keyring bytes");
    assert!(r.open(b"account 2", &copy).is_err());
    assert!(RecoveryKey::generate().unwrap().open(b"account 1", &copy).is_err());
    for n in 0..copy.len() {
        assert!(r.open(b"account 1", &copy[..n]).is_err());
    }
}

// --- junk never panics ---------------------------------------------------------------------

#[test]
fn junk_input_never_panics() {
    let k = fixed_key();
    let ring = Keyring::from(k.clone());
    let device = DeviceKeys::generate().unwrap();
    let public = device.public().unwrap();
    let recovery = RecoveryKey::generate().unwrap();
    let valid: Vec<SealedChange> = sample_changes().iter().map(|c| seal_change(&k, FILE, c).unwrap()).collect();
    let mut j = Junk(0x9e37_79b9_7f4a_7c15);
    for round in 0..3000 {
        let bytes = j.bytes(if round % 10 == 0 { 1200 } else { 160 });
        if let Ok(s) = Sealed::from_bytes(bytes.clone()) {
            for slot in all_slots() {
                assert!(open(&ring, FILE, &slot, &s).is_err());
            }
        }
        let _ = FileKey::from_bytes(&bytes);
        let _ = DeviceKeys::from_secret_bytes(&bytes);
        if let Ok(w) = Wrapped::from_bytes(&bytes) {
            assert!(unwrap(&device, FILE, &w).is_err());
        }
        let w = Wrapped { enc: [bytes.first().copied().unwrap_or(0); 32], ciphertext: bytes.clone() };
        assert!(unwrap(&device, FILE, &w).is_err());
        let text = String::from_utf8_lossy(&bytes);
        let _ = parse_link_fragment(&text);
        let _ = parse_link_fragment(&format!("#k={text}"));
        let _ = RecoveryKey::parse(&text);
        assert!(recovery.open(b"", &bytes).is_err());
        let _ = verify(&public, &bytes, &bytes);
        let _ = postcard::from_bytes::<SealedChange>(&bytes);
        let _ = serde_json::from_slice::<SealedChange>(&bytes);
        let _ = postcard::from_bytes::<Wrapped>(&bytes);
        let _ = postcard::from_bytes::<DevicePublic>(&bytes);
        // Valid changes with one byte of their wire form changed.
        if let Some(c) = valid.get(round % valid.len()) {
            let mut wire = postcard::to_allocvec(c).unwrap();
            if !wire.is_empty() {
                let at = (j.next() as usize) % wire.len();
                wire[at] ^= (j.next() as u8) | 1;
                if let Ok(c2) = postcard::from_bytes::<SealedChange>(&wire) {
                    let _ = open_change(&ring, FILE, &c2);
                }
            }
        }
    }
}

#[test]
fn keyrings_travel_in_link_fragments() {
    let first = FileKey::generate().unwrap();
    let second = first.rotate().unwrap();
    let mut ring = Keyring::from(second.clone());
    ring.insert(first.clone());
    let fragment = ring_fragment(&ring);
    // Oldest first; one epoch reads as a plain link key.
    assert_eq!(fragment, format!("{}&{}", link_fragment(&first), link_fragment(&second)));
    assert_eq!(parse_ring_fragment(&fragment).unwrap(), ring);
    assert_eq!(parse_ring_fragment(&format!("#{fragment}&other=1")).unwrap(), ring);
    assert_eq!(ring_fragment(&Keyring::from(first.clone())), link_fragment(&first));
    assert_eq!(parse_link_fragment(&fragment).unwrap(), first, "older readers take the first key");
    assert_eq!(ring.current(), Some(&second));
    // Merging keeps what is there and adds the rest.
    let mut other = Keyring::from(first.clone());
    other.merge(&ring);
    assert_eq!(other, ring);
    assert_eq!(other.len(), 2);
    // Junk is refused; too many keys too.
    for bad in ["", "k=", "x=1", "k=AAAA", &format!("{fragment}&k=nope")] {
        assert!(parse_ring_fragment(bad).is_err(), "{bad}");
    }
    let many = vec![link_fragment(&first); MAX_LINK_EPOCHS + 1].join("&");
    assert!(parse_ring_fragment(&many).is_err());
}
