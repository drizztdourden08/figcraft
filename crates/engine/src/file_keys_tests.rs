//! The keys of sealed files kept with the preferences: kept from a published file's link, by
//! server and file id; added to a link without one; carried by the links others get (without join
//! codes); used to open names in listings; never printed by `Debug`; and junk in the preferences
//! file never costs the rest.

use figcraft_collab::sealed::sealed_name_text;
use figcraft_collab_seal::{FileKey, Slot, link_fragment, seal};
use serde_json::json;

use crate::file_keys::{ENCRYPTED_NAME, MAX_FILE_KEYS, link_key, sealed_link};
use crate::live::{Shared, SharedLink};
use crate::{Prefs, Session};

const SERVER: &str = "wss://share.example/";
const FILE: &str = "0123456789abcdef";

fn key() -> (FileKey, String) {
    let k = FileKey::generate().unwrap();
    let f = link_fragment(&k);
    (k, f)
}

#[test]
fn a_published_files_key_is_kept_and_used() {
    let (k, fragment) = key();
    let link = format!("figcraft://join?server={SERVER}&file={FILE}#{fragment}");
    assert_eq!(link_key(&link), Some(fragment.as_str()));
    assert!(sealed_link(&link) && !sealed_link("figcraft://join?host=1.2.3.4:5&file=ab&token=x#section"));
    let mut s = Session::new();
    // A plain file's link keeps nothing.
    s.keep_file_key(SERVER, FILE, &format!("figcraft://join?server={SERVER}&file={FILE}"));
    assert!(s.prefs.file_keys.is_empty());
    s.keep_file_key("WSS://Share.Example?key=abc", FILE, &link);
    assert_eq!(s.prefs.file_keys.len(), 1);
    assert_eq!(s.file_key(SERVER, FILE), Some(fragment.as_str()), "by the server as kept, whatever the spelling");
    assert!(s.live.unsaved, "saved at once");
    assert!(!format!("{:?}", s.prefs).contains(&fragment[2..]), "Debug leaves the key out");
    // A member's link without the key gets it; one with a fragment stays as it is.
    let bare = format!("figcraft://join?server={SERVER}&file={FILE}");
    assert_eq!(s.link_with_key(&bare), link);
    assert_eq!(s.link_with_key(&link), link);
    let other = "figcraft://join?server=wss://share.example/&file=ffffffffffffffff";
    assert_eq!(s.link_with_key(other), other);
    // The links others get carry it, without join codes.
    let shared = Shared {
        edit: SharedLink { id: "e".into(), link: format!("{bare}&token=EditEditEditEditEdit00"), code: Some("K7M2QX9TD".into()) },
        view: Some(SharedLink { id: "v".into(), link: format!("{bare}&token=ViewViewViewViewView00"), code: Some("K7M2QX9TE".into()) }),
    };
    let keyed = s.links_with_key(SERVER, FILE, shared.clone());
    assert!(keyed.edit.link.ends_with(&format!("#{fragment}")) && keyed.view.as_ref().unwrap().link.ends_with(&format!("#{fragment}")));
    assert!(keyed.edit.code.is_none() && keyed.view.as_ref().unwrap().code.is_none());
    assert_eq!(s.links_with_key(SERVER, "ffffffffffffffff", shared.clone()), shared, "a plain file's links stay as they are");
    // Names in listings: opened with the key kept, or the link's; else "Encrypted file".
    let sealed = sealed_name_text(&seal(&k, FILE, &Slot::Meta { what: "name".into() }, b"Plans").unwrap());
    assert_eq!(s.listed_name(SERVER, FILE, &sealed, None), ("Plans".to_string(), true));
    assert_eq!(s.listed_name(SERVER, FILE, "Plain name", None), ("Plain name".to_string(), false));
    let fresh = Session::new();
    assert_eq!(fresh.listed_name(SERVER, FILE, &sealed, None), (ENCRYPTED_NAME.to_string(), true));
    assert_eq!(fresh.listed_name(SERVER, FILE, &sealed, Some(&link)), ("Plans".to_string(), true));
    assert_eq!(fresh.listed_name(SERVER, "ffffffffffffffff", &sealed, Some(&link)), (ENCRYPTED_NAME.to_string(), true), "bound to its file");
    // Renaming seals the new name with the key.
    let renamed = s.seal_name(SERVER, FILE, "New").unwrap().unwrap();
    assert_eq!(s.listed_name(SERVER, FILE, &sealed_name_text(&renamed), None).0, "New");
    assert!(fresh.seal_name(SERVER, FILE, "New").is_none());
}

#[test]
fn the_keys_survive_a_restart_and_junk() {
    let (_, fragment) = key();
    let mut s = Session::new();
    s.keep_file_key(SERVER, FILE, &format!("figcraft://join?server={SERVER}&file={FILE}#{fragment}"));
    let saved = serde_json::to_value(&s.prefs).unwrap();
    assert_eq!(saved["file_keys"][0]["key"], fragment.as_str(), "kept on this computer, with the preferences");
    let back: Prefs = serde_json::from_value(saved).unwrap();
    assert_eq!(back.file_keys, s.prefs.file_keys);
    assert!(serde_json::to_value(Prefs::default()).unwrap().get("file_keys").is_none());
    for junk in [
        json!(3),
        json!("x"),
        json!([1, null, {"server": SERVER}]),
        json!([{"server": SERVER, "file": "../x", "key": fragment}]),
        json!([{"server": SERVER, "file": FILE, "key": "k=short"}]),
    ] {
        let p: Prefs = serde_json::from_value(json!({"theme": "dark", "file_keys": junk})).unwrap();
        assert!(p.theme == "dark" && p.file_keys.is_empty(), "{junk}");
    }
    // Duplicates and too many are dropped.
    let many: Vec<_> =
        (0..MAX_FILE_KEYS + 5).map(|i| json!({"server": SERVER, "file": format!("{:016x}", i % (MAX_FILE_KEYS + 3)), "key": fragment})).collect();
    let p: Prefs = serde_json::from_value(json!({"file_keys": many})).unwrap();
    assert_eq!(p.file_keys.len(), MAX_FILE_KEYS);
}
