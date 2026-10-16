//! This device's keys and their preferences: made once and kept (with the preferences when no
//! keychain is installed, in the keychain when one is, with the preferences when it refuses),
//! never printed by `Debug`, junk in the preferences file dropped; and the commands refuse without
//! a sign-in.

use std::sync::{Arc, Mutex};

use serde_json::json;
use zeroize::Zeroizing;

use crate::devices::{DevicePrefs, Keychain, Registered};
use crate::{Prefs, Session};

#[derive(Clone, Default)]
struct Fake {
    kept: Arc<Mutex<Option<Vec<u8>>>>,
    refuse: bool,
}

impl Keychain for Fake {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Ok(self.kept.lock().unwrap().clone().map(Zeroizing::new))
    }
    fn store(&self, secret: &[u8]) -> Result<(), String> {
        if self.refuse {
            return Err("locked".into());
        }
        *self.kept.lock().unwrap() = Some(secret.to_vec());
        Ok(())
    }
}

#[test]
fn the_device_key_is_kept_where_it_can_be() {
    // No keychain: with the preferences, and the same key next time.
    let mut s = Session::new();
    let a = s.device_keys_public().unwrap();
    assert!(!s.prefs.device.secret.is_empty());
    assert_eq!(s.device_keys_public().unwrap(), a);
    let mut again = Session::new();
    again.prefs = s.prefs.clone();
    assert_eq!(again.device_keys_public().unwrap(), a);
    assert!(!format!("{:?}", s.prefs).contains(&s.prefs.device.secret), "Debug leaves the secret out");
    // A keychain: kept there, not in the preferences.
    let chain = Fake::default();
    let mut k = Session::new();
    k.keys.keychain = Some(Box::new(chain.clone()));
    let b = k.device_keys_public().unwrap();
    assert!(k.prefs.device.secret.is_empty());
    assert!(chain.kept.lock().unwrap().is_some());
    let mut k2 = Session::new();
    k2.keys.keychain = Some(Box::new(chain.clone()));
    assert_eq!(k2.device_keys_public().unwrap(), b, "read back from the keychain");
    // A keychain that refuses: with the preferences.
    let mut r = Session::new();
    r.keys.keychain = Some(Box::new(Fake { refuse: true, ..Fake::default() }));
    r.device_keys_public().unwrap();
    assert!(!r.prefs.device.secret.is_empty());
}

#[test]
fn device_prefs_survive_junk() {
    for junk in [json!(7), json!("x"), json!({"secret": 5}), json!({"registered": "no"}), json!({"secret": "A".repeat(500)})] {
        let p: Prefs = serde_json::from_value(json!({"theme": "dark", "device": junk})).unwrap();
        assert_eq!(p.theme, "dark");
        assert!(p.device.secret.len() <= 128, "{junk}");
    }
    let p = DevicePrefs {
        name: "Laptop".into(),
        secret: "c2VjcmV0".into(),
        registered: vec![Registered { server: "wss://a/".into(), device: "d1".into(), public: "pk".into() }],
        seen: vec![crate::devices::SeenNumber { server: "wss://a/".into(), account: "a1".into(), number: "1234 5678 9012".into() }],
    };
    let back: Prefs = serde_json::from_value(json!({"device": serde_json::to_value(&p).unwrap()})).unwrap();
    assert_eq!(back.device, p);
    assert!(serde_json::to_value(Prefs::default()).unwrap().get("device").is_none());
    // A damaged secret is an error, never a panic.
    let mut s = Session::new();
    s.prefs.device.secret = "!!!".into();
    assert!(s.device_keys_public().is_err());
}

#[test]
fn the_commands_need_a_sign_in() {
    let mut s = Session::new();
    for (cmd, p) in [
        ("account.devices", json!({"server": "wss://a.example/"})),
        ("account.revokeDevice", json!({"server": "wss://a.example/", "device": "d1"})),
        ("account.recoveryKey", json!({"server": "wss://a.example/"})),
        ("account.recover", json!({"server": "wss://a.example/", "recoveryKey": "AAAAA"})),
        ("account.syncKeys", json!({"server": "wss://a.example/"})),
        ("account.safetyNumber", json!({"server": "wss://a.example/"})),
    ] {
        assert!(s.execute(cmd, &p).is_err(), "{cmd}");
    }
    assert!(!s.live_summary()["waitingForAccess"].as_bool().unwrap());
}

/// The editors a session's server lists: the first devices seen of someone are remembered, a
/// different set later is a key change (`account.status` lists it), the same set again isn't.
#[test]
fn a_change_in_someones_devices_is_noticed() {
    use figcraft_collab::message::EditorDevice;
    use figcraft_collab_seal::DeviceKeys;

    let mut s = Session::new();
    let entry = |d: &DeviceKeys| EditorDevice { account: "a1".into(), device: "d".into(), public: d.public().unwrap(), recovery: false };
    let (one, two) = (DeviceKeys::generate().unwrap(), DeviceKeys::generate().unwrap());
    s.editors_seen("ws://h/", "f", &[entry(&one)]);
    assert!(s.keys.changes.is_empty(), "first seen: trusted");
    assert_eq!(s.prefs.device.seen.len(), 1);
    s.editors_seen("WS://h", "f", &[entry(&one)]);
    assert!(s.keys.changes.is_empty(), "the same devices");
    s.editors_seen("ws://h/", "f", &[entry(&one), entry(&two)]);
    assert_eq!(s.keys.changes.len(), 1);
    assert_eq!(s.message.as_deref(), Some(crate::devices::KEY_CHANGED));
    let status = s.execute("account.status", &json!({})).unwrap();
    assert_eq!(status["keyChanges"][0]["account"], "a1");
    assert_ne!(status["keyChanges"][0]["was"], status["keyChanges"][0]["now"]);
    // Kept with the preferences, junk dropped.
    let text = serde_json::to_string(&s.prefs).unwrap();
    let back: Prefs = serde_json::from_str(&text).unwrap();
    assert_eq!(back.device.seen, s.prefs.device.seen);
}
