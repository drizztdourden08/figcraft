//! Password hashes, rules and the guard against guessing.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;

/// Cheap parameters: the tests check the logic, not the cost.
const CHEAP: (u32, u32, u32) = (64, 1, 1);

#[test]
fn hashes_verify_and_record_their_parameters() {
    let h = hash_with("correct horse battery", CHEAP).unwrap();
    assert!(h.starts_with("$argon2id$v=19$m=64,t=1,p=1$"), "{h}");
    assert!(verify("correct horse battery", &h));
    assert!(!verify("correct horse batterY", &h));
    assert!(!verify("", &h));
    // Every hash has its own salt.
    assert_ne!(h, hash_with("correct horse battery", CHEAP).unwrap());
    // The real parameters work too.
    let real = hash_password("correct horse battery").unwrap();
    assert!(real.contains("m=19456,t=2,p=1"));
    assert!(verify("correct horse battery", &real));
}

#[test]
fn damaged_or_greedy_hashes_match_nothing() {
    let h = hash_with("correct horse battery", CHEAP).unwrap();
    for bad in [
        String::new(),
        "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaA".to_string(),
        h.replace("m=64", "m=99999999"),
        h.replace("t=1", "t=1000"),
        h.replace("v=19", "v=16"),
        format!("{h}$extra"),
        h.get(..h.len() - 4).unwrap().to_string(),
        "$argon2id$v=19$m=64,t=1,p=1$!!!$!!!".to_string(),
    ] {
        assert!(!verify("correct horse battery", &bad), "{bad}");
    }
}

#[test]
fn password_rules() {
    assert!(check_new("ann", "short").is_err());
    assert!(check_new("ann", &"x".repeat(257)).is_err());
    assert!(check_new("annabelle1", "Annabelle1").is_err());
    assert!(check_new("ann", "tab\tinside!!").is_err());
    assert!(check_new("ann", "long enough pass").is_ok());
    assert!(check_new("ann", &"é".repeat(256)).is_ok());
}

#[test]
fn usernames() {
    assert_eq!(username(" Ann.Lee "), Some("ann.lee".into()));
    assert_eq!(username("ann@example.com"), Some("ann@example.com".into()));
    for bad in ["", "-ann", "a b", "ann/x", &"a".repeat(65), "ännа"] {
        assert_eq!(username(bad), None, "{bad}");
    }
}

#[test]
fn generated_passwords_follow_the_rules() {
    let a = generate().unwrap();
    assert_eq!(a.len(), 23);
    assert_eq!(a.matches('-').count(), 3);
    assert!(check_new("someone", &a).is_ok());
    assert_ne!(a, generate().unwrap());
}

#[test]
fn the_book_adds_checks_resets_and_removes() {
    let dir = crate::test_util::TempDir::new("pw-book");
    let book = Passwords::open_with(dir.path(), CHEAP).unwrap();
    assert_eq!(book.add("Ann", Some("Ann@Example.com"), true, "Ann", Some("long enough pass")).unwrap(), None);
    assert!(book.add("ann", None, true, "", Some("another password")).unwrap_err().contains("taken"));
    assert!(book.add("bob", None, true, "", Some("bob")).is_err());
    let made = book.add("bob", None, true, "Bob", None).unwrap().unwrap();
    assert!(book.check("bob", &made).is_some_and(|u| u.temporary));
    assert_eq!(book.check("ANN", "long enough pass").unwrap().email.as_deref(), Some("ann@example.com"));
    assert!(book.check("ann", "wrong password!").is_none());
    assert!(book.check("nobody", "long enough pass").is_none());
    // Kept on disk without the password.
    let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
    assert!(!text.contains("long enough pass") && !text.contains(&made));
    let again = Passwords::open_with(dir.path(), CHEAP).unwrap();
    assert!(again.check("ann", "long enough pass").is_some());
    let reset = again.set("ann", None).unwrap().unwrap();
    assert!(again.check("ann", "long enough pass").is_none());
    assert!(again.check("ann", &reset).is_some());
    again.set("ann", Some("my own password")).unwrap();
    assert!(!again.get("ann").unwrap().temporary);
    again.remove("ann").unwrap();
    assert!(again.check("ann", "my own password").is_none());
    assert!(again.remove("ann").is_err());
}

#[test]
fn the_guard_locks_usernames_and_addresses_out() {
    let mut g = Guard::default();
    let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let other = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let t = Instant::now();
    for i in 0..WRONG_PER_USER {
        assert!(g.try_password("ann", ip, t).is_ok(), "{i}");
        g.wrong("ann", ip, t);
    }
    // Ann is locked out from everywhere; others still try from that address.
    assert_eq!(g.try_password("ann", other, t), Err(LOCKED));
    assert!(g.try_password("bob", ip, t).is_ok());
    assert!(g.user_locked("ann", t).is_some());
    // Over after the lockout.
    assert!(g.try_password("ann", other, t + LOCKOUT + Duration::from_secs(1)).is_ok());
    g.unlock("ann");
    assert!(g.user_locked("ann", t).is_none());

    // Many usernames from one address lock the address out.
    let mut g = Guard::default();
    let mut at = t;
    for i in 0..WRONG_PER_ADDRESS {
        at += Duration::from_secs(7);
        assert!(g.try_password(&format!("u{i}"), ip, at).is_ok(), "{i}");
        g.wrong(&format!("u{i}"), ip, at);
    }
    assert_eq!(g.try_password("new", ip, at), Err(LOCKED));
    assert!(g.try_password("new", other, at).is_ok());

    // At most TRIES_PER_MINUTE a minute from one address, right or wrong.
    let mut g = Guard::default();
    for _ in 0..TRIES_PER_MINUTE as u32 {
        assert!(g.try_password("ann", ip, t).is_ok());
        g.right("ann", ip);
    }
    assert_eq!(g.try_password("ann", ip, t), Err(SLOW_DOWN));
    assert!(g.try_password("ann", ip, t + Duration::from_secs(10)).is_ok());

    // Sign-ups.
    let mut g = Guard::default();
    for _ in 0..SIGNUPS_PER_HOUR as u32 {
        assert!(g.try_signup(IpAddr::V4(Ipv4Addr::LOCALHOST), t).is_ok());
    }
    assert!(g.try_signup(IpAddr::V4(Ipv4Addr::LOCALHOST), t).is_err());
}

#[test]
fn password_provider_settings() {
    let ok = ProviderConfig { id: "basic".into(), kind: "password".into(), allow_signup: true, ..ProviderConfig::default() };
    assert!(check_config(&ok).is_ok());
    let bad = ProviderConfig { issuer: "https://x".into(), ..ok.clone() };
    assert!(check_config(&bad).is_err());
}
