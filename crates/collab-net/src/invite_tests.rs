//! Invite links and server addresses: every form reads back, bad links are refused without
//! echoing them, and the parsers survive anything.

use proptest::prelude::*;

use crate::invite::{Endpoint, Invite};

const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUv";

fn invite() -> Invite {
    Invite::new("192.168.1.20:47900", "0123456789abcdef", TOKEN)
}

#[test]
fn both_forms_read_back() {
    let i = invite();
    assert_eq!(i.link(), format!("figcraft://join?host=192.168.1.20:47900&file=0123456789abcdef&token={TOKEN}"));
    assert_eq!(Invite::parse(&i.link()), Ok(i.clone()));
    assert_eq!(Invite::parse(&i.url()), Ok(i.clone()));
    // Pasted with spaces, quotes or angle brackets, or with escapes.
    assert_eq!(Invite::parse(&format!("  <{}>\n", i.link())), Ok(i.clone()));
    assert_eq!(Invite::parse(&format!("\"{}\"", i.url())), Ok(i.clone()));
    assert_eq!(Invite::parse(&format!("figcraft://join?host=192.168.1.20%3A47900&file=0123456789abcdef&token={TOKEN}")), Ok(i.clone()));
    // The secret never travels in the WebSocket request.
    assert_eq!(i.endpoint(), "ws://192.168.1.20:47900/");
    assert_eq!(i.server.display(), "192.168.1.20:47900");
}

#[test]
fn hosts_can_be_v6_or_names() {
    let v6 = Invite::new("[::1]:47900", "0123456789abcdef", TOKEN);
    assert_eq!(Invite::parse(&v6.link()), Ok(v6.clone()));
    assert_eq!(Invite::parse(&v6.url()), Ok(v6.clone()));
    assert!(v6.loopback());
    let name = Invite::new("studio.local:47900", "0123456789abcdef", TOKEN);
    assert_eq!(Invite::parse(&name.link()), Ok(name));
}

#[test]
fn server_links_carry_tls_and_a_path() {
    // A server behind a TLS reverse proxy, under a path: the server= form.
    let i = Invite { server: Endpoint { host: "figcraft.example.com:443".into(), path: "/live/".into(), secure: true }, ..invite() };
    assert_eq!(i.link(), format!("figcraft://join?server=wss://figcraft.example.com:443/live/&file=0123456789abcdef&token={TOKEN}"));
    assert_eq!(i.url(), format!("wss://figcraft.example.com:443/live/?file=0123456789abcdef&token={TOKEN}"));
    assert_eq!(i.endpoint(), "wss://figcraft.example.com:443/live/");
    assert_eq!(i.server.display(), "wss://figcraft.example.com:443/live/");
    assert_eq!(Invite::parse(&i.link()), Ok(i.clone()));
    assert_eq!(Invite::parse(&i.url()), Ok(i.clone()));
    // The scheme's port when there's none, and a path without its last slash.
    assert_eq!(Invite::parse(&format!("wss://figcraft.example.com/live?file=0123456789abcdef&token={TOKEN}")), Ok(i.clone()));
    assert_eq!(
        Invite::parse(&format!("figcraft://join?server=wss%3A%2F%2Ffigcraft.example.com%2Flive%2F&file=0123456789abcdef&token={TOKEN}")),
        Ok(i)
    );
    // A plain server at / is the same as an app's invite.
    let plain = Invite::parse(&format!("figcraft://join?server=ws://10.0.0.5:47900&file=0123456789abcdef&token={TOKEN}")).unwrap();
    assert_eq!(plain, Invite::new("10.0.0.5:47900", "0123456789abcdef", TOKEN));
    assert!(plain.link().starts_with("figcraft://join?host=10.0.0.5:47900&"));
}

#[test]
fn server_addresses_with_a_key() {
    let (e, q) = Endpoint::parse("ws://127.0.0.1:47900/?key=KeyKeyKeyKeyKeyKeyKey0").unwrap();
    assert_eq!(e, Endpoint::plain("127.0.0.1:47900"));
    assert_eq!(q, vec![("key".to_string(), "KeyKeyKeyKeyKeyKeyKey0".to_string())]);
    let (e, q) = Endpoint::parse(" wss://example.org ").unwrap();
    assert_eq!(e, Endpoint { host: "example.org:443".into(), path: "/".into(), secure: true });
    assert!(q.is_empty());
    let secret = "SuperSecretToken123456";
    for bad in [
        format!("http://example.org/?key={secret}"),
        format!("ws://exa mple.org/?key={secret}"),
        format!("ws://example.org:0/?key={secret}"),
        format!("ws://example.org/a/?key={secret}%zz"),
        format!("ws://example.org/<x>/?key={secret}"),
        format!("example.org?key={secret}"),
    ] {
        let e = Endpoint::parse(&bad).expect_err(&bad);
        assert!(!e.contains(secret), "{e}");
    }
}

#[test]
fn bad_links_are_refused_without_echoing_them() {
    let secret = "SuperSecretToken123456";
    for bad in [
        String::new(),
        "hello".into(),
        format!("https://example.com/?token={secret}"),
        format!("figcraft://node/12?token={secret}"),
        format!("figcraft://join?file=abc&token={secret}"),
        format!("figcraft://join?host=10.0.0.1&file=abc&token={secret}"),
        format!("figcraft://join?host=10.0.0.1:0&file=abc&token={secret}"),
        format!("figcraft://join?host=10.0.0.1:47900&token={secret}"),
        "figcraft://join?host=10.0.0.1:47900&file=abc&token=short".into(),
        format!("figcraft://join?host=10.0.0.1:47900&file=a/b&token={secret}"),
        format!("figcraft://join?host=10.0.0.1:47900&file=abc&token={secret}%zz"),
        format!("figcraft://join?server=http://10.0.0.1:47900/&file=abc&token={secret}"),
        format!("wss://10.0.0.1:47900/?file=abc&token=short{secret}!"),
        format!("figcraft://join?host=10.0.0.1:47900&file=abc&token={}", "x".repeat(3000)),
    ] {
        let e = Invite::parse(&bad).expect_err(&bad);
        assert!(!e.contains(secret), "{e}");
    }
}

/// A sealed file's link carries its key after `#k=`: it reads back, but it is never in what is
/// sent (the WebSocket URL), in `Debug` or in an error.
#[test]
fn sealed_links_carry_the_key_in_the_fragment_only() {
    let key = figcraft_collab_seal::FileKey::generate().unwrap();
    let fragment = figcraft_collab_seal::link_fragment(&key);
    let secret = fragment.trim_start_matches("k=").to_string();
    let i = invite().with_key(Some(key.clone()));
    assert_eq!(i.link(), format!("{}#{fragment}", invite().link()));
    assert_eq!(i.url(), format!("{}#{fragment}", invite().url()));
    assert_eq!(Invite::parse(&i.link()), Ok(i.clone()));
    assert_eq!(Invite::parse(&i.url()), Ok(i.clone()));
    assert_eq!(Invite::parse(&format!("  <{}>  ", i.link())), Ok(i.clone()));
    // Never sent, never printed.
    assert_eq!(i.endpoint(), "ws://192.168.1.20:47900/");
    assert!(!format!("{i:?}").contains(&secret), "{i:?}");
    // A member's link (no token) on a server with accounts keeps the key too.
    let member = Invite { token: String::new(), ..i.clone() };
    assert!(member.link().ends_with(&format!("&file=0123456789abcdef#{fragment}")), "{}", member.link());
    assert_eq!(Invite::parse(&member.link()), Ok(member));
    // A link with a fragment that isn't a key reads as plain; a broken key is refused unechoed.
    assert_eq!(Invite::parse(&format!("{}#section", invite().link())), Ok(invite()));
    for bad in [format!("{}#k={}", invite().link(), &secret[1..]), format!("{}#k={secret}AA", invite().link()), format!("{}#k=", invite().link())] {
        let e = Invite::parse(&bad).expect_err(&bad);
        assert!(e.contains("key") && !e.contains(&secret[1..20]), "{e}");
    }
    // A join code with a key keeps the key for the file the code opens.
    let (coded, code) = Invite::parse_join(&format!("figcraft://join?server=ws://10.0.0.5:47900/&code=K7M2QX9TD#{fragment}")).unwrap();
    assert!(code.is_some());
    assert_eq!(coded.key.map(|k| k.ring()), Some(figcraft_collab_seal::Keyring::from(key)));
}

proptest! {
    #[test]
    fn the_parsers_survive_anything(s in ".{0,300}") {
        let _ = Invite::parse(&format!("figcraft://join?host=10.0.0.1:47900&file=abc#k={s}"));
        let _ = Invite::parse(&s);
        let _ = Invite::parse(&format!("figcraft://join?{s}"));
        let _ = Invite::parse(&format!("figcraft://join?server={s}"));
        let _ = Invite::parse(&format!("ws://{s}"));
        let _ = Invite::parse(&format!("wss://{s}"));
        let _ = Endpoint::parse(&s);
        let _ = Endpoint::parse(&format!("ws://{s}"));
    }

    #[test]
    fn valid_invites_round_trip(a in 1u8..255, port in 1u16.., file in "[a-f0-9]{1,64}", token in "[A-Za-z0-9_-]{16,128}", path in "(/[a-z0-9]{1,8}){0,3}", secure: bool) {
        let i = Invite { server: Endpoint { host: format!("10.0.0.{a}:{port}"), path: format!("{path}/"), secure }, file, token, key: None };
        prop_assert_eq!(Invite::parse(&i.link()), Ok(i.clone()));
        prop_assert_eq!(Invite::parse(&i.url()), Ok(i.clone()));
        let sealed = i.with_key(figcraft_collab_seal::FileKey::generate().ok());
        prop_assert_eq!(Invite::parse(&sealed.link()), Ok(sealed));
    }
}

/// A file whose key changed epochs carries every epoch in its link; the newest seals, and keys
/// added later reach every copy of the invite.
#[test]
fn links_carry_every_epoch_and_keys_are_shared() {
    let first = figcraft_collab_seal::FileKey::generate().unwrap();
    let second = first.rotate().unwrap();
    let mut ring = figcraft_collab_seal::Keyring::from(first.clone());
    ring.insert(second.clone());
    let link = format!("{}#{}", invite().link(), figcraft_collab_seal::ring_fragment(&ring));
    let i = Invite::parse(&link).unwrap();
    let keys = i.key.clone().unwrap();
    assert_eq!(keys.ring(), ring);
    assert_eq!(keys.current(), Some(second.clone()));
    assert_eq!(i.link(), link);
    let copy = i.clone();
    let third = second.rotate().unwrap();
    keys.add(&figcraft_collab_seal::Keyring::from(third.clone()));
    assert_eq!(copy.key.as_ref().unwrap().current(), Some(third), "every copy sees the new epoch");
    assert!(!format!("{i:?}").contains(&figcraft_collab_seal::link_fragment(&first)[2..30]));
}
