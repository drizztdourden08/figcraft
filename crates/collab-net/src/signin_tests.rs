use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use figcraft_auth::{Flow, ProviderInfo};

use crate::signin::*;

#[test]
fn pkce_matches_rfc_7636() {
    // RFC 7636 appendix B.
    let p = Pkce { verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(), state: "s".into() };
    assert_eq!(p.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    let fresh = Pkce::new().unwrap();
    assert!(fresh.verifier.len() >= 43 && fresh.state.len() >= 20);
    assert_ne!(fresh.verifier, Pkce::new().unwrap().verifier);
}

#[test]
fn the_page_carries_everything_once() {
    let p = Pkce { verifier: "v".into(), state: "st8".into() };
    let url = p.authorize_url(
        "https://issuer.test/auth?hd=x",
        "client 1",
        &["openid".into(), "email".into()],
        &[("prompt".into(), "select_account".into()), ("state".into(), "evil".into())],
        "http://127.0.0.1:5/",
    );
    assert!(url.starts_with("https://issuer.test/auth?hd=x&response_type=code&client_id=client%201&redirect_uri=http%3A%2F%2F127.0.0.1%3A5%2F"));
    assert!(url.contains("scope=openid%20email") && url.contains("code_challenge_method=S256") && url.contains("prompt=select_account"));
    // A configured parameter can't replace ours.
    assert_eq!(url.matches("state=").count(), 1);
    assert!(url.contains("state=st8"));
}

#[test]
fn callbacks_are_read_and_others_ignored() {
    assert_eq!(callback("GET /?code=abc%2Fd&state=s HTTP/1.1", "s"), Some(Ok("abc/d".into())));
    assert_eq!(callback("GET /?code=abc&state=other HTTP/1.1", "s"), None, "someone else's redirect");
    assert_eq!(callback("GET /favicon.ico HTTP/1.1", "s"), None);
    assert!(
        matches!(callback("GET /?error=access_denied&error_description=no+thanks&state=s HTTP/1.1", "s"), Some(Err(e)) if e.contains("no thanks"))
    );
    assert_eq!(callback("POST /?code=a&state=s HTTP/1.1", "s"), None);
    assert_eq!(callback("garbage", "s"), None);
}

#[test]
fn flows_are_chosen_as_offered() {
    let p = |flows: Vec<Flow>| ProviderInfo { id: "p".into(), label: "P".into(), flows };
    let browser = Flow::Browser { authorize_url: "u".into(), client_id: "c".into(), scopes: vec![], params: vec![] };
    assert_eq!(choose(&p(vec![browser.clone(), Flow::Device]), None), Ok(Via::Browser));
    assert_eq!(choose(&p(vec![Flow::Device]), None), Ok(Via::Device));
    assert!(choose(&p(vec![Flow::Device]), Some(Via::Browser)).is_err());
    assert!(choose(&p(vec![Flow::Token { label: "T".into() }]), None).is_err(), "a token has to be given");
    assert_eq!(choose(&p(vec![Flow::Token { label: "T".into() }]), Some(Via::Token("t".into()))), Ok(Via::Token("t".into())));
    assert!(choose(&p(vec![]), None).is_err());
    let list = vec![p(vec![]), ProviderInfo { id: "q".into(), label: "Q".into(), flows: vec![] }];
    assert_eq!(pick(&list, Some("q")).unwrap().id, "q");
    assert_eq!(pick(&list, None).unwrap().id, "p");
    assert!(pick(&list, Some("zzz")).is_err());
    assert!(pick(&[], None).is_err());
}

#[test]
fn the_app_waits_for_the_browser_to_come_back() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let browser = std::thread::spawn(move || {
        let ask = |path: &str| {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
            let mut page = String::new();
            let _ = s.read_to_string(&mut page);
            page
        };
        // A stray request first (the favicon), then the real redirect.
        let stray = ask("/favicon.ico");
        let done = ask("/?state=st&code=the-code");
        (stray, done)
    });
    let code = wait_for_code(&listener, "st", Instant::now() + Duration::from_secs(10)).unwrap();
    assert_eq!(code, "the-code");
    let (stray, done) = browser.join().unwrap();
    assert!(stray.contains("Sign-in stopped") && done.contains("Signed in"));
    // Nobody comes back: it gives up at the deadline.
    let quiet = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    assert!(wait_for_code(&quiet, "st", Instant::now() + Duration::from_millis(300)).unwrap_err().contains("in time"));
}

#[test]
fn query_encoding() {
    assert_eq!(encode("a b/c?d=e&f~g"), "a%20b%2Fc%3Fd%3De%26f~g");
    assert_eq!(encode("é"), "%C3%A9");
}

#[test]
fn a_redirect_arriving_in_pieces_is_read_whole() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let browser = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_nodelay(true).unwrap();
        for piece in ["GET /?st", "ate=st&co", "de=slow-code HTTP/1.1\r\nHost: x\r\n\r\n"] {
            s.write_all(piece.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut page = String::new();
        let _ = s.read_to_string(&mut page);
        page
    });
    assert_eq!(wait_for_code(&listener, "st", Instant::now() + Duration::from_secs(10)).unwrap(), "slow-code");
    assert!(browser.join().unwrap().contains("Signed in"));
}

#[test]
fn the_app_reads_a_server_sign_out_as_the_end_of_its_sign_in() {
    // The engine forgets the sign-in when a session closes with this reason (it can't see the hub).
    assert!(crate::hub::SIGNED_OUT.starts_with(figcraft_engine::accounts::SIGNED_OUT));
    assert!(figcraft_engine::accounts::session_ended(crate::hub::SIGNED_OUT));
    assert!(!figcraft_engine::accounts::session_ended(crate::hub::REMOVED));
}
