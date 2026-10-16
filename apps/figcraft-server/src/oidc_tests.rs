//! A whole browser sign-in through a real OpenID Connect exchange, offline: a fake issuer on
//! loopback (discovery, keys, token endpoint checking the PKCE verifier against the challenge the
//! app sent), the server's `oidc` provider talking to it over HTTP, and the app's `account.signIn`
//! with this test standing in for the browser.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use figcraft_auth::{AuthConfig, ProviderConfig};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::test_util::{TempDir, config, session};

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// What the fake issuer saw.
#[derive(Default)]
struct Seen {
    /// code → the PKCE challenge it was issued for.
    codes: HashMap<String, String>,
    exchanges: u32,
}

struct Issuer {
    url: String,
    seen: Arc<Mutex<Seen>>,
}

fn query(path: &str) -> HashMap<String, String> {
    let q = path.split_once('?').map_or("", |(_, q)| q);
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace("%2F", "/").replace("%3A", ":").replace("%20", " ").replace("+", " ")))
        .collect()
}

fn respond(mut s: TcpStream, status: &str, body: &str) {
    let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// Read one HTTP request: its first line and body.
fn read_request(s: &mut TcpStream) -> (String, String) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
                return (text.lines().next().unwrap_or_default().to_string(), body);
            }
        }
    }
    (String::new(), String::new())
}

fn issuer() -> Issuer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (iss, shared) = (url.clone(), seen.clone());
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let (line, body) = read_request(&mut s);
            let path = line.split(' ').nth(1).unwrap_or_default().to_string();
            if path.starts_with("/.well-known/openid-configuration") {
                let d = json!({"issuer": iss, "authorization_endpoint": format!("{iss}/authorize"), "token_endpoint": format!("{iss}/token"), "jwks_uri": format!("{iss}/keys")});
                respond(s, "200 OK", &d.to_string());
            } else if path.starts_with("/keys") {
                let p = key.public_key().as_ref();
                let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig", "x": b64(&p[1..33]), "y": b64(&p[33..65])}]});
                respond(s, "200 OK", &jwks.to_string());
            } else if path.starts_with("/token") {
                let form = query(&format!("?{body}"));
                let mut seen = shared.lock().unwrap();
                seen.exchanges += 1;
                let challenge = form.get("code").and_then(|c| seen.codes.get(c)).cloned();
                let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                let ok = challenge.is_some_and(|c| c == b64(&Sha256::digest(verifier.as_bytes())))
                    && form.get("client_id").map(String::as_str) == Some("figcraft-desktop")
                    && form.get("client_secret").map(String::as_str) == Some("shh");
                if !ok {
                    respond(s, "400 Bad Request", r#"{"error":"invalid_grant"}"#);
                    continue;
                }
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let claims = json!({"iss": iss, "aud": "figcraft-desktop", "sub": "g-42", "email": "ann@example.com", "email_verified": true, "name": "Ann", "iat": now, "exp": now + 600});
                let signed = format!("{}.{}", b64(json!({"alg": "ES256", "kid": "k1"}).to_string().as_bytes()), b64(claims.to_string().as_bytes()));
                let sig = key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
                respond(s, "200 OK", &json!({"id_token": format!("{signed}.{}", b64(sig.as_ref())), "token_type": "Bearer"}).to_string());
            } else {
                respond(s, "404 Not Found", "{}");
            }
        }
    });
    Issuer { url, seen }
}

#[test]
fn a_browser_sign_in_through_openid_connect() {
    let is = issuer();
    let dir = TempDir::new("oidc");
    let cfg = Config {
        auth: AuthConfig {
            mode: "accounts".into(),
            provider: vec![ProviderConfig {
                id: "corp".into(),
                kind: "oidc".into(),
                label: "Corp".into(),
                issuer: is.url.clone(),
                client_id: "figcraft-desktop".into(),
                client_secret: "shh".into(),
                ..ProviderConfig::default()
            }],
            ..AuthConfig::default()
        },
        ..config(dir.path())
    };
    let mut server = crate::start(&cfg).unwrap();
    let url = format!("ws://{}/", server.addr());
    let mut ann = session("Ann");
    let info = ann.execute("account.info", &json!({"server": url})).unwrap();
    assert_eq!(info["providers"][0]["flows"], json!(["browser"]));
    let r = ann.execute("account.signIn", &json!({"server": url})).unwrap();
    assert_eq!(r["status"], "waitingForBrowser");
    let page = r["url"].as_str().unwrap().to_string();
    assert!(page.starts_with(&format!("{}/authorize?", is.url)), "{page}");
    // The UI is asked to open it.
    assert!(ann.ui_requests.iter().any(|u| u.kind == "open.url"));
    // The browser: the person signs in; the issuer sends them back with a code.
    let q = query(&page);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["client_id"], "figcraft-desktop");
    is.seen.lock().unwrap().codes.insert("code-1".into(), q["code_challenge"].clone());
    let back = format!("{}?state={}&code=code-1", q["redirect_uri"], q["state"]);
    let (host, path) = back.trim_start_matches("http://").split_once('/').unwrap();
    let mut s = TcpStream::connect(host).unwrap();
    write!(s, "GET /{path} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = s.read_to_string(&mut answer);
    assert!(answer.contains("Signed in"), "{answer}");
    // The app hears of it and keeps the sign-in.
    let start = Instant::now();
    while ann.prefs.accounts.is_empty() {
        ann.live_poll();
        assert!(start.elapsed() < Duration::from_secs(20), "no sign-in: {:?}", ann.accounts);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ann.prefs.accounts[0].name, "Ann");
    assert_eq!(ann.prefs.accounts[0].email.as_deref(), Some("ann@example.com"));
    assert_eq!(is.seen.lock().unwrap().exchanges, 1);
    let status: Value = ann.execute("account.status", &json!({})).unwrap();
    assert!(status["pending"].is_null());
    assert_eq!(status["last"]["signedInAs"], "Ann");
    server.stop();
}
