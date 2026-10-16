//! The built-in providers against a fake issuer and verifier (no network): real signatures,
//! made here with freshly generated keys.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use crate::registry::Registry;
use crate::*;

const ISSUER: &str = "https://issuer.test";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A signing key of the fake issuer.
enum Key {
    Es(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
}

impl Key {
    fn es() -> Key {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Key::Es(EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap())
    }

    fn ed() -> Key {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Key::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn alg(&self) -> &'static str {
        match self {
            Key::Es(_) => "ES256",
            Key::Ed(_) => "EdDSA",
        }
    }

    fn jwk(&self, kid: &str) -> Value {
        match self {
            Key::Es(k) => {
                let p = k.public_key().as_ref();
                json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256", "x": b64(&p[1..33]), "y": b64(&p[33..65])})
            }
            Key::Ed(k) => json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64(k.public_key().as_ref())}),
        }
    }

    fn sign(&self, kid: &str, claims: &Value) -> String {
        let header = json!({"alg": self.alg(), "kid": kid, "typ": "JWT"});
        let signed = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let sig = match self {
            Key::Es(k) => k.sign(&SystemRandom::new(), signed.as_bytes()).unwrap().as_ref().to_vec(),
            Key::Ed(k) => k.sign(signed.as_bytes()).as_ref().to_vec(),
        };
        format!("{signed}.{}", b64(&sig))
    }
}

fn claims(sub: &str) -> Value {
    json!({"iss": ISSUER, "aud": "client-1", "sub": sub, "email": "Ann@Example.com", "email_verified": true, "name": "Ann", "iat": now(), "exp": now() + 600})
}

type Answer = Result<Vec<u8>, FetchError>;

/// Answers by URL; remembers what was posted.
#[derive(Default)]
struct Fake {
    gets: Mutex<HashMap<String, Answer>>,
    posts: Mutex<HashMap<String, Vec<Answer>>>,
    asked: Mutex<Vec<String>>,
    sent: Mutex<Vec<String>>,
}

impl Fake {
    fn get(&self, url: &str, body: Value) {
        self.gets.lock().unwrap().insert(url.into(), Ok(body.to_string().into_bytes()));
    }

    fn post(&self, url: &str, answer: Result<Value, (u16, Value)>) {
        let a = answer.map(|v| v.to_string().into_bytes()).map_err(|(status, v)| FetchError::Status { status, body: v.to_string().into_bytes() });
        self.posts.lock().unwrap().entry(url.into()).or_default().push(a);
    }

    fn times_asked(&self, url: &str) -> usize {
        self.asked.lock().unwrap().iter().filter(|u| *u == url).count()
    }
}

impl Fetch for Fake {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        self.asked.lock().unwrap().push(url.into());
        self.gets.lock().unwrap().get(url).cloned().unwrap_or(Err(FetchError::Network("no route".into())))
    }

    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError> {
        self.sent.lock().unwrap().push(form.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&"));
        let mut posts = self.posts.lock().unwrap();
        let q = posts.get_mut(url).ok_or(FetchError::Network("no route".into()))?;
        if q.len() > 1 { q.remove(0) } else { q.first().cloned().ok_or(FetchError::Network("no route".into()))? }
    }

    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, FetchError> {
        self.sent.lock().unwrap().push(String::from_utf8_lossy(body).into_owned());
        let mut posts = self.posts.lock().unwrap();
        let q = posts.get_mut(url).ok_or(FetchError::Network("no route".into()))?;
        if q.len() > 1 { q.remove(0) } else { q.first().cloned().ok_or(FetchError::Network("no route".into()))? }
    }
}

fn issuer(fake: &Fake, keys: &[(&str, &Key)]) {
    fake.get(
        &format!("{ISSUER}/.well-known/openid-configuration"),
        json!({
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/keys"),
            "device_authorization_endpoint": format!("{ISSUER}/device"),
        }),
    );
    fake.get(&format!("{ISSUER}/keys"), json!({"keys": keys.iter().map(|(kid, k)| k.jwk(kid)).collect::<Vec<_>>()}));
}

fn oidc_cfg() -> ProviderConfig {
    ProviderConfig {
        id: "test".into(),
        kind: "oidc".into(),
        issuer: ISSUER.into(),
        client_id: "client-1".into(),
        client_secret: "s3cret".into(),
        flows: vec!["browser".into(), "device".into()],
        ..ProviderConfig::default()
    }
}

fn build(cfg: &ProviderConfig, fake: &Arc<Fake>) -> Box<dyn IdentityProvider> {
    Registry::builtin().build(cfg, fake.clone()).unwrap()
}

#[test]
fn oidc_signs_in_with_a_code_and_checks_the_token() {
    for key in [Key::es(), Key::ed()] {
        let fake = Arc::new(Fake::default());
        issuer(&fake, &[("k1", &key)]);
        fake.post(&format!("{ISSUER}/token"), Ok(json!({"id_token": key.sign("k1", &claims("u-1"))})));
        let p = build(&oidc_cfg(), &fake);
        let info = p.info();
        assert_eq!(info.id, "test");
        assert!(matches!(&info.flows[0], Flow::Browser { authorize_url, client_id, scopes, .. }
            if authorize_url == "https://issuer.test/authorize" && client_id == "client-1" && scopes.contains(&"openid".to_string())));
        assert_eq!(info.flows[1], Flow::Device);
        let who = p.exchange_code("the-code", "the-verifier", "http://127.0.0.1:5000/").unwrap();
        assert_eq!(
            who,
            Identity {
                provider: "test".into(),
                subject: "u-1".into(),
                email: Some("ann@example.com".into()),
                email_verified: true,
                name: Some("Ann".into())
            }
        );
        let sent = fake.sent.lock().unwrap().join(" ");
        assert!(sent.contains("code=the-code") && sent.contains("code_verifier=the-verifier") && sent.contains("client_secret=s3cret"), "{sent}");
        // The discovery document and keys are cached.
        p.exchange_code("again", "v", "http://127.0.0.1:5000/").unwrap();
        assert_eq!(fake.times_asked(&format!("{ISSUER}/.well-known/openid-configuration")), 1);
        assert_eq!(fake.times_asked(&format!("{ISSUER}/keys")), 1);
    }
}

#[test]
fn oidc_refuses_bad_tokens() {
    let key = Key::es();
    let other = Key::es();
    let fake = Arc::new(Fake::default());
    issuer(&fake, &[("k1", &key)]);
    let p = crate::oidc::Oidc::new(&oidc_cfg(), fake.clone()).unwrap();
    let mut c = claims("u");
    assert!(p.check_id_token(&key.sign("k1", &c)).is_ok());
    let refused = |t: &str| matches!(p.check_id_token(t), Err(AuthError::Refused(_)));
    // Signed by someone else under the issuer's key id.
    assert!(refused(&other.sign("k1", &c)));
    // Tampered claims.
    let good = key.sign("k1", &c);
    let mut parts: Vec<&str> = good.split('.').collect();
    let evil = b64(json!({"iss": ISSUER, "aud": "client-1", "sub": "admin", "exp": now() + 600}).to_string().as_bytes());
    parts[1] = &evil;
    assert!(refused(&parts.join(".")));
    // Wrong issuer, audience, expired, from the future, no subject.
    c["iss"] = json!("https://evil.test");
    assert!(refused(&key.sign("k1", &c)));
    let mut c = claims("u");
    c["aud"] = json!(["client-2"]);
    assert!(refused(&key.sign("k1", &c)));
    let mut c = claims("u");
    c["exp"] = json!(now() - 3600);
    assert!(refused(&key.sign("k1", &c)));
    let mut c = claims("u");
    c["iat"] = json!(now() + 3600);
    assert!(refused(&key.sign("k1", &c)));
    let mut c = claims("u");
    c["sub"] = json!("");
    assert!(refused(&key.sign("k1", &c)));
    // "none" and HMAC algorithms aren't accepted.
    let none = format!("{}.{}.", b64(br#"{"alg":"none"}"#), b64(claims("u").to_string().as_bytes()));
    assert!(refused(&none));
    let hs = format!("{}.{}.{}", b64(br#"{"alg":"HS256","kid":"k1"}"#), b64(claims("u").to_string().as_bytes()), b64(b"x"));
    assert!(refused(&hs));
    // Garbage.
    for junk in ["", "a.b", "a.b.c.d", "!!.??.**", &"x".repeat(20_000)] {
        assert!(refused(junk), "{junk:.20}");
    }
    // Several audiences: azp must be ours.
    let mut c = claims("u");
    c["aud"] = json!(["client-1", "other"]);
    c["azp"] = json!("other");
    assert!(refused(&key.sign("k1", &c)));
    c["azp"] = json!("client-1");
    assert!(p.check_id_token(&key.sign("k1", &c)).is_ok());
}

#[test]
fn oidc_fetches_the_keys_again_when_the_issuer_rotates() {
    let (old, new) = (Key::es(), Key::ed());
    let fake = Arc::new(Fake::default());
    issuer(&fake, &[("old", &old)]);
    let p = crate::oidc::Oidc::new(&oidc_cfg(), fake.clone()).unwrap();
    assert!(p.check_id_token(&old.sign("old", &claims("u"))).is_ok());
    issuer(&fake, &[("old", &old), ("new", &new)]);
    // Cached set doesn't know "new": fetched again (once), then it checks.
    assert!(p.check_id_token(&new.sign("new", &claims("u"))).is_ok());
    assert_eq!(fake.times_asked(&format!("{ISSUER}/keys")), 2);
    // A key nobody published: one more fetch at most a minute later, so none now.
    let stranger = Key::es();
    assert!(matches!(p.check_id_token(&stranger.sign("nobody", &claims("u"))), Err(AuthError::Refused(_))));
    assert_eq!(fake.times_asked(&format!("{ISSUER}/keys")), 2);
}

#[test]
fn oidc_device_flow_polls_until_the_code_is_entered() {
    let key = Key::es();
    let fake = Arc::new(Fake::default());
    issuer(&fake, &[("k1", &key)]);
    fake.post(&format!("{ISSUER}/device"), Ok(json!({"device_code": "dev-1", "user_code": "WXYZ-1234", "verification_url": "https://issuer.test/device", "interval": 5, "expires_in": 900})));
    fake.post(&format!("{ISSUER}/token"), Err((400, json!({"error": "authorization_pending"}))));
    fake.post(&format!("{ISSUER}/token"), Err((400, json!({"error": "slow_down"}))));
    fake.post(&format!("{ISSUER}/token"), Ok(json!({"id_token": key.sign("k1", &claims("u-2"))})));
    let p = build(&oidc_cfg(), &fake);
    let d = p.start_device().unwrap();
    assert_eq!((d.user_code.as_str(), d.verification_uri.as_str(), d.interval, d.expires_in), ("WXYZ-1234", "https://issuer.test/device", 5, 900));
    assert_eq!(p.poll_device(&d.device_code), Err(AuthError::Pending));
    assert_eq!(p.poll_device(&d.device_code), Err(AuthError::Pending));
    assert_eq!(p.poll_device(&d.device_code).unwrap().subject, "u-2");
    // Declined.
    let fake = Arc::new(Fake::default());
    issuer(&fake, &[("k1", &key)]);
    fake.post(&format!("{ISSUER}/token"), Err((400, json!({"error": "access_denied"}))));
    assert!(matches!(build(&oidc_cfg(), &fake).poll_device("x"), Err(AuthError::Refused(_))));
}

#[test]
fn oidc_settings_and_presets() {
    let fake: Arc<Fake> = Arc::new(Fake::default());
    let mk = |c: ProviderConfig| crate::oidc::Oidc::new(&c, fake.clone());
    let google =
        mk(ProviderConfig { id: "g".into(), kind: "oidc".into(), preset: "google".into(), client_id: "x".into(), ..ProviderConfig::default() })
            .unwrap();
    let _ = google;
    assert!(mk(ProviderConfig { id: "g".into(), preset: "nope".into(), client_id: "x".into(), ..ProviderConfig::default() }).is_err());
    assert!(mk(ProviderConfig { id: "g".into(), client_id: "x".into(), ..ProviderConfig::default() }).err().unwrap().contains("issuer"));
    assert!(
        mk(ProviderConfig { id: "g".into(), issuer: "http://insecure.test".into(), client_id: "x".into(), ..ProviderConfig::default() }).is_err()
    );
    assert!(mk(ProviderConfig { id: "g".into(), issuer: ISSUER.into(), ..ProviderConfig::default() }).err().unwrap().contains("client_id"));
    assert!(
        mk(ProviderConfig { id: "g".into(), issuer: ISSUER.into(), client_id: "x".into(), flows: vec!["magic".into()], ..ProviderConfig::default() })
            .is_err()
    );
    assert!(
        mk(ProviderConfig {
            id: "g".into(),
            issuer: ISSUER.into(),
            client_id: "x".into(),
            scopes: vec!["email".into()],
            ..ProviderConfig::default()
        })
        .is_err()
    );
    assert!(
        mk(ProviderConfig {
            id: "g".into(),
            issuer: ISSUER.into(),
            client_id: "x".into(),
            client_secret: "a".into(),
            client_secret_file: "b".into(),
            ..ProviderConfig::default()
        })
        .is_err()
    );
    // Without the discovery document the browser flow is left out (apps ask again later).
    let offline = mk(ProviderConfig { id: "g".into(), issuer: ISSUER.into(), client_id: "x".into(), ..ProviderConfig::default() }).unwrap();
    assert!(offline.info().flows.is_empty());
    // A discovery document naming another issuer isn't believed.
    let fake2 = Arc::new(Fake::default());
    fake2.get(
        &format!("{ISSUER}/.well-known/openid-configuration"),
        json!({"issuer": "https://evil.test", "authorization_endpoint": "a", "token_endpoint": "b", "jwks_uri": "c"}),
    );
    let p = crate::oidc::Oidc::new(&oidc_cfg(), fake2).unwrap();
    assert!(matches!(p.discovery(), Err(AuthError::Unavailable(_))));
}

#[test]
fn external_asks_the_verifier() {
    let fake = Arc::new(Fake::default());
    let url = "https://verify.test/check";
    fake.post(url, Ok(json!({"subject": "emp-7", "email": "Bo@Corp.test", "email_verified": true, "name": "Bo"})));
    let cfg = ProviderConfig {
        id: "corp".into(),
        kind: "external".into(),
        verify_url: url.into(),
        label: "Corp token".into(),
        ..ProviderConfig::default()
    };
    let p = build(&cfg, &fake);
    assert_eq!(p.info().flows, vec![Flow::Token { label: "Corp token".into() }]);
    let who = p.verify_token(" tok-123 ").unwrap();
    assert_eq!((who.subject.as_str(), who.email.as_deref(), who.email_verified), ("emp-7", Some("bo@corp.test"), true));
    assert!(fake.sent.lock().unwrap()[0].contains("\"token\":\"tok-123\""));
    assert_eq!(p.exchange_code("c", "v", "r"), Err(AuthError::Unsupported));
    // Refusals carry the verifier's reason; other failures are "unavailable".
    let fake = Arc::new(Fake::default());
    fake.post(url, Err((401, json!({"error": "token revoked"}))));
    assert_eq!(build(&cfg, &fake).verify_token("t"), Err(AuthError::Refused("token revoked".into())));
    let fake = Arc::new(Fake::default());
    fake.post(url, Err((500, json!({}))));
    assert!(matches!(build(&cfg, &fake).verify_token("t"), Err(AuthError::Unavailable(_))));
    let fake = Arc::new(Fake::default());
    fake.post(url, Ok(json!({"email": "x@y"})));
    assert!(matches!(build(&cfg, &fake).verify_token("t"), Err(AuthError::Unavailable(_))));
    assert!(matches!(build(&cfg, &fake).verify_token(""), Err(AuthError::Refused(_))));
    // Only https (or this machine).
    let plain = ProviderConfig { verify_url: "http://verify.test/".into(), ..cfg.clone() };
    assert!(Registry::builtin().build(&plain, fake.clone()).is_err());
    let local = ProviderConfig { verify_url: "http://127.0.0.1:9/".into(), ..cfg };
    assert!(Registry::builtin().build(&local, fake).is_ok());
}

#[test]
fn registry_takes_kinds_of_your_own() {
    struct Mine;
    impl IdentityProvider for Mine {
        fn info(&self) -> ProviderInfo {
            ProviderInfo { id: "mine".into(), label: "Mine".into(), flows: vec![Flow::Token { label: "Mine".into() }] }
        }
        fn verify_token(&self, token: &str) -> Result<Identity, AuthError> {
            Ok(Identity { provider: "mine".into(), subject: token.into(), email: None, email_verified: false, name: None })
        }
    }
    let fake = Arc::new(Fake::default());
    let mut r = Registry::builtin();
    let cfg = ProviderConfig { id: "mine".into(), kind: "Mine".into(), ..ProviderConfig::default() };
    assert!(r.build(&cfg, fake.clone()).err().unwrap().contains("unknown kind"));
    r.register("mine", |_, _| Ok(Box::new(Mine)));
    assert!(r.kinds().contains(&"mine"));
    assert_eq!(r.build(&cfg, fake).unwrap().verify_token("x").unwrap().subject, "x");
}

#[test]
fn trust_email_counts_an_unsaid_email_as_verified() {
    let key = Key::es();
    let token = |verified: Option<Value>| {
        let mut c = claims("u-1");
        match verified {
            Some(v) => c["email_verified"] = v,
            None => {
                c.as_object_mut().unwrap().remove("email_verified");
            }
        }
        key.sign("k1", &c)
    };
    let fake = Arc::new(Fake::default());
    issuer(&fake, &[("k1", &key)]);
    // Entra ID sends no `email_verified`: unverified unless the provider is trusted.
    let plain = crate::oidc::Oidc::new(&oidc_cfg(), fake.clone()).unwrap();
    assert!(!plain.check_id_token(&token(None)).unwrap().email_verified);
    let trusted = crate::oidc::Oidc::new(&ProviderConfig { trust_email: true, ..oidc_cfg() }, fake.clone()).unwrap();
    assert!(trusted.check_id_token(&token(None)).unwrap().email_verified);
    // An explicit "not verified" is never overridden.
    assert!(!trusted.check_id_token(&token(Some(json!(false)))).unwrap().email_verified);
    assert!(!trusted.check_id_token(&token(Some(json!("false")))).unwrap().email_verified);
    assert!(plain.check_id_token(&token(Some(json!(true)))).unwrap().email_verified);

    // The same for an external verifier that leaves `email_verified` out.
    let url = "https://verify.test/check";
    let cfg = ProviderConfig { id: "corp".into(), kind: "external".into(), verify_url: url.into(), ..ProviderConfig::default() };
    let ask = |cfg: &ProviderConfig, answer: Value| {
        let fake = Arc::new(Fake::default());
        fake.post(url, Ok(answer));
        build(cfg, &fake).verify_token("t").unwrap().email_verified
    };
    let trusted_cfg = ProviderConfig { trust_email: true, ..cfg.clone() };
    assert!(!ask(&cfg, json!({"subject": "s", "email": "a@b.c"})));
    assert!(ask(&trusted_cfg, json!({"subject": "s", "email": "a@b.c"})));
    assert!(!ask(&trusted_cfg, json!({"subject": "s", "email": "a@b.c", "email_verified": false})));
    // The setting reads from server.toml.
    let parsed: ProviderConfig = toml::from_str("id = \"entra\"\nkind = \"oidc\"\ntrust_email = true\n").unwrap();
    assert!(parsed.trust_email);
}

#[test]
fn registry_checks_settings_without_the_network() {
    let r = Registry::builtin();
    let oidc = |c: ProviderConfig| ProviderConfig { id: "p".into(), kind: "oidc".into(), ..c };
    // Good settings pass, and building asks nothing of the network.
    let fake = Arc::new(Fake::default());
    let good = oidc(ProviderConfig { preset: "google".into(), client_id: "x".into(), ..ProviderConfig::default() });
    assert!(r.check(&good).is_ok());
    r.build(&good, fake.clone()).unwrap();
    let ext = ProviderConfig { id: "e".into(), kind: "external".into(), verify_url: "https://v.test/".into(), ..ProviderConfig::default() };
    assert!(r.check(&ext).is_ok());
    r.build(&ext, fake.clone()).unwrap();
    assert!(fake.asked.lock().unwrap().is_empty() && fake.sent.lock().unwrap().is_empty());

    let secret = std::env::temp_dir().join(format!("figcraft-auth-secret-{}", std::process::id()));
    std::fs::write(&secret, "s3cret\n").unwrap();
    let secret_file = secret.display().to_string();
    assert!(
        r.check(&oidc(ProviderConfig {
            issuer: ISSUER.into(),
            client_id: "x".into(),
            client_secret_file: secret_file.clone(),
            ..ProviderConfig::default()
        }))
        .is_ok()
    );
    std::fs::remove_file(&secret).unwrap();

    let bad: &[(ProviderConfig, &str)] = &[
        (ProviderConfig { kind: "carrier-pigeon".into(), ..good.clone() }, "unknown kind"),
        (ProviderConfig { preset: "microsoft".into(), ..good.clone() }, "unknown preset"),
        (oidc(ProviderConfig { client_id: "x".into(), ..ProviderConfig::default() }), "issuer"),
        (oidc(ProviderConfig { issuer: "http://insecure.test".into(), client_id: "x".into(), ..ProviderConfig::default() }), "https"),
        (oidc(ProviderConfig { issuer: ISSUER.into(), ..ProviderConfig::default() }), "client_id"),
        (
            oidc(ProviderConfig { issuer: ISSUER.into(), client_id: "x".into(), client_secret_file: secret_file, ..ProviderConfig::default() }),
            "client_secret_file",
        ),
        (
            oidc(ProviderConfig {
                issuer: ISSUER.into(),
                client_id: "x".into(),
                client_secret: "a".into(),
                client_secret_file: "b".into(),
                ..ProviderConfig::default()
            }),
            "not both",
        ),
        (oidc(ProviderConfig { issuer: ISSUER.into(), client_id: "x".into(), flows: vec!["magic".into()], ..ProviderConfig::default() }), "flow"),
        (ProviderConfig { verify_url: "http://v.test/".into(), ..ext.clone() }, "verify_url"),
        (ProviderConfig { verify_url: String::new(), ..ext }, "verify_url"),
    ];
    for (cfg, why) in bad {
        let e = r.check(cfg).unwrap_err();
        assert!(e.contains(why), "{cfg:?}: {e}");
    }
}
