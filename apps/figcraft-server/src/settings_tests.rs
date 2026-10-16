//! Settings checks that need no network: `check` builds the identity providers offline, and the
//! providers' HTTPS client reads `FIGCRAFT_CA_FILE`.

use base64::Engine as _;
use figcraft_auth::registry::Registry;
use figcraft_auth::{AuthConfig, AuthError, Identity, IdentityProvider, ProviderConfig, ProviderInfo};

use crate::config::Config;
use crate::fetch::{Https, extra_certs, roots_with};
use crate::test_util::{TempDir, config};

fn with_provider(dir: &std::path::Path, p: ProviderConfig) -> Config {
    Config { auth: AuthConfig { mode: "accounts".into(), provider: vec![p], ..AuthConfig::default() }, ..config(dir) }
}

fn google() -> ProviderConfig {
    ProviderConfig { id: "google".into(), kind: "oidc".into(), preset: "google".into(), client_id: "x".into(), ..ProviderConfig::default() }
}

#[test]
fn check_builds_the_providers_without_the_network() {
    let dir = TempDir::new("settings-providers");
    assert!(with_provider(dir.path(), google()).check().is_ok());
    let secret = dir.path().join("google.secret");
    std::fs::write(&secret, "s3cret\n").unwrap();
    let file = secret.display().to_string();
    assert!(with_provider(dir.path(), ProviderConfig { client_secret_file: file.clone(), ..google() }).check().is_ok());

    for (p, why) in [
        (ProviderConfig { kind: "carrier-pigeon".into(), ..google() }, "unknown kind"),
        (ProviderConfig { preset: "microsoft".into(), ..google() }, "unknown preset"),
        (ProviderConfig { preset: String::new(), ..google() }, "issuer"),
        (ProviderConfig { client_id: String::new(), ..google() }, "client_id"),
        (ProviderConfig { client_secret_file: dir.path().join("missing").display().to_string(), ..google() }, "client_secret_file"),
        (ProviderConfig { client_secret: "a".into(), client_secret_file: file, ..google() }, "not both"),
        (ProviderConfig { flows: vec!["carrier".into()], ..google() }, "flow"),
        (
            ProviderConfig { id: "v".into(), kind: "external".into(), verify_url: "http://verify.example.com/".into(), ..ProviderConfig::default() },
            "verify_url",
        ),
    ] {
        let e = with_provider(dir.path(), p.clone()).check().unwrap_err();
        assert!(e.contains(why), "{p:?}: {e}");
    }
    // Settings that don't depend on the providers are reported first.
    let mut c = with_provider(dir.path(), ProviderConfig { kind: "carrier-pigeon".into(), ..google() });
    c.open_publish = true;
    assert!(c.check().unwrap_err().contains("open_publish"));
}

#[test]
fn check_with_knows_kinds_of_your_own() {
    struct Mine;
    impl IdentityProvider for Mine {
        fn info(&self) -> ProviderInfo {
            ProviderInfo { id: "mine".into(), label: "Mine".into(), flows: Vec::new() }
        }
        fn verify_token(&self, _token: &str) -> Result<Identity, AuthError> {
            Err(AuthError::Unsupported)
        }
    }
    let dir = TempDir::new("settings-kinds");
    let c = with_provider(dir.path(), ProviderConfig { id: "mine".into(), kind: "mine".into(), ..ProviderConfig::default() });
    assert!(c.check().unwrap_err().contains("unknown kind"));
    let mut r = Registry::builtin();
    r.register("mine", |_, _| Ok(Box::new(Mine)));
    assert!(c.check_with(&r).is_ok());
}

#[test]
fn the_providers_client_trusts_figcraft_ca_file() {
    let dir = TempDir::new("settings-ca");
    let der = include_bytes!("../../../crates/collab-net/src/testdata/test-ca.der");
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).unwrap()).collect();
    let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"));
    let good = dir.path().join("ca.pem");
    std::fs::write(&good, &pem).unwrap();
    let certs = extra_certs(&good).unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].der(), &der[..]);
    // Mozilla's roots are kept beside it.
    match roots_with(&certs) {
        ureq::tls::RootCerts::Specific(all) => {
            assert!(all.len() > 100);
            assert!(all.iter().any(|c| c.der() == &der[..]));
        }
        other => panic!("{other:?}"),
    }
    assert!(Https::with_ca_file(Some(&good)).is_ok());
    assert!(Https::with_ca_file(None).is_ok());

    // A missing file, or one without a certificate, stops the server with the reason.
    let missing = Https::with_ca_file(Some(&dir.path().join("nope.pem"))).err().unwrap();
    assert!(missing.contains("FIGCRAFT_CA_FILE") && missing.contains("nope.pem"), "{missing}");
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "not a certificate\n").unwrap();
    let e = Https::with_ca_file(Some(&empty)).err().unwrap();
    assert!(e.contains("no certificate"), "{e}");
}
