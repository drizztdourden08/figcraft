use crate::*;

fn who(email: Option<&str>, verified: bool) -> Identity {
    Identity { provider: "p".into(), subject: "s".into(), email: email.map(Into::into), email_verified: verified, name: None }
}

#[test]
fn modes_parse_and_say_what_they_allow() {
    for m in [AuthMode::Links, AuthMode::Accounts, AuthMode::AccountsAndLinks] {
        assert_eq!(AuthMode::parse(m.id()), Some(m));
    }
    assert_eq!(AuthMode::parse(" Accounts+Links "), Some(AuthMode::AccountsAndLinks));
    // "open" is what apps call a server of links only.
    assert_eq!(AuthMode::parse("open"), Some(AuthMode::Links));
    assert_eq!(AuthMode::parse("closed"), None);
    assert!(AuthMode::Links.links() && !AuthMode::Links.accounts());
    assert!(!AuthMode::Accounts.links() && AuthMode::Accounts.accounts());
    assert!(AuthMode::AccountsAndLinks.links() && AuthMode::AccountsAndLinks.accounts());
    for m in [E2eMode::Off, E2eMode::Optional, E2eMode::Required] {
        assert_eq!(E2eMode::parse(m.id()), Some(m));
    }
    assert_eq!(E2eMode::parse("on"), None);
}

#[test]
fn defaults_are_todays_server() {
    let c = AuthConfig::default();
    assert_eq!(c.mode(), Ok(AuthMode::Links));
    assert_eq!(c.check(), Ok(()));
    assert_eq!(E2eConfig::default().mode(), Ok(E2eMode::Off));
    assert_eq!(Links.info(), ServerInfo { auth: AuthMode::Links, providers: Vec::new(), e2e: E2eMode::Off });
    let (reply, person) = Links.sign_in(SignIn::Session { token: "x".into() });
    assert!(matches!(reply, SignInReply::Refused { .. }));
    assert_eq!(person, None);
}

#[test]
fn config_checks() {
    let p = |id: &str, kind: &str| ProviderConfig { id: id.into(), kind: kind.into(), ..ProviderConfig::default() };
    let accounts = AuthConfig { mode: "accounts".into(), ..AuthConfig::default() };
    assert!(accounts.check().unwrap_err().contains("at least one"));
    let ok = AuthConfig { provider: vec![p("google", "oidc")], ..accounts.clone() };
    assert_eq!(ok.check(), Ok(()));
    let twice = AuthConfig { provider: vec![p("a", "oidc"), p("a", "external")], ..accounts.clone() };
    assert!(twice.check().unwrap_err().contains("two providers"));
    let bad_id = AuthConfig { provider: vec![p("has space", "oidc")], ..accounts.clone() };
    assert!(bad_id.check().is_err());
    let no_kind = AuthConfig { provider: vec![p("a", " ")], ..accounts.clone() };
    assert!(no_kind.check().unwrap_err().contains("kind"));
    let bad_mode = AuthConfig { mode: "public".into(), ..AuthConfig::default() };
    assert!(bad_mode.check().is_err());
    let bad_days = AuthConfig { session_days: f64::NAN, ..AuthConfig::default() };
    assert!(bad_days.check().is_err());
    let bad_email = AuthConfig { admins: vec!["nobody".into()], ..AuthConfig::default() };
    assert!(bad_email.check().is_err());
    assert_eq!(AuthConfig { session_days: 1.0, ..AuthConfig::default() }.session_secs(), 86_400);
}

#[test]
fn config_reads_toml_and_refuses_unknown_keys() {
    #[derive(serde::Deserialize)]
    struct File {
        auth: AuthConfig,
        e2e: E2eConfig,
    }
    let text = r#"
        [auth]
        mode = "accounts+links"
        admins = ["Owner@Example.com"]
        [[auth.provider]]
        id = "google"
        kind = "oidc"
        preset = "google"
        client_id = "abc"
        params = [["prompt", "select_account"]]
        [e2e]
        mode = "optional"
    "#;
    let f: File = toml::from_str(text).unwrap();
    assert_eq!(f.auth.mode(), Ok(AuthMode::AccountsAndLinks));
    assert_eq!(f.auth.provider[0].params, vec![("prompt".to_string(), "select_account".to_string())]);
    assert_eq!(f.e2e.mode(), Ok(E2eMode::Optional));
    assert_eq!(f.auth.policy().admins, vec!["owner@example.com".to_string()]);
    assert!(
        toml::from_str::<File>(
            "[auth]
mode = \"links\"
open = true
[e2e]
"
        )
        .is_err()
    );
}

#[test]
fn policy_lets_in_by_verified_email_or_domain() {
    let open = Policy::new(&[], &[], &[]);
    assert_eq!(open.admit(&who(None, false)), Ok(policy::Admitted { admin: false }));
    let p = Policy::new(&["boss@example.com".into()], &["Friend@Else.org".into()], &["@example.com".into()]);
    assert_eq!(p.admit(&who(Some("boss@example.com"), true)), Ok(policy::Admitted { admin: true }));
    assert_eq!(p.admit(&who(Some("dev@EXAMPLE.com"), true)), Ok(policy::Admitted { admin: false }));
    assert_eq!(p.admit(&who(Some("friend@else.org"), true)), Ok(policy::Admitted { admin: false }));
    assert!(p.admit(&who(Some("stranger@else.org"), true)).is_err());
    // Unverified emails count for nothing, not even admin.
    assert!(p.admit(&who(Some("boss@example.com"), false)).is_err());
    assert!(p.admit(&who(Some("dev@example.com"), false)).is_err());
    assert!(p.admit(&who(None, true)).is_err());
    // A domain must match whole: example.com.evil.net isn't example.com.
    assert!(p.admit(&who(Some("x@example.com.evil.net"), true)).is_err());
}

#[test]
fn wire_types_round_trip_as_json() {
    let info = ServerInfo {
        auth: AuthMode::Accounts,
        providers: vec![ProviderInfo {
            id: "google".into(),
            label: "Google".into(),
            flows: vec![
                Flow::Browser {
                    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                    client_id: "abc".into(),
                    scopes: vec!["openid".into()],
                    params: vec![],
                },
                Flow::Device,
                Flow::Token { label: "Token".into() },
            ],
        }],
        e2e: E2eMode::Required,
    };
    let text = serde_json::to_string(&info).unwrap();
    assert_eq!(serde_json::from_str::<ServerInfo>(&text).unwrap(), info);
    let replies = [
        SignInReply::SignedIn(Me { account: "a1".into(), name: "Ann".into(), session: "t".into(), expires: 9, ..Me::default() }),
        SignInReply::Device(DeviceCode {
            user_code: "ABCD".into(),
            verification_uri: "https://x".into(),
            handle: "h".into(),
            interval: 5,
            expires_in: 600,
        }),
        SignInReply::Pending,
        SignInReply::SignedOut,
        SignInReply::Refused { reason: "no".into() },
    ];
    for r in replies {
        let text = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<SignInReply>(&text).unwrap(), r);
    }
}

#[test]
fn basic_accounts_flows_are_kept_from_older_apps() {
    let p = |flows: Vec<Flow>| ProviderInfo { id: "p".into(), label: "P".into(), flows };
    let info = ServerInfo {
        auth: AuthMode::Accounts,
        providers: vec![p(vec![Flow::Password { label: "Account".into() }, Flow::SignUp]), p(vec![Flow::Device])],
        e2e: E2eMode::Off,
    };
    assert_eq!(info.access(), "basic+sso");
    let old = info.clone().for_older_apps();
    assert_eq!(old.providers.len(), 2);
    assert!(old.providers[0].flows.is_empty());
    assert_eq!(old.providers[1].flows, vec![Flow::Device]);
    assert_eq!(ServerInfo::default().access(), "open");
    let basic = ServerInfo { auth: AuthMode::Accounts, providers: vec![p(vec![Flow::Password { label: "A".into() }])], e2e: E2eMode::Off };
    assert_eq!(basic.access(), "basic");
    // `Debug` leaves secrets out.
    let s = format!(
        "{:?} {:?} {:?}",
        SignIn::Password { provider: "p".into(), username: "ann".into(), password: "hunter2-secret".into() },
        SignIn::Token { provider: "p".into(), token: "tok-secret".into() },
        SignIn::Session { token: "sess-secret".into() }
    );
    assert!(!s.contains("secret") && s.contains("ann"), "{s}");
}

#[test]
fn redirect_flows_are_kept_from_older_apps() {
    let redirect = Flow::Redirect {
        authorize_url: "https://issuer.test/authorize".into(),
        client_id: "web".into(),
        scopes: vec!["openid".into()],
        params: vec![],
        redirect_uris: vec!["https://app.example/".into()],
    };
    let browser = Flow::Browser { authorize_url: "https://issuer.test/authorize".into(), client_id: "desk".into(), scopes: vec![], params: vec![] };
    let info = ServerInfo {
        auth: AuthMode::Accounts,
        providers: vec![
            ProviderInfo { id: "g".into(), label: "G".into(), flows: vec![browser.clone(), redirect.clone()] },
            ProviderInfo { id: "b".into(), label: "B".into(), flows: vec![Flow::Password { label: "A".into() }, Flow::SignUp] },
        ],
        e2e: E2eMode::Off,
    };
    assert_eq!(info.access(), "basic+sso");
    // `Info` (apps before basic accounts) and `About` (apps before redirects) leave it out.
    assert_eq!(info.clone().for_older_apps().providers[0].flows, vec![browser.clone()]);
    let about = info.clone().without_redirects();
    assert_eq!(about.providers[0].flows, vec![browser]);
    assert_eq!(about.providers[1].flows.len(), 2, "basic accounts stay in About");
    let text = serde_json::to_string(&redirect).unwrap();
    assert_eq!(serde_json::from_str::<Flow>(&text).unwrap(), redirect);
}
