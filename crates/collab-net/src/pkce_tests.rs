//! The browser build's redirect sign-in (`pkce.rs`): the page it starts, what it keeps while the
//! tab is away and what it reads when the tab comes back.

use figcraft_auth::Flow;

use crate::pkce::*;

fn flow(uris: &[&str]) -> Flow {
    Flow::Redirect {
        authorize_url: "https://issuer.test/authorize".into(),
        client_id: "web client".into(),
        scopes: vec!["openid".into(), "email".into()],
        params: vec![("prompt".into(), "select_account".into())],
        redirect_uris: uris.iter().map(|u| u.to_string()).collect(),
    }
}

#[test]
fn the_page_comes_back_to_its_own_listed_address_only() {
    let f = flow(&["https://app.example/", "https://app.example/signin"]);
    assert_eq!(redirect_for(&f, "https://app.example/"), Ok("https://app.example/"));
    assert_eq!(redirect_for(&f, "https://app.example/signin"), Ok("https://app.example/signin"));
    for page in ["https://app.example", "https://app.example/other", "https://other.example/", "http://app.example/"] {
        assert!(redirect_for(&f, page).unwrap_err().contains("web_redirect_uris"), "{page}");
    }
    let browser = Flow::Browser { authorize_url: "u".into(), client_id: "c".into(), scopes: vec![], params: vec![] };
    assert!(redirect_for(&browser, "https://app.example/").is_err());
}

#[test]
fn a_redirect_starts_with_pkce_and_state() {
    let f = flow(&["https://app.example/"]);
    let (r, url) = Redirect::start("wss://app.example/", "google", &f, "https://app.example/").unwrap();
    assert!(
        url.starts_with("https://issuer.test/authorize?response_type=code&client_id=web%20client&redirect_uri=https%3A%2F%2Fapp.example%2F"),
        "{url}"
    );
    let challenge = Pkce { verifier: r.verifier.clone(), state: r.state.clone() }.challenge();
    assert!(url.contains(&format!("code_challenge={challenge}")) && url.contains("code_challenge_method=S256"));
    assert!(url.contains(&format!("state={}", r.state)) && url.contains("prompt=select_account") && url.contains("scope=openid%20email"));
    assert!(!url.contains(&r.verifier), "the verifier stays here");
    assert_eq!((r.server.as_str(), r.provider.as_str(), r.redirect_uri.as_str()), ("wss://app.example/", "google", "https://app.example/"));
    // Kept while the tab is away, and read back the same.
    assert_eq!(Redirect::from_text(&r.to_text()), Some(r.clone()));
    assert_eq!(Redirect::from_text("server=x"), None);
    assert_eq!(Redirect::from_text(""), None);
    // `Debug` leaves the verifier out.
    assert!(!format!("{r:?}").contains(&r.verifier));
    assert!(Redirect::start("wss://app.example/", "google", &f, "https://elsewhere.example/").is_err());
}

#[test]
fn coming_back_checks_the_state() {
    let f = flow(&["https://app.example/"]);
    let (r, _) = Redirect::start("wss://app.example/", "google", &f, "https://app.example/").unwrap();
    let kept = r.to_text();
    let back = came_back(&format!("state={}&code=4%2F0Ab&scope=email&authuser=0", r.state), Some(&kept)).unwrap().unwrap();
    assert_eq!(back.code, "4/0Ab");
    assert_eq!((back.server.as_str(), back.provider.as_str(), back.redirect_uri.as_str()), ("wss://app.example/", "google", "https://app.example/"));
    assert_eq!(back.verifier, r.verifier);
    // Someone else's state, or none kept (another tab started it): refused, never exchanged.
    assert!(came_back("state=forged&code=c", Some(&kept)).unwrap().is_err());
    assert!(came_back(&format!("state={}&code=c", r.state), None).unwrap().is_err());
    // The provider said no.
    let no = came_back(&format!("state={}&error=access_denied&error_description=no+thanks", r.state), Some(&kept)).unwrap().unwrap_err();
    assert!(no.contains("access_denied") && no.contains("no thanks"), "{no}");
    // A page that isn't coming back from a sign-in.
    assert_eq!(came_back("", Some(&kept)), None);
    assert_eq!(came_back("webgl", Some(&kept)), None);
    assert_eq!(came_back("code=c", Some(&kept)), None, "no state");
    // The answer leaves the address; the page's own flags stay.
    assert_eq!(without_answer("webgl&code=c&state=s&scope=openid%20email&authuser=0&prompt=consent"), "webgl");
    assert_eq!(without_answer("state=s&error=x&error_description=y"), "");
    assert_eq!(without_answer("a=1&b"), "a=1&b");
}

#[test]
fn answers_are_read_for_the_state_given() {
    assert_eq!(answer("code=abc%2Fd&state=s", "s"), Some(Ok("abc/d".into())));
    assert_eq!(answer("code=abc&state=other", "s"), None);
    assert_eq!(answer("state=s", "s"), None);
    assert_eq!(answer(&format!("code={}&state=s", "x".repeat(5000)), "s"), None, "too long");
}
