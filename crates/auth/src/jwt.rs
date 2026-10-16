//! Checking an OpenID Connect ID token: a JWS in compact form, signed with one of the issuer's
//! published keys (JWKS). RS256/384/512, ES256/384 and EdDSA (Ed25519).

use base64::Engine as _;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;
use serde_json::Value;

use crate::provider::AuthError;

/// Seconds of clock difference forgiven between the server and the issuer.
pub const LEEWAY: u64 = 120;

/// Largest token accepted (bytes).
pub const MAX_TOKEN: usize = 16 << 10;

/// One key of a JWKS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// A JWKS document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Jwks {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// What must hold of a token's claims.
pub struct Expect<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    /// Seconds since 1970.
    pub now: u64,
}

/// A token's parts: the signed bytes, the header's algorithm and key id, the claims and the
/// signature.
pub struct Parsed {
    pub alg: String,
    pub kid: Option<String>,
    pub claims: Value,
    signed: Vec<u8>,
    signature: Vec<u8>,
}

fn b64(s: &str) -> Result<Vec<u8>, AuthError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| refused("its encoding is broken"))
}

fn refused(why: &str) -> AuthError {
    AuthError::Refused(format!("the sign-in couldn't be checked: {why}"))
}

/// Split and decode a compact JWS (nothing checked yet).
pub fn parse(token: &str) -> Result<Parsed, AuthError> {
    if token.len() > MAX_TOKEN {
        return Err(refused("it is too large"));
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(refused("it isn't a signed token"));
    };
    let header: Header = serde_json::from_slice(&b64(h)?).map_err(|_| refused("its header is broken"))?;
    let claims: Value = serde_json::from_slice(&b64(p)?).map_err(|_| refused("its claims are broken"))?;
    if !claims.is_object() {
        return Err(refused("its claims are broken"));
    }
    let signed = token.get(..h.len() + 1 + p.len()).unwrap_or_default().as_bytes().to_vec();
    Ok(Parsed { alg: header.alg, kid: header.kid, claims, signed, signature: b64(s)? })
}

/// The key in `jwks` that can check `parsed`, if any.
pub fn key_for<'a>(jwks: &'a Jwks, parsed: &Parsed) -> Option<&'a Jwk> {
    let usable = |k: &&Jwk| k.use_.as_deref().is_none_or(|u| u == "sig") && k.alg.as_deref().is_none_or(|a| a == parsed.alg);
    match &parsed.kid {
        Some(kid) => jwks.keys.iter().filter(usable).find(|k| k.kid.as_deref() == Some(kid.as_str())),
        // No key id: only when there is exactly one candidate.
        None => {
            let mut c = jwks.keys.iter().filter(usable).filter(|k| kty_for(&parsed.alg) == Some(k.kty.as_str()));
            match (c.next(), c.next()) {
                (Some(k), None) => Some(k),
                _ => None,
            }
        }
    }
}

fn kty_for(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" | "RS384" | "RS512" => Some("RSA"),
        "ES256" | "ES384" => Some("EC"),
        "EdDSA" => Some("OKP"),
        _ => None,
    }
}

/// Check `parsed`'s signature with `key`.
pub fn verify_signature(parsed: &Parsed, key: &Jwk) -> Result<(), AuthError> {
    let get = |v: &Option<String>| v.as_deref().ok_or_else(|| refused("the issuer's key is incomplete")).and_then(b64);
    let ok = match (parsed.alg.as_str(), key.kty.as_str()) {
        ("RS256" | "RS384" | "RS512", "RSA") => {
            let alg = match parsed.alg.as_str() {
                "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                _ => &signature::RSA_PKCS1_2048_8192_SHA512,
            };
            let (n, e) = (get(&key.n)?, get(&key.e)?);
            signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(alg, &parsed.signed, &parsed.signature).is_ok()
        }
        ("ES256" | "ES384", "EC") => {
            let (alg, crv, len): (&dyn VerificationAlgorithm, &str, usize) = match parsed.alg.as_str() {
                "ES256" => (&signature::ECDSA_P256_SHA256_FIXED, "P-256", 32),
                _ => (&signature::ECDSA_P384_SHA384_FIXED, "P-384", 48),
            };
            if key.crv.as_deref() != Some(crv) {
                return Err(refused("the issuer's key is of another curve"));
            }
            let (x, y) = (get(&key.x)?, get(&key.y)?);
            if x.len() != len || y.len() != len {
                return Err(refused("the issuer's key is broken"));
            }
            let mut point = Vec::with_capacity(1 + 2 * len);
            point.push(4);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(alg, &point).verify(&parsed.signed, &parsed.signature).is_ok()
        }
        ("EdDSA", "OKP") if key.crv.as_deref() == Some("Ed25519") => {
            UnparsedPublicKey::new(&signature::ED25519, get(&key.x)?).verify(&parsed.signed, &parsed.signature).is_ok()
        }
        _ => return Err(refused(&format!("tokens signed with {:?} aren't accepted", parsed.alg))),
    };
    if ok { Ok(()) } else { Err(refused("its signature is wrong")) }
}

/// Check the claims an ID token must have: issuer, audience (and `azp` when there are several),
/// expiry, not-before and issued-at, with [`LEEWAY`].
pub fn check_claims(claims: &Value, expect: &Expect) -> Result<(), AuthError> {
    if claims["iss"].as_str() != Some(expect.issuer) {
        return Err(refused("it comes from another issuer"));
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(a) => vec![a.as_str()],
        Value::Array(v) => v.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expect.audience) {
        return Err(refused("it was made for another application"));
    }
    if audiences.len() > 1 && claims["azp"].as_str().is_some_and(|azp| azp != expect.audience) {
        return Err(refused("it was made for another application"));
    }
    let time = |name: &str| claims[name].as_u64().or_else(|| claims[name].as_f64().filter(|f| f.is_finite() && *f >= 0.0).map(|f| f as u64));
    let Some(exp) = time("exp") else { return Err(refused("it has no expiry")) };
    if exp.saturating_add(LEEWAY) < expect.now {
        return Err(refused("it has expired: sign in again"));
    }
    if time("nbf").is_some_and(|nbf| nbf > expect.now.saturating_add(LEEWAY))
        || time("iat").is_some_and(|iat| iat > expect.now.saturating_add(LEEWAY))
    {
        return Err(refused("it isn't valid yet (is the server's clock right?)"));
    }
    if claims["sub"].as_str().is_none_or(str::is_empty) {
        return Err(refused("it doesn't say who you are"));
    }
    Ok(())
}
