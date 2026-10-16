//! The HTTPS identity providers use ([`figcraft_auth::Fetch`]): a small blocking client with the
//! same certificate roots as the rest of FigCraft (Mozilla's, plus the authorities in the PEM file
//! `FIGCRAFT_CA_FILE` names, as the app and `figcraft-cli` trust), short timeouts and capped
//! answers. Certificates are always verified.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use figcraft_auth::{Fetch, FetchError};
use figcraft_collab_net::tls::CA_FILE;
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

/// Largest answer read (discovery documents and key sets are a few KiB).
const MAX_BODY: u64 = 1 << 20;

/// Most certificates read from `FIGCRAFT_CA_FILE`.
const MAX_EXTRA_CERTS: usize = 1000;

pub struct Https {
    agent: ureq::Agent,
}

impl Https {
    /// The client, trusting the authorities in `FIGCRAFT_CA_FILE` when it is set (a file that
    /// can't be read or holds no certificate is an error, so the server doesn't start).
    pub fn new() -> Result<Https, String> {
        Https::with_ca_file(std::env::var_os(CA_FILE).as_deref().map(Path::new))
    }

    /// The client, trusting the authorities in `ca_file` (PEM) besides Mozilla's.
    pub fn with_ca_file(ca_file: Option<&Path>) -> Result<Https, String> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .user_agent(concat!("figcraft-server/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = ca_file {
            builder = builder.tls_config(TlsConfig::builder().root_certs(roots_with(&extra_certs(path)?)).build());
        }
        Ok(Https { agent: ureq::Agent::new_with_config(builder.build()) })
    }
}

/// The certificates in the PEM file `path` (at least one).
pub fn extra_certs(path: &Path) -> Result<Vec<Certificate<'static>>, String> {
    let shown = path.display();
    let pem = std::fs::read(path).map_err(|e| format!("can't read the certificates in {CA_FILE} ({shown}): {e}"))?;
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        // A key or anything else in the file isn't a certificate: skipped.
        if let PemItem::Certificate(c) = item.map_err(|e| format!("can't read the certificates in {CA_FILE} ({shown}): {e}"))? {
            certs.push(c);
        }
        if certs.len() > MAX_EXTRA_CERTS {
            return Err(format!("{CA_FILE} ({shown}) has more than {MAX_EXTRA_CERTS} certificates"));
        }
    }
    if certs.is_empty() {
        return Err(format!("{CA_FILE} ({shown}) has no certificate (expected PEM: -----BEGIN CERTIFICATE-----)"));
    }
    Ok(certs)
}

/// Mozilla's roots plus `extra`.
pub(crate) fn roots_with(extra: &[Certificate<'static>]) -> RootCerts {
    let mozilla = webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().map(|c| Certificate::from_der(c.as_ref()));
    RootCerts::Specific(Arc::new(mozilla.chain(extra.iter().cloned()).collect()))
}

fn network(e: ureq::Error) -> FetchError {
    // systemd's IPAddressDeny refuses connections with EPERM: say where to look.
    if let ureq::Error::Io(io) = &e
        && io.kind() == ErrorKind::PermissionDenied
    {
        return FetchError::Network(format!(
            "{e} (the system refused the connection: is the server's systemd unit limited to this machine? see docs/server-accounts.md)"
        ));
    }
    FetchError::Network(e.to_string())
}

fn answer(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Vec<u8>, FetchError> {
    answer_capped(r, MAX_BODY)
}

/// An answer of at most `max` bytes (a larger one is an error).
fn answer_capped(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>, max: u64) -> Result<Vec<u8>, FetchError> {
    let mut r = r.map_err(network)?;
    let status = r.status().as_u16();
    let body = r.body_mut().with_config().limit(max).read_to_vec().map_err(network)?;
    if (200..300).contains(&status) { Ok(body) } else { Err(FetchError::Status { status, body }) }
}

impl Fetch for Https {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.get(url).header("accept", "application/json").call())
    }

    fn get_image(&self, url: &str, max: usize) -> Result<Vec<u8>, FetchError> {
        answer_capped(self.agent.get(url).header("accept", "image/png, image/jpeg").call(), max as u64)
    }

    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.post(url).header("accept", "application/json").send_form(form.iter().copied()))
    }

    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.post(url).header("accept", "application/json").header("content-type", "application/json").send(body))
    }
}
