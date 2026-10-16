//! The HTTPS identity providers use ([`figcraft_auth::Fetch`]): a small blocking client with the
//! same certificate roots as the rest of the server (Mozilla's), short timeouts and capped answers.

use std::time::Duration;

use figcraft_auth::{Fetch, FetchError};

/// Largest answer read (discovery documents and key sets are a few KiB).
const MAX_BODY: u64 = 1 << 20;

pub struct Https {
    agent: ureq::Agent,
}

impl Https {
    pub fn new() -> Https {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .user_agent(concat!("figcraft-server/", env!("CARGO_PKG_VERSION")))
            .build();
        Https { agent: ureq::Agent::new_with_config(config) }
    }
}

impl Default for Https {
    fn default() -> Self {
        Self::new()
    }
}

fn answer(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Vec<u8>, FetchError> {
    let mut r = r.map_err(|e| FetchError::Network(e.to_string()))?;
    let status = r.status().as_u16();
    let body = r.body_mut().with_config().limit(MAX_BODY).read_to_vec().map_err(|e| FetchError::Network(e.to_string()))?;
    if (200..300).contains(&status) { Ok(body) } else { Err(FetchError::Status { status, body }) }
}

impl Fetch for Https {
    fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.get(url).header("accept", "application/json").call())
    }

    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.post(url).header("accept", "application/json").send_form(form.iter().copied()))
    }

    fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, FetchError> {
        answer(self.agent.post(url).header("accept", "application/json").header("content-type", "application/json").send(body))
    }
}
