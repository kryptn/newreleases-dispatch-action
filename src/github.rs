use anyhow::Result;

use axum::http::StatusCode;

use serde::{Deserialize, Serialize};

use tracing_futures::Instrument;

use std::env;

static GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";
static USER_AGENT_BASE: &str = "kryptn/newreleases-dispatch-action";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Dispatch<T>
where
    T: Serialize,
{
    event_type: String,
    client_payload: T,
}

impl<T> Dispatch<T>
where
    T: Serialize,
{
    pub fn new(event_type: &str, client_payload: T) -> Self {
        let event_type = event_type.to_string();
        Self {
            event_type,
            client_payload,
        }
    }
}

#[tracing::instrument]
fn build_dispatch_request(owner: &str, repo: &str) -> Result<reqwest::RequestBuilder> {
    let token = env::var(GITHUB_TOKEN_ENV)?;
    let uri = format!("https://api.github.com/repos/{}/{}/dispatches", owner, repo);

    let version = crate::VERSION.unwrap_or("unknown");

    let req = reqwest::Client::new()
        .post(uri)
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", format!("{}@v{}", USER_AGENT_BASE, version));

    Ok(req)
}

#[tracing::instrument]
pub(crate) async fn dispatch_update<T>(
    owner: String,
    repo: String,
    event_type: String,
    dispatch: Dispatch<T>,
) -> StatusCode
where
    T: Serialize + std::fmt::Debug,
{
    let req = match build_dispatch_request(&owner, &repo) {
        Ok(req) => req,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let resp = req.json(&dispatch).send().in_current_span().await.unwrap();

    match resp.status() {
        StatusCode::NO_CONTENT => tracing::info!("dispatch for {}/{} sent", owner, repo),
        StatusCode::UNPROCESSABLE_ENTITY => tracing::error!("dispatch for {}/{} sent", owner, repo),
        v => tracing::warn!(
            "dispatch for {}/{} received unexpected response: {}",
            owner,
            repo,
            v
        ),
    }

    StatusCode::OK
}
