use anyhow::Result;
use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};

static GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";
static KNOWN_VALUE_ENV: &str = "NEWRELEASES_KNOWN_VALUE";

static KNOWN_VALUE_HEADER: &str = "X-Known-Value";
static NR_OWNER_HEADER: &str = "X-NewReleases-Owner";
static NR_REPO_HEADER: &str = "X-NewReleases-Repo";

#[derive(Debug, Serialize, Deserialize)]
struct ReleaseNote {
    title: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Release {
    provider: String,
    project: String,
    version: String,
    time: String,
    cve: Option<Vec<String>>,
    is_prerelease: Option<bool>,
    is_updated: Option<bool>,
    note: Option<ReleaseNote>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Dispatch<T>
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
    fn new(event_type: &str, client_payload: T) -> Self {
        let event_type = event_type.to_string();
        Self {
            event_type,
            client_payload,
        }
    }
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        .route("/", get(health))
        .route("/healthz", get(health))
        .route("/newreleases", post(dispatch_action));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health() -> StatusCode {
    StatusCode::OK
}

fn build_request(owner: &str, repo: &str) -> Result<reqwest::RequestBuilder> {
    let token = env::var(GITHUB_TOKEN_ENV)?;
    let uri = format!("https://api.github.com/repos/{}/{}/dispatches", owner, repo);

    let req = reqwest::Client::new()
        .post(uri)
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "newreleases-disp-v0.0.1");

    Ok(req)
}

async fn dispatch_action(Json(payload): Json<Release>, headers: HeaderMap) -> impl IntoResponse {
    let expected_known_value = match env::var(KNOWN_VALUE_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("expected environment variable \"{}\"", KNOWN_VALUE_ENV);
            return StatusCode::INTERNAL_SERVER_ERROR
        },
    };

    if let Some(known_value) = headers.get(KNOWN_VALUE_HEADER) {
        if known_value != &expected_known_value {
            tracing::error!("known value did not match expected \"{}\"", KNOWN_VALUE_ENV);
            return StatusCode::UNAUTHORIZED;
        }
    } else {
        tracing::error!("expected header \"{}\"", KNOWN_VALUE_HEADER);
        return StatusCode::UNAUTHORIZED;
    }

    let owner = headers
        .get(NR_OWNER_HEADER)
        .expect("guaranteed value")
        .to_str()
        .unwrap();
    let repo = headers
        .get(NR_REPO_HEADER)
        .expect("guaranteed value")
        .to_str()
        .unwrap();

    let req = match build_request(owner, repo) {
        Ok(req) => req,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let dispatch = Dispatch::new("newreleases", payload);
    let resp = req.json(&dispatch).send().await.unwrap();

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
