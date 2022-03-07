use anyhow::Result;

use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use serde::{Deserialize, Serialize};

use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_futures::Instrument;

use std::{error::Error, net::SocketAddr};

mod app;
mod github;
mod newreleases;

static GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";
static KNOWN_VALUE_ENV: &str = "NEWRELEASES_KNOWN_VALUE";
static NR_WEBHOOK_SECRET_ENV: &str = "NEWRELEASES_WEBHOOK_SECRET_KEY";
static ENABLE_TRACE_TREE: &str = "ENABLE_TRACE_TREE";

static KNOWN_VALUE_HEADER: &str = "X-Known-Value";
static NR_SIGNATURE: &str = "X-Newreleases-Signature";
static NR_TIMESTAMP: &str = "X-Newreleases-Timestamp";

static USER_AGENT_BASE: &str = "kryptn/newreleases-dispatch-action";

static PKG_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
static VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

#[tracing::instrument]
async fn run_server() -> Result<(), Box<dyn Error>> {
    // build our application with a route
    let app = Router::new()
        .route("/", get(health))
        .route("/healthz", get(health))
        .route("/:owner/:repo/:event_type", post(handle_release))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        );

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(app::shutdown_signal())
        .await
        .unwrap();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    app::setup_tracing()?;

    tracing::info!(target: "app start", PKG_NAME, VERSION);

    run_server().await?;

    app::teardown_tracing();
    Ok(())
}

#[derive(Deserialize, Serialize, Debug)]
struct ServiceMetadata {
    version: Option<&'static str>,
    pkg_name: Option<&'static str>,
}

impl<'a> ServiceMetadata {
    fn new() -> Self {
        Self {
            version: VERSION,
            pkg_name: PKG_NAME,
        }
    }
}

async fn health() -> (StatusCode, Json<ServiceMetadata>) {
    (StatusCode::OK, Json(ServiceMetadata::new()))
}

#[tracing::instrument]
async fn handle_release(
    //Json(payload): Json<Release>,
    Path((owner, repo, event_type)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    tracing::info!(target: "handling release", owner= ?owner, repo = ?repo, event_type = ?event_type);

    if let Err(code) = newreleases::check_known_value(&headers) {
        tracing::warn!(target: "known value didn't match", owner= ?owner, repo = ?repo, event_type = ?event_type);
        return code;
    }

    if let Err(code) = newreleases::check_signature(&headers, &body) {
        tracing::warn!(target: "newreleases signature failure", owner= ?owner, repo = ?repo, event_type = ?event_type);
        return code;
    }

    let payload: newreleases::Release = serde_json::from_slice(&body).unwrap();
    let dispatch = github::Dispatch::new(&event_type, payload);

    github::dispatch_update(owner, repo, event_type, dispatch)
        .in_current_span()
        .await
}
