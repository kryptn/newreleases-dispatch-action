use anyhow::Result;

use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use ring::hmac;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_futures::Instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;

use std::{env, error::Error, net::SocketAddr};

static GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";
static KNOWN_VALUE_ENV: &str = "NEWRELEASES_KNOWN_VALUE";
static NR_WEBHOOK_SECRET_ENV: &str = "WEBHOOK_SECRET";

static KNOWN_VALUE_HEADER: &str = "X-Known-Value";

static NR_SIGNATURE: &str = "X-Newreleases-Signature";
static NR_TIMESTAMP: &str = "X-Newreleases-Timestamp";

static USER_AGENT_BASE: &str = "kryptn/newreleases-dispatch-action";

static PKG_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
static VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize, Deserialize)]
struct ReleaseNote {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Release {
    provider: String,
    project: String,
    version: String,
    time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_prerelease: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_updated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
        .await
        .unwrap();

    Ok(())
}

fn setup_tracing() -> Result<(), Box<dyn Error>> {
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name("newreleases_dispatch")
        .install_batch(opentelemetry::runtime::Tokio)?;

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(
            HierarchicalLayer::new(2)
                .with_targets(true)
                .with_bracketed_fields(true),
        )
        .with(telemetry)
        .init();

    Ok(())
}

fn teardown_tracing() {
    opentelemetry::global::shutdown_tracer_provider();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    setup_tracing()?;

    // initialize tracing
    // tracing_subscriber::fmt::init();
    tracing::info!(target: "app start", PKG_NAME, VERSION);

    // Registry::default()
    //     .with(EnvFilter::from_default_env())
    //     .with(
    //         HierarchicalLayer::new(2)
    //             .with_targets(true)
    //             .with_bracketed_fields(true),
    //     )
    //     .init();

    run_server().await?;

    teardown_tracing();
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
fn build_dispatch_request(owner: &str, repo: &str) -> Result<reqwest::RequestBuilder> {
    let token = env::var(GITHUB_TOKEN_ENV)?;
    let uri = format!("https://api.github.com/repos/{}/{}/dispatches", owner, repo);

    let version = VERSION.unwrap_or("unknown");

    let req = reqwest::Client::new()
        .post(uri)
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", format!("{}@{}", USER_AGENT_BASE, version));

    Ok(req)
}

#[tracing::instrument]
fn get_header(headers: &HeaderMap, key: &str) -> Result<String, StatusCode> {
    if let Some(value) = headers.get(key) {
        let value = value.to_str().unwrap();
        Ok(value.to_string())
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

#[tracing::instrument]
fn check_known_value(headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected_known_value = match env::var(KNOWN_VALUE_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("expected environment variable \"{}\"", KNOWN_VALUE_ENV);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let known_value = match get_header(&headers, KNOWN_VALUE_HEADER) {
        Ok(v) => v,
        Err(code) => {
            tracing::error!("expected header \"{}\"", KNOWN_VALUE_HEADER);
            return Err(code);
        }
    };

    if known_value != expected_known_value {
        tracing::error!("known value did not match expected \"{}\"", KNOWN_VALUE_ENV);
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

#[tracing::instrument]
fn check_signature(headers: &HeaderMap, body: &Bytes) -> Result<(), StatusCode> {
    let secret = match env::var(NR_WEBHOOK_SECRET_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                "expected environment variable \"{}\"",
                NR_WEBHOOK_SECRET_ENV
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let timestamp = get_header(headers, NR_TIMESTAMP).expect("NewReleases.io sends this");
    let signature = get_header(headers, NR_SIGNATURE).expect("NewReleases.io sends this");
    let signature = hex::decode(signature).unwrap();

    let v_key = hmac::Key::new(hmac::HMAC_SHA256, &secret.as_bytes());
    let body = std::str::from_utf8(body).unwrap();
    let message = format!("{}.{}", timestamp, body);

    match hmac::verify(&v_key, message.as_bytes(), &signature) {
        Ok(_) => {
            tracing::debug!("signature verified");
            Ok(())
        }
        Err(_) => {
            tracing::error!("uh oh");
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[tracing::instrument]
async fn dispatch_update(
    owner: String,
    repo: String,
    event_type: String,
    release: Release,
) -> StatusCode {
    let req = match build_dispatch_request(&owner, &repo) {
        Ok(req) => req,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let dispatch = Dispatch::new(&event_type, release);
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

#[tracing::instrument]
async fn handle_release(
    //Json(payload): Json<Release>,
    Path((owner, repo, event_type)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    tracing::info!(target: "handling release", owner= ?owner, repo = ?repo, event_type = ?event_type);

    if let Err(code) = check_known_value(&headers) {
        tracing::warn!(target: "known value didn't match", owner= ?owner, repo = ?repo, event_type = ?event_type);
        return code;
    }

    if let Err(code) = check_signature(&headers, &body) {
        tracing::warn!(target: "newreleases signature failure", owner= ?owner, repo = ?repo, event_type = ?event_type);
        return code;
    }

    let payload: Release = serde_json::from_slice(&body).unwrap();

    dispatch_update(owner, repo, event_type, payload)
        .in_current_span()
        .await
}
