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
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_futures::Instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;

use std::{env, error::Error, net::SocketAddr};

fn tree_layer() -> Option<HierarchicalLayer> {
    let enable_tree_layer = if let Ok(v) = env::var(crate::ENABLE_TRACE_TREE) {
        v == "true"
    } else {
        false
    };

    if enable_tree_layer {
        Some(
            HierarchicalLayer::new(2)
                .with_targets(true)
                .with_bracketed_fields(true),
        )
    } else {
        None
    }
}

pub(crate) fn setup_tracing() -> Result<(), Box<dyn Error>> {
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name("newreleases_dispatch")
        .install_batch(opentelemetry::runtime::Tokio)?;

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(tree_layer())
        .with(telemetry)
        .init();

    Ok(())
}

pub(crate) fn teardown_tracing() {
    opentelemetry::global::shutdown_tracer_provider();
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}
