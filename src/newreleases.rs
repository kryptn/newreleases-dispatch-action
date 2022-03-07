use anyhow::Result;

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};

use ring::hmac;
use serde::{Deserialize, Serialize};

use std::env;

static KNOWN_VALUE_ENV: &str = "NEWRELEASES_KNOWN_VALUE";
static NR_WEBHOOK_SECRET_ENV: &str = "NEWRELEASES_WEBHOOK_SECRET_KEY";

static KNOWN_VALUE_HEADER: &str = "X-Known-Value";
static NR_SIGNATURE: &str = "X-Newreleases-Signature";
static NR_TIMESTAMP: &str = "X-Newreleases-Timestamp";
#[derive(Debug, Serialize, Deserialize)]
struct ReleaseNote {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Release {
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

#[tracing::instrument(skip(headers))]
fn get_header(headers: &HeaderMap, key: &str) -> Result<String, StatusCode> {
    if let Some(value) = headers.get(key) {
        let value = value.to_str().unwrap();
        Ok(value.to_string())
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

#[tracing::instrument(skip(headers))]
pub(crate) fn check_known_value(headers: &HeaderMap) -> Result<(), StatusCode> {
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

#[tracing::instrument(skip(headers))]
pub(crate) fn check_signature(headers: &HeaderMap, body: &Bytes) -> Result<(), StatusCode> {
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
