use anyhow::Result;

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};

use ring::hmac;
use serde::{Deserialize, Serialize};

use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct ReleaseNote {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Release {
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
pub fn check_known_value(headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected_known_value = match env::var(crate::KNOWN_VALUE_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                "expected environment variable \"{}\"",
                crate::KNOWN_VALUE_ENV
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let known_value = match get_header(&headers, crate::KNOWN_VALUE_HEADER) {
        Ok(v) => v,
        Err(code) => {
            tracing::error!("expected header \"{}\"", crate::KNOWN_VALUE_HEADER);
            return Err(code);
        }
    };

    if known_value != expected_known_value {
        tracing::error!(
            "known value did not match expected \"{}\"",
            crate::KNOWN_VALUE_ENV
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

#[tracing::instrument]
pub fn check_signature(headers: &HeaderMap, body: &Bytes) -> Result<(), StatusCode> {
    let secret = match env::var(crate::NR_WEBHOOK_SECRET_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                "expected environment variable \"{}\"",
                crate::NR_WEBHOOK_SECRET_ENV
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let timestamp = get_header(headers, crate::NR_TIMESTAMP).expect("NewReleases.io sends this");
    let signature = get_header(headers, crate::NR_SIGNATURE).expect("NewReleases.io sends this");
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
