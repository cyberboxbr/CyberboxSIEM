use axum::{
    http::{header::RETRY_AFTER, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CyberboxError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("not found")]
    NotFound,
    #[error("too many requests: {message}")]
    TooManyRequests {
        message: String,
        retry_after_seconds: u64,
    },
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    message: String,
}

impl IntoResponse for CyberboxError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            CyberboxError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            CyberboxError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            CyberboxError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            CyberboxError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg),
            CyberboxError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            CyberboxError::TooManyRequests {
                message,
                retry_after_seconds,
            } => {
                let mut response =
                    (StatusCode::TOO_MANY_REQUESTS, Json(ErrorBody { message })).into_response();
                let retry_after = retry_after_seconds.max(1).to_string();
                if let Ok(value) = HeaderValue::from_str(&retry_after) {
                    response.headers_mut().insert(RETRY_AFTER, value);
                }
                return response;
            }
            CyberboxError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(ErrorBody { message })).into_response()
    }
}
