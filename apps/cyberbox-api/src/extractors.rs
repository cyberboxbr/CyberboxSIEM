/// Custom Axum extractor that uses `simd_json` for JSON deserialisation on the
/// ingest hot path.  `simd_json::from_slice` operates in-place on a mutable byte
/// slice (~3× faster than `serde_json` on SIMD-capable CPUs) and falls back to a
/// scalar path automatically on CPUs without SSE4.2/AVX2.
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

/// Drop-in replacement for `axum::Json<T>` on the ingest path.
/// Parses the request body with `simd_json` instead of `serde_json`.
pub struct SimdJson<T>(pub T);

pub struct SimdJsonRejection(StatusCode, String);

impl IntoResponse for SimdJsonRejection {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

#[async_trait]
impl<T, S> FromRequest<S> for SimdJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = SimdJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| SimdJsonRejection(StatusCode::BAD_REQUEST, e.to_string()))?;
        // simd_json mutates the buffer in-place — copy required since Bytes is immutable.
        let mut buf = bytes.to_vec();
        simd_json::from_slice::<T>(&mut buf)
            .map(SimdJson)
            .map_err(|e| {
                SimdJsonRejection(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("JSON parse error: {e}"),
                )
            })
    }
}
