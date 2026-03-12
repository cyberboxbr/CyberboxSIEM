pub mod extractors;
pub mod persist;
pub mod routes;
pub mod rules_pack;
pub mod scheduler;
pub mod state;
pub mod stream;
pub mod syslog_receiver;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::Extension;
use axum::Router;
use cyberbox_auth::{AuthBypass, JwtValidator, TenantOverride};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tower_http::{
    cors::CorsLayer,
    decompression::RequestDecompressionLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use state::AppState;

/// Generates a UUID v4 as the X-Request-ID for every incoming request.
#[derive(Clone, Copy, Default)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _req: &axum::http::Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        axum::http::HeaderValue::from_str(&id)
            .ok()
            .map(RequestId::new)
    }
}

pub fn build_router(state: AppState) -> Router {
    let max_ingest_body_bytes = state.max_ingest_body_bytes.max(1024);
    let jwt_validator = state.jwt_validator.clone();
    let auth_disabled = state.auth_disabled;
    let tenant_override = state.tenant_id_override.clone();

    let router = Router::new()
        .merge(routes::api_router())
        .route("/healthz", axum::routing::get(routes::healthz))
        .route("/metrics", axum::routing::get(routes::metrics))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_ingest_body_bytes))
        .layer(RequestDecompressionLayer::new())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        // Propagate or generate X-Request-ID on every request/response.
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId));

    // Auth extension must be the outermost layer so it is resolved first.
    // When auth is enabled but OIDC failed at startup (jwt_validator=None),
    // do NOT inject AuthBypass — that would silently skip JWT validation and
    // require x-tenant-id headers the UI never sends.  Instead, leave both
    // extensions absent so from_request_parts returns Unauthorized.
    let router = if auth_disabled {
        tracing::info!("auth layer: bypass (auth_disabled=true)");
        router.layer(Extension(AuthBypass))
    } else if let Some(validator) = jwt_validator {
        tracing::info!("auth layer: JWT/OIDC validation active");
        router.layer(Extension(validator as Arc<JwtValidator>))
    } else {
        tracing::error!(
            "auth layer: OIDC validator is None but auth_disabled=false — \
             all API requests will return 401. Check that the pod can reach \
             the OIDC issuer (login.microsoftonline.com) and that \
             CYBERBOX__OIDC_ISSUER / CYBERBOX__OIDC_AUDIENCE are set correctly."
        );
        router
    };

    // Single-tenant override — inject after auth so it applies regardless of mode
    if let Some(forced) = tenant_override {
        router.layer(Extension(TenantOverride(forced)))
    } else {
        router
    }
}

pub fn install_metrics_exporter() -> anyhow::Result<PrometheusHandle> {
    let builder = PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Full("api_request_duration_seconds".to_string()),
        &[0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 2.0],
    )?;

    Ok(builder.install_recorder()?)
}
