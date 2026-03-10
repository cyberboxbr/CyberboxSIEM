//! JWT/OIDC authentication for the CyberboxSIEM API.
//!
//! Two modes of operation:
//!
//! 1. **JWT mode** (production): validates RS256 Bearer tokens against an OIDC
//!    issuer.  The `JwtValidator` is added as an Axum `Extension` by the
//!    router builder.
//! 2. **Bypass mode** (dev / integration tests): reads `x-tenant-id`,
//!    `x-user-id`, `x-roles` headers directly, with no signature check.
//!    Enabled by adding the `AuthBypass` extension instead.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use cyberbox_core::CyberboxError;

// ── Role ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Analyst,
    Viewer,
    Ingestor,
}

impl Role {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "admin" => Some(Self::Admin),
            "analyst" => Some(Self::Analyst),
            "viewer" => Some(Self::Viewer),
            "ingestor" => Some(Self::Ingestor),
            _ => None,
        }
    }
}

// ── AuthContext ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub tenant_id: String,
    pub roles: Vec<Role>,
}

impl AuthContext {
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn require_any(&self, roles: &[Role]) -> Result<(), CyberboxError> {
        if roles.iter().any(|role| self.has_role(role)) {
            return Ok(());
        }
        Err(CyberboxError::Forbidden)
    }
}

// ── AuthBypass ────────────────────────────────────────────────────────────────

/// Axum extension marker.  When present, JWT validation is skipped and auth
/// is read from plain request headers (`x-tenant-id`, `x-user-id`, `x-roles`).
/// Intended for local development and integration tests only.
#[derive(Clone, Copy)]
pub struct AuthBypass;

// ── OIDC / JWKS internal types ───────────────────────────────────────────────

#[derive(Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    /// RSA modulus (base64url)
    n: Option<String>,
    /// RSA public exponent (base64url)
    e: Option<String>,
}

/// JWT claims we care about.  jsonwebtoken validates `exp`, `iss`, `aud`
/// automatically via `Validation`; we only extract identity fields here.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    /// Custom claim — explicit tenant identifier.
    #[serde(default)]
    tenant_id: Option<String>,
    /// Authorized party (client_id) — used as tenant fallback.
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    /// Keycloak realm-level roles.
    #[serde(default)]
    realm_access: Option<RealmAccess>,
}

#[derive(Debug, Deserialize)]
struct RealmAccess {
    #[serde(default)]
    roles: Vec<String>,
}

// ── JwtValidator ─────────────────────────────────────────────────────────────

/// Thread-safe OIDC JWT validator with JWKS key caching and automatic
/// key-rotation recovery.  Wrap in `Arc` and inject via Axum `Extension`.
pub struct JwtValidator {
    issuer: String,
    audience: String,
    jwks_uri: String,
    /// kid → (n, e) RSA public key material (base64url strings).
    keys: RwLock<HashMap<String, (String, String)>>,
    http: reqwest::Client,
}

impl JwtValidator {
    /// Fetch the OIDC discovery document, pre-load JWKS, and return a ready
    /// validator.  Fails fast if the issuer is unreachable.
    pub async fn from_discovery(issuer: &str, audience: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        let discovery: OidcDiscovery = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery request failed: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery parse failed: {e}"))?;

        let validator = Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            jwks_uri: discovery.jwks_uri,
            keys: RwLock::new(HashMap::new()),
            http,
        };

        validator
            .refresh_keys()
            .await
            .map_err(|e| anyhow::anyhow!("Initial JWKS load failed: {e}"))?;

        Ok(validator)
    }

    /// Validate a raw Bearer token string.
    ///
    /// On unknown `kid` (key rotation), refreshes JWKS once and retries.
    pub async fn validate(&self, raw_token: &str) -> Result<AuthContext, CyberboxError> {
        let header = decode_header(raw_token).map_err(|e| {
            debug!(error = %e, "JWT header decode failed");
            CyberboxError::Unauthorized
        })?;

        let kid = header.kid.as_deref().unwrap_or("default").to_string();

        match self.try_validate(raw_token, &kid) {
            Ok(ctx) => return Ok(ctx),
            Err(_) => {
                // Unknown kid or stale key — refresh and retry once
                if let Err(e) = self.refresh_keys().await {
                    warn!(error = %e, "JWKS refresh failed during key-rotation recovery");
                }
            }
        }

        self.try_validate(raw_token, &kid)
    }

    /// Synchronous validation step; the RwLock is held only for the brief
    /// HashMap read and is never held across an await point.
    fn try_validate(&self, raw_token: &str, kid: &str) -> Result<AuthContext, CyberboxError> {
        let (n, e) = {
            let keys = self.keys.read().unwrap();
            keys.get(kid)
                .cloned()
                .ok_or(CyberboxError::Unauthorized)?
        };

        let decoding_key = DecodingKey::from_rsa_components(&n, &e).map_err(|e| {
            debug!(error = %e, kid, "RSA key construction failed");
            CyberboxError::Unauthorized
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);

        let token_data =
            decode::<OidcClaims>(raw_token, &decoding_key, &validation).map_err(|e| {
                debug!(error = %e, "JWT validation failed");
                CyberboxError::Unauthorized
            })?;

        Ok(claims_to_auth_context(token_data.claims))
    }

    /// Fetch JWKS and replace the in-memory key cache atomically.
    pub async fn refresh_keys(&self) -> anyhow::Result<()> {
        let jwks: JwkSet = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await?
            .json()
            .await?;

        let mut map = self.keys.write().unwrap();
        map.clear();
        for key in jwks.keys {
            if key.kty != "RSA" {
                continue;
            }
            // Skip non-signing keys (e.g. encryption keys marked use=enc)
            if matches!(key.use_.as_deref(), Some(u) if u != "sig") {
                continue;
            }
            if let (Some(n), Some(e)) = (key.n, key.e) {
                let kid = key.kid.unwrap_or_else(|| "default".to_string());
                map.insert(kid, (n, e));
            }
        }

        Ok(())
    }
}

// ── Claims → AuthContext ──────────────────────────────────────────────────────

fn claims_to_auth_context(claims: OidcClaims) -> AuthContext {
    let user_id = claims
        .preferred_username
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| claims.sub.clone());

    // Tenant resolution order: explicit claim > azp (client_id) > "default"
    let tenant_id = claims
        .tenant_id
        .filter(|s| !s.is_empty())
        .or_else(|| claims.azp.filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "default".to_string());

    let roles = claims
        .realm_access
        .map(|ra| {
            ra.roles
                .iter()
                .filter_map(|r| Role::parse(r))
                .collect::<Vec<_>>()
        })
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| vec![Role::Viewer]);

    AuthContext {
        user_id,
        tenant_id,
        roles,
    }
}

// ── FromRequestParts ──────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = CyberboxError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Dev / test bypass — read identity from plain request headers
        if parts.extensions.get::<AuthBypass>().is_some() {
            return extract_from_headers(&parts.headers);
        }

        // Production — validate Bearer JWT
        let validator = parts
            .extensions
            .get::<Arc<JwtValidator>>()
            .cloned()
            .ok_or(CyberboxError::Unauthorized)?;

        let token = extract_bearer_token(&parts.headers)?;
        validator.validate(&token).await
    }
}

// ── Header helpers ────────────────────────────────────────────────────────────

fn extract_from_headers(headers: &axum::http::HeaderMap) -> Result<AuthContext, CyberboxError> {
    let tenant_id = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or(CyberboxError::Unauthorized)?;

    let user_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "anonymous".to_string());

    let roles = headers
        .get("x-roles")
        .and_then(|v| v.to_str().ok())
        .map(|raw| raw.split(',').filter_map(Role::parse).collect::<Vec<_>>())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| vec![Role::Viewer]);

    Ok(AuthContext {
        user_id,
        tenant_id,
        roles,
    })
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<String, CyberboxError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
        .ok_or(CyberboxError::Unauthorized)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_parser_accepts_known_roles() {
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("analyst"), Some(Role::Analyst));
        assert_eq!(Role::parse("viewer"), Some(Role::Viewer));
        assert_eq!(Role::parse("ingestor"), Some(Role::Ingestor));
        assert_eq!(Role::parse("unknown"), None);
    }

    #[test]
    fn claims_to_auth_context_uses_azp_as_tenant_fallback() {
        let claims = OidcClaims {
            sub: "abc-sub".to_string(),
            tenant_id: None,
            azp: Some("client-acme".to_string()),
            preferred_username: Some("alice".to_string()),
            realm_access: Some(RealmAccess {
                roles: vec!["admin".to_string()],
            }),
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "client-acme");
        assert_eq!(ctx.user_id, "alice");
        assert!(ctx.has_role(&Role::Admin));
    }

    #[test]
    fn claims_explicit_tenant_beats_azp() {
        let claims = OidcClaims {
            sub: "sub".to_string(),
            tenant_id: Some("tenant-x".to_string()),
            azp: Some("client-y".to_string()),
            preferred_username: None,
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "tenant-x");
        assert_eq!(ctx.user_id, "sub"); // preferred_username absent → sub
        assert!(ctx.has_role(&Role::Viewer)); // no realm_access → Viewer
    }

    #[test]
    fn claims_defaults_to_viewer_and_default_tenant() {
        let claims = OidcClaims {
            sub: "xyz".to_string(),
            tenant_id: None,
            azp: None,
            preferred_username: None,
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "default");
        assert!(ctx.has_role(&Role::Viewer));
    }

    #[test]
    fn require_any_enforces_role_check() {
        let ctx = AuthContext {
            user_id: "u".to_string(),
            tenant_id: "t".to_string(),
            roles: vec![Role::Viewer],
        };
        assert!(ctx.require_any(&[Role::Admin]).is_err());
        assert!(ctx.require_any(&[Role::Viewer]).is_ok());
        assert!(ctx.require_any(&[Role::Admin, Role::Viewer]).is_ok());
    }
}
