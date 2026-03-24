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
use dashmap::DashMap;
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

// ── TenantOverride ────────────────────────────────────────────────────────────

/// Axum extension.  When present, overrides the tenant_id extracted from the
/// JWT (or bypass headers) for every request.  Used in single-tenant deployments
/// where all data must be scoped to a fixed tenant regardless of the token claim.
/// Set `CYBERBOX__TENANT_ID_OVERRIDE=<name>` to enable.
#[derive(Clone)]
pub struct TenantOverride(pub String);

/// Axum extension.  When present, requests with a matching `X-Api-Key` or
/// `Authorization: ApiKey <key>` header are authenticated as an `Ingestor`
/// without JWT validation.  Used for machine-to-machine ingestion (agents,
/// collectors, attack simulations).
/// Set `CYBERBOX__INGEST_API_KEY=<secret>` to enable.
#[derive(Clone)]
pub struct IngestApiKey(pub String);

/// Axum extension containing live per-user RBAC grants.
///
/// Keys are stored as `"{tenant_id}:{user_id}"` and merged with the roles
/// derived from JWT claims or auth-bypass headers.
#[derive(Clone)]
pub struct RoleOverrideStore(pub Arc<DashMap<String, Vec<Role>>>);

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
///
/// Supports multiple OIDC providers:
///   - **Azure AD / Entra ID**: `tid` (tenant), `roles` (app roles), `groups`,
///     `preferred_username` or `email`, `name`
///   - **Keycloak**: `realm_access.roles`, `azp` (client_id as tenant)
///   - **Generic OIDC**: `tenant_id` custom claim
#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,

    /// Custom claim — explicit tenant identifier.
    #[serde(default)]
    tenant_id: Option<String>,
    /// Azure AD tenant ID.
    #[serde(default)]
    tid: Option<String>,
    /// Authorized party (client_id) — used as tenant fallback.
    #[serde(default)]
    azp: Option<String>,

    /// Display name (Azure AD `name` claim).
    #[serde(default)]
    name: Option<String>,
    /// Preferred username (Azure AD, Keycloak).
    #[serde(default)]
    preferred_username: Option<String>,
    /// Email claim (fallback for user identification).
    #[serde(default)]
    email: Option<String>,

    /// Azure AD app roles (top-level `roles` array, configured in App Registration).
    #[serde(default)]
    roles: Vec<String>,
    /// Azure AD group object IDs (when "groupMembershipClaims" is enabled).
    #[serde(default)]
    #[allow(dead_code)]
    groups: Vec<String>,

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

    /// Derive the Azure AD v1 issuer from a v2 issuer URL.
    /// v2: `https://login.microsoftonline.com/{tid}/v2.0`
    /// v1: `https://sts.windows.net/{tid}/`
    fn derive_v1_issuer(&self) -> Option<String> {
        let prefix = "https://login.microsoftonline.com/";
        let suffix = "/v2.0";
        if self.issuer.starts_with(prefix) && self.issuer.ends_with(suffix) {
            let tid = &self.issuer[prefix.len()..self.issuer.len() - suffix.len()];
            Some(format!("https://sts.windows.net/{tid}/"))
        } else {
            None
        }
    }

    /// Synchronous validation step; the RwLock is held only for the brief
    /// HashMap read and is never held across an await point.
    fn try_validate(&self, raw_token: &str, kid: &str) -> Result<AuthContext, CyberboxError> {
        let (n, e) = {
            let keys = self.keys.read().unwrap();
            keys.get(kid).cloned().ok_or(CyberboxError::Unauthorized)?
        };

        let decoding_key = DecodingKey::from_rsa_components(&n, &e).map_err(|e| {
            debug!(error = %e, kid, "RSA key construction failed");
            CyberboxError::Unauthorized
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.audience.as_str()]);
        // Accept both Azure AD v1 and v2 issuer formats.
        // v2: https://login.microsoftonline.com/{tid}/v2.0
        // v1: https://sts.windows.net/{tid}/
        // Access tokens for custom API scopes often use the v1 issuer
        // even when the app is configured for v2.
        let v1_issuer = self.derive_v1_issuer();
        let issuers: Vec<&str> = if let Some(ref v1) = v1_issuer {
            vec![self.issuer.as_str(), v1.as_str()]
        } else {
            vec![self.issuer.as_str()]
        };
        validation.set_issuer(&issuers);

        let token_data =
            decode::<OidcClaims>(raw_token, &decoding_key, &validation).map_err(|e| {
                debug!(error = %e, "JWT validation failed");
                CyberboxError::Unauthorized
            })?;

        Ok(claims_to_auth_context(token_data.claims))
    }

    /// Fetch JWKS and replace the in-memory key cache atomically.
    pub async fn refresh_keys(&self) -> anyhow::Result<()> {
        let jwks: JwkSet = self.http.get(&self.jwks_uri).send().await?.json().await?;

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
    // User resolution: preferred_username > email > name > sub
    let user_id = claims
        .preferred_username
        .filter(|s| !s.is_empty())
        .or_else(|| claims.email.filter(|s| !s.is_empty()))
        .or_else(|| claims.name.filter(|s| !s.is_empty()))
        .unwrap_or_else(|| claims.sub.clone());

    // Tenant resolution: explicit claim > Azure AD tid > azp (client_id) > "default"
    let tenant_id = claims
        .tenant_id
        .filter(|s| !s.is_empty())
        .or_else(|| claims.tid.filter(|s| !s.is_empty()))
        .or_else(|| claims.azp.filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "default".to_string());

    // Role resolution: Azure AD top-level roles > Keycloak realm_access > Viewer
    let mut parsed_roles: Vec<Role> = claims.roles.iter().filter_map(|r| Role::parse(r)).collect();

    // Merge Keycloak realm_access roles if present
    if let Some(ra) = claims.realm_access {
        for r in &ra.roles {
            if let Some(role) = Role::parse(r) {
                if !parsed_roles.contains(&role) {
                    parsed_roles.push(role);
                }
            }
        }
    }

    if parsed_roles.is_empty() {
        parsed_roles.push(Role::Viewer);
    }

    AuthContext {
        user_id,
        tenant_id,
        roles: parsed_roles,
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
        let mut ctx = if parts.extensions.get::<AuthBypass>().is_some() {
            extract_from_headers(&parts.headers)?
        } else if let Some(api_key_ext) = parts.extensions.get::<IngestApiKey>().cloned() {
            // Static API key for machine-to-machine ingestion
            match extract_api_key(&parts.headers) {
                Some(key) if key == api_key_ext.0 => {
                    debug!("API key authentication successful");
                    let tenant_id = parts
                        .headers
                        .get("x-tenant-id")
                        .and_then(|v| v.to_str().ok())
                        .filter(|tenant| !tenant.trim().is_empty())
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| "default".to_string());
                    let user_id = parts
                        .headers
                        .get("x-agent-id")
                        .and_then(|v| v.to_str().ok())
                        .filter(|value| !value.trim().is_empty())
                        .map(ToOwned::to_owned)
                        .or_else(|| {
                            parts
                                .headers
                                .get("x-user-id")
                                .and_then(|v| v.to_str().ok())
                                .filter(|value| !value.trim().is_empty())
                                .map(ToOwned::to_owned)
                        })
                        .unwrap_or_else(|| "api-key".to_string());
                    AuthContext {
                        user_id,
                        tenant_id,
                        roles: vec![Role::Ingestor],
                    }
                }
                Some(_) => {
                    // API key present but wrong — try JWT fallback
                    if let Some(validator) = parts.extensions.get::<Arc<JwtValidator>>().cloned() {
                        let token = extract_bearer_token(&parts.headers)?;
                        validator.validate(&token).await?
                    } else {
                        warn!("invalid API key and no JWT validator available");
                        return Err(CyberboxError::Unauthorized);
                    }
                }
                None => {
                    // No API key header — fall through to JWT
                    if let Some(validator) = parts.extensions.get::<Arc<JwtValidator>>().cloned() {
                        let token = extract_bearer_token(&parts.headers)?;
                        validator.validate(&token).await?
                    } else {
                        warn!("no API key or Bearer token provided");
                        return Err(CyberboxError::Unauthorized);
                    }
                }
            }
        } else if let Some(validator) = parts.extensions.get::<Arc<JwtValidator>>().cloned() {
            // Production — validate Bearer JWT
            let token = extract_bearer_token(&parts.headers)?;
            validator.validate(&token).await?
        } else {
            // Neither AuthBypass nor JwtValidator present — OIDC init failed
            warn!(
                "no auth extension (OIDC validator likely failed at startup); \
                 rejecting request — check pod logs for OIDC discovery errors"
            );
            return Err(CyberboxError::Unauthorized);
        };

        // Single-tenant override — replace whatever the token said
        if let Some(TenantOverride(ref forced)) = parts.extensions.get::<TenantOverride>().cloned()
        {
            ctx.tenant_id = forced.clone();
        }

        if let Some(RoleOverrideStore(store)) = parts.extensions.get::<RoleOverrideStore>().cloned()
        {
            let key = format!("{}:{}", ctx.tenant_id, ctx.user_id);
            if let Some(stored) = store.get(&key) {
                for role in stored.iter() {
                    if !ctx.roles.contains(role) {
                        ctx.roles.push(role.clone());
                    }
                }
            }
        }

        Ok(ctx)
    }
}

// ── Header helpers ────────────────────────────────────────────────────────────

fn extract_from_headers(headers: &axum::http::HeaderMap) -> Result<AuthContext, CyberboxError> {
    let tenant_id = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "default".to_string());

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
        .unwrap_or_else(|| vec![Role::Admin]);

    Ok(AuthContext {
        user_id,
        tenant_id,
        roles,
    })
}

fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<String> {
    // Check X-Api-Key header first
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(key.to_string());
    }
    // Check Authorization: ApiKey <key>
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("ApiKey "))
        .map(ToOwned::to_owned)
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
            tid: None,
            azp: Some("client-acme".to_string()),
            name: None,
            preferred_username: Some("alice".to_string()),
            email: None,
            roles: vec![],
            groups: vec![],
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
            tid: None,
            azp: Some("client-y".to_string()),
            name: None,
            preferred_username: None,
            email: None,
            roles: vec![],
            groups: vec![],
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "tenant-x");
        assert_eq!(ctx.user_id, "sub"); // preferred_username absent → sub
        assert!(ctx.has_role(&Role::Viewer)); // no roles → Viewer
    }

    #[test]
    fn claims_defaults_to_viewer_and_default_tenant() {
        let claims = OidcClaims {
            sub: "xyz".to_string(),
            tenant_id: None,
            tid: None,
            azp: None,
            name: None,
            preferred_username: None,
            email: None,
            roles: vec![],
            groups: vec![],
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "default");
        assert!(ctx.has_role(&Role::Viewer));
    }

    #[test]
    fn azure_ad_claims_use_tid_and_top_level_roles() {
        let claims = OidcClaims {
            sub: "oid-12345".to_string(),
            tenant_id: None,
            tid: Some("azure-tenant-abc".to_string()),
            azp: None,
            name: Some("Alice Silva".to_string()),
            preferred_username: Some("alice@contoso.com".to_string()),
            email: Some("alice@contoso.com".to_string()),
            roles: vec!["admin".to_string(), "analyst".to_string()],
            groups: vec!["group-soc-team".to_string()],
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.tenant_id, "azure-tenant-abc");
        assert_eq!(ctx.user_id, "alice@contoso.com");
        assert!(ctx.has_role(&Role::Admin));
        assert!(ctx.has_role(&Role::Analyst));
        assert!(!ctx.has_role(&Role::Ingestor));
    }

    #[test]
    fn azure_ad_email_fallback_when_no_preferred_username() {
        let claims = OidcClaims {
            sub: "oid-99".to_string(),
            tenant_id: None,
            tid: Some("tid-xyz".to_string()),
            azp: None,
            name: None,
            preferred_username: None,
            email: Some("bob@example.com".to_string()),
            roles: vec!["viewer".to_string()],
            groups: vec![],
            realm_access: None,
        };
        let ctx = claims_to_auth_context(claims);
        assert_eq!(ctx.user_id, "bob@example.com");
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
