use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use cyberbox_core::CyberboxError;
use cyberbox_models::AgentRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentDeviceCertificateClaims {
    sub: String,
    tenant_id: String,
    credential_version: u64,
    serial: String,
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Debug, Clone)]
pub struct IssuedAgentDeviceCertificate {
    pub token: String,
    pub serial: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VerifiedAgentDeviceCertificate {
    pub tenant_id: String,
    pub agent_id: String,
    pub credential_version: u64,
    pub serial: String,
    pub expires_at: DateTime<Utc>,
}

pub fn issue_agent_device_certificate(
    signing_secret: &str,
    ttl_secs: u64,
    agent: &AgentRecord,
) -> Result<IssuedAgentDeviceCertificate, CyberboxError> {
    if signing_secret.trim().is_empty() {
        return Err(CyberboxError::Internal(
            "agent device certificate signing secret is empty".to_string(),
        ));
    }

    let now = Utc::now();
    let expires_at = now + Duration::seconds(ttl_secs.max(60) as i64);
    let serial = Uuid::new_v4().to_string();
    let claims = AgentDeviceCertificateClaims {
        sub: agent.agent_id.clone(),
        tenant_id: agent.tenant_id.clone(),
        credential_version: agent.credential_version,
        serial: serial.clone(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        iss: "cyberbox-api".to_string(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_secret.as_bytes()),
    )
    .map_err(|err| CyberboxError::Internal(format!("sign agent device certificate: {err}")))?;

    Ok(IssuedAgentDeviceCertificate {
        token,
        serial,
        expires_at,
    })
}

pub fn verify_agent_device_certificate(
    signing_secret: &str,
    certificate: &str,
    tenant_id: &str,
    agent_id: &str,
) -> Result<VerifiedAgentDeviceCertificate, CyberboxError> {
    if signing_secret.trim().is_empty() {
        return Err(CyberboxError::Unauthorized);
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["cyberbox-api"]);
    let claims = decode::<AgentDeviceCertificateClaims>(
        certificate,
        &DecodingKey::from_secret(signing_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| CyberboxError::Unauthorized)?
    .claims;

    if claims.tenant_id != tenant_id || claims.sub != agent_id {
        return Err(CyberboxError::Forbidden);
    }

    let expires_at = DateTime::from_timestamp(claims.exp, 0).ok_or_else(|| {
        CyberboxError::Internal("agent device certificate contains invalid exp".to_string())
    })?;

    Ok(VerifiedAgentDeviceCertificate {
        tenant_id: claims.tenant_id,
        agent_id: claims.sub,
        credential_version: claims.credential_version,
        serial: claims.serial,
        expires_at,
    })
}
