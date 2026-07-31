use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use connector_core::ConnectionId;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{PolicyError, Result};

const MAX_GRANT_LIFETIME_SECONDS: i64 = 120;
const GRANT_REPLAY_KEY_DOMAIN: &[u8] = b"sql-connector/authorization-grant-replay/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationClaims {
    pub subject: String,
    pub session_id: String,
    pub connection_id: ConnectionId,
    pub tool: String,
    pub arguments_hash: String,
    pub policy_version: u64,
    pub max_rows: u32,
    pub max_bytes: u64,
    pub max_affected: u64,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationGrant {
    pub claims: AuthorizationClaims,
    pub signature: String,
}

/// Opaque replay identity returned only after a grant passes every verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorizationGrant {
    replay_key: [u8; 32],
    expires_at_millis: i64,
}

impl VerifiedAuthorizationGrant {
    pub const fn replay_key(&self) -> &[u8; 32] {
        &self.replay_key
    }

    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }
}

pub struct GrantIssuer {
    signing_key: SigningKey,
}

impl GrantIssuer {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue(&self, claims: AuthorizationClaims) -> Result<AuthorizationGrant> {
        let canonical = serde_jcs::to_vec(&claims)
            .map_err(|error| PolicyError::Serialization(error.to_string()))?;
        let signature = self.signing_key.sign(&canonical);
        Ok(AuthorizationGrant {
            claims,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

pub struct VerificationContext<'a> {
    pub subject: &'a str,
    pub session_id: &'a str,
    pub connection_id: ConnectionId,
    pub tool: &'a str,
    pub arguments: &'a serde_json::Value,
    pub policy_version: u64,
    pub max_rows: u32,
    pub max_bytes: u64,
    pub max_affected: u64,
}

pub struct GrantVerifier {
    verifying_key: VerifyingKey,
}

impl GrantVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    pub fn verify(
        &self,
        grant: &AuthorizationGrant,
        context: &VerificationContext<'_>,
    ) -> Result<VerifiedAuthorizationGrant> {
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&grant.signature)
            .map_err(|error| PolicyError::InvalidGrant(error.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| PolicyError::InvalidGrant(error.to_string()))?;
        let canonical = serde_jcs::to_vec(&grant.claims)
            .map_err(|error| PolicyError::Serialization(error.to_string()))?;
        self.verifying_key
            .verify(&canonical, &signature)
            .map_err(|error| PolicyError::InvalidGrant(error.to_string()))?;

        let now = Utc::now();
        if grant.claims.expires_at <= now {
            return Err(PolicyError::Expired);
        }
        if grant.claims.expires_at > now + TimeDelta::seconds(MAX_GRANT_LIFETIME_SECONDS) {
            return Err(PolicyError::InvalidGrant(
                "grant expiry exceeds the maximum lifetime".into(),
            ));
        }
        if grant.claims.subject != context.subject {
            return Err(PolicyError::GrantMismatch("subject".into()));
        }
        if grant.claims.session_id != context.session_id {
            return Err(PolicyError::GrantMismatch("session_id".into()));
        }
        if grant.claims.connection_id != context.connection_id {
            return Err(PolicyError::GrantMismatch("connection_id".into()));
        }
        if grant.claims.tool != context.tool {
            return Err(PolicyError::GrantMismatch("tool".into()));
        }
        if grant.claims.policy_version != context.policy_version {
            return Err(PolicyError::GrantMismatch("policy_version".into()));
        }
        if grant.claims.arguments_hash != canonical_arguments_hash(context.arguments)? {
            return Err(PolicyError::GrantMismatch("arguments_hash".into()));
        }
        if grant.claims.max_rows > context.max_rows
            || grant.claims.max_bytes > context.max_bytes
            || grant.claims.max_affected > context.max_affected
        {
            return Err(PolicyError::GrantMismatch("limits".into()));
        }

        let replay_key = grant_replay_key(&self.verifying_key, &grant.claims.nonce);
        Ok(VerifiedAuthorizationGrant {
            replay_key,
            expires_at_millis: grant.claims.expires_at.timestamp_millis(),
        })
    }
}

fn grant_replay_key(verifying_key: &VerifyingKey, nonce: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(GRANT_REPLAY_KEY_DOMAIN);
    digest.update(verifying_key.as_bytes());
    digest.update(nonce.as_bytes());
    digest.finalize().into()
}

pub fn canonical_arguments_hash(arguments: &serde_json::Value) -> Result<String> {
    let canonical = serde_jcs::to_vec(arguments)
        .map_err(|error| PolicyError::Serialization(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}
