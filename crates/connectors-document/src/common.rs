use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connector_core::{
    CatalogEntity, CatalogPage, CatalogQuery, ConnectionProfile, ConnectorContext, ConnectorError,
    DbRecord, ErrorCategory, Result,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(crate) fn invalid(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::InvalidRequest, message)
}

pub(crate) fn unsupported(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::Unsupported, message)
}

pub(crate) fn required_secret<'a>(
    secret: &'a connector_core::SecretMaterial,
    name: &str,
) -> Result<&'a str> {
    secret
        .fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("secret field `{name}` is required")))
}

pub(crate) fn effective_limit(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested: u32,
) -> Result<u32> {
    if requested == 0 {
        return Err(invalid("limit must be greater than zero"));
    }
    Ok(requested.min(context.max_rows).min(profile.policy.max_rows))
}

pub(crate) fn effective_timeout(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    requested_ms: Option<u64>,
) -> Result<Duration> {
    let remaining = context
        .deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| ConnectorError::new(ErrorCategory::Timeout, "request deadline exceeded"))?;
    let configured = Duration::from_millis(profile.policy.timeout_ms.max(1));
    let requested = Duration::from_millis(requested_ms.unwrap_or(u64::MAX).max(1));
    Ok(remaining.min(configured).min(requested))
}

pub(crate) fn bounded_write_limit(profile: &ConnectionProfile, requested: u64) -> Result<u64> {
    if requested == 0 {
        return Err(invalid("max_affected must be greater than zero"));
    }
    Ok(requested.min(profile.policy.max_affected))
}

pub(crate) fn effective_max_bytes(context: &ConnectorContext, profile: &ConnectionProfile) -> u64 {
    context.max_bytes.min(profile.policy.max_bytes)
}

pub(crate) fn elapsed_ms(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn redact_error(
    mut error: ConnectorError,
    secret: &connector_core::SecretMaterial,
) -> ConnectorError {
    for value in secret.fields.values().filter(|value| !value.is_empty()) {
        error.message = redact_value(&error.message, value);
    }
    error
}

fn redact_value(message: &str, value: &str) -> String {
    if value.chars().count() >= 4 {
        return message.replace(value, "[REDACTED]");
    }

    let mut redacted = String::with_capacity(message.len());
    let mut copied_until = 0;
    for (start, _) in message.match_indices(value) {
        let end = start + value.len();
        let before = message[..start].chars().next_back();
        let after = message[end..].chars().next();
        if before.is_none_or(|character| !secret_token_character(character))
            && after.is_none_or(|character| !secret_token_character(character))
        {
            redacted.push_str(&message[copied_until..start]);
            redacted.push_str("[REDACTED]");
            copied_until = end;
        }
    }
    redacted.push_str(&message[copied_until..]);
    redacted
}

fn secret_token_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

#[cfg(any(feature = "mongodb", feature = "cassandra"))]
pub(crate) fn error_sources_include_rustls(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if source.is::<rustls::Error>()
            || source.is::<rustls::pki_types::InvalidDnsNameError>()
            || source.is::<rustls::pki_types::pem::Error>()
        {
            return true;
        }
        current = source.source();
    }
    false
}

pub(crate) fn enforce_records_size(records: &mut Vec<DbRecord>, max_bytes: u64) -> Result<bool> {
    let mut used = 0_u64;
    let mut keep = records.len();
    for (index, record) in records.iter().enumerate() {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| invalid(format!("could not serialize result: {error}")))?
            .len() as u64;
        if used.saturating_add(bytes) > max_bytes {
            keep = index;
            break;
        }
        used = used.saturating_add(bytes);
    }
    let truncated = keep < records.len();
    records.truncate(keep);
    Ok(truncated)
}

pub(crate) fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String> {
    let bytes = serde_json::to_vec(cursor)
        .map_err(|error| invalid(format!("could not encode cursor: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn decode_cursor<T: DeserializeOwned>(cursor: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| invalid("cursor is not valid base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("cursor payload is invalid"))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct OffsetCursor {
    pub(crate) offset: u64,
}

pub(crate) fn catalog_page(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
    mut entities: Vec<CatalogEntity>,
) -> Result<CatalogPage> {
    let limit = effective_limit(context, profile, query.limit)? as usize;
    let has_more = entities.len() > limit;
    entities.truncate(limit);
    let next_cursor = if has_more {
        let offset = query
            .cursor
            .as_deref()
            .map(decode_cursor::<OffsetCursor>)
            .transpose()?
            .map_or(0, |cursor| cursor.offset);
        let returned = u64::try_from(entities.len())
            .map_err(|_| invalid("catalog page is too large to encode"))?;
        Some(encode_cursor(&OffsetCursor {
            offset: offset
                .checked_add(returned)
                .ok_or_else(|| invalid("catalog cursor offset is too large"))?,
        })?)
    } else {
        None
    };
    Ok(CatalogPage {
        entities,
        next_cursor,
    })
}

pub(crate) fn catalog_fetch_inputs(
    context: &ConnectorContext,
    profile: &ConnectionProfile,
    query: &CatalogQuery,
) -> Result<(ConnectorContext, ConnectionProfile, CatalogQuery)> {
    let output_limit = effective_limit(context, profile, query.limit)?;
    let fetch_limit = output_limit
        .checked_add(1)
        .ok_or_else(|| invalid("catalog limit is too large"))?;
    let mut fetch_context = context.clone();
    fetch_context.max_rows = fetch_context.max_rows.max(fetch_limit);
    let mut fetch_profile = profile.clone();
    fetch_profile.policy.max_rows = fetch_profile.policy.max_rows.max(fetch_limit);
    let mut fetch_query = query.clone();
    fetch_query.limit = fetch_limit;
    Ok((fetch_context, fetch_profile, fetch_query))
}

pub(crate) fn split_resource<'a>(
    resource: &'a str,
    default_namespace: Option<&'a str>,
) -> Result<(&'a str, &'a str)> {
    if let Some((namespace, name)) = resource.split_once('.') {
        if namespace.is_empty() || name.is_empty() {
            return Err(invalid("resource must use `namespace.name`"));
        }
        Ok((namespace, name))
    } else {
        default_namespace
            .filter(|namespace| !namespace.is_empty())
            .map(|namespace| (namespace, resource))
            .filter(|(_, name)| !name.is_empty())
            .ok_or_else(|| invalid("resource must use `namespace.name` when no default is set"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use connector_core::{
        AuthKind, CatalogEntity, CatalogQuery, ConnectionId, ConnectionPolicy, ConnectionProfile,
        ConnectorContext, ConnectorError, ErrorCategory, Product, SecretMaterial, TlsConfig,
    };
    use url::Url;

    use super::{
        OffsetCursor, catalog_fetch_inputs, catalog_page, decode_cursor, encode_cursor,
        redact_error, split_resource,
    };

    #[test]
    fn cursor_is_opaque_and_round_trips() {
        let encoded = encode_cursor(&OffsetCursor { offset: 42 }).unwrap();
        assert!(!encoded.contains("offset"));
        let decoded: OffsetCursor = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.offset, 42);
    }

    #[test]
    fn default_namespace_supports_bare_names() {
        assert_eq!(
            split_resource("events", Some("analytics")).unwrap(),
            ("analytics", "events")
        );
        assert!(split_resource("events", None).is_err());
    }

    #[test]
    fn catalog_page_requires_an_extra_entity_for_a_next_cursor() {
        let context = ConnectorContext {
            request_id: "catalog-page".into(),
            session_id: "test".into(),
            deadline: Instant::now() + Duration::from_secs(1),
            max_rows: 1,
            max_bytes: 1024,
        };
        let profile = ConnectionProfile {
            id: ConnectionId::new(),
            display_name: "test".into(),
            product: Product::MongoDb,
            api_mode: "mongodb".into(),
            endpoint: Url::parse("mongodb://localhost").unwrap(),
            database: None,
            tags: Vec::new(),
            auth_kind: AuthKind::Anonymous,
            secret_ref: "test".into(),
            tls: TlsConfig::default(),
            policy: ConnectionPolicy {
                max_rows: 1,
                ..ConnectionPolicy::default()
            },
            policy_version: 1,
            expected_version: None,
            options: BTreeMap::new(),
        };
        let query = CatalogQuery {
            pattern: None,
            namespace: None,
            limit: 1,
            cursor: None,
        };
        let (fetch_context, fetch_profile, fetch_query) =
            catalog_fetch_inputs(&context, &profile, &query).unwrap();
        assert_eq!(fetch_context.max_rows, 2);
        assert_eq!(fetch_profile.policy.max_rows, 2);
        assert_eq!(fetch_query.limit, 2);

        let entity = |name: &str| CatalogEntity {
            id: name.into(),
            namespace: None,
            name: name.into(),
            kind: "collection".into(),
            comment: None,
        };
        let final_page = catalog_page(&context, &profile, &query, vec![entity("one")]).unwrap();
        assert!(final_page.next_cursor.is_none());
        let continued = catalog_page(
            &context,
            &profile,
            &query,
            vec![entity("one"), entity("two")],
        )
        .unwrap();
        assert_eq!(continued.entities.len(), 1);
        assert!(continued.next_cursor.is_some());
    }

    #[test]
    fn secret_values_are_removed_from_connector_errors() {
        let secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "agent-user".into()),
                ("password".into(), "very-secret".into()),
            ]),
        };
        let error = redact_error(
            ConnectorError::new(
                ErrorCategory::Authentication,
                "login agent-user/very-secret was rejected",
            ),
            &secret,
        );
        assert_eq!(error.message, "login [REDACTED]/[REDACTED] was rejected");

        let short_secret = SecretMaterial {
            kind: AuthKind::UsernamePassword,
            fields: BTreeMap::from([
                ("username".into(), "u".into()),
                ("password".into(), "p".into()),
            ]),
        };
        let ordinary_message = redact_error(
            ConnectorError::new(
                ErrorCategory::InvalidRequest,
                "Couchbase connection string target or options do not match the profile endpoint",
            ),
            &short_secret,
        );
        assert_eq!(
            ordinary_message.message,
            "Couchbase connection string target or options do not match the profile endpoint"
        );
        let token_message = redact_error(
            ConnectorError::new(ErrorCategory::Authentication, "login u/p was rejected"),
            &short_secret,
        );
        assert_eq!(
            token_message.message,
            "login [REDACTED]/[REDACTED] was rejected"
        );
    }
}
