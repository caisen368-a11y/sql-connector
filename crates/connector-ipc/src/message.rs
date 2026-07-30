use connector_core::{
    CatalogPage, CatalogQuery, ConnectionId, ConnectionInfo, ConnectionProfile, ConnectorContext,
    ConnectorError, ConnectorManifest, DataOperation, EntityDescription, OperationResult,
    SecretMaterial,
};
use prost::{Enumeration, Message};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{IpcError, PROTOCOL_VERSION, Result};

#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub request_id: String,
    #[prost(enumeration = "MessageKind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

impl Envelope {
    pub fn request<T: Serialize>(request_id: impl Into<String>, payload: &T) -> Result<Self> {
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            kind: MessageKind::Request.into(),
            payload: encode_payload(payload)?,
        })
    }

    pub fn response<T: Serialize>(request_id: impl Into<String>, payload: &T) -> Result<Self> {
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            kind: MessageKind::Response.into(),
            payload: encode_payload(payload)?,
        })
    }

    pub fn decode_payload<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(IpcError::Protocol(format!(
                "unsupported protocol version {}, expected {}",
                self.protocol_version, PROTOCOL_VERSION
            )));
        }
        ciborium::from_reader(self.payload.as_slice())
            .map_err(|error| IpcError::Serialization(error.to_string()))
    }
}

fn encode_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(payload, &mut encoded)
        .map_err(|error| IpcError::Serialization(error.to_string()))?;
    Ok(encoded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum MessageKind {
    Unspecified = 0,
    Request = 1,
    Response = 2,
    Error = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    pub pack_id: String,
    pub pack_version: String,
    pub protocol_version: u32,
    pub connectors: Vec<ConnectorManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireContext {
    pub request_id: String,
    pub session_id: String,
    pub deadline_unix_ms: i64,
    pub max_rows: u32,
    pub max_bytes: u64,
}

impl WireContext {
    pub fn from_context(context: &ConnectorContext) -> Self {
        let remaining = context
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        let deadline = std::time::SystemTime::now() + remaining;
        let deadline_unix_ms = deadline
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX);
        Self {
            request_id: context.request_id.clone(),
            session_id: context.session_id.clone(),
            deadline_unix_ms,
            max_rows: context.max_rows,
            max_bytes: context.max_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum ConnectorCall {
    GetPackManifest,
    TestConnection {
        context: WireContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
    },
    SearchCatalog {
        context: WireContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
        query: CatalogQuery,
    },
    DescribeEntity {
        context: WireContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
        entity_id: String,
    },
    Execute {
        context: WireContext,
        profile: ConnectionProfile,
        secret: SecretMaterial,
        operation: DataOperation,
    },
    Cancel {
        request_id: String,
    },
    InvalidateConnection {
        connection_id: ConnectionId,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum ConnectorReply {
    PackManifest(PackManifest),
    ConnectionInfo(ConnectionInfo),
    Catalog(CatalogPage),
    Entity(EntityDescription),
    Operation(OperationResult),
    Acknowledged,
    Error(WorkerError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerError {
    pub error: ConnectorError,
}
