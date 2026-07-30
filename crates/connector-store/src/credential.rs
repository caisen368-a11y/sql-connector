use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex, RwLock},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use connector_core::SecretMaterial;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
use uuid::Uuid;

use crate::{Result, StoreError};

pub trait CredentialStore: Send + Sync {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> Result<()>;
    fn get(&self, reference: &str) -> Result<SecretMaterial>;
    fn delete(&self, reference: &str) -> Result<()>;
}

const SQLITE_ENCRYPTION_VERSION: i64 = 1;
const SQLITE_NONCE_BYTES: usize = 12;
const SQLITE_KEY_CHECK_NAME: &str = "key-check";
const SQLITE_KEY_CHECK_AAD: &[u8] = b"sql-connector-credential-store-key-check-v1";
const SQLITE_KEY_CHECK_PLAINTEXT: &[u8] = b"sql-connector credential key verified";

struct EncryptedCredentialRecord {
    namespace: String,
    reference: String,
    version: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// `SQLite` credential storage encrypted with one caller-managed AES-256 key.
pub struct SqliteCredentialStore {
    connection: Mutex<Connection>,
    key: Arc<Zeroizing<[u8; 32]>>,
    namespace: String,
}

impl SqliteCredentialStore {
    pub fn open(
        path: impl AsRef<Path>,
        namespace: impl Into<String>,
        key: Arc<Zeroizing<[u8; 32]>>,
    ) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA busy_timeout=5000;
             PRAGMA journal_mode=WAL;",
        )?;
        Self::verify_or_initialize_key(&mut connection, &key)?;
        Ok(Self {
            connection: Mutex::new(connection),
            key,
            namespace: namespace.into(),
        })
    }

    fn verify_or_initialize_key(
        connection: &mut Connection,
        key: &Zeroizing<[u8; 32]>,
    ) -> Result<()> {
        let cipher = Self::cipher_for_key(key.as_ref());
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (
                 namespace TEXT NOT NULL,
                 reference TEXT NOT NULL,
                 version INTEGER NOT NULL,
                 nonce BLOB NOT NULL,
                 ciphertext BLOB NOT NULL,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY(namespace, reference)
             );
             CREATE TABLE IF NOT EXISTS credential_store_metadata (
                 name TEXT PRIMARY KEY,
                 version INTEGER NOT NULL,
                 nonce BLOB NOT NULL,
                 ciphertext BLOB NOT NULL
             );",
        )?;

        let marker: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT version, nonce, ciphertext FROM credential_store_metadata
                 WHERE name=?1",
                [SQLITE_KEY_CHECK_NAME],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((version, nonce, ciphertext)) = marker {
            Self::verify_key_marker(&cipher, version, nonce, &ciphertext)?;
        } else {
            Self::verify_existing_credentials(&transaction, &cipher)?;
            Self::insert_key_marker(&transaction, &cipher)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn verify_key_marker(
        cipher: &Aes256Gcm,
        version: i64,
        nonce: Vec<u8>,
        ciphertext: &[u8],
    ) -> Result<()> {
        if version != SQLITE_ENCRYPTION_VERSION {
            return Err(StoreError::Credential(format!(
                "unsupported credential key-check version {version}"
            )));
        }
        let nonce: [u8; SQLITE_NONCE_BYTES] = nonce.try_into().map_err(|_| {
            StoreError::Credential("stored credential key-check nonce has an invalid length".into())
        })?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext,
                        aad: SQLITE_KEY_CHECK_AAD,
                    },
                )
                .map_err(|_| {
                    StoreError::Credential(
                        "credential key verification failed; the key or stored data is invalid"
                            .into(),
                    )
                })?,
        );
        if plaintext.as_slice() != SQLITE_KEY_CHECK_PLAINTEXT {
            return Err(StoreError::Credential(
                "credential key verification failed; the key or stored data is invalid".into(),
            ));
        }
        Ok(())
    }

    fn verify_existing_credentials(
        transaction: &Transaction<'_>,
        cipher: &Aes256Gcm,
    ) -> Result<()> {
        let records = {
            let mut statement = transaction.prepare(
                "SELECT namespace, reference, version, nonce, ciphertext FROM credentials",
            )?;
            statement
                .query_map([], |row| {
                    Ok(EncryptedCredentialRecord {
                        namespace: row.get(0)?,
                        reference: row.get(1)?,
                        version: row.get(2)?,
                        nonce: row.get(3)?,
                        ciphertext: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for record in records {
            if record.version != SQLITE_ENCRYPTION_VERSION {
                return Err(StoreError::Credential(format!(
                    "unsupported credential encryption version {}",
                    record.version
                )));
            }
            let nonce: [u8; SQLITE_NONCE_BYTES] = record.nonce.try_into().map_err(|_| {
                StoreError::Credential("stored credential nonce has an invalid length".into())
            })?;
            let associated_data = Self::associated_data_for(&record.namespace, &record.reference);
            let _plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &record.ciphertext,
                            aad: &associated_data,
                        },
                    )
                    .map_err(|_| {
                        StoreError::Credential(
                            "credential key verification failed; the key or stored data is invalid"
                                .into(),
                        )
                    })?,
            );
        }
        Ok(())
    }

    fn insert_key_marker(transaction: &Transaction<'_>, cipher: &Aes256Gcm) -> Result<()> {
        let mut nonce = [0_u8; SQLITE_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: SQLITE_KEY_CHECK_PLAINTEXT,
                    aad: SQLITE_KEY_CHECK_AAD,
                },
            )
            .map_err(|_| {
                StoreError::Credential("failed to initialize credential key check".into())
            })?;
        transaction.execute(
            "INSERT INTO credential_store_metadata (name, version, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                SQLITE_KEY_CHECK_NAME,
                SQLITE_ENCRYPTION_VERSION,
                nonce.as_slice(),
                ciphertext
            ],
        )?;
        Ok(())
    }

    fn cipher(&self) -> Aes256Gcm {
        Self::cipher_for_key(self.key.as_ref().as_ref())
    }

    fn cipher_for_key(key: &[u8]) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(key)
            .expect("a 32-byte credential key is always a valid AES-256 key")
    }

    fn associated_data(&self, reference: &str) -> Vec<u8> {
        Self::associated_data_for(&self.namespace, reference)
    }

    fn associated_data_for(namespace: &str, reference: &str) -> Vec<u8> {
        let namespace = namespace.as_bytes();
        let reference = reference.as_bytes();
        let mut value = Vec::with_capacity(40 + namespace.len() + reference.len());
        value.extend_from_slice(b"sql-connector-credential");
        value.extend_from_slice(&SQLITE_ENCRYPTION_VERSION.to_be_bytes());
        value.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        value.extend_from_slice(namespace);
        value.extend_from_slice(reference);
        value
    }
}

impl CredentialStore for SqliteCredentialStore {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> Result<()> {
        let encoded = Zeroizing::new(serde_json::to_vec(secret)?);
        let mut nonce = [0_u8; SQLITE_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let associated_data = self.associated_data(reference);
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: encoded.as_slice(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| StoreError::Credential("failed to encrypt credential".into()))?;
        self.connection
            .lock()
            .expect("credential database poisoned")
            .execute(
                "INSERT INTO credentials
                    (namespace, reference, version, nonce, ciphertext, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
                 ON CONFLICT(namespace, reference) DO UPDATE SET
                    version=excluded.version,
                    nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext,
                    updated_at=CURRENT_TIMESTAMP",
                params![
                    self.namespace,
                    reference,
                    SQLITE_ENCRYPTION_VERSION,
                    nonce.as_slice(),
                    ciphertext
                ],
            )?;
        Ok(())
    }

    fn get(&self, reference: &str) -> Result<SecretMaterial> {
        let stored: Option<(i64, Vec<u8>, Vec<u8>)> = self
            .connection
            .lock()
            .expect("credential database poisoned")
            .query_row(
                "SELECT version, nonce, ciphertext FROM credentials
                 WHERE namespace=?1 AND reference=?2",
                params![self.namespace, reference],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (version, nonce, ciphertext) = stored.ok_or(StoreError::NotFound)?;
        if version != SQLITE_ENCRYPTION_VERSION {
            return Err(StoreError::Credential(format!(
                "unsupported credential encryption version {version}"
            )));
        }
        let nonce: [u8; SQLITE_NONCE_BYTES] = nonce.try_into().map_err(|_| {
            StoreError::Credential("stored credential nonce has an invalid length".into())
        })?;
        let associated_data = self.associated_data(reference);
        let encoded = Zeroizing::new(
            self.cipher()
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &associated_data,
                    },
                )
                .map_err(|_| {
                    StoreError::Credential(
                        "credential decryption failed; the key or stored data is invalid".into(),
                    )
                })?,
        );
        Ok(serde_json::from_slice(&encoded)?)
    }

    fn delete(&self, reference: &str) -> Result<()> {
        let affected = self
            .connection
            .lock()
            .expect("credential database poisoned")
            .execute(
                "DELETE FROM credentials WHERE namespace=?1 AND reference=?2",
                params![self.namespace, reference],
            )?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryCredentialStore {
    secrets: RwLock<HashMap<String, Zeroizing<String>>>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> Result<()> {
        let encoded = Zeroizing::new(serde_json::to_string(secret)?);
        self.secrets
            .write()
            .expect("credential map poisoned")
            .insert(reference.to_owned(), encoded);
        Ok(())
    }

    fn get(&self, reference: &str) -> Result<SecretMaterial> {
        let encoded = self
            .secrets
            .read()
            .expect("credential map poisoned")
            .get(reference)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        Ok(serde_json::from_str(encoded.as_str())?)
    }

    fn delete(&self, reference: &str) -> Result<()> {
        let removed = self
            .secrets
            .write()
            .expect("credential map poisoned")
            .remove(reference);
        if removed.is_none() {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

pub struct OsCredentialStore {
    service: String,
}

impl OsCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl CredentialStore for OsCredentialStore {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> Result<()> {
        let encoded = Zeroizing::new(serde_json::to_string(secret)?);
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        entry
            .set_password(&encoded)
            .map_err(|error| StoreError::Credential(error.to_string()))
    }

    fn get(&self, reference: &str) -> Result<SecretMaterial> {
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        let encoded = Zeroizing::new(entry.get_password().map_err(map_keyring_error)?);
        Ok(serde_json::from_str(encoded.as_str())?)
    }

    fn delete(&self, reference: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        entry.delete_credential().map_err(map_keyring_error)
    }
}

#[cfg(target_os = "windows")]
const WINDOWS_CREDENTIAL_CHUNK_BYTES: usize = 2_400;
#[cfg(target_os = "windows")]
const WINDOWS_CHUNK_HEADER_PREFIX: &str = "sql-connector-chunks-v1:";

#[cfg(target_os = "windows")]
struct WindowsChunkHeader {
    generation: Uuid,
    chunks: usize,
    length: usize,
}

#[cfg(target_os = "windows")]
impl WindowsChunkHeader {
    fn encode(&self) -> String {
        format!(
            "{WINDOWS_CHUNK_HEADER_PREFIX}{}:{}:{}",
            self.generation, self.chunks, self.length
        )
    }
}

#[cfg(target_os = "windows")]
impl CredentialStore for OsCredentialStore {
    fn put(&self, reference: &str, secret: &SecretMaterial) -> Result<()> {
        let encoded = Zeroizing::new(serde_json::to_string(secret)?);
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        let previous_header = match entry.get_secret() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                parse_windows_chunk_header(&value)?
            }
            Err(keyring::Error::NoEntry) => None,
            Err(error) => return Err(StoreError::Credential(error.to_string())),
        };

        let generation = Uuid::new_v4();
        let chunks = encoded.len().div_ceil(WINDOWS_CREDENTIAL_CHUNK_BYTES);
        for (index, chunk) in encoded
            .as_bytes()
            .chunks(WINDOWS_CREDENTIAL_CHUNK_BYTES)
            .enumerate()
        {
            let chunk_entry = windows_chunk_entry(&self.service, reference, generation, index)?;
            if let Err(error) = chunk_entry.set_secret(chunk) {
                delete_windows_chunks(&self.service, reference, generation, index);
                return Err(StoreError::Credential(error.to_string()));
            }
        }

        let header = WindowsChunkHeader {
            generation,
            chunks,
            length: encoded.len(),
        };
        if let Err(error) = entry.set_secret(header.encode().as_bytes()) {
            delete_windows_chunks(&self.service, reference, generation, chunks);
            return Err(StoreError::Credential(error.to_string()));
        }
        if let Some(previous) = previous_header {
            delete_windows_chunks(
                &self.service,
                reference,
                previous.generation,
                previous.chunks,
            );
        }
        Ok(())
    }

    fn get(&self, reference: &str) -> Result<SecretMaterial> {
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        let stored = Zeroizing::new(entry.get_secret().map_err(map_keyring_error)?);
        let Some(header) = parse_windows_chunk_header(&stored)? else {
            drop(stored);
            let encoded = Zeroizing::new(entry.get_password().map_err(map_keyring_error)?);
            return Ok(serde_json::from_str(encoded.as_str())?);
        };

        let mut encoded = Zeroizing::new(Vec::with_capacity(header.length));
        for index in 0..header.chunks {
            let chunk_entry =
                windows_chunk_entry(&self.service, reference, header.generation, index)?;
            let chunk = Zeroizing::new(chunk_entry.get_secret().map_err(map_keyring_error)?);
            encoded.extend_from_slice(&chunk);
        }
        if encoded.len() != header.length {
            return Err(StoreError::Credential(
                "stored credential chunks have an invalid total length".into(),
            ));
        }
        Ok(serde_json::from_slice(&encoded)?)
    }

    fn delete(&self, reference: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|error| StoreError::Credential(error.to_string()))?;
        let stored = Zeroizing::new(entry.get_secret().map_err(map_keyring_error)?);
        let header = parse_windows_chunk_header(&stored)?;
        entry.delete_credential().map_err(map_keyring_error)?;
        if let Some(header) = header {
            delete_windows_chunks(&self.service, reference, header.generation, header.chunks);
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn parse_windows_chunk_header(value: &[u8]) -> Result<Option<WindowsChunkHeader>> {
    let Ok(value) = std::str::from_utf8(value) else {
        return Ok(None);
    };
    let Some(value) = value.strip_prefix(WINDOWS_CHUNK_HEADER_PREFIX) else {
        return Ok(None);
    };
    let mut fields = value.split(':');
    let generation = fields.next().and_then(|value| Uuid::parse_str(value).ok());
    let chunks = fields.next().and_then(|value| value.parse::<usize>().ok());
    let length = fields.next().and_then(|value| value.parse::<usize>().ok());
    if fields.next().is_some() {
        return Err(invalid_windows_chunk_header());
    }
    let (Some(generation), Some(chunks), Some(length)) = (generation, chunks, length) else {
        return Err(invalid_windows_chunk_header());
    };
    if length == 0 || chunks != length.div_ceil(WINDOWS_CREDENTIAL_CHUNK_BYTES) {
        return Err(invalid_windows_chunk_header());
    }
    Ok(Some(WindowsChunkHeader {
        generation,
        chunks,
        length,
    }))
}

#[cfg(target_os = "windows")]
fn invalid_windows_chunk_header() -> StoreError {
    StoreError::Credential("stored credential chunk header is invalid".into())
}

#[cfg(target_os = "windows")]
fn windows_chunk_entry(
    service: &str,
    reference: &str,
    generation: Uuid,
    index: usize,
) -> Result<keyring::Entry> {
    keyring::Entry::new(service, &format!("{reference}/chunk/{generation}/{index}"))
        .map_err(|error| StoreError::Credential(error.to_string()))
}

#[cfg(target_os = "windows")]
fn delete_windows_chunks(service: &str, reference: &str, generation: Uuid, chunks: usize) {
    for index in 0..chunks {
        if let Ok(entry) = windows_chunk_entry(service, reference, generation, index) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn map_keyring_error(error: keyring::Error) -> StoreError {
    match error {
        keyring::Error::NoEntry => StoreError::NotFound,
        other => StoreError::Credential(other.to_string()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl CredentialStore for OsCredentialStore {
    fn put(&self, _reference: &str, _secret: &SecretMaterial) -> Result<()> {
        Err(StoreError::Credential(format!(
            "OS credential storage for service {} is supported only on macOS and Windows",
            self.service
        )))
    }

    fn get(&self, _reference: &str) -> Result<SecretMaterial> {
        Err(StoreError::Credential(format!(
            "OS credential storage for service {} is supported only on macOS and Windows",
            self.service
        )))
    }

    fn delete(&self, _reference: &str) -> Result<()> {
        Err(StoreError::Credential(format!(
            "OS credential storage for service {} is supported only on macOS and Windows",
            self.service
        )))
    }
}
