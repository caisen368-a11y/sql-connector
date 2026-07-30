use std::{
    collections::BTreeMap,
    io::{self, Read},
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use connection_string::AdoNetString;
use connector_control::{ConnectionDraft, ConnectionUpdateDraft};
use connector_core::{
    AuthKind, ConnectionId, ConnectionPolicy, ConnectionProfile, ConnectorError, ErrorCategory,
    Product, SecretMaterial, TlsConfig, canonical_api_mode,
};
use mongodb::options::{ConnectionString, HostInfo, ServerAddress, Tls};
use mysql_async::Opts;
use oracle_rs::{Config as OracleConfig, config::ServiceMethod};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use tiberius::Config as SqlServerConfig;
use tokio_postgres::{
    Config as PostgresConfig,
    config::{Host as PostgresHost, SslMode},
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
struct ConnectionStringDraft {
    display_name: String,
    product: Product,
    api_mode: String,
    connection_string: String,
    #[serde(default, alias = "secret_fields")]
    credentials: Option<BTreeMap<String, String>>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    tls_enabled: Option<bool>,
    #[serde(default)]
    policy: Option<ConnectionPolicy>,
    #[serde(default)]
    expected_version: Option<String>,
    #[serde(default)]
    options: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ConnectionStringProbeInput {
    display_name: String,
    connection_string: String,
    #[serde(default, alias = "secret_fields")]
    credentials: Option<BTreeMap<String, String>>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    tls_enabled: Option<bool>,
    #[serde(default)]
    policy: Option<ConnectionPolicy>,
    #[serde(default)]
    expected_version: Option<String>,
    #[serde(default)]
    options: BTreeMap<String, serde_json::Value>,
}

impl Drop for ConnectionStringDraft {
    fn drop(&mut self) {
        self.connection_string.zeroize();
        if let Some(credentials) = std::mem::take(&mut self.credentials) {
            for (mut name, mut value) in credentials {
                name.zeroize();
                value.zeroize();
            }
        }
    }
}

impl Drop for ConnectionStringProbeInput {
    fn drop(&mut self) {
        self.connection_string.zeroize();
        if let Some(credentials) = std::mem::take(&mut self.credentials) {
            for (mut name, mut value) in credentials {
                name.zeroize();
                value.zeroize();
            }
        }
    }
}

#[derive(Deserialize)]
struct ConnectionStringUpdateInput {
    connection_id: ConnectionId,
    #[serde(flatten)]
    connection: ConnectionStringDraft,
}

pub(crate) struct ImportedConnectionUpdate {
    connection_id: ConnectionId,
    connection: ConnectionDraft,
    reuse_additional_credentials: bool,
}

impl ImportedConnectionUpdate {
    pub(crate) fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    pub(crate) fn into_profile_and_secret(
        mut self,
        existing: &ConnectionProfile,
        mut existing_secret: SecretMaterial,
    ) -> (ConnectionProfile, SecretMaterial) {
        if self.reuse_additional_credentials {
            let connection_string = self
                .connection
                .credentials
                .as_mut()
                .and_then(|credentials| credentials.remove("connection_string"))
                .expect("imported drafts always contain a connection string");
            existing_secret
                .fields
                .insert("connection_string".into(), connection_string);
            self.connection.credentials = None;
        }
        ConnectionUpdateDraft {
            connection_id: self.connection_id,
            connection: self.connection,
        }
        .into_profile_and_secret(existing, existing_secret)
    }
}

struct ParsedTarget {
    endpoint: Url,
    database: Option<String>,
    tls_enabled: bool,
    sid: Option<bool>,
}

#[derive(Clone, Copy)]
enum ConnectionStringFormat {
    Postgres,
    MySql,
    SqlServer,
    Oracle,
    MongoDb,
    Couchbase,
    Cql,
    Ycql,
}

#[derive(Clone, Copy)]
pub(crate) struct ConnectionStringCandidate {
    pub(crate) product: Product,
    pub(crate) api_mode: &'static str,
}

const POSTGRES_CANDIDATES: [ConnectionStringCandidate; 3] = [
    ConnectionStringCandidate {
        product: Product::PostgreSql,
        api_mode: "postgresql",
    },
    ConnectionStringCandidate {
        product: Product::CockroachDb,
        api_mode: "postgresql",
    },
    ConnectionStringCandidate {
        product: Product::YugabyteDb,
        api_mode: "ysql",
    },
];

const MYSQL_CANDIDATES: [ConnectionStringCandidate; 3] = [
    ConnectionStringCandidate {
        product: Product::MySql,
        api_mode: "mysql",
    },
    ConnectionStringCandidate {
        product: Product::TiDb,
        api_mode: "mysql",
    },
    ConnectionStringCandidate {
        product: Product::OceanBase,
        api_mode: "oceanbase_mysql",
    },
];

const SQL_SERVER_CANDIDATES: [ConnectionStringCandidate; 1] = [ConnectionStringCandidate {
    product: Product::SqlServer,
    api_mode: "tds",
}];

const ORACLE_CANDIDATES: [ConnectionStringCandidate; 1] = [ConnectionStringCandidate {
    product: Product::Oracle,
    api_mode: "tns",
}];

const MONGODB_CANDIDATES: [ConnectionStringCandidate; 1] = [ConnectionStringCandidate {
    product: Product::MongoDb,
    api_mode: "mongodb",
}];

const COUCHBASE_CANDIDATES: [ConnectionStringCandidate; 1] = [ConnectionStringCandidate {
    product: Product::Couchbase,
    api_mode: "couchbase",
}];

const CQL_CANDIDATES: [ConnectionStringCandidate; 2] = [
    ConnectionStringCandidate {
        product: Product::Cassandra,
        api_mode: "cql",
    },
    ConnectionStringCandidate {
        product: Product::YugabyteDb,
        api_mode: "ycql",
    },
];

const YCQL_CANDIDATES: [ConnectionStringCandidate; 1] = [ConnectionStringCandidate {
    product: Product::YugabyteDb,
    api_mode: "ycql",
}];

pub(crate) struct ConnectionStringProbe {
    input: ConnectionStringProbeInput,
    format: ConnectionStringFormat,
}

impl ConnectionStringProbe {
    pub(crate) fn candidates(&self) -> &'static [ConnectionStringCandidate] {
        match self.format {
            ConnectionStringFormat::Postgres => &POSTGRES_CANDIDATES,
            ConnectionStringFormat::MySql => &MYSQL_CANDIDATES,
            ConnectionStringFormat::SqlServer => &SQL_SERVER_CANDIDATES,
            ConnectionStringFormat::Oracle => &ORACLE_CANDIDATES,
            ConnectionStringFormat::MongoDb => &MONGODB_CANDIDATES,
            ConnectionStringFormat::Couchbase => &COUCHBASE_CANDIDATES,
            ConnectionStringFormat::Cql => &CQL_CANDIDATES,
            ConnectionStringFormat::Ycql => &YCQL_CANDIDATES,
        }
    }

    pub(crate) fn connection_draft(
        &self,
        candidate: ConnectionStringCandidate,
    ) -> connector_core::Result<ConnectionDraft> {
        ConnectionStringDraft {
            display_name: self.input.display_name.clone(),
            product: candidate.product,
            api_mode: candidate.api_mode.into(),
            connection_string: self.input.connection_string.clone(),
            credentials: self.input.credentials.clone(),
            tags: self.input.tags.clone(),
            tls_enabled: self.input.tls_enabled,
            policy: self.input.policy.clone(),
            expected_version: self.input.expected_version.clone(),
            options: self.input.options.clone(),
        }
        .to_connection_draft()
    }
}

pub(crate) fn read_connection_string_draft() -> Result<ConnectionDraft> {
    let mut json = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut json)
        .context("failed to read connection-string draft from stdin")?;
    if json.trim().is_empty() {
        bail!("connection-string draft stdin must contain one JSON object");
    }
    let input: ConnectionStringDraft =
        serde_json::from_str(&json).context("connection-string draft is not valid JSON")?;
    input.to_connection_draft().map_err(Into::into)
}

pub(crate) fn read_connection_string_update() -> Result<ImportedConnectionUpdate> {
    let mut json = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut json)
        .context("failed to read connection-string update from stdin")?;
    if json.trim().is_empty() {
        bail!("connection-string update stdin must contain one JSON object");
    }
    let input: ConnectionStringUpdateInput =
        serde_json::from_str(&json).context("connection-string update is not valid JSON")?;
    let reuse_additional_credentials = input.connection.credentials.is_none();
    let connection = input.connection.to_connection_draft()?;
    Ok(ImportedConnectionUpdate {
        connection_id: input.connection_id,
        connection,
        reuse_additional_credentials,
    })
}

pub(crate) fn read_connection_string_probe() -> Result<ConnectionStringProbe> {
    let mut json = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut json)
        .context("failed to read connection-string probe from stdin")?;
    if json.trim().is_empty() {
        bail!("connection-string probe stdin must contain one JSON object");
    }
    let input: ConnectionStringProbeInput =
        serde_json::from_str(&json).context("connection-string probe is not valid JSON")?;
    let format = detect_connection_string_format(&input.connection_string)?;
    Ok(ConnectionStringProbe { input, format })
}

impl ConnectionStringDraft {
    fn to_connection_draft(&self) -> connector_core::Result<ConnectionDraft> {
        if self.connection_string.trim().is_empty() {
            return Err(invalid("connection_string must not be empty"));
        }
        let (format, api_mode) = connection_string_format(self.product, &self.api_mode)?;
        let mut target = match format {
            ConnectionStringFormat::Postgres => parse_postgres(&self.connection_string)?,
            ConnectionStringFormat::MySql => parse_mysql(&self.connection_string)?,
            ConnectionStringFormat::SqlServer => parse_sql_server(&self.connection_string)?,
            ConnectionStringFormat::Oracle => parse_oracle(&self.connection_string)?,
            ConnectionStringFormat::MongoDb => parse_mongodb(&self.connection_string)?,
            ConnectionStringFormat::Couchbase => parse_couchbase(&self.connection_string)?,
            ConnectionStringFormat::Cql | ConnectionStringFormat::Ycql => {
                parse_cql(&self.connection_string)?
            }
        };
        let tls_enabled = self.tls_enabled.unwrap_or(target.tls_enabled);
        if self.product == Product::Oracle {
            target
                .endpoint
                .set_scheme(if tls_enabled { "oracles" } else { "oracle" })
                .map_err(|()| invalid("could not construct the Oracle endpoint"))?;
        }

        let mut credentials = self.credentials.clone().unwrap_or_default();
        credentials.insert("connection_string".into(), self.connection_string.clone());
        let mut options = self.options.clone();
        if let Some(sid) = target.sid {
            options.insert("sid".into(), sid.into());
        }
        let tls = TlsConfig {
            enabled: tls_enabled,
            ..TlsConfig::default()
        };

        Ok(ConnectionDraft {
            display_name: self.display_name.clone(),
            product: self.product,
            api_mode,
            endpoint: target.endpoint,
            database: target.database,
            tags: self.tags.clone(),
            auth_kind: AuthKind::ConnectionString,
            credentials: Some(credentials),
            tls: Some(tls),
            tls_enabled: None,
            policy: self.policy.clone(),
            expected_version: self.expected_version.clone(),
            options,
        })
    }
}

fn connection_string_format(
    product: Product,
    api_mode: &str,
) -> connector_core::Result<(ConnectionStringFormat, String)> {
    let mode = canonical_api_mode(product, api_mode);
    let matched = match (product, mode.as_str()) {
        (Product::PostgreSql | Product::CockroachDb, "postgresql") => {
            (ConnectionStringFormat::Postgres, "postgresql")
        }
        (Product::YugabyteDb, "ysql") => (ConnectionStringFormat::Postgres, "ysql"),
        (Product::MySql | Product::TiDb, "mysql") => (ConnectionStringFormat::MySql, "mysql"),
        (Product::OceanBase, "oceanbase-mysql") => {
            (ConnectionStringFormat::MySql, "oceanbase_mysql")
        }
        (Product::SqlServer, "tds") => (ConnectionStringFormat::SqlServer, "tds"),
        (Product::Oracle, "tns") => (ConnectionStringFormat::Oracle, "tns"),
        (Product::MongoDb, "mongodb") => (ConnectionStringFormat::MongoDb, "mongodb"),
        (Product::Couchbase, "couchbase") => (ConnectionStringFormat::Couchbase, "couchbase"),
        (Product::Cassandra, "cql") => (ConnectionStringFormat::Cql, "cql"),
        (Product::YugabyteDb, "ycql") => (ConnectionStringFormat::Cql, "ycql"),
        _ => {
            return Err(invalid(
                "connection-string import is not supported for this product/api_mode",
            ));
        }
    };
    Ok((matched.0, matched.1.into()))
}

fn detect_connection_string_format(
    connection_string: &str,
) -> connector_core::Result<ConnectionStringFormat> {
    let value = connection_string.trim();
    if value.is_empty() {
        return Err(invalid("connection_string must not be empty"));
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase.starts_with("postgresql://") || lowercase.starts_with("postgres://") {
        return Ok(ConnectionStringFormat::Postgres);
    }
    if lowercase.starts_with("mysql://") {
        return Ok(ConnectionStringFormat::MySql);
    }
    if lowercase.starts_with("mongodb://") || lowercase.starts_with("mongodb+srv://") {
        return Ok(ConnectionStringFormat::MongoDb);
    }
    if lowercase.starts_with("couchbase://") || lowercase.starts_with("couchbases://") {
        return Ok(ConnectionStringFormat::Couchbase);
    }
    if lowercase.starts_with("ycql://") {
        return Ok(ConnectionStringFormat::Ycql);
    }
    if lowercase.starts_with("cql://") || lowercase.starts_with("cassandra://") {
        return Ok(ConnectionStringFormat::Cql);
    }
    if value
        .parse::<AdoNetString>()
        .ok()
        .is_some_and(|properties| {
            properties.contains_key("server") || properties.contains_key("data source")
        })
    {
        return Ok(ConnectionStringFormat::SqlServer);
    }
    if value.contains('=') && parse_postgres(value).is_ok() {
        return Ok(ConnectionStringFormat::Postgres);
    }
    if (value.contains('/') || value.matches(':').count() >= 2) && parse_oracle(value).is_ok() {
        return Ok(ConnectionStringFormat::Oracle);
    }
    Err(invalid(
        "connection-string protocol could not be identified; specify product and api_mode explicitly",
    ))
}

fn parse_postgres(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let config = PostgresConfig::from_str(connection_string)
        .map_err(|_| invalid("PostgreSQL connection string is invalid"))?;
    let [PostgresHost::Tcp(host)] = config.get_hosts() else {
        return Err(invalid(
            "PostgreSQL connection string must contain exactly one TCP host",
        ));
    };
    if !config.get_hostaddrs().is_empty() {
        return Err(invalid(
            "PostgreSQL hostaddr is not accepted by connection-string import",
        ));
    }
    let port = match config.get_ports() {
        [] => 5_432,
        [port] => *port,
        _ => {
            return Err(invalid(
                "PostgreSQL connection string must contain at most one port",
            ));
        }
    };
    Ok(ParsedTarget {
        endpoint: endpoint_url("postgresql", host, Some(port))?,
        database: config.get_dbname().map(str::to_owned),
        tls_enabled: config.get_ssl_mode() != SslMode::Disable,
        sid: None,
    })
}

fn parse_mysql(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let options = Opts::from_url(connection_string)
        .map_err(|_| invalid("MySQL connection string is invalid"))?;
    if options.socket().is_some() || !options.init().is_empty() || !options.setup().is_empty() {
        return Err(invalid(
            "MySQL socket and init/setup options are not accepted by connection-string import",
        ));
    }
    Ok(ParsedTarget {
        endpoint: endpoint_url("mysql", options.ip_or_hostname(), Some(options.tcp_port()))?,
        database: options.db_name().map(str::to_owned),
        tls_enabled: options.ssl_opts().is_some(),
        sid: None,
    })
}

fn parse_sql_server(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let properties = connection_string
        .parse::<AdoNetString>()
        .map_err(|_| invalid("SQL Server ADO.NET connection string is invalid"))?;
    let server = properties
        .get("server")
        .or_else(|| properties.get("data source"));
    if server.is_some_and(|server| server.contains('\\')) {
        return Err(invalid(
            "SQL Server named instances are not supported; specify a TCP port",
        ));
    }
    reject_sql_server_auth_options(&properties)?;
    let config = SqlServerConfig::from_ado_string(connection_string)
        .map_err(|_| invalid("SQL Server ADO.NET connection string is invalid"))?;
    let address = config.get_addr();
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| invalid("SQL Server connection string has no TCP target"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| invalid("SQL Server connection string has an invalid TCP port"))?;
    let database = properties
        .get("database")
        .or_else(|| properties.get("initial catalog"))
        .or_else(|| properties.get("databasename"))
        .cloned();
    let tls_enabled = properties
        .get("encrypt")
        .is_none_or(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "yes"));
    Ok(ParsedTarget {
        endpoint: endpoint_url("sqlserver", host.trim_matches(['[', ']']), Some(port))?,
        database,
        tls_enabled,
        sid: None,
    })
}

fn reject_sql_server_auth_options(properties: &AdoNetString) -> connector_core::Result<()> {
    if properties
        .get("integratedsecurity")
        .or_else(|| properties.get("integrated security"))
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "yes"))
    {
        return Err(invalid(
            "SQL Server integrated authentication is not supported",
        ));
    }
    if properties.contains_key("authentication") {
        return Err(invalid("SQL Server Entra authentication is not supported"));
    }
    if properties
        .get("trustservercertificate")
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "yes"))
    {
        return Err(invalid(
            "SQL Server connection string cannot disable certificate verification",
        ));
    }
    if properties.contains_key("trustservercertificateca") {
        return Err(invalid(
            "SQL Server custom CA paths in connection strings are not supported",
        ));
    }
    Ok(())
}

fn parse_oracle(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let config = OracleConfig::from_str(connection_string)
        .map_err(|_| invalid("Oracle EZConnect connection string is invalid"))?;
    if config.host.is_empty() {
        return Err(invalid("Oracle connection string must contain a host"));
    }
    let (database, sid) = match config.service {
        ServiceMethod::ServiceName(service) => (service, false),
        ServiceMethod::Sid(sid) => (sid, true),
    };
    Ok(ParsedTarget {
        endpoint: endpoint_url("oracle", &config.host, Some(config.port))?,
        database: Some(database),
        tls_enabled: false,
        sid: Some(sid),
    })
}

fn parse_mongodb(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let parsed = ConnectionString::parse(connection_string)
        .map_err(|_| invalid("MongoDB connection string is invalid"))?;
    let endpoint = match &parsed.host_info {
        HostInfo::HostIdentifiers(hosts) => match hosts.as_slice() {
            [ServerAddress::Tcp { host, port }] => {
                endpoint_url("mongodb", host, Some(port.unwrap_or(27_017)))?
            }
            _ => {
                return Err(invalid(
                    "MongoDB connection-string import requires exactly one TCP seed",
                ));
            }
        },
        HostInfo::DnsRecord(host) => endpoint_url("mongodb+srv", host, None)?,
        _ => return Err(invalid("MongoDB connection-string target is not supported")),
    };
    let tls_enabled = matches!(parsed.tls, Some(Tls::Enabled(_)));
    Ok(ParsedTarget {
        endpoint,
        database: parsed.default_database,
        tls_enabled,
        sid: None,
    })
}

fn parse_couchbase(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let endpoint = Url::parse(connection_string)
        .map_err(|_| invalid("Couchbase connection string is invalid"))?;
    if !matches!(endpoint.scheme(), "couchbase" | "couchbases") {
        return Err(invalid(
            "Couchbase connection string must use couchbase:// or couchbases://",
        ));
    }
    if endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.fragment().is_some()
    {
        return Err(invalid(
            "Couchbase connection string must contain a host and no credentials, path, or fragment",
        ));
    }
    Ok(ParsedTarget {
        tls_enabled: endpoint.scheme() == "couchbases",
        endpoint,
        database: None,
        sid: None,
    })
}

fn parse_cql(connection_string: &str) -> connector_core::Result<ParsedTarget> {
    let parsed =
        Url::parse(connection_string).map_err(|_| invalid("CQL connection string is invalid"))?;
    if !matches!(parsed.scheme(), "cql" | "cassandra" | "ycql") {
        return Err(invalid(
            "CQL connection string must use cql://, cassandra://, or ycql://",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("CQL connection string must contain a host"))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid(
            "CQL connection string query parameters and fragments are not supported",
        ));
    }
    let has_username = !parsed.username().is_empty();
    let has_password = parsed
        .password()
        .is_some_and(|password| !password.is_empty());
    if has_username != has_password {
        return Err(invalid(
            "CQL connection string must contain both username and password or neither",
        ));
    }
    let database = match parsed.path() {
        "" | "/" => None,
        path => {
            let keyspace = path
                .strip_prefix('/')
                .filter(|keyspace| !keyspace.is_empty() && !keyspace.contains('/'))
                .ok_or_else(|| {
                    invalid("CQL connection string may contain at most one keyspace path")
                })?;
            Some(decode_url_component(keyspace, "CQL keyspace")?)
        }
    };
    Ok(ParsedTarget {
        endpoint: endpoint_url("cql", host, Some(parsed.port().unwrap_or(9_042)))?,
        database,
        tls_enabled: false,
        sid: None,
    })
}

fn decode_url_component(value: &str, description: &str) -> connector_core::Result<String> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| invalid(format!("{description} is not valid UTF-8")))?
        .into_owned();
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        return Err(invalid(format!("{description} is empty or invalid")));
    }
    Ok(decoded)
}

fn endpoint_url(scheme: &str, host: &str, port: Option<u16>) -> connector_core::Result<Url> {
    let mut endpoint = Url::parse(&format!("{scheme}://localhost"))
        .map_err(|_| invalid("could not construct a connection endpoint"))?;
    endpoint
        .set_host(Some(host))
        .map_err(|_| invalid("connection string contains an invalid host"))?;
    endpoint
        .set_port(port)
        .map_err(|()| invalid("connection string contains an invalid port"))?;
    Ok(endpoint)
}

fn invalid(message: impl Into<String>) -> ConnectorError {
    ConnectorError::new(ErrorCategory::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import(
        json: serde_json::Value,
    ) -> (
        connector_core::ConnectionProfile,
        connector_core::SecretMaterial,
    ) {
        let input: ConnectionStringDraft = serde_json::from_value(json).unwrap();
        input
            .to_connection_draft()
            .unwrap()
            .into_profile_and_secret()
    }

    #[test]
    fn postgres_import_keeps_credentials_out_of_the_profile() {
        let (profile, secret) = import(serde_json::json!({
            "display_name": "Production",
            "product": "postgresql",
            "api_mode": "postgresql",
            "connection_string": "postgresql://alice:secret@db.example:5433/app?sslmode=require"
        }));

        assert_eq!(profile.endpoint.as_str(), "postgresql://db.example:5433");
        assert_eq!(profile.database.as_deref(), Some("app"));
        assert!(profile.tls.enabled);
        assert_eq!(
            secret.fields.get("connection_string").map(String::as_str),
            Some("postgresql://alice:secret@db.example:5433/app?sslmode=require")
        );
    }

    #[test]
    fn oracle_import_derives_sid_and_accepts_separate_credentials() {
        let (profile, secret) = import(serde_json::json!({
            "display_name": "Oracle",
            "product": "oracle",
            "api_mode": "tns",
            "connection_string": "db.example:1521:ORCL",
            "credentials": {"username": "scott", "password": "tiger"},
            "tls_enabled": false
        }));

        assert_eq!(profile.endpoint.as_str(), "oracle://db.example:1521");
        assert_eq!(profile.database.as_deref(), Some("ORCL"));
        assert_eq!(profile.options.get("sid"), Some(&serde_json::json!(true)));
        assert_eq!(
            secret.fields.get("username").map(String::as_str),
            Some("scott")
        );
    }

    #[test]
    fn mongodb_import_rejects_multiple_seed_hosts() {
        let input: ConnectionStringDraft = serde_json::from_value(serde_json::json!({
            "display_name": "MongoDB",
            "product": "mongodb",
            "api_mode": "mongodb",
            "connection_string": "mongodb://db1.example,db2.example/app"
        }))
        .unwrap();

        assert!(input.to_connection_draft().is_err());
    }

    #[test]
    fn cql_import_derives_a_credential_free_target_and_keyspace() {
        let (profile, secret) = import(serde_json::json!({
            "display_name": "Cassandra",
            "product": "cassandra",
            "api_mode": "cql",
            "connection_string": "cql://alice:secret@db.example:9042/application",
            "tls_enabled": false
        }));

        assert_eq!(profile.endpoint.as_str(), "cql://db.example:9042");
        assert_eq!(profile.database.as_deref(), Some("application"));
        assert_eq!(profile.auth_kind, AuthKind::ConnectionString);
        assert_eq!(secret.fields.len(), 1);
        crate::validate_connection_input(&profile, &secret).unwrap();
    }

    #[test]
    fn probe_identifies_supported_connection_string_families() {
        let cases = [
            (
                "postgresql://user:password@db.example/app",
                Product::PostgreSql,
            ),
            ("mysql://user:password@db.example/app", Product::MySql),
            (
                "Server=tcp:db.example,1433;Database=app;User ID=user;Password=password",
                Product::SqlServer,
            ),
            ("db.example:1521/app", Product::Oracle),
            ("mongodb://user:password@db.example/app", Product::MongoDb),
            ("couchbases://db.example", Product::Couchbase),
            ("cql://user:password@db.example/app", Product::Cassandra),
            ("ycql://user:password@db.example/app", Product::YugabyteDb),
        ];

        for (connection_string, expected) in cases {
            let format = detect_connection_string_format(connection_string).unwrap();
            let probe = ConnectionStringProbe {
                input: serde_json::from_value(serde_json::json!({
                    "display_name": "Detected",
                    "connection_string": connection_string
                }))
                .unwrap(),
                format,
            };
            assert_eq!(probe.candidates()[0].product, expected);
        }
    }

    #[test]
    fn imported_drafts_pass_each_connector_input_contract() {
        let drafts = [
            serde_json::json!({
                "display_name": "PostgreSQL",
                "product": "postgresql",
                "api_mode": "postgresql",
                "connection_string": "postgresql://alice:secret@db.example:5432/app?sslmode=require"
            }),
            serde_json::json!({
                "display_name": "MySQL",
                "product": "mysql",
                "api_mode": "mysql",
                "connection_string": "mysql://alice:secret@db.example:3306/app?require_ssl=true"
            }),
            serde_json::json!({
                "display_name": "SQL Server",
                "product": "sql_server",
                "api_mode": "tds",
                "connection_string": "Server=tcp:db.example,1433;Database=app;User ID=alice;Password=secret;Encrypt=true;TrustServerCertificate=false"
            }),
            serde_json::json!({
                "display_name": "Oracle",
                "product": "oracle",
                "api_mode": "tns",
                "connection_string": "db.example:1521/app",
                "credentials": {"username": "alice", "password": "secret"}
            }),
            serde_json::json!({
                "display_name": "MongoDB",
                "product": "mongodb",
                "api_mode": "mongodb",
                "connection_string": "mongodb://alice:secret@db.example:27017/app?tls=true"
            }),
            serde_json::json!({
                "display_name": "Couchbase",
                "product": "couchbase",
                "api_mode": "couchbase",
                "connection_string": "couchbases://db.example",
                "credentials": {"username": "alice", "password": "secret"}
            }),
            serde_json::json!({
                "display_name": "Cassandra",
                "product": "cassandra",
                "api_mode": "cql",
                "connection_string": "cql://alice:secret@db.example:9042/app",
                "tls_enabled": false
            }),
            serde_json::json!({
                "display_name": "YugabyteDB YCQL",
                "product": "yugabytedb",
                "api_mode": "ycql",
                "connection_string": "ycql://alice:secret@db.example:9042/app",
                "tls_enabled": false
            }),
        ];

        for draft in drafts {
            let (profile, secret) = import(draft);
            crate::validate_connection_input(&profile, &secret).unwrap();
        }
    }

    #[test]
    fn connection_string_update_reuses_omitted_additional_credentials() {
        let (existing, existing_secret) = import(serde_json::json!({
            "display_name": "Oracle",
            "product": "oracle",
            "api_mode": "tns",
            "connection_string": "old.example:1521/app",
            "credentials": {"username": "alice", "password": "secret"}
        }));
        let input: ConnectionStringUpdateInput = serde_json::from_value(serde_json::json!({
            "connection_id": existing.id,
            "display_name": "Oracle",
            "product": "oracle",
            "api_mode": "tns",
            "connection_string": "new.example:1521/app"
        }))
        .unwrap();
        let update = ImportedConnectionUpdate {
            connection_id: input.connection_id,
            connection: input.connection.to_connection_draft().unwrap(),
            reuse_additional_credentials: input.connection.credentials.is_none(),
        };

        let (profile, secret) = update.into_profile_and_secret(&existing, existing_secret);

        assert_eq!(profile.id, existing.id);
        assert_eq!(profile.endpoint.as_str(), "oracle://new.example:1521");
        assert_eq!(
            secret.fields.get("username").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            secret.fields.get("password").map(String::as_str),
            Some("secret")
        );
        assert_eq!(
            secret.fields.get("connection_string").map(String::as_str),
            Some("new.example:1521/app")
        );
    }
}
