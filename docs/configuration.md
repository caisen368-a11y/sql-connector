# Configuration

## Test and add a connection

The normal desktop flow uses a compact draft. The command tests the selected
connector first and writes the profile and credentials only after success:

```json
{
  "display_name": "Local application database",
  "product": "postgresql",
  "api_mode": "postgresql",
  "endpoint": "postgresql://127.0.0.1:5432",
  "database": "app",
  "auth_kind": "username_password",
  "credentials": {
    "username": "agent_reader",
    "password": "replace-me"
  },
  "tls_enabled": false
}
```

```bash
sql-connector --data-dir /private/agent-data add-connection < connection.json
```

For a settings-page Test button, use the same draft without persisting it:

```bash
sql-connector --data-dir /private/agent-data test-connection < connection.json
```

For local form validation without creating a data directory, opening the OS
credential store, or contacting the database, use:

```bash
sql-connector validate-connection < connection.json
```

It returns `valid: true` and the matched connector descriptor on success. Input
errors are returned before any network request.

To import a common connection string, replace `endpoint`, `database`, and
`auth_kind` with `connection_string`. The importer derives a credential-free
endpoint, database, protocol mode, and TLS setting. Oracle and Couchbase still
take their separate username/password fields in `credentials`:

```json
{
  "display_name": "Production database",
  "product": "postgresql",
  "api_mode": "postgresql",
  "connection_string": "postgresql://agent:replace-me@db.example:5432/app?sslmode=require"
}
```

```bash
sql-connector validate-connection-string < connection-string.json
sql-connector --data-dir /private/agent-data test-connection-string < connection-string.json
sql-connector --data-dir /private/agent-data add-connection-string < connection-string.json
```

`validate-connection-string` is offline and returns the derived non-secret
target. The test and add commands retain the original connection string only in
the transient secret payload and operating-system credential store.

For a paste-first flow where the user has not selected a product, omit
`product` and `api_mode` and use one of these commands:

```bash
sql-connector --data-dir /private/agent-data detect-connection-string < connection-string.json
sql-connector --data-dir /private/agent-data add-detected-connection-string < connection-string.json
```

The detector first identifies the protocol syntax, then connects and reads the
server fingerprint. It distinguishes PostgreSQL, CockroachDB, and YugabyteDB
YSQL, and separately MySQL, TiDB, and OceanBase MySQL mode. Authentication,
TLS, and network failures stop immediately; only an explicit product mismatch
advances to the next compatible candidate. CQL URLs use
`cql://[username:password@]host[:port][/keyspace]` or `cassandra://`; `ycql://`
selects YugabyteDB YCQL directly. Set `tls_enabled` explicitly when the CQL
endpoint uses TLS.

For a form-based flow, omit `product` and `api_mode` from the normal compact
draft and use endpoint detection:

```json
{
  "display_name": "Detected database",
  "endpoint": "http://127.0.0.1:6333",
  "database": null,
  "auth_kind": "api_key",
  "credentials": {"api_key": "replace-me"},
  "tls_enabled": false
}
```

```bash
sql-connector --data-dir /private/agent-data detect-endpoint < endpoint.json
sql-connector --data-dir /private/agent-data add-detected-endpoint < endpoint.json
```

The detector reuses every installed connector's server fingerprint and returns
the exact product, API mode, connector input contract, and server information.
`add-detected-endpoint` then validates and tests the final product-specific
draft before saving it. Generic `tcp://` targets are rejected because Oracle,
CQL, and HBase cannot be distinguished safely without a product-specific
scheme. InfluxDB detection can identify its generation without a database,
organization, or bucket, but those required fields must be supplied before the
connection can be saved.

The command generates `id` and `secret_ref`, applies the default bounded
read-only policy, and returns both model-safe connection metadata and detected
server information. `test-connection` returns only detected server information.
Advanced callers can include complete `tls`, `policy`, `tags`,
`expected_version`, and `options` fields. Use `control` when a profile must be
stored without an immediate connection test.

When a new draft omits both `tls` and `tls_enabled`, explicit plaintext schemes
(`http`, `couchbase`, `mongodb`, `oracle`, and HBase `thrift`/`tcp`) default to
TLS disabled. Secure schemes and protocol schemes that do not encode transport
security default to TLS enabled. `tls` and `tls_enabled` always override this
inference. Connection updates retain the saved TLS settings when both fields
are omitted.

When set, `expected_version` must be a prefix of the version reported by the
server; add, update, and later MCP connection tests reject a mismatch.

Trusted desktop commands (`control`, connection validation/test/add/update,
authorization-key, authorize, and audit) exit nonzero and write one
machine-readable `error` object to stdout on failure. This includes malformed
input, connection, profile, SQLite, OS credential-store, policy, and signing-key
failures. The object contains `code`, diagnostic `phase`, safe `message`,
`retryable`, and optional `driver_code` fields. Phases are `configuration`,
`network`, `tls`, `authentication`, `authorization`, `protocol`, or `operation`.

## Test and update a connection

To retest a saved connection without retrieving or resending its credentials:

```json
{"connection_id":"0190f1d8-871f-7c62-82a8-2c112f2c9147"}
```

```bash
sql-connector --data-dir /private/agent-data test-saved-connection < saved-connection.json
```

To edit an existing connection, send the same complete draft with its current
`connection_id`:

```bash
sql-connector --data-dir /private/agent-data update-connection < connection-update.json
```

The command retains the saved ID and credential reference. Omitted `tls` and
`policy` objects retain their current values. Omit `credentials` to reuse the
secret already held in the OS credential store; changing `auth_kind` requires
new credentials. An explicitly supplied credentials object replaces the saved
secret. The command resolves the selected adapter and tests the new endpoint
with the resulting credentials before replacing either saved value; on test or
persistence failure, the previous connection remains available.

An imported connection string uses the equivalent command:

```bash
sql-connector --data-dir /private/agent-data update-connection-string < connection-string-update.json
```

The JSON is the import object plus `connection_id`. Omit `credentials` to keep
the existing username, password, and certificate fields while replacing the
connection string; provide it to replace those additional fields.

## Rotate connection credentials

To change only a saved password, token, API key, or certificate payload, send
the connection ID and new credential fields to the trusted rotation command:

```json
{
  "connection_id": "0190f1d8-871f-7c62-82a8-2c112f2c9147",
  "credentials": {
    "username": "agent_reader",
    "password": "new-secret"
  }
}
```

```bash
sql-connector --data-dir /private/agent-data rotate-credentials < credential-rotation.json
```

The authentication kind and endpoint come from the saved profile. The command
validates the fields and tests the real database before replacing the OS-stored
secret. Validation or connection failure leaves the previous credentials
unchanged. Use `update-connection` when the authentication kind must also
change.

## Update only a connection policy

The desktop permission editor can update policy without reading and resending
the complete connection profile. Send this trusted request to `control`:

```json
{
  "action": "set_policy",
  "connection_id": "0190f1d8-871f-7c62-82a8-2c112f2c9147",
  "policy": {
    "enabled": true,
    "egress": "local_only",
    "max_rows": 1000,
    "max_bytes": 10485760,
    "timeout_ms": 30000,
    "max_affected": 100,
    "allow_native_read": false,
    "allow_native_write": false,
    "allow_time_series_query": true,
    "resources": [
      {
        "pattern": "public.*",
        "allow_read": true,
        "allow_insert": false,
        "allow_update": true,
        "allow_delete": false,
        "masked_fields": []
      }
    ]
  }
}
```

```bash
sql-connector --data-dir /private/agent-data control < policy-update.json
```

The response contains the updated non-secret profile and its incremented
`policy_version`. Grant signing and MCP execution both load this per-connection
revision from the profile store, so grants issued before a policy change are
rejected immediately. The desktop host does not pass or synchronize a policy
version. Invalid limits are rejected by the same profile validation used when
a connection is created. All four numeric limits must be greater than zero,
and every resource `pattern` must be a valid non-empty glob.

`local_only` allows results to cross local MCP stdio into the desktop Agent but
the Agent must not forward them to a cloud model. With `cloud_allowed_masked`,
the runtime replaces each configured `masked_fields` value before returning a
result. A value can be a top-level field such as `password` or a dotted nested
path such as `customer.ssn`; nested paths are also applied to documents inside
arrays. Native reads are rejected in this mode because their output cannot be
reliably associated with a resource masking rule. The dedicated
`timeseries_query` tool is the exception: add an `@timeseries_query` resource
rule with `allow_read: true` and the required masked fields to opt in. Runtime
uses that fixed target for both authorization and masking.

When multiple resource globs match one target, the most specific rule wins:
an exact target pattern ranks first, followed by patterns with more literal
characters, a longer literal prefix, and fewer glob expressions. Original
configuration order breaks a complete tie. Authorization and masking use the
same selected rule.

To pause or resume every database operation without deleting the profile or
credential, use the compact trusted control action:

```json
{"action":"set_enabled","connection_id":"0190f1d8-871f-7c62-82a8-2c112f2c9147","enabled":false}
```

Disabled connections remain visible to the desktop and MCP client, but MCP
connection tests, discovery, descriptions, reads, and writes are denied. The
change increments `policy_version`, invalidating previously issued grants.

## Create a connection

The desktop host sends one JSON object to the trusted control process stdin.
This PostgreSQL example starts with a single readable resource and no writes:

```json
{
  "action": "create",
  "profile": {
    "id": "0190f1d8-871f-7c62-82a8-2c112f2c9147",
    "display_name": "Local application database",
    "product": "postgresql",
    "api_mode": "postgresql",
    "endpoint": "postgresql://127.0.0.1:5432",
    "database": "app",
    "tags": ["local", "development"],
    "auth_kind": "username_password",
    "secret_ref": "connection/0190f1d8-871f-7c62-82a8-2c112f2c9147",
    "tls": {
      "enabled": true,
      "verify_server_certificate": true,
      "ca_certificate_ref": null,
      "client_certificate_ref": null,
      "server_name": null
    },
    "policy": {
      "enabled": true,
      "egress": "local_only",
      "max_rows": 1000,
      "max_bytes": 10485760,
      "timeout_ms": 30000,
      "max_affected": 100,
      "allow_native_read": false,
      "allow_native_write": false,
      "allow_time_series_query": true,
      "resources": [
        {
          "pattern": "public.*",
          "allow_read": true,
          "allow_insert": false,
          "allow_update": false,
          "allow_delete": false,
          "masked_fields": []
        }
      ]
    },
    "expected_version": null,
    "options": {}
  },
  "secret": {
    "kind": "username_password",
    "fields": {
      "username": "agent_reader",
      "password": "replace-me"
    }
  }
}
```

```bash
sql-connector --data-dir /private/agent-data control < create-connection.json
```

The `id` must be a UUID. The endpoint must not contain user info or sensitive
query parameters. TLS server verification cannot be disabled. `secret_ref` is
an opaque unique key chosen by the host; it is not a path and is safe to store
in SQLite.

Other control actions are:

```json
{"action":"list"}
{"action":"update_profile","profile":{}}
{"action":"replace_secret","connection_id":"UUID","secret":{"kind":"api_key","fields":{"api_key":"..."}}}
{"action":"delete","connection_id":"UUID"}
{"action":"get_profile","connection_id":"UUID"}
{"action":"list_profiles"}
```

`update_profile` requires the full profile and cannot change `secret_ref` or
`auth_kind`. Prefer `rotate-credentials` over the low-level `replace_secret`
action so the replacement is tested first; use `replace_secret` only when the
desktop host has already performed equivalent validation. The desktop host
may create, update, rotate, enable, disable, or delete connections while MCP is
running. MCP detects the change, invalidates cached database clients, and sends
`notifications/resources/list_changed`; the Host should then refresh resources
or call `db_list_connections`. `get_profile` and `list_profiles` are trusted
desktop actions that return complete non-secret configuration for settings
forms; they remain unavailable through MCP.

## Query audit history

The trusted desktop activity view can request recent non-secret audit metadata:

```json
{
  "connection_id": "0190f1d8-871f-7c62-82a8-2c112f2c9147",
  "since": "2026-07-28T00:00:00Z",
  "error_category": "unknown_outcome",
  "limit": 100
}
```

```bash
sql-connector --data-dir /private/agent-data audit < audit-query.json
```

Empty stdin returns the newest 100 events. Optional filters are `since`,
`until`, `connection_id`, `subject`, `session_id`, `tool`, and
`error_category`; results are newest first and `limit` is capped at 1000.
Events contain targets, counts, timing, policy decisions, confirmation state,
and error category, but never arguments, statements, credentials, or returned
records. Audit access is not exposed through MCP.

## Authentication fields

Common field names are:

| Authentication kind | Secret fields |
| --- | --- |
| `anonymous` | none |
| `username_password` | `username`, `password` |
| `connection_string` | `connection_string` or connector-documented URI field |
| `api_key` | `api_key`; some products also accept product-specific key ID/secret fields |
| `bearer_token` | `token` or `bearer_token` |
| `client_certificate` | `client_certificate_pem` and `client_private_key_pem` |

For `connection_string` authentication, the profile still records the
non-secret network identity. Its endpoint host/port and optional database must
match the values inside the secret connection string. PostgreSQL host lists and
`hostaddr`, MySQL socket and `init`/`setup` options, SQL Server named instances,
and MongoDB multi-seed strings are rejected because their effective target
cannot be represented by the single profile endpoint. Cluster discovery after
connecting to the recorded seed remains supported.

Custom CA PEM data is stored in the secret payload under
`ca_certificate_pem`. `tls.ca_certificate_ref` and
`tls.client_certificate_ref` are field names inside that same `secret.fields`
object, not filesystem paths and not operating-system credential identifiers.
The named field takes precedence; `ca_certificate_pem` and
`client_certificate_pem` are the respective fallback field names. Client
certificate authentication also requires `client_private_key_pem` (or the
`private_key_pem` fallback). For example:

```json
{
  "tls": {
    "enabled": true,
    "verify_server_certificate": true,
    "ca_certificate_ref": "corporate_ca",
    "client_certificate_ref": "database_client_certificate",
    "server_name": null
  },
  "secret": {
    "kind": "client_certificate",
    "fields": {
      "corporate_ca": "-----BEGIN CERTIFICATE-----...",
      "database_client_certificate": "-----BEGIN CERTIFICATE-----...",
      "client_private_key_pem": "-----BEGIN PRIVATE KEY-----..."
    }
  }
}
```

Certificate and private-key material must be sent through trusted control
stdin and stored in the operating-system credential store. Do not create
persistent certificate files. A connector that cannot pass custom TLS material
to its driver without a path rejects that configuration explicitly. Run
`manifests` before creating a profile and use only an authentication kind
listed for the exact product/API mode.

## MCP host configuration

macOS example:

```json
{
  "mcpServers": {
    "databases": {
      "command": "/Applications/MyAgent.app/Contents/Resources/sql-connector",
      "args": [
        "--data-dir",
        "/Users/alice/Library/Application Support/MyAgent/databases",
        "mcp",
        "--local-authorization",
        "--session-id",
        "DESKTOP_GENERATED_SESSION_ID"
      ]
    }
  }
}
```

Windows uses the same argument order with absolute Windows paths. The Agent
must keep stdout reserved for MCP JSON-RPC and must treat stderr as logs.

The desktop host generates a new `session-id` for each MCP process. After its
own permission check and user confirmation, it sends the exact tool name and
arguments to the trusted authorizer:

```json
{
  "session_id": "DESKTOP_GENERATED_SESSION_ID",
  "tool": "sql_update",
  "arguments": {
    "connection_id": "0190f1d8-871f-7c62-82a8-2c112f2c9147",
    "request_id": "write-1",
    "request": {
      "target": "public.users",
      "filter": {"op":"eq","field":"id","value":{"type":"int64","value":7}},
      "changes": {"name":{"type":"string","value":"Ada"}},
      "max_affected": 1,
      "idempotency_key": null
    }
  }
}
```

```bash
sql-connector --data-dir /private/agent-data authorize < confirmed-write.json
```

The command reloads the saved connection policy, rejects denied or malformed
operations, and returns a grant under `_meta.com.sql-connector/authorization`.
The host adds that `_meta` object to the MCP `tools/call` parameters while
leaving `arguments` unchanged. The grant defaults to 30 seconds and is valid
once. `lifetime_seconds` and `subject` may be supplied. The current connection
`policy_version` is loaded automatically. `authorization-key` prints the local
public key for diagnostics or external MCP configuration without exposing the
private key.

## Product routing

`product` and `api_mode` jointly select an adapter. Protocol-compatible
products remain distinct products for auditing and compatibility warnings. Use
the exact values emitted by `manifests`; do not infer a mode from the endpoint
scheme.

Each manifest also includes `connection_input` for the desktop connection
form. It provides accepted endpoint schemes, the default port, whether
`database` is required, canonical secret-field alternatives for every
advertised authentication kind, TLS support, and typed profile options with
required flags, defaults, and allowed values. The host can therefore build
connector-specific inputs without embedding a second product table. The normal
`test-connection`, `add-connection`, and `update-connection` flows apply the
same hints before opening a network connection. Secrets still belong in the
draft `credentials` object sent over stdin; they must never be added to the
endpoint URL.

The `resource_target` object describes the target accepted by CRUD tools. Its
`formats` are ordered templates; a format is available when its optional
`prerequisite` field is configured. Catalog entities whose `kind` appears in
`discovery_entity_kinds` expose an `id` that can be passed directly as the
target. InfluxDB writes use exactly the configured database for v1/v3 or the
configured `options.bucket` for v2. Prometheus writes always use
`remote_write` as the target.

The `mcp_tools` array pairs each advertised capability with the exact MCP tool
name that invokes it. A route with `fixed_policy_target` identifies the resource
rule target used by an operation that has no target in its request schema. The
Agent should use this routing data instead of maintaining product-to-tool or
special policy-target tables.

| Product value | API mode | Initial adapter |
| --- | --- | --- |
| `postgresql` | `postgresql` | PostgreSQL wire |
| `mysql` | `mysql` | MySQL wire |
| `oracle` | `tns` | Pure Rust Oracle TNS protocol |
| `sql_server` | `tds` | SQL Server TDS |
| `mongodb` | `mongodb` | MongoDB wire |
| `couchbase` | `couchbase` | Official Couchbase Rust SDK with KV CRUD and SQL++ reads |
| `cassandra` | `cql` | CQL v4 |
| `hbase` | `thrift2` | Apache Thrift2 TCP with row CRUD and table discovery |
| `influxdb` | `v1` | InfluxQL HTTP API |
| `influxdb` | `v2` | Flux HTTP API |
| `influxdb` | `v3` | SQL HTTP API |
| `prometheus` | `prometheus` | PromQL and Remote Write |
| `elasticsearch` | `elasticsearch_rest` | Elasticsearch REST |
| `opensearch` | `opensearch_rest` | OpenSearch REST |
| `splunk` | `splunk_rest_hec` | Search REST and HEC |
| `pinecone` | `pinecone_2025_10` | Pinecone database HTTP API |
| `milvus` | `milvus_rest_v2` | Milvus REST v2 |
| `qdrant` | `qdrant_rest_v1` | Qdrant REST v1 |
| `weaviate` | `weaviate_rest_v1` | Weaviate REST/GraphQL v1 |
| `cockroachdb` | `postgresql` | PostgreSQL-compatible wire |
| `tidb` | `mysql` | MySQL-compatible wire |
| `yugabytedb` | `ycql` | Cassandra-compatible YCQL |
| `yugabytedb` | `ysql` | PostgreSQL-compatible YSQL |
| `oceanbase` | `oceanbase_mysql` | OceanBase MySQL mode |

InfluxDB v2 profiles require string options named `org` and `bucket`. Other
product-specific limitations are returned by `manifests`; the desktop UI
should use the manifest to filter authentication choices and must not offer an
authentication kind from a different mode.

Couchbase username/password profiles use a `couchbase://` endpoint when TLS is
disabled and `couchbases://` when TLS is enabled. The optional `database`
field is the default bucket. Connection-string profiles put the complete seed
string in `secret.fields.connection_string` and also provide static
`username` and `password` fields. Structured targets use
`bucket.scope.collection`; with a default bucket they may use
`scope.collection` or a collection name in the default scope. KV inserts use
the synthetic `$document_id` field returned by discovery, and this field is
not stored inside the JSON document.

HBase Thrift2 profiles use an anonymous `thrift://host:9090` endpoint with TLS
disabled. `database` is the optional default HBase namespace. The string
options `transport` (`buffered` or `framed`) and `protocol` (`binary` or
`compact`) select server-compatible Thrift modes; their defaults are
`buffered` and `binary`. The boolean `include_system_tables` option controls
catalog discovery. Rows expose `$row_key`, while cells use
`family:qualifier` field names and base64 `binary` values.
