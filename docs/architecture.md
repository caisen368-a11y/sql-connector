# Architecture

## Trust boundaries

```text
Desktop Agent / trusted UI
  |  control JSON over private stdin (profiles + secrets + policies)
  |  one-use Ed25519 grants for confirmed writes
  |  bounded audit queries for the local activity view
  v
sql-connector
  +-- SQLite: non-secret profiles and append-only audit records
  +-- credential store (selected by the trusted host)
  |    +-- default: macOS Keychain / Windows Credential Manager
  |    +-- optional: AES-256-GCM encrypted SQLite + separate key file
  +-- MCP 2025-11-25 stdio: connection_id and typed operations only
  +-- policy runtime: classify, authorize, limit, mask, timeout, audit
  +-- connector registry: worker-backed connector proxies
       +-- sql worker
       +-- document worker
       +-- timeseries worker
       +-- search/vector HTTP worker
              |
              v
        Database service and database-account permissions
```

The model-facing MCP boundary cannot create, update, or delete connection
profiles and cannot retrieve credentials. The desktop host is responsible for
authenticating its user, protecting its grant signing key, choosing whether
data may be sent to a cloud model, and displaying write confirmation UI.
The built-in local authorization mode keeps that key in the selected credential
store; the trusted `authorize` command accepts an already confirmed MCP call and
performs policy checking, canonical hashing, and signing outside MCP. Selecting
SQLite requires the host to pass the same key file to every MCP and trusted
control process. Key contents never cross MCP or command-line arguments.

## Authorization

Every operation must pass three independent layers:

1. The desktop Agent decides which MCP tools the current user may invoke and
   issues a confirmation grant when required.
2. The runtime evaluates the saved per-connection policy, resource rules,
   egress class, row/byte/time/affected-row limits, and optional grant.
3. The database server applies the privileges of the configured database
   account.

Profiles default to read-only: native reads and writes are disabled, no
resource is writable, and bounded limits are mandatory. Signed grants expire
within 120 seconds, are single-use, and bind the session, connection, MCP tool,
canonical argument hash, policy version, and limits. They do not override a
policy denial.

## Operation lifecycle

1. MCP parses typed JSON input and rejects credentials in its schemas.
2. Runtime resolves the profile and secret reference locally.
3. Policy classifies the structured operation before any network activity.
   Policy denials and failed confirmation grants are audited locally.
4. Runtime registers a caller request ID against its MCP session.
5. The adapter performs a bounded request with strict TLS verification.
6. Runtime enforces final row/byte limits and field masking, then records an
   audit event without arguments, query text, credentials, or returned data.
7. An active operation can be cancelled only from its owning MCP session.

For a write carrying `idempotency_key`, the runtime atomically binds the key to
the canonical operation hash in `audit.sqlite` before contacting the database.
Keys must contain 1 to 128 UTF-8 bytes without surrounding whitespace or
control characters.
Succeeded, unknown, and interrupted in-flight writes are never sent again; a
key bound to different content returns `conflict`, while a definite connector
failure releases the key. Database responses are not cached. Writes without a
key retain the normal behavior. A timed-out write returns `unknown_outcome`; the
runtime never claims a write failed when the server may have committed it.

## Worker protocol

Worker IPC uses a 32-bit length prefix and a protobuf envelope containing the
protocol version, request ID, message kind, and a JSON payload. Frames are
limited to 64 MiB. Worker executable paths must be absolute. The client has a
single response reader and routes out-of-order responses by request ID, so a
cancel call can run while another request is pending.

The MCP process starts four connector-pack workers from the same executable and
registers their manifests as connector proxies. Connector calls, cancellation,
and connection-cache invalidation cross the worker protocol. Trusted control
commands still use built-in adapters directly for short-lived validation and
connection tests.

Each pack has a supervisor. If its process or response stream fails, one new
worker generation is started. Read-only calls retry once on the replacement;
writes are never replayed and return `unknown_outcome` because the previous
worker may have lost its response after the database committed the operation.

## Deliberate v1 exclusions

There is no DDL, administration, backup, ETL, cross-database federation, SSH
tunnelling, Kerberos, OAuth browser flow, cloud-provider identity/default
credential chains, or SSO. Authentication is limited to anonymous,
username/password, connection string, static API/bearer token, client
certificate, and product-specific static tokens.
