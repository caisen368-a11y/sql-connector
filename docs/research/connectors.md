# Connector Dependency Research

Research was performed before adapter implementation. The main selection rule
was protocol correctness and active upstream maintenance. License was recorded
but, per product requirements, did not block a technically suitable driver.
Links below are the upstream sources used as protocol or implementation
references; versions actually compiled are pinned in `Cargo.lock`.

| Product family | Upstream evaluated | Decision |
| --- | --- | --- |
| PostgreSQL / CockroachDB / YugabyteDB YSQL | [rust-postgres](https://github.com/sfackler/rust-postgres) | Use `tokio-postgres`; keep separate product manifests over the shared protocol implementation. |
| MySQL / TiDB / OceanBase MySQL mode | [mysql_async](https://github.com/blackbeam/mysql_async) | Use the async native protocol driver; apply product-specific manifests and compatibility warnings. |
| SQL Server | [Tiberius](https://github.com/prisma/tiberius) | Use the Rust TDS implementation with parameter binding. |
| Oracle | [oracle-rs](https://github.com/stiang/oracle-rs), [rust-oracle](https://github.com/kubo/rust-oracle), [ODPI-C](https://github.com/oracle/odpi) | Use `oracle-rs` 0.1.7 for async pure Rust TNS connectivity without an installed Oracle Client; keep the mature OCI option as a researched fallback. |
| MongoDB | [MongoDB Rust driver](https://github.com/mongodb/mongo-rust-driver), [windows-acl](https://github.com/trailofbits/windows-acl) | Use the official driver for BSON fidelity and CRUD. Because its Rustls API accepts certificate paths only, stage PEM in owner-only temporary files; use mode bits on Unix and a protected current-user DACL on Windows. |
| Couchbase | [Couchbase Rust SDK](https://github.com/couchbaselabs/couchbase-rs) | Use the official `couchbase` 1.0.1 SDK for static RBAC authentication, bucket/scope/collection discovery, KV CRUD, and parameterized SQL++ reads. |
| Cassandra / YugabyteDB YCQL | [Scylla Rust driver](https://github.com/scylladb/scylla-rust-driver) | Use the maintained CQL driver for structured/native CQL operations; products remain separate modes. |
| HBase | [Apache HBase](https://github.com/apache/hbase) Thrift2 IDL, [Apache Thrift](https://github.com/apache/thrift) | Community `hbase-thrift` crates target incompatible Thrift1. Generate a minimal client from the HBase 2.6.3 Thrift2 contract and use the Apache `thrift` 0.24.0 runtime for discovery and row CRUD. |
| InfluxDB | [InfluxDB Rust client](https://github.com/influxdata/influxdb-client-rust), vendor HTTP API specifications | Implement HTTP adapters separately for v1 InfluxQL, v2 Flux, and v3 SQL because one community client does not cover all generations accurately. |
| Prometheus | [Prometheus](https://github.com/prometheus/prometheus), [prometheus/prometheus protobuf](https://github.com/prometheus/prometheus/tree/main/prompb) | Implement HTTP query APIs and the official Remote Write protobuf with Snappy compression. |
| Elasticsearch | [elasticsearch-rs](https://github.com/elastic/elasticsearch-rs) | Official client remains pre-1.0; use a narrow REST adapter and test exact payloads. |
| OpenSearch | [opensearch-rs](https://github.com/opensearch-project/opensearch-rs) | Keep separate from Elasticsearch despite API overlap; use product-specific REST behavior. |
| Splunk | [Splunk REST API examples](https://github.com/splunk/splunk-app-examples) | Use direct management/search and HEC REST endpoints rather than a weak community SDK. |
| Pinecone | [Pinecone API](https://github.com/pinecone-io/pinecone-python-client) and published OpenAPI definitions | Use the current HTTP API shape; do not depend on stale alpha Rust SDKs. |
| Milvus | [Milvus Rust SDK](https://github.com/milvus-io/milvus-sdk-rust), [Milvus](https://github.com/milvus-io/milvus) | The Rust SDK surface is incomplete; use documented REST v2 endpoints for the initial adapter. |
| Qdrant | [Qdrant Rust client](https://github.com/qdrant/rust-client) | Official client is mature; the first pack uses a bounded REST adapter to align cancellation, TLS, and response-limit behavior with other HTTP connectors. |
| Weaviate | [Weaviate](https://github.com/weaviate/weaviate) | No sufficiently complete official Rust client was found; use the product REST/GraphQL APIs directly. |

## Rejected shortcuts

- A shared "SQL-compatible" product identity was rejected because protocol
  compatibility does not imply identical metadata, types, errors, or version
  support.
- Elasticsearch and OpenSearch do not share a manifest or silently retry one
  product's endpoints against the other.
- OceanBase Oracle mode is not treated as OCI-compatible without evidence.
- HBase Thrift1 crates are not used for a Thrift2 server contract.
- Native statements are never constructed by concatenating model-provided
  values. Drivers preserve their own placeholder syntax and bind values.

## Verification evidence

Unit and mock-server tests validate request construction, serialization,
limits, cancellation bookkeeping, and error mapping without live credentials.
The repository intentionally keeps every network adapter `Experimental` until
the certification gates in the capability matrix are executed against real
services.
