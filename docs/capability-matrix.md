# Capability Matrix

The executable manifest is authoritative. Generate it with:

```bash
sql-connector manifests
```

Every connector starts as `Experimental`. `Unavailable` means the product is
represented for routing and configuration validation but this build does not
execute network operations for it. No adapter becomes `Verified` until CI runs
the declared operation set against real service versions on each supported
desktop platform.

| Family | Products / modes | Initial implementation |
| --- | --- | --- |
| PostgreSQL wire | PostgreSQL, CockroachDB, YugabyteDB YSQL | Parameterized SQL adapter |
| MySQL wire | MySQL, TiDB, OceanBase MySQL mode | Parameterized SQL adapter |
| TDS | SQL Server | Parameterized SQL adapter |
| Oracle TNS | Oracle Database 12c+ | Pure Rust parameterized SQL adapter |
| Document | MongoDB | Native document CRUD and discovery |
| Key-value/document services | Couchbase | Official SDK adapter with bucket/scope/collection discovery, KV CRUD, and SQL++ reads |
| CQL | Cassandra, YugabyteDB YCQL | Native CQL adapter |
| Wide column | HBase Thrift2 | Generated Apache Thrift2 adapter with table discovery and row CRUD |
| Time series | InfluxDB v1/v2/v3, Prometheus | HTTP query/write APIs; no administrative operations |
| Search/log | Elasticsearch, OpenSearch, Splunk | Product-specific REST APIs |
| Vector | Pinecone, Milvus REST, Qdrant REST, Weaviate | Product-specific REST APIs |

Capabilities are deliberately fine-grained. An unavailable connector
advertises no `Read`, `Insert`, `Update`, `Delete`, native, search, vector, or
time-series capabilities. Tools must call `db_get_capabilities` before routing
an operation and must surface the connector's limitations to the user.

## Certification gates

A connector can move from `Experimental` to `Verified` only after all of the
following are recorded:

- successful authentication tests for every advertised authentication kind;
- TLS verification and custom CA/client-certificate tests where advertised;
- discovery, value conversion, pagination, limits, cancellation, and error
  classification tests;
- read/write tests for every advertised capability, including unknown-outcome
  handling around timeouts;
- supported server-version matrix tests on macOS and Windows;
- confirmation that logs, MCP output, audit rows, and errors contain no secret
  material.

Cloud credentials and paid service instances are not present in this source
workspace, so no manifest in the initial build claims that certification.
