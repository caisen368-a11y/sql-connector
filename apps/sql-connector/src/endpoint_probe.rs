use std::{
    collections::BTreeMap,
    io::{self, Read},
};

use anyhow::{Context, Result, bail};
use connector_control::ConnectionDraft;
use connector_core::{AuthKind, ConnectionPolicy, Product, TlsConfig};
use serde::Deserialize;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
struct EndpointProbeInput {
    display_name: String,
    endpoint: Url,
    pub database: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    auth_kind: AuthKind,
    #[serde(default, alias = "secret_fields")]
    credentials: Option<BTreeMap<String, String>>,
    #[serde(default)]
    tls: Option<TlsConfig>,
    #[serde(default)]
    tls_enabled: Option<bool>,
    #[serde(default)]
    policy: Option<ConnectionPolicy>,
    expected_version: Option<String>,
    #[serde(default)]
    options: BTreeMap<String, serde_json::Value>,
}

impl Drop for EndpointProbeInput {
    fn drop(&mut self) {
        if let Some(credentials) = std::mem::take(&mut self.credentials) {
            for (mut name, mut value) in credentials {
                name.zeroize();
                value.zeroize();
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct EndpointCandidate {
    pub(crate) product: Product,
    pub(crate) api_mode: &'static str,
}

const CANDIDATES: [EndpointCandidate; 24] = [
    EndpointCandidate {
        product: Product::PostgreSql,
        api_mode: "postgresql",
    },
    EndpointCandidate {
        product: Product::CockroachDb,
        api_mode: "postgresql",
    },
    EndpointCandidate {
        product: Product::YugabyteDb,
        api_mode: "ysql",
    },
    EndpointCandidate {
        product: Product::MySql,
        api_mode: "mysql",
    },
    EndpointCandidate {
        product: Product::TiDb,
        api_mode: "mysql",
    },
    EndpointCandidate {
        product: Product::OceanBase,
        api_mode: "oceanbase_mysql",
    },
    EndpointCandidate {
        product: Product::Oracle,
        api_mode: "tns",
    },
    EndpointCandidate {
        product: Product::SqlServer,
        api_mode: "tds",
    },
    EndpointCandidate {
        product: Product::MongoDb,
        api_mode: "mongodb",
    },
    EndpointCandidate {
        product: Product::Cassandra,
        api_mode: "cql",
    },
    EndpointCandidate {
        product: Product::YugabyteDb,
        api_mode: "ycql",
    },
    EndpointCandidate {
        product: Product::HBase,
        api_mode: "thrift2",
    },
    EndpointCandidate {
        product: Product::Elasticsearch,
        api_mode: "elasticsearch_rest",
    },
    EndpointCandidate {
        product: Product::OpenSearch,
        api_mode: "opensearch_rest",
    },
    EndpointCandidate {
        product: Product::Qdrant,
        api_mode: "qdrant_rest_v1",
    },
    EndpointCandidate {
        product: Product::Weaviate,
        api_mode: "weaviate_rest_v1",
    },
    EndpointCandidate {
        product: Product::Prometheus,
        api_mode: "prometheus",
    },
    EndpointCandidate {
        product: Product::Milvus,
        api_mode: "milvus_rest_v2",
    },
    EndpointCandidate {
        product: Product::Splunk,
        api_mode: "splunk_rest_hec",
    },
    EndpointCandidate {
        product: Product::Pinecone,
        api_mode: "pinecone_2025_10",
    },
    EndpointCandidate {
        product: Product::InfluxDb,
        api_mode: "v2",
    },
    EndpointCandidate {
        product: Product::InfluxDb,
        api_mode: "v1",
    },
    EndpointCandidate {
        product: Product::InfluxDb,
        api_mode: "v3",
    },
    EndpointCandidate {
        product: Product::Couchbase,
        api_mode: "couchbase",
    },
];

pub(crate) struct EndpointProbe {
    input: EndpointProbeInput,
}

impl EndpointProbe {
    pub(crate) fn candidates(&self) -> &'static [EndpointCandidate] {
        &CANDIDATES
    }

    pub(crate) fn connection_draft(&self, candidate: EndpointCandidate) -> ConnectionDraft {
        ConnectionDraft {
            display_name: self.input.display_name.clone(),
            product: candidate.product,
            api_mode: candidate.api_mode.into(),
            endpoint: self.input.endpoint.clone(),
            database: self.input.database.clone(),
            tags: self.input.tags.clone(),
            auth_kind: self.input.auth_kind,
            credentials: self.input.credentials.clone(),
            tls: self.input.tls.clone(),
            tls_enabled: self.input.tls_enabled,
            policy: self.input.policy.clone(),
            expected_version: self.input.expected_version.clone(),
            options: self.input.options.clone(),
        }
    }

    pub(crate) fn probe_draft(&self, candidate: EndpointCandidate) -> ConnectionDraft {
        let mut draft = self.connection_draft(candidate);
        draft.expected_version = None;
        if candidate.product == Product::InfluxDb {
            match candidate.api_mode {
                "v1" | "v3" => {
                    draft.database.get_or_insert_with(|| "__probe__".into());
                }
                "v2" => {
                    draft
                        .options
                        .entry("org".into())
                        .or_insert_with(|| serde_json::Value::String("__probe__".into()));
                    draft
                        .options
                        .entry("bucket".into())
                        .or_insert_with(|| serde_json::Value::String("__probe__".into()));
                }
                _ => {}
            }
        }
        draft
    }
}

pub(crate) fn read_endpoint_probe() -> Result<EndpointProbe> {
    let mut json = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut json)
        .context("failed to read endpoint probe from stdin")?;
    if json.trim().is_empty() {
        bail!("endpoint probe stdin must contain one JSON object");
    }
    let input: EndpointProbeInput =
        serde_json::from_str(&json).context("endpoint probe is not valid JSON")?;
    if input.endpoint.scheme() == "tcp" {
        bail!("generic tcp:// endpoints are ambiguous; use a product-specific endpoint scheme");
    }
    Ok(EndpointProbe { input })
}
