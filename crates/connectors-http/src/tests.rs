use std::{
    collections::{BTreeMap, BTreeSet},
    future::pending,
    time::{Duration, Instant},
};

use connector_core::{
    AuthKind, Capability, CatalogEntity, CatalogQuery, ConnectionId, ConnectionPolicy,
    ConnectionProfile, Connector, ConnectorContext, ConnectorError, ConnectorStatus, DataOperation,
    DbValue, ErrorCategory, Filter, InsertRequest, NativeRequest, Product, QueryOptions,
    ReadRequest, SearchRequest, SecretMaterial, SortDirection, SortField, TlsConfig, VectorPoint,
    VectorSearchRequest, VectorUpsertRequest,
};
use reqwest::Url;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, body_string_contains, header, method, path, query_param},
};

use crate::{
    ElasticsearchConnector, MilvusRestConnector, OpenSearchConnector, PineconeConnector,
    QdrantRestConnector, SplunkConnector, WeaviateConnector,
    common::{HttpRuntime, catalog_fetch_inputs, catalog_page, send_json},
};

fn profile(
    endpoint: &str,
    product: Product,
    api_mode: &str,
    auth_kind: AuthKind,
) -> ConnectionProfile {
    ConnectionProfile {
        id: ConnectionId::new(),
        display_name: "test".to_owned(),
        product,
        api_mode: api_mode.to_owned(),
        endpoint: Url::parse(endpoint).expect("mock URL is valid"),
        database: None,
        tags: Vec::new(),
        auth_kind,
        secret_ref: "test-secret".to_owned(),
        tls: TlsConfig {
            enabled: false,
            verify_server_certificate: true,
            ca_certificate_ref: None,
            client_certificate_ref: None,
            server_name: None,
        },
        policy: ConnectionPolicy {
            max_rows: 100,
            max_bytes: 2 * 1024 * 1024,
            timeout_ms: 5_000,
            max_affected: 100,
            ..ConnectionPolicy::default()
        },
        policy_version: 1,
        expected_version: None,
        options: BTreeMap::new(),
    }
}

fn context(request_id: &str) -> ConnectorContext {
    ConnectorContext {
        request_id: request_id.to_owned(),
        session_id: "test-session".to_owned(),
        deadline: Instant::now() + Duration::from_secs(5),
        max_rows: 100,
        max_bytes: 2 * 1024 * 1024,
    }
}

fn secret(kind: AuthKind, fields: &[(&str, &str)]) -> SecretMaterial {
    SecretMaterial {
        kind,
        fields: fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn native_request(language: &str, statement: &Value) -> NativeRequest {
    NativeRequest {
        language: language.to_owned(),
        statement: statement.to_string(),
        parameters: BTreeMap::new(),
        positional_parameters: Vec::new(),
        max_affected: None,
        idempotency_key: None,
    }
}

#[test]
fn catalog_page_requires_an_extra_entity_for_a_next_cursor() {
    let mut context = context("catalog-page");
    context.max_rows = 1;
    let mut profile = profile(
        "http://localhost/",
        Product::Qdrant,
        "qdrant_rest_v1",
        AuthKind::Anonymous,
    );
    profile.policy.max_rows = 1;
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
fn manifests_are_experimental_and_do_not_claim_native_writes() {
    let connectors: Vec<Box<dyn Connector>> = vec![
        Box::new(ElasticsearchConnector::default()),
        Box::new(OpenSearchConnector::default()),
        Box::new(SplunkConnector::default()),
        Box::new(PineconeConnector::default()),
        Box::new(MilvusRestConnector::default()),
        Box::new(QdrantRestConnector::default()),
        Box::new(WeaviateConnector::default()),
    ];
    let mut ids = BTreeSet::new();
    for connector in connectors {
        let manifest = connector.manifest();
        assert_eq!(manifest.status, ConnectorStatus::Experimental);
        assert!(manifest.capabilities.contains(&Capability::TestConnection));
        assert!(!manifest.capabilities.contains(&Capability::NativeExecute));
        assert!(ids.insert(manifest.id));
        if manifest.product == Product::OpenSearch {
            assert!(!manifest.auth_kinds.contains(&AuthKind::ApiKey));
        }
    }
}

#[tokio::test]
async fn elastic_read_maps_dsl_auth_hits_and_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/books/_search"))
        .and(header("authorization", "Basic YWxpY2U6c2VjcmV0"))
        .and(body_json(json!({
            "query": {"term": {"status": "open"}},
            "size": 3,
            "sort": [{"created": "asc"}]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"hits": [
                {
                    "_id": "book-1",
                    "_index": "books",
                    "_source": {"title": "Rust"},
                    "sort": [7]
                },
                {
                    "_id": "book-2",
                    "_index": "books",
                    "_source": {"title": "Databases"},
                    "sort": [8]
                },
                {
                    "_id": "book-3",
                    "_index": "books",
                    "_source": {"title": "Search"},
                    "sort": [9]
                }
            ]}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let connector = ElasticsearchConnector::default();
    let result = connector
        .execute(
            &context("elastic-read"),
            &profile(
                &server.uri(),
                Product::Elasticsearch,
                "elasticsearch_rest",
                AuthKind::UsernamePassword,
            ),
            &secret(
                AuthKind::UsernamePassword,
                &[("username", "alice"), ("password", "secret")],
            ),
            DataOperation::Read(ReadRequest {
                target: "books".to_owned(),
                fields: Vec::new(),
                filter: Some(Filter::Eq {
                    field: "status".to_owned(),
                    value: DbValue::String("open".to_owned()),
                }),
                options: QueryOptions {
                    limit: 2,
                    cursor: None,
                    sort: vec![SortField {
                        field: "created".to_owned(),
                        direction: SortDirection::Asc,
                    }],
                    timeout_ms: None,
                },
            }),
        )
        .await
        .expect("Elasticsearch read succeeds");

    assert_eq!(
        result.records[0].get("title"),
        Some(&DbValue::String("Rust".to_owned()))
    );
    assert_eq!(
        result.records[0].get("_id"),
        Some(&DbValue::String("book-1".to_owned()))
    );
    assert_eq!(result.records.len(), 2);
    assert!(!result.records[0].contains_key("sort"));
    assert!(result.truncated);
    assert!(result.next_cursor.is_some());
}

#[tokio::test]
async fn opensearch_accepts_anonymous_and_verifies_product_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "node-1",
            "version": {"number": "3.2.0", "distribution": "opensearch"},
            "tagline": "The OpenSearch Project: https://opensearch.org/"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let info = OpenSearchConnector::default()
        .test_connection(
            &context("opensearch-test"),
            &profile(
                &server.uri(),
                Product::OpenSearch,
                "opensearch_rest",
                AuthKind::Anonymous,
            ),
            &secret(AuthKind::Anonymous, &[]),
        )
        .await
        .expect("anonymous OpenSearch connection succeeds");
    assert_eq!(info.product_version.as_deref(), Some("3.2.0"));
}

#[tokio::test]
async fn splunk_hec_uses_splunk_auth_and_native_query_blocks_delete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("authorization", "Splunk hec-secret"))
        .and(body_string_contains("\"index\":\"main\""))
        .and(body_string_contains("\"message\":\"hello\""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"text": "Success", "code": 0})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let connector = SplunkConnector::default();
    let mut splunk_profile = profile(
        &server.uri(),
        Product::Splunk,
        "splunk_rest_hec",
        AuthKind::BearerToken,
    );
    splunk_profile
        .options
        .insert("hec_endpoint".to_owned(), Value::String(server.uri()));
    let splunk_secret = secret(AuthKind::BearerToken, &[("bearer_token", "hec-secret")]);
    let inserted = connector
        .execute(
            &context("splunk-insert"),
            &splunk_profile,
            &splunk_secret,
            DataOperation::Insert(InsertRequest {
                target: "main".to_owned(),
                records: vec![BTreeMap::from([(
                    "message".to_owned(),
                    DbValue::String("hello".to_owned()),
                )])],
                idempotency_key: None,
            }),
        )
        .await
        .expect("HEC insert succeeds");
    assert_eq!(inserted.metrics.affected, 1);

    let rejected = connector
        .execute(
            &context("splunk-native-delete"),
            &splunk_profile,
            &splunk_secret,
            DataOperation::NativeQuery(NativeRequest {
                language: "spl".to_owned(),
                statement: "search index=main | delete".to_owned(),
                parameters: BTreeMap::new(),
                positional_parameters: Vec::new(),
                max_affected: None,
                idempotency_key: None,
            }),
        )
        .await
        .expect_err("mutating SPL is rejected");
    assert_eq!(rejected.category, ErrorCategory::PermissionDenied);
}

#[tokio::test]
async fn splunk_catalog_filter_advances_by_scanned_entries() {
    let server = MockServer::start().await;
    for (offset, entries) in [
        ("0", json!([{"name": "main"}, {"name": "history"}])),
        ("2", json!([{"name": "audit-one"}, {"name": "audit-two"}])),
        ("3", json!([{"name": "audit-two"}])),
    ] {
        Mock::given(method("GET"))
            .and(path("/services/data/indexes"))
            .and(query_param("count", "100"))
            .and(query_param("offset", offset))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "entry": entries,
                "paging": {"total": 4}
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let connector = SplunkConnector::default();
    let splunk_profile = profile(
        &server.uri(),
        Product::Splunk,
        "splunk_rest_hec",
        AuthKind::ApiKey,
    );
    let splunk_secret = secret(
        AuthKind::ApiKey,
        &[("management_token", "management-secret")],
    );
    let first = connector
        .search_catalog_page(
            &context("splunk-catalog-1"),
            &splunk_profile,
            &splunk_secret,
            CatalogQuery {
                pattern: Some("audit".to_owned()),
                namespace: Some("index".to_owned()),
                limit: 1,
                cursor: None,
            },
        )
        .await
        .expect("filtered Splunk catalog page succeeds");
    assert_eq!(first.entities[0].name, "audit-one");
    assert_eq!(first.next_cursor.as_deref(), Some("3"));

    let second = connector
        .search_catalog_page(
            &context("splunk-catalog-2"),
            &splunk_profile,
            &splunk_secret,
            CatalogQuery {
                pattern: Some("audit".to_owned()),
                namespace: Some("index".to_owned()),
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .await
        .expect("second filtered Splunk catalog page succeeds");
    assert_eq!(second.entities[0].name, "audit-two");
    assert!(second.next_cursor.is_none());
}

#[tokio::test]
async fn pinecone_2025_10_maps_data_plane_query_and_blocks_control_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/query"))
        .and(header("api-key", "pinecone-secret"))
        .and(header("x-pinecone-api-version", "2025-10"))
        .and(body_json(json!({
            "vector": [0.25, 0.75],
            "topK": 3,
            "namespace": "tenant-a",
            "includeValues": false,
            "includeMetadata": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [{"id": "doc-1", "score": 0.9, "metadata": {"title": "A"}}],
            "namespace": "tenant-a"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/query"))
        .and(body_json(json!({
            "vector": [0.5, 0.5],
            "topK": 2,
            "namespace": "tenant-a"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [{"id": "doc-2", "score": 0.8}],
            "namespace": "tenant-a"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/indexes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "indexes": [
                {"name": "docs", "status": {"state": "Ready"}},
                {"name": "images", "status": {"state": "Ready"}}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = PineconeConnector::default();
    let mut pinecone_profile = profile(
        &server.uri(),
        Product::Pinecone,
        "pinecone_2025_10",
        AuthKind::ApiKey,
    );
    pinecone_profile
        .options
        .insert("index_host".to_owned(), Value::String(server.uri()));
    pinecone_profile
        .options
        .insert("namespace".to_owned(), Value::String("tenant-a".to_owned()));
    pinecone_profile.database = Some("docs".to_owned());
    let pinecone_secret = secret(AuthKind::ApiKey, &[("api_key", "pinecone-secret")]);

    let result = connector
        .execute(
            &context("pinecone-query"),
            &pinecone_profile,
            &pinecone_secret,
            DataOperation::VectorSearch(VectorSearchRequest {
                target: "docs".to_owned(),
                vector: vec![0.25, 0.75],
                top_k: 3,
                filter: None,
                namespace: None,
                include_vectors: false,
            }),
        )
        .await
        .expect("Pinecone query succeeds");
    assert_eq!(
        result.records[0].get("id"),
        Some(&DbValue::String("doc-1".to_owned()))
    );

    let generic = connector
        .execute(
            &context("pinecone-generic-query"),
            &pinecone_profile,
            &pinecone_secret,
            DataOperation::Search(SearchRequest {
                target: "docs".to_owned(),
                query: json!({"vector": [0.5, 0.5]}),
                options: QueryOptions {
                    limit: 2,
                    ..QueryOptions::default()
                },
            }),
        )
        .await
        .expect("generic Pinecone query uses the configured namespace");
    assert_eq!(
        generic.records[0].get("id"),
        Some(&DbValue::String("doc-2".to_owned()))
    );

    let catalog = connector
        .search_catalog_page(
            &context("pinecone-catalog"),
            &pinecone_profile,
            &pinecone_secret,
            CatalogQuery {
                pattern: None,
                namespace: Some("index".to_owned()),
                limit: 2,
                cursor: None,
            },
        )
        .await
        .expect("Pinecone catalog succeeds");
    assert_eq!(catalog.entities.len(), 2);
    assert!(catalog.next_cursor.is_none());

    let rejected = connector
        .execute(
            &context("pinecone-control-post"),
            &pinecone_profile,
            &pinecone_secret,
            DataOperation::NativeQuery(native_request(
                "pinecone_http",
                &json!({"method": "POST", "path": "/indexes", "body": {}}),
            )),
        )
        .await
        .expect_err("native control-plane POST is rejected");
    assert_eq!(rejected.category, ErrorCategory::PermissionDenied);
}

#[tokio::test]
async fn milvus_catalog_and_describe_use_rest_v2_contract() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/vectordb/collections/list"))
        .and(query_param("dbName", "default"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "data": ["docs"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/vectordb/collections/describe"))
        .and(body_json(
            json!({"dbName": "default", "collectionName": "docs"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "data": {
                "collectionName": "docs",
                "fields": [{"name": "id", "dataType": "Int64", "isPrimary": true}],
                "partitionsNum": 2,
                "shardsNum": 1
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = MilvusRestConnector::default();
    let mut milvus_profile = profile(
        &server.uri(),
        Product::Milvus,
        "milvus_rest_v2",
        AuthKind::Anonymous,
    );
    milvus_profile.database = Some("default".to_owned());
    let catalog = connector
        .search_catalog_page(
            &context("milvus-catalog"),
            &milvus_profile,
            &secret(AuthKind::Anonymous, &[]),
            CatalogQuery {
                pattern: None,
                namespace: Some("collection".to_owned()),
                limit: 10,
                cursor: None,
            },
        )
        .await
        .expect("Milvus catalog succeeds");
    assert_eq!(catalog.entities[0].id, "docs");
    let description = connector
        .describe_entity(
            &context("milvus-describe"),
            &milvus_profile,
            &secret(AuthKind::Anonymous, &[]),
            "docs",
        )
        .await
        .expect("Milvus describe succeeds");
    assert_eq!(description.fields.len(), 1);
    assert_eq!(
        description.metadata.get("partitionsNum"),
        Some(&DbValue::Int64(2))
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    assert!(requests[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn qdrant_upsert_maps_ids_payload_and_api_key() {
    let server = MockServer::start().await;
    let point_id = "4b39d9be-679a-4c00-8db7-06ad46fe9a3a";
    Mock::given(method("PUT"))
        .and(path("/collections/docs/points"))
        .and(query_param("wait", "true"))
        .and(header("api-key", "qdrant-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {"operation_id": 7, "status": "completed"},
            "status": "ok",
            "time": 0.001
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = QdrantRestConnector::default();
    let qdrant_profile = profile(
        &server.uri(),
        Product::Qdrant,
        "qdrant_rest_v1",
        AuthKind::ApiKey,
    );
    let qdrant_secret = secret(AuthKind::ApiKey, &[("api_key", "qdrant-secret")]);
    let result = connector
        .execute(
            &context("qdrant-upsert"),
            &qdrant_profile,
            &qdrant_secret,
            DataOperation::VectorUpsert(VectorUpsertRequest {
                target: "docs".to_owned(),
                points: vec![VectorPoint {
                    id: point_id.to_owned(),
                    vector: vec![0.1, 0.2],
                    metadata: BTreeMap::from([(
                        "title".to_owned(),
                        DbValue::String("Rust".to_owned()),
                    )]),
                }],
                namespace: None,
                idempotency_key: None,
            }),
        )
        .await
        .expect("Qdrant upsert succeeds");
    assert_eq!(result.metrics.affected, 1);
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("Qdrant body is JSON");
    assert_eq!(
        body.pointer("/points/0/id"),
        Some(&Value::String(point_id.to_owned()))
    );
    assert_eq!(
        body.pointer("/points/0/payload/title"),
        Some(&json!("Rust"))
    );
    let first_vector_value = body
        .pointer("/points/0/vector/0")
        .and_then(Value::as_f64)
        .expect("first vector value is numeric");
    assert!((first_vector_value - 0.1).abs() < 1e-6);

    let rejected = connector
        .execute(
            &context("qdrant-native-batch"),
            &qdrant_profile,
            &qdrant_secret,
            DataOperation::NativeQuery(native_request(
                "qdrant_http",
                &json!({
                    "method": "POST",
                    "path": "/collections/docs/points/batch",
                    "body": {"operations": []}
                }),
            )),
        )
        .await
        .expect_err("native Qdrant batch updates are rejected");
    assert_eq!(rejected.category, ErrorCategory::PermissionDenied);
}

#[tokio::test]
async fn weaviate_search_is_target_scoped_and_native_mutation_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/schema/Article"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "class": "Article",
            "properties": [{"name": "title", "dataType": ["text"]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/graphql"))
        .and(body_string_contains("Get { Article"))
        .and(body_string_contains("nearText"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"Get": {"Article": [{
                "title": "Rust",
                "_additional": {"id": "4b39d9be-679a-4c00-8db7-06ad46fe9a3a"}
            }]}}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = WeaviateConnector::default();
    let weaviate_profile = profile(
        &server.uri(),
        Product::Weaviate,
        "weaviate_rest_v1",
        AuthKind::Anonymous,
    );
    let anonymous = secret(AuthKind::Anonymous, &[]);
    let result = connector
        .execute(
            &context("weaviate-search"),
            &weaviate_profile,
            &anonymous,
            DataOperation::Search(SearchRequest {
                target: "Article".to_owned(),
                query: json!({"nearText": {"concepts": ["rust"]}}),
                options: QueryOptions {
                    limit: 2,
                    cursor: None,
                    sort: Vec::new(),
                    timeout_ms: None,
                },
            }),
        )
        .await
        .expect("structured Weaviate search succeeds");
    assert_eq!(
        result.records[0].get("title"),
        Some(&DbValue::String("Rust".to_owned()))
    );

    let rejected = connector
        .execute(
            &context("weaviate-mutation"),
            &weaviate_profile,
            &anonymous,
            DataOperation::NativeQuery(NativeRequest {
                language: "weaviate_graphql".to_owned(),
                statement: "mutation { Delete { Article(id: \"x\") } }".to_owned(),
                parameters: BTreeMap::new(),
                positional_parameters: Vec::new(),
                max_affected: None,
                idempotency_key: None,
            }),
        )
        .await
        .expect_err("GraphQL mutation is rejected");
    assert_eq!(rejected.category, ErrorCategory::PermissionDenied);
}

#[tokio::test]
async fn response_body_limit_rejects_oversized_payloads() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024 * 1024 + 1]))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("test HTTP client builds");
    let error = send_json(client.get(server.uri()), 1)
        .await
        .expect_err("oversized HTTP response is rejected");
    assert_eq!(error.category, ErrorCategory::Protocol);
}

#[tokio::test]
async fn cancellation_classifies_reads_and_writes_differently() {
    let runtime = HttpRuntime::default();
    let read_runtime = runtime.clone();
    let read_context = context("cancel-read");
    let read = tokio::spawn(async move {
        read_runtime
            .run(
                &read_context,
                false,
                pending::<connector_core::Result<()>>(),
            )
            .await
    });
    tokio::task::yield_now().await;
    runtime.cancel("cancel-read");
    assert_eq!(
        read.await
            .expect("read task joins")
            .expect_err("read is cancelled")
            .category,
        ErrorCategory::Cancelled
    );

    let write_runtime = runtime.clone();
    let write_context = context("cancel-write");
    let write = tokio::spawn(async move {
        write_runtime
            .run(
                &write_context,
                true,
                pending::<connector_core::Result<()>>(),
            )
            .await
    });
    tokio::task::yield_now().await;
    runtime.cancel("cancel-write");
    assert_eq!(
        write
            .await
            .expect("write task joins")
            .expect_err("write result is unknown")
            .category,
        ErrorCategory::UnknownOutcome
    );
}

#[tokio::test]
async fn transport_timeout_does_not_mark_a_write_as_retryable() {
    let error = HttpRuntime::default()
        .run(&context("write-timeout"), true, async {
            Err::<(), _>(
                ConnectorError::new(ErrorCategory::Timeout, "HTTP write timed out").retryable(true),
            )
        })
        .await
        .expect_err("a timed-out write has an unknown outcome");

    assert_eq!(error.category, ErrorCategory::UnknownOutcome);
    assert!(!error.retryable);
}
