use std::sync::Arc;

use connector_mcp::DatabaseMcpServer;
use connector_runtime::{ConnectorRegistry, Runtime};
use connector_store::{AuditRepository, InMemoryCredentialStore, ProfileRepository};
use rmcp::{ServiceExt, model::CallToolRequestParams};

fn runtime() -> Arc<Runtime> {
    Arc::new(Runtime::new(
        Arc::new(ProfileRepository::open_in_memory().unwrap()),
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(AuditRepository::open_in_memory().unwrap()),
        Arc::new(ConnectorRegistry::new()),
        None,
    ))
}

#[tokio::test]
async fn stdio_protocol_advertises_typed_tools_without_secret_arguments() {
    let (server_transport, client_transport) = tokio::io::duplex(256 * 1024);
    let server_task = tokio::spawn(async move {
        DatabaseMcpServer::with_identity(runtime(), "desktop-user", "test-session")
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = ().serve(client_transport).await.unwrap();

    let listed = client.list_tools(Option::default()).await.unwrap();
    let names: Vec<_> = listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert!(names.contains(&"db_list_connections"));
    assert!(names.contains(&"db_list_connectors"));
    assert!(names.contains(&"db_cancel"));
    assert!(names.contains(&"sql_read"));
    assert!(names.contains(&"sql_query"));
    assert!(names.contains(&"vector_search"));

    let sql_read = listed
        .tools
        .iter()
        .find(|tool| tool.name == "sql_read")
        .unwrap();
    let schema = serde_json::to_string(&sql_read.input_schema).unwrap();
    assert!(schema.contains("target"));
    assert!(schema.contains("filter"));

    let sql_query = listed
        .tools
        .iter()
        .find(|tool| tool.name == "sql_query")
        .unwrap();
    let schema = serde_json::to_string(&sql_query.input_schema).unwrap();
    assert!(schema.contains("statement"));
    assert!(!schema.contains("max_affected"));

    let all_schemas = serde_json::to_string(&listed.tools).unwrap();
    assert!(!all_schemas.contains("\"password\""));
    assert!(!all_schemas.contains("\"secret\""));

    let result = client
        .call_tool(CallToolRequestParams::new("db_list_connections"))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(false));
    assert_eq!(result.structured_content, Some(serde_json::json!([])));

    client.cancel().await.unwrap();
    server_task.await.unwrap();
}
