use std::sync::Arc;

use connector_mcp::DatabaseMcpServer;
use connector_runtime::{ConnectorRegistry, Runtime};
use connector_store::{AuditRepository, InMemoryCredentialStore, ProfileRepository};

fn server() -> DatabaseMcpServer {
    let runtime = Runtime::new(
        Arc::new(ProfileRepository::open_in_memory().unwrap()),
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(AuditRepository::open_in_memory().unwrap()),
        Arc::new(ConnectorRegistry::new()),
        None,
    );
    DatabaseMcpServer::new(Arc::new(runtime))
}

#[test]
fn exposes_discovery_and_all_data_model_tool_families() {
    let tools = server().tool_definitions();
    let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    for expected in [
        "db_list_connections",
        "db_get_capabilities",
        "db_inspect_schema",
        "sql_read",
        "document_find",
        "kv_read",
        "kv_update",
        "timeseries_query",
        "search_query",
        "search_document_read",
        "search_document_update",
        "vector_search",
        "vector_insert",
    ] {
        assert!(names.contains(&expected), "missing MCP tool {expected}");
    }
    assert!(
        tools
            .iter()
            .all(|tool| tool.input_schema.contains_key("type"))
    );

    let inspect = tools
        .iter()
        .find(|tool| tool.name == "db_inspect_schema")
        .unwrap();
    assert_eq!(inspect.input_schema["properties"]["limit"]["default"], 10);
    assert_eq!(inspect.input_schema["properties"]["limit"]["maximum"], 20);
}

#[test]
fn destructive_annotations_are_present_but_not_used_as_policy() {
    let tools = server().tool_definitions();
    let delete = tools.iter().find(|tool| tool.name == "sql_delete").unwrap();
    let annotations = delete.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(true));
}
