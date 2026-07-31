//! Parameterized SQL connectors for `PostgreSQL`-, `MySQL`-, and TDS-compatible products.

mod cancellation;
mod common;
mod mysql;
mod oracle;
mod postgres;
mod relational_metadata;
mod sql_server;

pub use mysql::MySqlConnector;
pub use oracle::OracleConnector;
pub use postgres::PostgresConnector;
pub use sql_server::SqlServerConnector;

use std::sync::Arc;

use connector_core::Connector;

/// All relational product/mode adapters implemented by this crate.
pub fn connectors() -> Vec<Arc<dyn Connector>> {
    vec![
        Arc::new(PostgresConnector::postgresql()),
        Arc::new(PostgresConnector::cockroachdb()),
        Arc::new(PostgresConnector::yugabyte_ysql()),
        Arc::new(MySqlConnector::mysql()),
        Arc::new(MySqlConnector::tidb()),
        Arc::new(MySqlConnector::oceanbase_mysql()),
        Arc::new(SqlServerConnector::new()),
        Arc::new(OracleConnector::new()),
    ]
}
