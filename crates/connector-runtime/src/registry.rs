use std::{collections::HashMap, sync::Arc};

use connector_core::{ConnectionId, Connector, ConnectorManifest, Product, canonical_api_mode};

use crate::{Result, RuntimeError};

#[derive(Default)]
pub struct ConnectorRegistry {
    connectors: HashMap<(Product, String), Arc<dyn Connector>>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, connector: Arc<dyn Connector>) -> Result<()> {
        let manifest = connector.manifest();
        let key = (
            manifest.product,
            canonical_api_mode(manifest.product, &manifest.api_mode),
        );
        if self.connectors.insert(key.clone(), connector).is_some() {
            return Err(RuntimeError::DuplicateConnector {
                product: key.0,
                api_mode: key.1,
            });
        }
        Ok(())
    }

    pub fn resolve(&self, product: Product, api_mode: &str) -> Result<Arc<dyn Connector>> {
        self.connectors
            .get(&(product, canonical_api_mode(product, api_mode)))
            .cloned()
            .ok_or_else(|| RuntimeError::ConnectorNotFound {
                product,
                api_mode: api_mode.to_owned(),
            })
    }

    pub fn manifests(&self) -> Vec<ConnectorManifest> {
        let mut manifests: Vec<_> = self
            .connectors
            .values()
            .map(|connector| connector.manifest())
            .collect();
        manifests.sort_by(|left, right| {
            left.product
                .cmp(&right.product)
                .then(left.api_mode.cmp(&right.api_mode))
        });
        manifests
    }

    /// Drop cached clients for a connection across all registered adapters.
    pub fn invalidate_connection(&self, connection_id: ConnectionId) {
        for connector in self.connectors.values() {
            connector.invalidate_connection(connection_id);
        }
    }

    /// Snapshot all registered adapters for worker-level fan-out operations.
    pub fn all(&self) -> Vec<Arc<dyn Connector>> {
        self.connectors.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_adapter_declared_mode_aliases() {
        assert_eq!(
            canonical_api_mode(Product::PostgreSql, "pgwire"),
            "postgresql"
        );
        assert_eq!(
            canonical_api_mode(Product::MySql, "mysql_protocol"),
            "mysql"
        );
        assert_eq!(canonical_api_mode(Product::SqlServer, "sql_server"), "tds");
        assert_eq!(canonical_api_mode(Product::MongoDb, "mongo"), "mongodb");
        assert_eq!(canonical_api_mode(Product::Cassandra, "cassandra"), "cql");
        assert_eq!(
            canonical_api_mode(Product::CockroachDb, "pgwire"),
            "postgresql"
        );
        assert_eq!(
            canonical_api_mode(Product::OceanBase, "mysql"),
            "oceanbase-mysql"
        );
    }

    #[test]
    fn keeps_yugabyte_protocol_aliases_distinct() {
        assert_eq!(canonical_api_mode(Product::YugabyteDb, "cql"), "ycql");
        assert_eq!(canonical_api_mode(Product::YugabyteDb, "pgwire"), "ysql");
        assert_eq!(canonical_api_mode(Product::YugabyteDb, "ycql"), "ycql");
        assert_eq!(canonical_api_mode(Product::YugabyteDb, "ysql"), "ysql");
    }

    #[test]
    fn keeps_influx_versions_distinct() {
        assert_eq!(canonical_api_mode(Product::InfluxDb, "v1"), "v1");
        assert_eq!(canonical_api_mode(Product::InfluxDb, "v2"), "v2");
        assert_eq!(canonical_api_mode(Product::InfluxDb, "v3"), "v3");
    }
}
