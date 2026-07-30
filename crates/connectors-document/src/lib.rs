//! Document and CQL-compatible database connectors.

mod cancellation;
mod common;
#[cfg(feature = "hbase")]
mod generated {
    pub(crate) mod hbase_thrift2;
}

#[cfg(feature = "couchbase")]
mod couchbase;
#[cfg(feature = "cassandra")]
mod cql;
#[cfg(feature = "hbase")]
mod hbase;
#[cfg(feature = "mongodb")]
mod mongo;

#[cfg(feature = "couchbase")]
pub use couchbase::CouchbaseConnector;
#[cfg(feature = "cassandra")]
pub use cql::CqlConnector;
#[cfg(feature = "hbase")]
pub use hbase::HBaseThrift2Connector;
#[cfg(feature = "mongodb")]
pub use mongo::MongoConnector;
