//! HTTP implementations for databases that expose stable REST APIs.

mod common;
mod elastic;
mod milvus;
mod pinecone;
mod qdrant;
mod splunk;
mod weaviate;

pub use elastic::{ElasticsearchConnector, OpenSearchConnector};
pub use milvus::MilvusRestConnector;
pub use pinecone::PineconeConnector;
pub use qdrant::QdrantRestConnector;
pub use splunk::SplunkConnector;
pub use weaviate::WeaviateConnector;

#[cfg(test)]
mod tests;
