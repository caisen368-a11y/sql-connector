use connector_core::{DbRecord, DbValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedColumns {
    pub name: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForeignKeyMetadata {
    pub name: String,
    pub columns: Vec<String>,
    pub referenced_entity: String,
    pub referenced_columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexMetadata {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RelationalMetadata {
    pub primary_key: Option<NamedColumns>,
    pub foreign_keys: Vec<ForeignKeyMetadata>,
    pub unique_constraints: Vec<NamedColumns>,
    pub indexes: Vec<IndexMetadata>,
}

impl RelationalMetadata {
    pub fn into_record(self) -> DbRecord {
        DbRecord::from([
            (
                "primary_key".into(),
                self.primary_key.map_or(DbValue::Null, named_columns_value),
            ),
            (
                "foreign_keys".into(),
                DbValue::Array(
                    self.foreign_keys
                        .into_iter()
                        .map(|key| {
                            DbValue::Document(DbRecord::from([
                                ("name".into(), DbValue::String(key.name)),
                                ("columns".into(), string_array(key.columns)),
                                (
                                    "referenced_entity".into(),
                                    DbValue::String(key.referenced_entity),
                                ),
                                (
                                    "referenced_columns".into(),
                                    string_array(key.referenced_columns),
                                ),
                            ]))
                        })
                        .collect(),
                ),
            ),
            (
                "unique_constraints".into(),
                DbValue::Array(
                    self.unique_constraints
                        .into_iter()
                        .map(named_columns_value)
                        .collect(),
                ),
            ),
            (
                "indexes".into(),
                DbValue::Array(
                    self.indexes
                        .into_iter()
                        .map(|index| {
                            DbValue::Document(DbRecord::from([
                                ("name".into(), DbValue::String(index.name)),
                                ("columns".into(), string_array(index.columns)),
                                ("unique".into(), DbValue::Bool(index.unique)),
                            ]))
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn named_columns_value(key: NamedColumns) -> DbValue {
    DbValue::Document(DbRecord::from([
        ("name".into(), DbValue::String(key.name)),
        ("columns".into(), string_array(key.columns)),
    ]))
}

fn string_array(values: Vec<String>) -> DbValue {
    DbValue::Array(values.into_iter().map(DbValue::String).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relational_metadata_has_stable_model_facing_shape() {
        let record = RelationalMetadata {
            primary_key: Some(NamedColumns {
                name: "users_pkey".into(),
                columns: vec!["id".into()],
            }),
            foreign_keys: vec![ForeignKeyMetadata {
                name: "users_team_id_fkey".into(),
                columns: vec!["team_id".into()],
                referenced_entity: "public.teams".into(),
                referenced_columns: vec!["id".into()],
            }],
            unique_constraints: vec![],
            indexes: vec![IndexMetadata {
                name: "users_email_idx".into(),
                columns: vec!["email".into()],
                unique: true,
            }],
        }
        .into_record();

        assert!(matches!(record["primary_key"], DbValue::Document(_)));
        assert!(matches!(record["foreign_keys"], DbValue::Array(ref keys) if keys.len() == 1));
        assert!(
            matches!(record["unique_constraints"], DbValue::Array(ref keys) if keys.is_empty())
        );
        assert!(matches!(record["indexes"], DbValue::Array(ref indexes) if indexes.len() == 1));
    }
}
