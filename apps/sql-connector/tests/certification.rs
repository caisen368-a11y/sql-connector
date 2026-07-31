use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    process::Command,
};

use connector_core::{AuthKind, ConnectorDescriptor, ConnectorManifest, ConnectorStatus};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CERTIFICATION_LEDGER: &str = include_str!("../../../docs/connector-certification.json");
const REQUIRED_PLATFORMS: [&str; 3] = ["macos-15", "macos-15-intel", "windows-2022"];
const REQUIRED_TIER1_CHECKS: [&str; 18] = [
    "all_advertised_authentication",
    "bounded_reads",
    "cancellation",
    "custom_ca",
    "db_inspect_schema",
    "encrypted_credential_boundary",
    "error_classification",
    "native_operations",
    "policy_scoped_sql_query",
    "persistent_grant_replay_protection",
    "secret_non_disclosure",
    "test_connection",
    "tls_client_certificate",
    "tls_server_verification",
    "value_conversion",
    "worker_restart",
    "write_unknown_outcome",
    "writes_all_advertised",
];
const REQUIRED_SECRET_SURFACES: [&str; 7] = [
    "audit_rows",
    "control_output",
    "encrypted_credential_database",
    "errors",
    "host_worker_logs",
    "mcp_output",
    "profile_database",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificationLedger {
    schema_version: u32,
    tier1: Vec<Tier1Record>,
    verified: Vec<VerifiedRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tier1Record {
    manifest_id: String,
    server_versions: Vec<String>,
    platforms: Vec<String>,
    auth_kinds: Vec<AuthKind>,
    requirements: Vec<String>,
    workflow: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedRecord {
    manifest_id: String,
    descriptor: ConnectorDescriptor,
    server_versions: Vec<String>,
    platforms: Vec<String>,
    tested_auth_kinds: Vec<AuthKind>,
    passed_requirements: Vec<String>,
    secret_surfaces: Vec<String>,
    source_fingerprint: String,
    tested_commit: String,
    workflow_run_url: String,
}

#[test]
fn connector_statuses_match_machine_readable_certification_evidence() {
    let manifests = load_manifests();
    let ledger: CertificationLedger = serde_json::from_str(CERTIFICATION_LEDGER).unwrap();

    validate_certification(&manifests, &ledger).unwrap();
}

#[test]
fn verified_status_without_evidence_is_rejected() {
    let mut manifests = load_manifests();
    manifests
        .iter_mut()
        .find(|manifest| manifest.id == "mysql-protocol")
        .unwrap()
        .status = ConnectorStatus::Verified;
    let mut ledger: CertificationLedger = serde_json::from_str(CERTIFICATION_LEDGER).unwrap();
    ledger
        .verified
        .retain(|record| record.manifest_id != "mysql-protocol");

    let error = validate_certification(&manifests, &ledger).unwrap_err();

    assert!(error.contains("has no certification evidence"));
}

#[test]
#[ignore = "operator helper for recording Tier 1 certification evidence"]
fn print_tier1_source_fingerprint() {
    println!("{}", tier1_source_fingerprint());
}

fn load_manifests() -> Vec<ConnectorManifest> {
    let temporary = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sql-connector"))
        .args([
            "--data-dir",
            temporary.path().to_str().unwrap(),
            "manifests",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn validate_certification(
    manifests: &[ConnectorManifest],
    ledger: &CertificationLedger,
) -> Result<(), String> {
    if ledger.schema_version != 2 {
        return Err("unsupported connector certification schema version".into());
    }
    let manifests = unique_manifests(manifests)?;
    let tier1 = validate_tier1(&manifests, &ledger.tier1)?;
    let verified = unique_verified_records(&ledger.verified)?;

    for manifest in manifests.values() {
        let evidence = verified.get(&manifest.id);
        match (manifest.status, evidence) {
            (ConnectorStatus::Verified, None) => {
                return Err(format!(
                    "verified connector {} has no certification evidence",
                    manifest.id
                ));
            }
            (ConnectorStatus::Verified, Some(evidence)) => {
                validate_verified_record(manifest, evidence, tier1.get(&manifest.id))?;
            }
            (_, Some(_)) => {
                return Err(format!(
                    "connector {} has certification evidence but is not verified",
                    manifest.id
                ));
            }
            (_, None) => {}
        }
    }
    Ok(())
}

fn unique_manifests(
    manifests: &[ConnectorManifest],
) -> Result<BTreeMap<String, &ConnectorManifest>, String> {
    let mut by_id = BTreeMap::new();
    for manifest in manifests {
        if by_id.insert(manifest.id.clone(), manifest).is_some() {
            return Err(format!("duplicate connector manifest id {}", manifest.id));
        }
    }
    Ok(by_id)
}

fn validate_tier1<'a>(
    manifests: &BTreeMap<String, &ConnectorManifest>,
    records: &'a [Tier1Record],
) -> Result<BTreeMap<String, &'a Tier1Record>, String> {
    let mut by_id = BTreeMap::new();
    for record in records {
        let manifest = manifests
            .get(&record.manifest_id)
            .ok_or_else(|| format!("Tier 1 connector {} does not exist", record.manifest_id))?;
        if manifest.status == ConnectorStatus::Unavailable {
            return Err(format!(
                "Tier 1 connector {} is unavailable",
                record.manifest_id
            ));
        }
        if by_id.insert(record.manifest_id.clone(), record).is_some() {
            return Err(format!("duplicate Tier 1 id {}", record.manifest_id));
        }
        require_values(
            &record.platforms,
            &REQUIRED_PLATFORMS,
            &format!("Tier 1 connector {} platforms", record.manifest_id),
        )?;
        require_values(
            &record.requirements,
            &REQUIRED_TIER1_CHECKS,
            &format!("Tier 1 connector {} requirements", record.manifest_id),
        )?;
        require_auth_kinds(
            &record.auth_kinds,
            &manifest.auth_kinds,
            &format!("Tier 1 connector {} authentication", record.manifest_id),
        )?;
        if record.server_versions.len() < 2 || record.server_versions.iter().any(String::is_empty) {
            return Err(format!(
                "Tier 1 connector {} must declare at least two server versions",
                record.manifest_id
            ));
        }
        if record.workflow != ".github/workflows/tier1-connectors.yml" {
            return Err(format!(
                "Tier 1 connector {} uses an unexpected workflow",
                record.manifest_id
            ));
        }
    }
    let actual = by_id.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = ["mysql-protocol", "postgresql-pgwire"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("Tier 1 must contain exactly MySQL and PostgreSQL".into());
    }
    Ok(by_id)
}

fn unique_verified_records(
    records: &[VerifiedRecord],
) -> Result<BTreeMap<String, &VerifiedRecord>, String> {
    let mut by_id = BTreeMap::new();
    for record in records {
        if record.manifest_id != record.descriptor.manifest.id {
            return Err(format!(
                "certification evidence id {} does not match its descriptor",
                record.manifest_id
            ));
        }
        if by_id.insert(record.manifest_id.clone(), record).is_some() {
            return Err(format!(
                "duplicate certification evidence for {}",
                record.manifest_id
            ));
        }
    }
    Ok(by_id)
}

fn validate_verified_record(
    manifest: &ConnectorManifest,
    evidence: &VerifiedRecord,
    tier1: Option<&&Tier1Record>,
) -> Result<(), String> {
    let current_descriptor = manifest.clone().into_descriptor();
    if evidence.descriptor != current_descriptor {
        return Err(format!(
            "certification evidence for {} is stale",
            manifest.id
        ));
    }
    require_values(
        &evidence.platforms,
        &REQUIRED_PLATFORMS,
        &format!("verified connector {} platforms", manifest.id),
    )?;
    require_auth_kinds(
        &evidence.tested_auth_kinds,
        &manifest.auth_kinds,
        &format!("verified connector {} authentication", manifest.id),
    )?;
    require_values(
        &evidence.secret_surfaces,
        &REQUIRED_SECRET_SURFACES,
        &format!("verified connector {} secret surfaces", manifest.id),
    )?;
    if evidence.source_fingerprint != tier1_source_fingerprint() {
        return Err(format!(
            "certification evidence for {} has a stale source fingerprint",
            manifest.id
        ));
    }
    if evidence.server_versions.is_empty() || evidence.server_versions.iter().any(String::is_empty)
    {
        return Err(format!(
            "verified connector {} has no tested server versions",
            manifest.id
        ));
    }
    if let Some(tier1) = tier1 {
        require_values(
            &evidence.passed_requirements,
            &tier1
                .requirements
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &format!("verified connector {} passed requirements", manifest.id),
        )?;
        for required in &tier1.server_versions {
            if !evidence.server_versions.iter().any(|tested| {
                tested == required
                    || tested
                        .strip_prefix(required)
                        .is_some_and(|suffix| suffix.starts_with('.'))
            }) {
                return Err(format!(
                    "verified connector {} is missing Tier 1 server version {}",
                    manifest.id, required
                ));
            }
        }
    }
    if evidence.tested_commit.len() != 40
        || !evidence
            .tested_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "verified connector {} has an invalid tested commit",
            manifest.id
        ));
    }
    let run_id = evidence
        .workflow_run_url
        .strip_prefix("https://github.com/caisen368-a11y/sql-connector/actions/runs/");
    if run_id
        .is_none_or(|run_id| run_id.is_empty() || !run_id.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!(
            "verified connector {} has an invalid workflow run URL",
            manifest.id
        ));
    }
    Ok(())
}

fn require_auth_kinds(
    actual: &[AuthKind],
    expected: &[AuthKind],
    label: &str,
) -> Result<(), String> {
    let actual = actual.iter().copied().collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("{label} do not match the connector manifest"));
    }
    Ok(())
}

fn tier1_source_fingerprint() -> String {
    let sources: &[(&str, &[u8])] = &[
        ("Cargo.toml", include_bytes!("../../../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../../../Cargo.lock")),
        (
            ".github/workflows/tier1-connectors.yml",
            include_bytes!("../../../.github/workflows/tier1-connectors.yml"),
        ),
        (
            "apps/sql-connector/Cargo.toml",
            include_bytes!("../Cargo.toml"),
        ),
        (
            "apps/sql-connector/src/main.rs",
            include_bytes!("../src/main.rs"),
        ),
        (
            "apps/sql-connector/src/worker.rs",
            include_bytes!("../src/worker.rs"),
        ),
        (
            "apps/sql-connector/tests/tier1_auth_live.rs",
            include_bytes!("tier1_auth_live.rs"),
        ),
        (
            "apps/sql-connector/tests/certification.rs",
            include_bytes!("certification.rs"),
        ),
        (
            "crates/connector-control/Cargo.toml",
            include_bytes!("../../../crates/connector-control/Cargo.toml"),
        ),
        (
            "crates/connector-control/src/lib.rs",
            include_bytes!("../../../crates/connector-control/src/lib.rs"),
        ),
        (
            "crates/connector-control/tests/control.rs",
            include_bytes!("../../../crates/connector-control/tests/control.rs"),
        ),
        (
            "crates/connector-core/Cargo.toml",
            include_bytes!("../../../crates/connector-core/Cargo.toml"),
        ),
        (
            "crates/connector-core/src/capability.rs",
            include_bytes!("../../../crates/connector-core/src/capability.rs"),
        ),
        (
            "crates/connector-core/src/config.rs",
            include_bytes!("../../../crates/connector-core/src/config.rs"),
        ),
        (
            "crates/connector-core/src/connector.rs",
            include_bytes!("../../../crates/connector-core/src/connector.rs"),
        ),
        (
            "crates/connector-core/src/error.rs",
            include_bytes!("../../../crates/connector-core/src/error.rs"),
        ),
        (
            "crates/connector-core/src/operation.rs",
            include_bytes!("../../../crates/connector-core/src/operation.rs"),
        ),
        (
            "crates/connector-core/src/value.rs",
            include_bytes!("../../../crates/connector-core/src/value.rs"),
        ),
        (
            "crates/connector-core/src/lib.rs",
            include_bytes!("../../../crates/connector-core/src/lib.rs"),
        ),
        (
            "crates/connector-core/tests/contracts.rs",
            include_bytes!("../../../crates/connector-core/tests/contracts.rs"),
        ),
        (
            "crates/connector-ipc/Cargo.toml",
            include_bytes!("../../../crates/connector-ipc/Cargo.toml"),
        ),
        (
            "crates/connector-ipc/src/client.rs",
            include_bytes!("../../../crates/connector-ipc/src/client.rs"),
        ),
        (
            "crates/connector-ipc/src/connector.rs",
            include_bytes!("../../../crates/connector-ipc/src/connector.rs"),
        ),
        (
            "crates/connector-ipc/src/frame.rs",
            include_bytes!("../../../crates/connector-ipc/src/frame.rs"),
        ),
        (
            "crates/connector-ipc/src/message.rs",
            include_bytes!("../../../crates/connector-ipc/src/message.rs"),
        ),
        (
            "crates/connector-ipc/src/supervisor.rs",
            include_bytes!("../../../crates/connector-ipc/src/supervisor.rs"),
        ),
        (
            "crates/connector-ipc/src/lib.rs",
            include_bytes!("../../../crates/connector-ipc/src/lib.rs"),
        ),
        (
            "crates/connector-ipc/tests/framing.rs",
            include_bytes!("../../../crates/connector-ipc/tests/framing.rs"),
        ),
        (
            "crates/connector-mcp/Cargo.toml",
            include_bytes!("../../../crates/connector-mcp/Cargo.toml"),
        ),
        (
            "crates/connector-mcp/src/input.rs",
            include_bytes!("../../../crates/connector-mcp/src/input.rs"),
        ),
        (
            "crates/connector-mcp/src/server.rs",
            include_bytes!("../../../crates/connector-mcp/src/server.rs"),
        ),
        (
            "crates/connector-mcp/src/lib.rs",
            include_bytes!("../../../crates/connector-mcp/src/lib.rs"),
        ),
        (
            "crates/connector-mcp/tests/mysql_live.rs",
            include_bytes!("../../../crates/connector-mcp/tests/mysql_live.rs"),
        ),
        (
            "crates/connector-mcp/tests/postgres_live.rs",
            include_bytes!("../../../crates/connector-mcp/tests/postgres_live.rs"),
        ),
        (
            "crates/connector-mcp/tests/support/mod.rs",
            include_bytes!("../../../crates/connector-mcp/tests/support/mod.rs"),
        ),
        (
            "crates/connector-policy/Cargo.toml",
            include_bytes!("../../../crates/connector-policy/Cargo.toml"),
        ),
        (
            "crates/connector-policy/src/grant.rs",
            include_bytes!("../../../crates/connector-policy/src/grant.rs"),
        ),
        (
            "crates/connector-policy/src/lib.rs",
            include_bytes!("../../../crates/connector-policy/src/lib.rs"),
        ),
        (
            "crates/connector-policy/src/policy.rs",
            include_bytes!("../../../crates/connector-policy/src/policy.rs"),
        ),
        (
            "crates/connector-policy/tests/authorization.rs",
            include_bytes!("../../../crates/connector-policy/tests/authorization.rs"),
        ),
        (
            "crates/connector-runtime/Cargo.toml",
            include_bytes!("../../../crates/connector-runtime/Cargo.toml"),
        ),
        (
            "crates/connector-runtime/src/lib.rs",
            include_bytes!("../../../crates/connector-runtime/src/lib.rs"),
        ),
        (
            "crates/connector-runtime/src/registry.rs",
            include_bytes!("../../../crates/connector-runtime/src/registry.rs"),
        ),
        (
            "crates/connector-runtime/src/runtime.rs",
            include_bytes!("../../../crates/connector-runtime/src/runtime.rs"),
        ),
        (
            "crates/connector-runtime/tests/runtime.rs",
            include_bytes!("../../../crates/connector-runtime/tests/runtime.rs"),
        ),
        (
            "crates/connector-store/Cargo.toml",
            include_bytes!("../../../crates/connector-store/Cargo.toml"),
        ),
        (
            "crates/connector-store/src/audit.rs",
            include_bytes!("../../../crates/connector-store/src/audit.rs"),
        ),
        (
            "crates/connector-store/src/credential.rs",
            include_bytes!("../../../crates/connector-store/src/credential.rs"),
        ),
        (
            "crates/connector-store/src/lib.rs",
            include_bytes!("../../../crates/connector-store/src/lib.rs"),
        ),
        (
            "crates/connector-store/src/profile.rs",
            include_bytes!("../../../crates/connector-store/src/profile.rs"),
        ),
        (
            "crates/connector-store/tests/os_credential.rs",
            include_bytes!("../../../crates/connector-store/tests/os_credential.rs"),
        ),
        (
            "crates/connector-store/tests/persistence.rs",
            include_bytes!("../../../crates/connector-store/tests/persistence.rs"),
        ),
        (
            "crates/connector-store/tests/sqlite_credential.rs",
            include_bytes!("../../../crates/connector-store/tests/sqlite_credential.rs"),
        ),
        (
            "crates/connectors-sql/Cargo.toml",
            include_bytes!("../../../crates/connectors-sql/Cargo.toml"),
        ),
        (
            "crates/connectors-sql/src/cancellation.rs",
            include_bytes!("../../../crates/connectors-sql/src/cancellation.rs"),
        ),
        (
            "crates/connectors-sql/src/common.rs",
            include_bytes!("../../../crates/connectors-sql/src/common.rs"),
        ),
        (
            "crates/connectors-sql/src/lib.rs",
            include_bytes!("../../../crates/connectors-sql/src/lib.rs"),
        ),
        (
            "crates/connectors-sql/src/mysql.rs",
            include_bytes!("../../../crates/connectors-sql/src/mysql.rs"),
        ),
        (
            "crates/connectors-sql/src/postgres.rs",
            include_bytes!("../../../crates/connectors-sql/src/postgres.rs"),
        ),
        (
            "crates/connectors-sql/src/relational_metadata.rs",
            include_bytes!("../../../crates/connectors-sql/src/relational_metadata.rs"),
        ),
        (
            "scripts/tier1/mysql.sql",
            include_bytes!("../../../scripts/tier1/mysql.sql"),
        ),
        (
            "scripts/tier1/postgres.sql",
            include_bytes!("../../../scripts/tier1/postgres.sql"),
        ),
    ];
    let mut hasher = Sha256::new();
    for (path, source) in sources {
        hasher.update(path.len().to_le_bytes());
        hasher.update(path.as_bytes());
        let source = String::from_utf8_lossy(source)
            .replace(
                "const MYSQL_TIER1_STATUS: ConnectorStatus = ConnectorStatus::Experimental;",
                "const MYSQL_TIER1_STATUS: ConnectorStatus = ConnectorStatus::CertificationState;",
            )
            .replace(
                "const MYSQL_TIER1_STATUS: ConnectorStatus = ConnectorStatus::Verified;",
                "const MYSQL_TIER1_STATUS: ConnectorStatus = ConnectorStatus::CertificationState;",
            )
            .replace(
                "const POSTGRES_TIER1_STATUS: ConnectorStatus = ConnectorStatus::Experimental;",
                "const POSTGRES_TIER1_STATUS: ConnectorStatus = ConnectorStatus::CertificationState;",
            )
            .replace(
                "const POSTGRES_TIER1_STATUS: ConnectorStatus = ConnectorStatus::Verified;",
                "const POSTGRES_TIER1_STATUS: ConnectorStatus = ConnectorStatus::CertificationState;",
            );
        hasher.update(source.len().to_le_bytes());
        hasher.update(source.as_bytes());
    }
    let mut fingerprint = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut fingerprint, "{byte:02x}").unwrap();
    }
    fingerprint
}

fn require_values(actual: &[String], expected: &[&str], label: &str) -> Result<(), String> {
    let actual = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("{label} do not match the certification contract"));
    }
    Ok(())
}
