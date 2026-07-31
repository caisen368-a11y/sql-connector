use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

use connector_core::{ConnectorDescriptor, ConnectorManifest, ConnectorStatus};
use serde::Deserialize;

const CERTIFICATION_LEDGER: &str = include_str!("../../../docs/connector-certification.json");
const REQUIRED_PLATFORMS: [&str; 3] = ["macos-15", "macos-15-intel", "windows-2022"];
const REQUIRED_TIER1_CHECKS: [&str; 6] = [
    "bounded_reads",
    "cancellation",
    "db_inspect_schema",
    "test_connection",
    "tls_server_verification",
    "worker_restart",
];

#[derive(Debug, Deserialize)]
struct CertificationLedger {
    schema_version: u32,
    tier1: Vec<Tier1Record>,
    verified: Vec<VerifiedRecord>,
}

#[derive(Debug, Deserialize)]
struct Tier1Record {
    manifest_id: String,
    server_versions: Vec<String>,
    platforms: Vec<String>,
    requirements: Vec<String>,
    workflow: String,
}

#[derive(Debug, Deserialize)]
struct VerifiedRecord {
    manifest_id: String,
    descriptor: ConnectorDescriptor,
    server_versions: Vec<String>,
    platforms: Vec<String>,
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
    let ledger: CertificationLedger = serde_json::from_str(CERTIFICATION_LEDGER).unwrap();

    let error = validate_certification(&manifests, &ledger).unwrap_err();

    assert!(error.contains("has no certification evidence"));
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
    if ledger.schema_version != 1 {
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
    if evidence.server_versions.is_empty() || evidence.server_versions.iter().any(String::is_empty)
    {
        return Err(format!(
            "verified connector {} has no tested server versions",
            manifest.id
        ));
    }
    if let Some(tier1) = tier1 {
        for required in &tier1.server_versions {
            if !evidence
                .server_versions
                .iter()
                .any(|tested| tested.starts_with(required))
            {
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
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "verified connector {} has an invalid tested commit",
            manifest.id
        ));
    }
    if !evidence.workflow_run_url.starts_with("https://github.com/")
        || !evidence.workflow_run_url.contains("/actions/runs/")
    {
        return Err(format!(
            "verified connector {} has an invalid workflow run URL",
            manifest.id
        ));
    }
    Ok(())
}

fn require_values(actual: &[String], expected: &[&str], label: &str) -> Result<(), String> {
    let actual = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("{label} do not match the certification contract"));
    }
    Ok(())
}
