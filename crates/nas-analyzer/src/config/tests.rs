use super::*;

const VALID: &str = r#"
config_version: 2
server:
  listen: "0.0.0.0:8080"
  default_timezone: UTC
  trusted_proxy_cidrs: []
  allow_insecure_lan_http: true
storage:
  data_dir: /data
  approved_output_roots:
    - /data/exports
  data_budget_bytes: "21474836480"
  hash_cache_budget_bytes: "2147483648"
approved_mounts:
  - key: main
    container_path: /sources/main
    writable: false
    allow_submounts: false
security:
  allow_write_operations: false
  session_idle_minutes: 30
  session_absolute_hours: 24
  reauth_minutes: 5
resources:
  max_running_scans: 1
  max_queued_scans: 20
  metadata_workers: 2
  hash_workers: 1
  hash_read_limit_mib_s: 30
  max_open_files: 128
  api_memory_budget_mib: 128
  worker_memory_budget_mib: 512
  max_parallel_exports: 1
sampling:
  interval_minutes: 60
  raw_retention_days: 180
  daily_retention_days: 1825
"#;

#[test]
fn valid_v2_config_parses() {
    let cfg = DeploymentConfig::from_yaml_str(VALID).expect("valid config must parse");
    cfg.validate_semantics().unwrap();
    assert_eq!(cfg.resources.api_memory_budget_mib, 128);
    assert_eq!(cfg.resources.worker_memory_budget_mib, 512);
    assert_eq!(cfg.approved_mounts[0].key, "main");
    assert!(!cfg.approved_mounts[0].writable);
    assert_eq!(cfg.storage.data_budget_bytes, 21474836480u64);
}

#[test]
fn design_package_example_parses() {
    let text = std::fs::read_to_string("../../docs/design/deploy/config.example.yaml")
        .expect("design example must exist");
    let cfg = DeploymentConfig::from_yaml_str(&text).expect("design v2 example must parse");
    cfg.validate_semantics().unwrap();
}

#[test]
fn v1_config_version_rejected_with_migration_hint() {
    let text = VALID.replace("config_version: 2", "config_version: 1");
    let err = DeploymentConfig::from_yaml_str(&text).unwrap_err();
    assert!(err.message.contains("config_version=1"));
    assert!(err.message.contains("api_memory_budget_mib"));
}

#[test]
fn v1_legacy_limit_fields_rejected() {
    let text = VALID.replace("api_memory_budget_mib: 128", "api_memory_limit_mib: 128");
    let err = DeploymentConfig::from_yaml_str(&text).unwrap_err();
    assert!(err.message.contains("api_memory_limit_mib"));
}

#[test]
fn unknown_fields_rejected() {
    let text = VALID.replace(
        "max_parallel_exports: 1",
        "max_parallel_exports: 1\n  typo_field: true",
    );
    let err = DeploymentConfig::from_yaml_str(&text).unwrap_err();
    assert!(err.message.contains("typo_field") || err.message.contains("unknown field"));
}

#[test]
fn bad_timezone_rejected() {
    let text = VALID.replace("default_timezone: UTC", "default_timezone: Not/AZone");
    assert!(DeploymentConfig::from_yaml_str(&text).is_err());
}

#[test]
fn bad_cidr_rejected() {
    let text = VALID.replace(
        "trusted_proxy_cidrs: []",
        "trusted_proxy_cidrs: [\"999.1.1.1/8\"]",
    );
    assert!(DeploymentConfig::from_yaml_str(&text).is_err());
}

#[test]
fn submounts_fixed_false() {
    let text = VALID.replace("allow_submounts: false", "allow_submounts: true");
    let err = DeploymentConfig::from_yaml_str(&text).unwrap_err();
    assert!(err.message.contains("allow_submounts"));
}

#[test]
fn max_running_scans_fixed_one() {
    let text = VALID.replace("max_running_scans: 1", "max_running_scans: 2");
    assert!(DeploymentConfig::from_yaml_str(&text).is_err());
}

#[test]
fn mount_key_rules_enforced() {
    let text = VALID.replace("key: main", "key: Main_Bad!");
    assert!(DeploymentConfig::from_yaml_str(&text).is_err());
    let text2 = VALID.replace("key: main", "key: main\n  - key: main");
    // duplicate key (the second entry reuses the remaining fields of first)
    let _ = DeploymentConfig::from_yaml_str(text2.as_str());
}

#[test]
fn duplicate_mount_key_rejected() {
    let text = VALID.replace(
        "approved_mounts:\n  - key: main\n    container_path: /sources/main\n    writable: false\n    allow_submounts: false",
        "approved_mounts:\n  - key: main\n    container_path: /sources/main\n    writable: false\n    allow_submounts: false\n  - key: main\n    container_path: /sources/other\n    writable: false\n    allow_submounts: false",
    );
    let err = DeploymentConfig::from_yaml_str(&text).unwrap_err();
    assert!(err.message.contains("duplicate mount key"));
}

#[test]
fn data_dir_inside_source_rejected() {
    let text = VALID.replace("data_dir: /data", "data_dir: /sources/main/data");
    let cfg = DeploymentConfig::from_yaml_str(&text).unwrap();
    assert!(cfg.validate_semantics().is_err());
}

#[test]
fn budget_bytes_leading_zero_rejected() {
    let text = VALID.replace("\"21474836480\"", "\"0123\"");
    assert!(DeploymentConfig::from_yaml_str(&text).is_err());
}

#[test]
fn hash_read_limit_zero_means_unlimited_and_is_accepted() {
    let text = VALID.replace("hash_read_limit_mib_s: 30", "hash_read_limit_mib_s: 0");
    let cfg = DeploymentConfig::from_yaml_str(&text).unwrap();
    assert_eq!(cfg.resources.hash_read_limit_mib_s, 0);
}
