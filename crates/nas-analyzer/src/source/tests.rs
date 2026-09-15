//! Tests: in-memory control DB + DeploymentConfig over tempdir fixture roots.

use std::path::PathBuf;

use base64::Engine;
use rusqlite::{Connection, params};

use super::*;
use crate::config::{
    ApprovedMount, DeploymentConfig, ResourceConfig, SamplingConfig, SecurityConfig, ServerConfig,
    StorageConfig,
};
use crate::fixture::{
    FixtureRoot, create_golden, create_keep_sentinel, create_symlink, verify_keep_sentinel,
};
use crate::store::migrate::{CONTROL_MIGRATIONS, apply};

pub(crate) struct TestEnv {
    pub(crate) conn: Connection,
    pub(crate) fixture: FixtureRoot,
    keep: PathBuf,
}

fn test_cfg(mounts: Vec<ApprovedMount>, allow_write: bool) -> DeploymentConfig {
    DeploymentConfig {
        server: ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            default_timezone: jiff::tz::TimeZone::UTC,
            default_timezone_name: "UTC".to_string(),
            trusted_proxy_cidrs: vec![],
            allow_insecure_lan_http: true,
        },
        storage: StorageConfig {
            data_dir: PathBuf::from("/tmp/nas-analyzer-test-data"),
            approved_output_roots: vec![PathBuf::from("/tmp/nas-analyzer-test-out")],
            data_budget_bytes: 1024,
            hash_cache_budget_bytes: 1024,
        },
        approved_mounts: mounts,
        security: SecurityConfig {
            allow_write_operations: allow_write,
            setup_token_minutes: 30,
            session_idle_minutes: 30,
            session_absolute_hours: 24,
            reauth_minutes: 5,
        },
        resources: ResourceConfig {
            max_running_scans: 1,
            max_queued_scans: 20,
            metadata_workers: 1,
            hash_workers: 1,
            hash_read_limit_mib_s: 0,
            max_open_files: 64,
            api_memory_budget_mib: 256,
            worker_memory_budget_mib: 512,
            max_parallel_exports: 1,
        },
        sampling: SamplingConfig {
            interval_minutes: 60,
            raw_retention_days: 180,
            daily_retention_days: 1825,
        },
    }
}

pub(crate) fn mount(fixture: &FixtureRoot, key: &str, writable: bool) -> ApprovedMount {
    ApprovedMount {
        key: key.to_string(),
        container_path: fixture.root.clone(),
        writable,
        allow_submounts: false,
    }
}

pub(crate) fn setup_env() -> (TestEnv, DeploymentConfig) {
    let fixture = FixtureRoot::new().unwrap();
    create_golden(&fixture.root).unwrap();
    let tmp = tempfile::Builder::new()
        .prefix("nas-analyzer-keep-")
        .tempdir()
        .unwrap();
    let keep = create_keep_sentinel(tmp.path()).unwrap();
    std::mem::forget(tmp); // keep the sentinel dir alive for the test duration
    let mut conn = Connection::open_in_memory().unwrap();
    apply(&mut conn, CONTROL_MIGRATIONS).unwrap();
    let cfg = test_cfg(vec![mount(&fixture, "main", false)], false);
    (
        TestEnv {
            conn,
            fixture,
            keep,
        },
        cfg,
    )
}

pub(crate) fn input(name: &str, rel: &[u8]) -> CreateSourceInput {
    CreateSourceInput {
        name: name.to_string(),
        mount_key: "main".to_string(),
        raw_relative_root: rel.to_vec(),
        volume_id: None,
        storage_kind: StorageKind::Local,
        read_policy: ReadPolicy::MetadataOnly,
        write_enabled: false,
        protected: false,
        exclusions: vec![],
    }
}

#[test]
fn create_get_list_roundtrip() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("照片", b"alpha")).unwrap();
    assert_eq!(src.raw_relative_root, b"alpha");
    assert_eq!(src.identity_status, IdentityStatus::Provisional);
    assert_eq!(src.availability, Availability::Unknown);
    assert!(!src.write_enabled);

    let got = get_source(&env.conn, &src.id).unwrap();
    assert_eq!(got.name, "照片");
    let list = list_sources(&env.conn, false).unwrap();
    assert_eq!(list.len(), 1);
    // DTO carries base64 raw bytes and a display string.
    let dto = got.to_dto();
    assert_eq!(dto.relative_root_display, "alpha");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&dto.relative_root_base64)
            .unwrap(),
        b"alpha"
    );
    verify_keep_sentinel(&env.keep).unwrap();
}

#[test]
fn name_validation() {
    let (env, cfg) = setup_env();
    let e = create_source(&env.conn, &cfg, input("", b"alpha")).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
    let long = "x".repeat(81);
    let e = create_source(&env.conn, &cfg, input(&long, b"alpha")).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
    let e = create_source(&env.conn, &cfg, input("a\u{0007}b", b"alpha")).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
    // Exactly 80 chars is accepted.
    let ok = "x".repeat(80);
    create_source(&env.conn, &cfg, input(&ok, b"alpha")).unwrap();
}

#[test]
fn unknown_mount_key_rejected() {
    let (env, cfg) = setup_env();
    let mut i = input("s", b"alpha");
    i.mount_key = "nope".to_string();
    let e = create_source(&env.conn, &cfg, i).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn absolute_path_rejected() {
    let (env, cfg) = setup_env();
    let e = create_source(&env.conn, &cfg, input("s", b"/etc")).unwrap_err();
    assert_eq!(e.code, ErrorCode::PathOutsideRoot);
}

#[test]
fn dotdot_component_rejected() {
    let (env, cfg) = setup_env();
    for raw in [b"../etc".as_slice(), b"a/../b", b"a/.."] {
        let e = create_source(&env.conn, &cfg, input("s", raw)).unwrap_err();
        assert_eq!(e.code, ErrorCode::PathOutsideRoot, "input {raw:?}");
    }
}

#[test]
fn control_chars_rejected() {
    let (env, cfg) = setup_env();
    let e = create_source(&env.conn, &cfg, input("s", b"a\nb")).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
    let e = create_source(&env.conn, &cfg, input("s", b"a\x7fb")).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn canonicalization_collapses_dot_and_empty_components() {
    assert_eq!(canonicalize_relative_root(b"a/./b//c").unwrap(), b"a/b/c");
    assert_eq!(canonicalize_relative_root(b"").unwrap(), b"");
    assert_eq!(canonicalize_relative_root(b"./").unwrap(), b"");
}

#[test]
fn invalid_glob_exclusion_rejected() {
    let (env, cfg) = setup_env();
    let mut i = input("s", b"alpha");
    i.exclusions = vec!["**/*.tmp".to_string()];
    create_source(&env.conn, &cfg, i).unwrap();

    let mut bad = input("s2", b"beta");
    bad.exclusions = vec!["[unclosed".to_string()];
    let e = create_source(&env.conn, &cfg, bad).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn duplicate_name_rejected() {
    let (env, cfg) = setup_env();
    create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();
    let e = create_source(&env.conn, &cfg, input("s", b"beta")).unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
}

#[test]
fn overlap_rejected_and_siblings_allowed() {
    let (env, cfg) = setup_env();
    create_source(&env.conn, &cfg, input("parent", b"alpha")).unwrap();
    // Child of an enabled source under the same mount.
    let e = create_source(&env.conn, &cfg, input("child", b"alpha/docs")).unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    // Parent of an enabled source.
    let e = create_source(&env.conn, &cfg, input("grand", b"")).unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    // Sibling sharing a string prefix but not a path component.
    create_source(&env.conn, &cfg, input("sibling", b"beta")).unwrap();
}

#[test]
fn duplicate_canonical_registration_rejected() {
    let (env, cfg) = setup_env();
    create_source(&env.conn, &cfg, input("a", b"alpha")).unwrap();
    // Same directory via non-canonical spelling.
    let e = create_source(&env.conn, &cfg, input("b", b"alpha/./")).unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert!(e.message.contains("同一目录"));
}

#[test]
fn overlap_ignored_for_different_mounts_and_disabled_sources() {
    let (env, _cfg) = setup_env();
    let fixture2 = FixtureRoot::new().unwrap();
    let cfg = test_cfg(
        vec![
            mount(&env.fixture, "main", false),
            mount(&fixture2, "second", false),
        ],
        false,
    );
    let a = create_source(&env.conn, &cfg, input("a", b"alpha")).unwrap();
    // Same relative path under a different mount is fine.
    let mut i = input("b", b"alpha/docs");
    i.mount_key = "second".to_string();
    create_source(&env.conn, &cfg, i).unwrap();
    // After soft delete the path can be re-registered.
    soft_delete_source(&env.conn, &a.id).unwrap();
    create_source(&env.conn, &cfg, input("c", b"alpha/docs")).unwrap();
    // And the disabled row is preserved.
    assert_eq!(list_sources(&env.conn, true).unwrap().len(), 3);
    assert_eq!(list_sources(&env.conn, false).unwrap().len(), 2);
}

#[test]
fn write_enabled_gating_matrix() {
    let (env, _) = setup_env();

    // 1. global switch off → 403 READ_ONLY_MODE even on a writable mount.
    let cfg = test_cfg(vec![mount(&env.fixture, "main", true)], false);
    let mut i = input("s1", b"alpha");
    i.write_enabled = true;
    let e = create_source(&env.conn, &cfg, i).unwrap_err();
    assert_eq!(e.code, ErrorCode::ReadOnlyMode);

    // 2. global on, mount read-only → 403.
    let cfg = test_cfg(vec![mount(&env.fixture, "main", false)], true);
    let mut i = input("s2", b"alpha");
    i.write_enabled = true;
    let e = create_source(&env.conn, &cfg, i).unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);

    // 3. global on, mount writable, but source protected → 403.
    let cfg = test_cfg(vec![mount(&env.fixture, "main", true)], true);
    let mut i = input("s3", b"alpha");
    i.write_enabled = true;
    i.protected = true;
    let e = create_source(&env.conn, &cfg, i).unwrap_err();
    assert_eq!(e.code, ErrorCode::ProtectedFile);

    // 4. global on, mount writable, not protected → allowed.
    let mut i = input("s4", b"alpha");
    i.write_enabled = true;
    let src = create_source(&env.conn, &cfg, i).unwrap();
    assert!(src.write_enabled);

    // update path: turning on write on a protected source is refused.
    let mut i = input("s5", b"beta");
    i.protected = true;
    let protected_src = create_source(&env.conn, &cfg, i).unwrap();
    let e = update_source(
        &env.conn,
        &cfg,
        &protected_src.id,
        UpdateSourceInput {
            write_enabled: Some(true),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ProtectedFile);

    // update path: global switch off → READ_ONLY_MODE.
    let cfg_ro = test_cfg(vec![mount(&env.fixture, "main", true)], false);
    let e = update_source(
        &env.conn,
        &cfg_ro,
        &src.id,
        UpdateSourceInput {
            write_enabled: Some(true),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ReadOnlyMode);

    // update path: allowed combination works and can be turned off again.
    let src = update_source(
        &env.conn,
        &cfg,
        &src.id,
        UpdateSourceInput {
            write_enabled: Some(false),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!src.write_enabled);
}

#[test]
fn soft_delete_and_update_rules() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();

    let updated = update_source(
        &env.conn,
        &cfg,
        &src.id,
        UpdateSourceInput {
            name: Some("新名字".to_string()),
            exclusions: Some(vec!["**/@eaDir".to_string()]),
            read_policy: Some(ReadPolicy::ContentAllowed),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(updated.name, "新名字");
    assert_eq!(updated.exclusions, vec!["**/@eaDir"]);
    assert_eq!(updated.read_policy, ReadPolicy::ContentAllowed);

    let deleted = soft_delete_source(&env.conn, &src.id).unwrap();
    assert!(deleted.disabled_at.is_some());
    // History row still readable via get, but update/delete of a disabled
    // source is a 404.
    get_source(&env.conn, &src.id).unwrap();
    let e = update_source(&env.conn, &cfg, &src.id, UpdateSourceInput::default()).unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = soft_delete_source(&env.conn, &src.id).unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = get_source(&env.conn, "no-such-id").unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[test]
fn probe_online_source() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();
    let probe = probe_source(&env.conn, &cfg, &src.id).unwrap();
    assert!(probe.mounted);
    assert!(probe.traversable);
    assert!(probe.sampled_entries >= 3); // docs/, media/, empty.dat, 名称... 
    assert!(!probe.sample_truncated);
    assert_eq!(probe.availability, Availability::Online);
    assert!(probe.fs_identity.is_some());
    // Persisted back to the row.
    let after = get_source(&env.conn, &src.id).unwrap();
    assert_eq!(after.availability, Availability::Online);
    // On this dev host mountinfo is unavailable; Linux CI covers the rest.
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(probe.read_only, None);
        assert_eq!(probe.atime_quality, AtimeQuality::Unknown);
    }
    verify_keep_sentinel(&env.keep).unwrap();
}

#[test]
fn probe_offline_nonexistent_subdir() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"no-such-dir")).unwrap();
    let probe = probe_source(&env.conn, &cfg, &src.id).unwrap();
    assert!(!probe.mounted);
    assert!(!probe.traversable);
    assert_eq!(probe.availability, Availability::Offline);
    let after = get_source(&env.conn, &src.id).unwrap();
    assert_eq!(after.availability, Availability::Offline);
    verify_keep_sentinel(&env.keep).unwrap();
}

#[test]
fn probe_rejects_symlink_escape() {
    let (env, cfg) = setup_env();
    // Symlink inside the approved mount pointing outside of it.
    create_symlink(&env.fixture.root, "escape", std::path::Path::new("/etc")).unwrap();
    let src = create_source(&env.conn, &cfg, input("s", b"escape")).unwrap();
    let probe = probe_source(&env.conn, &cfg, &src.id).unwrap();
    assert!(!probe.mounted);
    assert!(!probe.traversable);
    assert_ne!(probe.availability, Availability::Online);
    assert!(probe.error.is_some());
    verify_keep_sentinel(&env.keep).unwrap();
}

#[test]
fn confirm_identity_and_epoch() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();
    let confirmed = confirm_identity(&env.conn, &cfg, &src.id).unwrap();
    assert_eq!(confirmed.identity_status, IdentityStatus::Verified);
    assert_eq!(confirmed.identity_epoch, 1);
    assert!(confirmed.identity_json.get("device_id").is_some());

    // Probing with a matching stored identity does not flag a change.
    let probe = probe_source(&env.conn, &cfg, &src.id).unwrap();
    assert!(!probe.identity_changed);
    assert_eq!(
        get_source(&env.conn, &src.id).unwrap().identity_status,
        IdentityStatus::Verified
    );

    let again = confirm_identity(&env.conn, &cfg, &src.id).unwrap();
    assert_eq!(again.identity_epoch, 2);
}

#[test]
fn probe_detects_identity_change() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();
    confirm_identity(&env.conn, &cfg, &src.id).unwrap();
    // Simulate a rebind to a different filesystem: stored identity no longer
    // matches what the probe observes.
    env.conn
        .execute(
            "UPDATE sources SET identity_json = '{\"device_id\":\"999999999\",\"mount_fsid\":\"0:0\"}' WHERE id = ?1",
            params![src.id],
        )
        .unwrap();
    let probe = probe_source(&env.conn, &cfg, &src.id).unwrap();
    assert!(probe.identity_changed);
    let after = get_source(&env.conn, &src.id).unwrap();
    assert_eq!(after.identity_status, IdentityStatus::Changed);
    // Admin re-confirms the new identity.
    let confirmed = confirm_identity(&env.conn, &cfg, &src.id).unwrap();
    assert_eq!(confirmed.identity_status, IdentityStatus::Verified);
    assert_eq!(confirmed.identity_epoch, 2);
}

#[test]
fn confirm_identity_requires_available_source() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"no-such-dir")).unwrap();
    let e = confirm_identity(&env.conn, &cfg, &src.id).unwrap_err();
    assert_eq!(e.code, ErrorCode::SourceUnavailable);
}

#[test]
fn mountinfo_parsing() {
    let text = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,seclabel
25 24 0:23 / /sys rw,nosuid,nodev,noexec,noatime shared:2 - sysfs sysfs rw
26 24 8:2 / /mnt/data\\040disk ro,noatime shared:3 - btrfs /dev/sda2 ro
27 26 0:50 / /mnt/data\\040disk/sub rw,strictatime - nfs4 nas:/share rw
garbage line without separator
";
    let entries = parse_mountinfo(text);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].major_minor, "8:1");
    assert_eq!(entries[0].filesystem_type, "ext4");
    assert_eq!(entries[2].mount_point, "/mnt/data disk");
    assert_eq!(entries[2].filesystem_type, "btrfs");

    // Longest component-boundary prefix wins.
    let e = find_mount_entry(&entries, std::path::Path::new("/mnt/data disk/sub/dir")).unwrap();
    assert_eq!(e.major_minor, "0:50");
    assert_eq!(mount_read_only(e), Some(false));
    assert_eq!(mount_atime_quality(e), AtimeQuality::Reliable);

    let e = find_mount_entry(&entries, std::path::Path::new("/mnt/data disk/other")).unwrap();
    assert_eq!(e.major_minor, "8:2");
    assert_eq!(mount_read_only(e), Some(true));
    assert_eq!(mount_atime_quality(e), AtimeQuality::Disabled);

    // "/mnt/data" must NOT match "/mnt/data disk" (component boundary).
    let e = find_mount_entry(&entries, std::path::Path::new("/mnt/data")).unwrap();
    assert_eq!(e.major_minor, "8:1");
    assert_eq!(mount_atime_quality(e), AtimeQuality::Relative);

    let e = find_mount_entry(&entries, std::path::Path::new("/sys/kernel")).unwrap();
    assert_eq!(mount_atime_quality(e), AtimeQuality::Disabled);

    assert_eq!(
        btrfs_shared_block_risk(Some("btrfs")),
        BtrfsSharedBlockRisk::Possible
    );
    assert_eq!(
        btrfs_shared_block_risk(Some("ext4")),
        BtrfsSharedBlockRisk::NotDetected
    );
    assert_eq!(btrfs_shared_block_risk(None), BtrfsSharedBlockRisk::Unknown);
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_real_host_degrades_or_reads() {
    // On Linux CI the file must exist and parse; read_only/atime then come
    // from real mount data.
    let text = read_system_mountinfo().expect("/proc/self/mountinfo readable");
    let entries = parse_mountinfo(&text);
    assert!(!entries.is_empty());
}
