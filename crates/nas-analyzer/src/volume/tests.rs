//! Tests: real tmpdir fixture for statvfs math; in-memory control DB.

use rusqlite::Connection;

use super::*;
use crate::error::ErrorCode;
use crate::source::tests::{input, setup_env};
use crate::source::{create_source, soft_delete_source};

fn make_volume(
    conn: &Connection,
    cfg: &DeploymentConfig,
    with_source: bool,
) -> (Volume, Option<String>) {
    let sid = if with_source {
        Some(
            create_source(conn, cfg, input("容量源", b"alpha"))
                .unwrap()
                .id,
        )
    } else {
        None
    };
    let vol = create_volume(
        conn,
        CreateVolumeInput {
            name: "卷A".to_string(),
            capacity_source_id: sid.clone(),
        },
    )
    .unwrap();
    (vol, sid)
}

#[test]
fn create_list_update_roundtrip() {
    let (env, cfg) = setup_env();
    let (vol, sid) = make_volume(&env.conn, &cfg, true);
    assert_eq!(vol.capacity_source_id, sid);
    assert_eq!(vol.status, VolumeStatus::Active);
    assert!(!vol.is_confirmed()); // identity not yet confirmed

    let got = get_volume(&env.conn, &vol.id).unwrap();
    assert_eq!(got.name, "卷A");
    assert_eq!(list_volumes(&env.conn).unwrap().len(), 1);

    let updated = update_volume(
        &env.conn,
        &vol.id,
        UpdateVolumeInput {
            name: Some("卷B".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(updated.name, "卷B");
    assert_eq!(updated.capacity_source_id, sid);

    let e = get_volume(&env.conn, "no-such").unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[test]
fn capacity_source_must_exist() {
    let (env, cfg) = setup_env();
    let e = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: Some("no-such-source".to_string()),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);

    // Disabled sources cannot be sampling sources either.
    let src = create_source(&env.conn, &cfg, input("s", b"alpha")).unwrap();
    soft_delete_source(&env.conn, &src.id).unwrap();
    let e = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: Some(src.id),
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);

    // Same check on update.
    let vol = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: None,
        },
    )
    .unwrap();
    let e = update_volume(
        &env.conn,
        &vol.id,
        UpdateVolumeInput {
            capacity_source_id: Some(Some("no-such-source".to_string())),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn volume_name_validation() {
    let (env, _cfg) = setup_env();
    let e = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: String::new(),
            capacity_source_id: None,
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
    let e = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "x".repeat(129),
            capacity_source_id: None,
        },
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn sample_capacity_math_and_dedupe() {
    let (env, cfg) = setup_env();
    let (vol, _) = make_volume(&env.conn, &cfg, true);

    let s = sample_capacity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(s.quality, SampleQuality::Ok);
    assert!(s.inserted);
    let total = s.total_bytes.unwrap();
    let free = s.free_bytes.unwrap();
    let avail = s.available_bytes.unwrap();
    let used = s.used_bytes.unwrap();
    assert!(total > 0);
    assert!(free <= total);
    assert!(avail <= free);
    assert_eq!(used, total - free);
    assert_eq!(s.reserved_diff_bytes, Some(free - avail));
    // Minute-truncated timestamp.
    assert!(s.sample_time.ends_with(":00.000Z"), "{}", s.sample_time);

    // Same minute → dedupe, single row.
    let s2 = sample_capacity(&env.conn, &cfg, &vol.id).unwrap();
    assert!(!s2.inserted);
    assert_eq!(s2.sample_time, s.sample_time);
    let n: i64 = env
        .conn
        .query_row(
            "SELECT COUNT(*) FROM volume_samples WHERE volume_id = ?1",
            rusqlite::params![vol.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);

    let listed = list_samples(&env.conn, &vol.id, 10).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].total_bytes, Some(total));
}

#[test]
fn sample_without_capacity_source_records_error_not_zeros() {
    let (env, _cfg) = setup_env();
    let vol = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: None,
        },
    )
    .unwrap();
    let s = sample_capacity(&env.conn, &_cfg, &vol.id).unwrap();
    assert_eq!(s.quality, SampleQuality::Error);
    assert_eq!(s.total_bytes, None);
    assert_eq!(s.used_bytes, None);
    assert!(s.error.as_deref().unwrap().contains("容量采样源"));

    // The error row exists with NULL byte fields (never fake zeros).
    let (q, t): (String, Option<String>) = env
        .conn
        .query_row(
            "SELECT quality, total_bytes FROM volume_samples WHERE volume_id = ?1",
            rusqlite::params![vol.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(q, "error");
    assert_eq!(t, None);
}

#[test]
fn sample_with_unavailable_source_records_error() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"no-such-dir")).unwrap();
    let vol = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: Some(src.id),
        },
    )
    .unwrap();
    let s = sample_capacity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(s.quality, SampleQuality::Error);
    assert_eq!(s.total_bytes, None);
    assert!(s.error.is_some());
}

#[test]
fn confirm_and_redetect_identity() {
    let (env, cfg) = setup_env();
    let (vol, _) = make_volume(&env.conn, &cfg, true);

    let confirmed = confirm_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(confirmed.status, VolumeStatus::Active);
    assert!(confirmed.is_confirmed());
    let stored = confirmed.identity_json.clone();
    assert!(stored.get("device_id").and_then(|v| v.as_str()).is_some());

    let check = redetect_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(check.outcome, VolumeIdentityOutcome::Unchanged);

    // A different observed identity must NOT auto-inherit: identity_json
    // stays as stored and the caller gets Changed.
    env.conn
        .execute(
            "UPDATE volumes SET identity_json = '{\"device_id\":\"424242\",\"mount_fsid\":\"0:0\"}' WHERE id = ?1",
            rusqlite::params![vol.id],
        )
        .unwrap();
    let check = redetect_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(check.outcome, VolumeIdentityOutcome::Changed);
    let after = get_volume(&env.conn, &vol.id).unwrap();
    assert_eq!(
        after
            .identity_json
            .get("device_id")
            .and_then(|v| v.as_str()),
        Some("424242")
    );

    // Re-confirming stores the real identity again.
    let confirmed = confirm_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(confirmed.identity_json, stored);
}

#[test]
fn redetect_marks_disconnected_when_source_gone() {
    let (env, cfg) = setup_env();
    let src = create_source(&env.conn, &cfg, input("s", b"gone-soon")).unwrap();
    std::fs::create_dir(env.fixture.path("gone-soon")).unwrap();
    let vol = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: Some(src.id),
        },
    )
    .unwrap();
    confirm_volume_identity(&env.conn, &cfg, &vol.id).unwrap();

    // External disk unplugged: directory disappears (fixture tempdir only).
    std::fs::remove_dir(env.fixture.path("gone-soon")).unwrap();
    let check = redetect_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    assert_eq!(check.outcome, VolumeIdentityOutcome::Unavailable);
    assert_eq!(check.volume.status, VolumeStatus::Disconnected);
    // History/identity preserved.
    assert!(check.volume.identity_json.get("device_id").is_some());
}

#[test]
fn confirm_identity_without_capacity_source_fails() {
    let (env, cfg) = setup_env();
    let vol = create_volume(
        &env.conn,
        CreateVolumeInput {
            name: "v".to_string(),
            capacity_source_id: None,
        },
    )
    .unwrap();
    let e = confirm_volume_identity(&env.conn, &cfg, &vol.id).unwrap_err();
    assert_eq!(e.code, ErrorCode::ValidationFailed);
}

#[test]
fn double_count_guard_totals() {
    let (env, cfg) = setup_env();
    // Two sources on the same fixture: one attributed to a confirmed volume,
    // one unattributed. Both must NOT be summed twice (spec 4.3).
    let (vol, sid) = make_volume(&env.conn, &cfg, true);
    let sid = sid.unwrap();
    create_source(&env.conn, &cfg, input("未归属源", b"beta")).unwrap();

    // No sample yet → volume not in totals, both sources unattributed.
    let t = used_capacity_totals(&env.conn).unwrap();
    assert_eq!(t.confirmed_volumes.len(), 0);
    assert_eq!(t.total_bytes, None);
    assert_eq!(t.unattributed_source_count, 2);

    // Identity confirmed + one sample → volume contributes; attribute the
    // capacity source to the volume, beta stays out.
    confirm_volume_identity(&env.conn, &cfg, &vol.id).unwrap();
    let s = sample_capacity(&env.conn, &cfg, &vol.id).unwrap();
    env.conn
        .execute(
            "UPDATE sources SET volume_id = ?1 WHERE id = ?2",
            rusqlite::params![vol.id, sid],
        )
        .unwrap();
    let t = used_capacity_totals(&env.conn).unwrap();
    assert_eq!(t.confirmed_volumes.len(), 1);
    assert_eq!(t.total_bytes, s.total_bytes);
    assert_eq!(t.used_bytes, s.used_bytes);
    assert_eq!(t.available_bytes, s.available_bytes);
    assert_eq!(t.unattributed_source_count, 1);

    // Attribute beta to the same volume → no longer unattributed, but the
    // volume total is still counted exactly once.
    env.conn
        .execute(
            "UPDATE sources SET volume_id = ?1 WHERE id != ?2",
            rusqlite::params![vol.id, sid],
        )
        .unwrap();
    let t = used_capacity_totals(&env.conn).unwrap();
    assert_eq!(t.unattributed_source_count, 0);
    assert_eq!(t.confirmed_volumes.len(), 1);
    assert_eq!(t.total_bytes, s.total_bytes);

    // Reassigning the capacity source invalidates the confirmed identity.
    let src2 =
        create_source(&env.conn, &cfg, input("容量源2", b"beta/docs".as_slice())).unwrap_err();
    assert_eq!(src2.code, ErrorCode::Conflict); // beta already registered; use another dir
    std::fs::create_dir_all(env.fixture.path("gamma")).unwrap();
    let src2 = create_source(&env.conn, &cfg, input("容量源2", b"gamma")).unwrap();
    let updated = update_volume(
        &env.conn,
        &vol.id,
        UpdateVolumeInput {
            capacity_source_id: Some(Some(src2.id)),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!updated.is_confirmed());
    let t = used_capacity_totals(&env.conn).unwrap();
    assert_eq!(t.confirmed_volumes.len(), 0);
    assert_eq!(t.total_bytes, None);
}
