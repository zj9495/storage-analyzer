use super::*;
use crate::profile::{
    FileKindPolicy, MisfirePolicyInput, OverlapPolicyInput, ProfileConfig, ProfileDuplicates,
    ProfileNotifications, ProfileResources, ProfileRetention, ProfileSchedule, ProfileScope,
    ProfileSection, ScheduleTypeInput, ScopeMode,
};

fn daily(tz: &str, tod: &str) -> ScheduleSpec {
    ScheduleSpec {
        schedule_type: ScheduleType::Daily,
        cron_expression: None,
        time_of_day: Some(tod.into()),
        days_of_week: vec![],
        day_of_month: None,
        timezone: tz.into(),
        misfire_policy: MisfirePolicy::Skip,
        overlap_policy: OverlapPolicy::CoalesceOnce,
    }
}

fn profile_config(enabled: bool, schedule: ProfileSchedule) -> ProfileConfig {
    ProfileConfig {
        name: "scheduler test".into(),
        enabled,
        description: None,
        scope: ProfileScope {
            mode: ScopeMode::All,
            source_ids: vec![],
            include_future_registered: false,
            include_globs: vec![],
            exclude_globs: vec![],
            file_kind_policy: FileKindPolicy::RegularOnly,
        },
        sections: vec![ProfileSection::Folders],
        owner_ids_to_list: vec![],
        duplicates: ProfileDuplicates::default(),
        rank_limit: 200,
        schedule,
        retention: ProfileRetention::default(),
        notifications: ProfileNotifications::default(),
        resources: ProfileResources::default(),
    }
}

fn profile_daily(timezone: &str, time_of_day: &str) -> ProfileSchedule {
    ProfileSchedule {
        schedule_type: ScheduleTypeInput::Daily,
        expression: None,
        time_of_day: Some(time_of_day.into()),
        days_of_week: vec![],
        day_of_month: None,
        timezone: Some(timezone.into()),
        misfire_policy: MisfirePolicyInput::Skip,
        overlap_policy: OverlapPolicyInput::CoalesceOnce,
    }
}

#[test]
fn daily_utc_fires_each_day() {
    let s = daily("UTC", "02:00");
    s.validate().unwrap();
    let from = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let occ = next_occurrences(&s, from, 5).unwrap();
    assert_eq!(occ.len(), 5);
    for (i, o) in occ.iter().enumerate() {
        let at = o.at_utc.unwrap();
        assert_eq!(at.format("%H:%M").to_string(), "02:00");
        if i > 0 {
            assert_eq!((at - occ[i - 1].at_utc.unwrap()).num_hours(), 24);
        }
    }
}

#[test]
fn next_occurrences_with_zero_count_returns_empty() {
    let s = daily("UTC", "02:00");
    let from = "2026-09-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap();

    assert!(next_occurrences(&s, from, 0).unwrap().is_empty());
}

#[test]
fn occurrences_until_has_strict_lower_and_inclusive_upper_bounds() {
    let s = daily("UTC", "02:00");
    s.validate().unwrap();
    let from = "2026-09-09T02:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let until = "2026-09-11T02:00:00Z".parse::<DateTime<Utc>>().unwrap();

    let occ = occurrences_until(&s, from, until).unwrap();
    let keys: Vec<&str> = occ
        .iter()
        .map(|item| item.occurrence_key.as_str())
        .collect();
    assert_eq!(keys, vec!["2026-09-10T02:00", "2026-09-11T02:00"]);
    assert_eq!(occ.last().unwrap().at_utc, Some(until));
    assert!(occurrences_until(&s, until, until).unwrap().is_empty());
    assert!(occurrences_until(&s, until, from).unwrap().is_empty());
}

#[test]
fn spring_forward_nonexistent_time_is_skipped() {
    // America/New_York 2024-03-10 02:30 does not exist.
    let s = daily("America/New_York", "02:30");
    s.validate().unwrap();
    let from = "2024-03-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let occ = next_occurrences(&s, from, 4).unwrap();
    let keys: Vec<&str> = occ.iter().map(|o| o.occurrence_key.as_str()).collect();
    assert!(keys.contains(&"2024-03-09T02:30"));
    // 03-10 02:30 never matches (gap): next is 03-11.
    assert!(!keys.contains(&"2024-03-10T02:30"));
    assert!(keys.contains(&"2024-03-11T02:30"));
    // ...and the preview marks it nonexistent.
    assert!(!wall_time_exists(s.tz().unwrap(), "2024-03-10T02:30"));
    assert!(wall_time_exists(s.tz().unwrap(), "2024-03-11T02:30"));
}

#[test]
fn fall_back_repeated_hour_fires_once_per_wall_time() {
    // America/New_York 2024-11-03 01:30 happens twice in UTC.
    let s = daily("America/New_York", "01:30");
    let from = "2024-11-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let occ = next_occurrences(&s, from, 4).unwrap();
    let keys: Vec<&str> = occ.iter().map(|o| o.occurrence_key.as_str()).collect();
    let count_113 = keys.iter().filter(|k| **k == "2024-11-03T01:30").count();
    assert_eq!(count_113, 1, "repeated wall hour must fire once: {keys:?}");
}

#[test]
fn occurrences_until_uses_profile_timezone_and_deduplicates_fall_back() {
    let s = daily("America/New_York", "01:30");
    let from = "2024-11-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let until = "2024-11-04T07:00:00Z".parse::<DateTime<Utc>>().unwrap();

    let occ = occurrences_until(&s, from, until).unwrap();
    let keys: Vec<&str> = occ
        .iter()
        .map(|item| item.occurrence_key.as_str())
        .collect();
    let utc_times: Vec<String> = occ
        .iter()
        .map(|item| item.at_utc.unwrap().to_rfc3339())
        .collect();

    assert_eq!(
        keys,
        vec!["2024-11-02T01:30", "2024-11-03T01:30", "2024-11-04T01:30"]
    );
    assert_eq!(
        utc_times,
        vec![
            "2024-11-02T05:30:00+00:00",
            "2024-11-03T05:30:00+00:00",
            "2024-11-04T06:30:00+00:00"
        ]
    );
}

#[test]
fn occurrences_until_records_spring_forward_nonexistent_wall_time() {
    let s = daily("America/New_York", "02:30");
    let from = "2024-03-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let until = "2024-03-11T08:00:00Z".parse::<DateTime<Utc>>().unwrap();

    let occurrences = occurrences_until(&s, from, until).unwrap();
    let keys: Vec<&str> = occurrences
        .iter()
        .map(|item| item.occurrence_key.as_str())
        .collect();
    assert_eq!(
        keys,
        vec!["2024-03-09T02:30", "2024-03-10T02:30", "2024-03-11T02:30"]
    );
    let skipped = &occurrences[1];
    assert!(skipped.skipped_nonexistent);
    assert_eq!(skipped.at_utc, None);
    assert_eq!(
        skipped_occurrences_until(&s, from, until)
            .unwrap()
            .into_iter()
            .map(|item| item.occurrence_key)
            .collect::<Vec<_>>(),
        vec!["2024-03-10T02:30"]
    );
}

#[test]
fn month_31_skips_short_months() {
    let s = ScheduleSpec {
        schedule_type: ScheduleType::Monthly,
        day_of_month: Some(31),
        ..daily("UTC", "09:00")
    };
    s.validate().unwrap();
    let from = "2026-01-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let occ = next_occurrences(&s, from, 5).unwrap();
    let keys: Vec<&str> = occ.iter().map(|o| o.occurrence_key.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "2026-01-31T09:00",
            "2026-03-31T09:00",
            "2026-05-31T09:00",
            "2026-07-31T09:00",
            "2026-08-31T09:00"
        ],
        "February/April/June must be skipped"
    );
}

#[test]
fn occurrences_until_finds_sparse_leap_day_cron() {
    let s = ScheduleSpec {
        schedule_type: ScheduleType::Cron,
        cron_expression: Some("0 0 29 2 *".into()),
        ..daily("UTC", "00:00")
    };
    s.validate().unwrap();
    let from = "2023-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let until = "2028-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();

    let occ = occurrences_until(&s, from, until).unwrap();
    let keys: Vec<&str> = occ
        .iter()
        .map(|item| item.occurrence_key.as_str())
        .collect();
    assert_eq!(keys, vec!["2024-02-29T00:00", "2028-02-29T00:00"]);
    assert!(occ.iter().all(|item| !item.skipped_nonexistent));
}

#[test]
fn weekly_multi_days() {
    let s = ScheduleSpec {
        schedule_type: ScheduleType::Weekly,
        days_of_week: vec![1, 3, 5],
        ..daily("Asia/Shanghai", "06:00")
    };
    s.validate().unwrap();
    let from = "2026-09-07T00:00:00Z".parse::<DateTime<Utc>>().unwrap(); // Monday
    let occ = next_occurrences(&s, from, 6).unwrap();
    // Monday 06:00 CST has already passed at `from` (Mon 08:00 CST), so the
    // first fire is Wednesday.
    let weekdays: Vec<String> = occ
        .iter()
        .map(|o| {
            o.at_utc
                .unwrap()
                .with_timezone(&chrono_tz::Asia::Shanghai)
                .format("%a")
                .to_string()
        })
        .collect();
    assert_eq!(weekdays, vec!["Wed", "Fri", "Mon", "Wed", "Fri", "Mon"]);
    // Asia/Shanghai UTC+8: 06:00 local = 22:00 previous day UTC.
    assert_eq!(occ[0].at_utc.unwrap().format("%H:%M").to_string(), "22:00");
}

#[test]
fn cron_expression_validated_and_previewed() {
    let s = ScheduleSpec {
        schedule_type: ScheduleType::Cron,
        cron_expression: Some("0 2 * * 0".into()),
        ..daily("UTC", "00:00")
    };
    s.validate().unwrap();
    let from = "2026-09-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let occ = next_occurrences(&s, from, 3).unwrap();
    assert_eq!(occ[0].occurrence_key, "2026-09-13T02:00"); // next Sunday

    let bad = ScheduleSpec {
        cron_expression: Some("not a cron".into()),
        ..s.clone()
    };
    assert!(bad.validate().is_err());
}

#[test]
fn profile_next_run_at_is_utc_and_strictly_after_from() {
    let config = profile_config(true, profile_daily("Asia/Shanghai", "09:00"));
    let from = "2026-09-07T01:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let expected = "2026-09-08T01:00:00Z".parse::<DateTime<Utc>>().unwrap();

    assert_eq!(
        crate::profile::next_run_at(&config, from).unwrap(),
        Some(expected.to_rfc3339())
    );
}

#[test]
fn profile_next_run_at_skips_nonexistent_local_time() {
    let config = profile_config(true, profile_daily("America/New_York", "02:30"));
    let from = "2024-03-10T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let expected = "2024-03-11T06:30:00Z".parse::<DateTime<Utc>>().unwrap();

    assert_eq!(
        crate::profile::next_run_at(&config, from).unwrap(),
        Some(expected.to_rfc3339())
    );
}

#[test]
fn profile_next_run_at_is_empty_for_manual_or_disabled_profiles() {
    let from = "2026-09-09T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let manual = profile_config(true, ProfileSchedule::default());
    let disabled = profile_config(false, profile_daily("UTC", "02:00"));

    assert_eq!(crate::profile::next_run_at(&manual, from).unwrap(), None);
    assert_eq!(crate::profile::next_run_at(&disabled, from).unwrap(), None);
}

#[test]
fn invalid_timezone_and_fields_rejected() {
    assert!(daily("Mars/Olympus", "02:00").validate().is_err());
    assert!(daily("UTC", "25:00").validate().is_err());
    let w = ScheduleSpec {
        schedule_type: ScheduleType::Weekly,
        days_of_week: vec![7],
        ..daily("UTC", "02:00")
    };
    assert!(w.validate().is_err());
    let m = ScheduleSpec {
        schedule_type: ScheduleType::Monthly,
        day_of_month: Some(32),
        ..daily("UTC", "02:00")
    };
    assert!(m.validate().is_err());
}

#[test]
fn misfire_policies() {
    let spec_skip = daily("UTC", "02:00");
    let spec_once = ScheduleSpec {
        misfire_policy: MisfirePolicy::RunOnce,
        ..daily("UTC", "02:00")
    };
    let now = "2026-09-09T08:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let mk = |ts: &str| Occurrence {
        at_utc: Some(ts.parse::<DateTime<Utc>>().unwrap()),
        occurrence_key: ts[..16].to_string(),
        skipped_nonexistent: false,
    };
    // recent miss within 6h → run once
    let recent = vec![mk("2026-09-09T02:00:00Z")];
    assert_eq!(
        resolve_misfire(&spec_skip, recent.clone(), now),
        MisfireDecision::Skip
    );
    match resolve_misfire(&spec_once, recent, now) {
        MisfireDecision::RunOnce { planned_at, .. } => {
            assert_eq!(
                planned_at,
                "2026-09-09T02:00:00Z".parse::<DateTime<Utc>>().unwrap()
            )
        }
        other => panic!("expected RunOnce, got {other:?}"),
    }
    // backlog of many misses → only the most recent, and only if <6h old
    let old = vec![mk("2026-09-08T02:00:00Z"), mk("2026-09-07T02:00:00Z")];
    assert_eq!(resolve_misfire(&spec_once, old, now), MisfireDecision::Skip);
}

#[test]
fn spec_example_expression() {
    // docs/design/contracts/profile-create.example.json schedule
    let s = ScheduleSpec {
        schedule_type: ScheduleType::Cron,
        cron_expression: Some("0 2 * * 0".into()),
        time_of_day: None,
        days_of_week: vec![],
        day_of_month: None,
        timezone: "UTC".into(),
        misfire_policy: MisfirePolicy::Skip,
        overlap_policy: OverlapPolicy::CoalesceOnce,
    };
    s.validate().unwrap();
}
