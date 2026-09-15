use std::str::FromStr;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult, ErrorCode};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScheduleType {
    Daily,
    Weekly,
    Monthly,
    Cron,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MisfirePolicy {
    Skip,
    RunOnce,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// Do not enqueue a run while another run for the same profile is active
    /// or already queued.
    Skip,
    /// Coalesce into at most one queued follow-up run (default).
    CoalesceOnce,
}

/// Validated schedule specification as stored in a profile version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduleSpec {
    pub schedule_type: ScheduleType,
    /// 5-field cron expression; required for Cron. For Daily/Weekly/Monthly
    /// the canonical expression is derived from the fields below.
    pub cron_expression: Option<String>,
    /// "HH:MM" local wall time for Daily/Weekly/Monthly.
    pub time_of_day: Option<String>,
    /// 0=Sunday .. 6=Saturday for Weekly.
    pub days_of_week: Vec<u8>,
    /// 1..=31 for Monthly.
    pub day_of_month: Option<u8>,
    /// IANA timezone name.
    pub timezone: String,
    pub misfire_policy: MisfirePolicy,
    pub overlap_policy: OverlapPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// UTC instant when the run fires. This is `None` for a local wall-clock
    /// time that does not exist during a spring-forward transition.
    pub at_utc: Option<DateTime<Utc>>,
    /// Local wall-clock key "YYYY-MM-DDTHH:MM" in the profile timezone.
    /// Dedupe key protecting against DST fall-back double fire; also embeds
    /// the profile version upstream (schedule_occurrences PK).
    pub occurrence_key: String,
    /// True when the local wall time was skipped because it does not exist
    /// (spring-forward gap). Such occurrences are recorded, not fired.
    pub skipped_nonexistent: bool,
}

/// Public convention (and the profile-create contract): day-of-week numbers
/// follow standard 5-field cron — 0 or 7 = Sunday, 1 = Monday .. 6 =
/// Saturday. The cron crate instead uses 1 = Sunday .. 7 = Saturday, so
/// numeric DOW tokens are translated before parsing.
fn dow_public_to_crate(d: u8) -> u8 {
    (d % 7) + 1
}

/// Translate the DOW field of a standard 5-field expression and pin seconds
/// to 0, producing the crate's 6-field form. Names (mon, sun, …) pass
/// through unchanged.
fn translate_expr5(expr5: &str) -> AppResult<String> {
    let fields: Vec<&str> = expr5.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(err(format!(
            "cron 表达式必须是 5 段（分 时 日 月 星期），实际 {} 段：{expr5:?}",
            fields.len()
        )));
    }
    let dow = translate_dow_field(fields[4])?;
    Ok(format!(
        "0 {} {} {} {} {}",
        fields[0], fields[1], fields[2], fields[3], dow
    ))
}

fn translate_dow_field(field: &str) -> AppResult<String> {
    let mut parts = Vec::new();
    for item in field.split(',') {
        parts.push(translate_dow_item(item)?);
    }
    Ok(parts.join(","))
}

fn translate_dow_item(item: &str) -> AppResult<String> {
    let (range_part, step) = match item.split_once('/') {
        Some((r, s)) => (r, Some(s)),
        None => (item, None),
    };
    let mapped = if range_part == "*" || range_part.is_empty() {
        "*".to_string()
    } else if range_part.bytes().all(|b| b.is_ascii_digit()) {
        let n: u8 = range_part
            .parse()
            .map_err(|_| err(format!("cron 星期值非法：{item:?}")))?;
        if n > 7 {
            return Err(err(format!("cron 星期值超出 0–7：{item:?}")));
        }
        dow_public_to_crate(n).to_string()
    } else if let Some((a, b)) = range_part.split_once('-') {
        if a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()) {
            let a: u8 = a
                .parse()
                .map_err(|_| err(format!("cron 星期值非法：{item:?}")))?;
            let b: u8 = b
                .parse()
                .map_err(|_| err(format!("cron 星期值非法：{item:?}")))?;
            if a > 7 || b > 7 {
                return Err(err(format!("cron 星期值超出 0–7：{item:?}")));
            }
            format!("{}-{}", dow_public_to_crate(a), dow_public_to_crate(b))
        } else {
            range_part.to_string() // named range, e.g. mon-fri
        }
    } else {
        range_part.to_string() // named token
    };
    Ok(match step {
        Some(s) => format!("{mapped}/{s}"),
        None => mapped,
    })
}

fn err(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::ValidationFailed, msg)
}

impl ScheduleSpec {
    pub fn validate(&self) -> AppResult<()> {
        self.tz()?;
        self.cron_schedule()?;
        match self.schedule_type {
            ScheduleType::Daily => {
                self.parsed_time_of_day()?;
            }
            ScheduleType::Weekly => {
                self.parsed_time_of_day()?;
                if self.days_of_week.is_empty() || self.days_of_week.iter().any(|d| *d > 6) {
                    return Err(err("weekly 调度需要 1–7 个 0..=6 的星期值"));
                }
            }
            ScheduleType::Monthly => {
                self.parsed_time_of_day()?;
                match self.day_of_month {
                    Some(1..=31) => {}
                    _ => return Err(err("monthly 调度需要 day_of_month 在 1..=31")),
                }
            }
            ScheduleType::Cron => {
                if self.cron_expression.is_none() {
                    return Err(err("cron 调度需要 cron_expression"));
                }
            }
        }
        Ok(())
    }

    pub fn tz(&self) -> AppResult<chrono_tz::Tz> {
        self.timezone
            .parse::<chrono_tz::Tz>()
            .map_err(|_| err(format!("未知 IANA 时区：{:?}", self.timezone)))
    }

    fn parsed_time_of_day(&self) -> AppResult<(u32, u32)> {
        let t = self
            .time_of_day
            .as_deref()
            .ok_or_else(|| err("需要 time_of_day (HH:MM)"))?;
        let (h, m) = t
            .split_once(':')
            .ok_or_else(|| err(format!("time_of_day 格式非法：{t:?}")))?;
        let h: u32 = h
            .parse()
            .map_err(|_| err(format!("time_of_day 格式非法：{t:?}")))?;
        let m: u32 = m
            .parse()
            .map_err(|_| err(format!("time_of_day 格式非法：{t:?}")))?;
        if h > 23 || m > 59 {
            return Err(err(format!("time_of_day 超出范围：{t:?}")));
        }
        Ok((h, m))
    }

    /// Canonical 6-field cron (seconds pinned to 0) for the cron crate.
    fn cron_schedule(&self) -> AppResult<cron::Schedule> {
        let expr6 = match self.schedule_type {
            ScheduleType::Cron => {
                let expr5 = self
                    .cron_expression
                    .clone()
                    .ok_or_else(|| err("缺少 cron_expression"))?;
                translate_expr5(&expr5)?
            }
            ScheduleType::Daily => {
                let (h, m) = self.parsed_time_of_day()?;
                format!("0 {m} {h} * * *")
            }
            ScheduleType::Weekly => {
                let (h, m) = self.parsed_time_of_day()?;
                // Already in crate numbering (1=Sun..7=Sat); do NOT pass
                // through translate_expr5, which maps user-facing numbers.
                let days: Vec<String> = self
                    .days_of_week
                    .iter()
                    .map(|d| dow_public_to_crate(*d).to_string())
                    .collect();
                format!("0 {m} {h} * * {}", days.join(","))
            }
            ScheduleType::Monthly => {
                let (h, m) = self.parsed_time_of_day()?;
                let d = self.day_of_month.ok_or_else(|| err("缺少 day_of_month"))?;
                format!("0 {m} {h} {d} * *")
            }
        };
        cron::Schedule::from_str(&expr6)
            .map_err(|e| err(format!("cron 表达式非法：{expr6:?}：{e}")))
    }
}

/// Compute the next `count` fire times strictly after `from`.
///
/// Iteration happens over UTC instants (the cron crate steps in UTC and
/// matches fields in local time), so a nonexistent local wall time simply
/// never matches (spring-forward skip) and a repeated wall time yields two
/// distinct UTC instants — we collapse the second one via the occurrence key
/// (fall-back: same wall time fires once).
pub fn next_occurrences(
    spec: &ScheduleSpec,
    from: DateTime<Utc>,
    count: usize,
) -> AppResult<Vec<Occurrence>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let sched = spec.cron_schedule()?;
    let tz = spec.tz()?;
    let mut out: Vec<Occurrence> = Vec::with_capacity(count);
    let mut seen_keys = std::collections::HashSet::new();
    // The cron crate matches fields in the timezone of the passed DateTime;
    // iterate in the profile's local timezone so wall-clock fields and DST
    // gaps/overlaps are interpreted correctly.
    for local in sched.after(&from.with_timezone(&tz)) {
        let utc = local.with_timezone(&Utc);
        let key = local.format("%Y-%m-%dT%H:%M").to_string();
        if !seen_keys.insert(key.clone()) {
            continue; // DST fall-back duplicate wall time: fire once.
        }
        out.push(Occurrence {
            at_utc: Some(utc),
            occurrence_key: key,
            skipped_nonexistent: false,
        });
        if out.len() == count {
            break;
        }
    }
    Ok(out)
}

/// Return every logical occurrence strictly after `from` and no later than
/// `until`. The upper bound is the termination condition, so sparse cron
/// expressions (for example February 29) are not silently truncated by a
/// fixed number of iterator steps.
pub fn occurrences_until(
    spec: &ScheduleSpec,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> AppResult<Vec<Occurrence>> {
    if until <= from {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    visit_occurrences_until(spec, from, until, |occurrence| out.push(occurrence))?;
    Ok(out)
}

/// Return only nonexistent local wall-clock occurrences in the interval.
/// The iterator is evaluated in the wall-clock domain using UTC as a neutral
/// carrier, then each candidate is resolved against the profile timezone.
/// This keeps skipped occurrences observable without manufacturing a UTC
/// instant for a time that has none.
pub fn skipped_occurrences_until(
    spec: &ScheduleSpec,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> AppResult<Vec<Occurrence>> {
    if until <= from {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    visit_occurrences_until(spec, from, until, |occurrence| {
        if occurrence.skipped_nonexistent {
            out.push(occurrence);
        }
    })?;
    Ok(out)
}

fn visit_occurrences_until<F>(
    spec: &ScheduleSpec,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
    mut visit: F,
) -> AppResult<()>
where
    F: FnMut(Occurrence),
{
    let sched = spec.cron_schedule()?;
    let tz = spec.tz()?;
    let lower_wall = from.with_timezone(&tz).naive_local();
    let upper_wall = until.with_timezone(&tz).naive_local();
    // `cron` operates on a TimeZone. UTC is used only as a neutral carrier
    // for local calendar fields; the candidate is resolved in `tz` below.
    let lower_carrier = Utc.from_utc_datetime(&lower_wall);
    let mut seen_keys = std::collections::HashSet::new();
    for wall in sched.after(&lower_carrier) {
        let wall_naive = wall.naive_utc();
        if wall_naive > upper_wall {
            break;
        }
        let key = wall_naive.format("%Y-%m-%dT%H:%M").to_string();
        if !seen_keys.insert(key.clone()) {
            continue;
        }
        match tz.from_local_datetime(&wall_naive) {
            chrono::LocalResult::None => visit(Occurrence {
                at_utc: None,
                occurrence_key: key,
                skipped_nonexistent: true,
            }),
            chrono::LocalResult::Single(local) => {
                let utc = local.with_timezone(&Utc);
                if utc > from && utc <= until {
                    visit(Occurrence {
                        at_utc: Some(utc),
                        occurrence_key: key,
                        skipped_nonexistent: false,
                    });
                }
            }
            chrono::LocalResult::Ambiguous(earlier, _later) => {
                let utc = earlier.with_timezone(&Utc);
                if utc > from && utc <= until {
                    visit(Occurrence {
                        at_utc: Some(utc),
                        occurrence_key: key,
                        skipped_nonexistent: false,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Whether a local wall time exists in the timezone (false inside the
/// spring-forward gap). Used to surface "skipped" markers in previews.
pub fn wall_time_exists(tz: chrono_tz::Tz, key: &str) -> bool {
    let Ok(naive) = chrono::NaiveDateTime::parse_from_str(key, "%Y-%m-%dT%H:%M") else {
        return false;
    };
    !matches!(tz.from_local_datetime(&naive), chrono::LocalResult::None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MisfireDecision {
    Skip,
    RunOnce {
        planned_at: DateTime<Utc>,
        occurrence_key: String,
    },
}

const MISFIRE_WINDOW_HOURS: i64 = 6;

/// Resolve missed occurrences at startup/after downtime (spec 7.2): default
/// skip; run_once accepts only the most recent occurrence planned within the
/// last 6 hours — never replays a whole backlog.
pub fn resolve_misfire(
    spec: &ScheduleSpec,
    missed: Vec<Occurrence>,
    now: DateTime<Utc>,
) -> MisfireDecision {
    if missed.is_empty() {
        return MisfireDecision::Skip;
    }
    match spec.misfire_policy {
        MisfirePolicy::Skip => MisfireDecision::Skip,
        MisfirePolicy::RunOnce => {
            let Some(latest) = missed
                .into_iter()
                .filter(|occurrence| !occurrence.skipped_nonexistent)
                .max_by_key(|o| o.at_utc)
            else {
                return MisfireDecision::Skip;
            };
            let Some(planned_at) = latest.at_utc else {
                return MisfireDecision::Skip;
            };
            let age = now - planned_at;
            if age >= chrono::Duration::zero()
                && age <= chrono::Duration::hours(MISFIRE_WINDOW_HOURS)
            {
                MisfireDecision::RunOnce {
                    planned_at,
                    occurrence_key: latest.occurrence_key,
                }
            } else {
                MisfireDecision::Skip
            }
        }
    }
}

#[cfg(test)]
mod tests;
