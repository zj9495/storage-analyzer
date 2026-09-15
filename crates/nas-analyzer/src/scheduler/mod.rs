//! Durable scheduling semantics (spec 7.2, F02/F03).
//!
//! - daily / weekly (multi-select) / monthly (day-of-month) / 5-field cron;
//! - IANA timezones per profile; all persisted times are UTC;
//! - DST: a repeated wall-clock hour (fall-back) fires at most once per local
//!   wall time via the occurrence key; a nonexistent local time (spring
//!   forward) never matches and is reported as skipped;
//! - day-31 monthly schedules skip months without that day (UI shows this);
//! - misfire: default `skip`; `run_once` catches up at most one occurrence
//!   and only if it was planned within the last 6 hours.

pub mod schedule;

pub use schedule::{
    MisfireDecision, MisfirePolicy, Occurrence, OverlapPolicy, ScheduleSpec, ScheduleType,
    next_occurrences, occurrences_until, resolve_misfire, skipped_occurrences_until,
};
