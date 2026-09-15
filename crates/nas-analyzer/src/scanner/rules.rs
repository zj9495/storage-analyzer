//! Include/exclude rule engine (spec 10.2).
//!
//! Evaluation order for every entry (matched on the source-relative path,
//! raw bytes for the name-component checks, lossy display string for globs —
//! rules never feed back into identity):
//!
//! 1. system-forced exclusions (always on, cannot be disabled):
//!    `.nas-analyzer-quarantine` and the app data dir names `runs/`,
//!    `reports/`, `exports/`, `cache/`, `secrets/`, `config-backups/`, matched
//!    against ANY path component;
//! 2. preset "skip system index & recycle" names (`@eaDir`, `#recycle`,
//!    `$RECYCLE.BIN`), toggleable, default on;
//! 3. hidden entries (leading-dot components) when `include_hidden` is false;
//! 4. task + source exclusion globs (exclusion wins over inclusion);
//! 5. inclusion globs apply to FILES only — a directory that matches no
//!    include pattern is still descended, because it may contain matching
//!    descendants (spec 10.2: 包含条件不得跳过可能匹配的后代).
//!
//! Glob semantics (globset, `literal_separator(true)`): `/` is the path
//! separator, `*` does not cross `/`, `**` matches any depth; a pattern
//! without `/` also matches the entry basename at any depth (gitignore-like).
//! Matching is case-sensitive.

use globset::{Glob, GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};

use crate::error::{AppError, AppResult, ErrorCode};

/// App-internal trees that must never be scanned even if they end up inside
/// a source (spec 10.2: 应用自己的数据…永久排除，不能通过 UI 取消).
const FORCED_EXCLUDE_NAMES: &[&[u8]] = &[
    b".nas-analyzer-quarantine",
    b"runs",
    b"reports",
    b"exports",
    b"cache",
    b"secrets",
    b"config-backups",
];

/// Preset "skip system index & recycle" names. These are common NAS vendor
/// names, NOT a UGREEN directory-structure guarantee; users may toggle the
/// preset off.
const PRESET_SYSTEM_NAMES: &[&[u8]] = &[b"@eaDir", b"#recycle", b"$RECYCLE.BIN"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludeReason {
    SystemForced,
    SystemPreset,
    Hidden,
    ExcludeGlob,
    NotIncluded,
}

impl ExcludeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SystemForced => "system_forced",
            Self::SystemPreset => "system_preset",
            Self::Hidden => "hidden",
            Self::ExcludeGlob => "exclude_glob",
            Self::NotIncluded => "not_included",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Include,
    Exclude(ExcludeReason),
}

pub struct RuleEngine {
    include_hidden: bool,
    preset_enabled: bool,
    exclude_set: GlobSet,
    exclude_basename: Vec<GlobMatcher>,
    include_set: GlobSet,
    include_basename: Vec<GlobMatcher>,
    has_includes: bool,
}

fn compile(patterns: &[String]) -> AppResult<(GlobSet, Vec<GlobMatcher>)> {
    let mut set = GlobSetBuilder::new();
    let mut basename = Vec::new();
    for pat in patterns {
        let glob: Glob = GlobBuilder::new(pat)
            .literal_separator(true)
            .build()
            .map_err(|e| {
                AppError::new(
                    ErrorCode::ValidationFailed,
                    format!("排除/包含规则不是有效的 glob: {pat:?}（{e}）"),
                )
            })?;
        if !pat.contains('/') {
            basename.push(glob.compile_matcher());
        }
        set.add(glob);
    }
    let set = set.build().map_err(|e| {
        AppError::new(
            ErrorCode::ValidationFailed,
            format!("构建 glob 集合失败: {e}"),
        )
    })?;
    Ok((set, basename))
}

impl RuleEngine {
    pub fn build(
        exclude_globs: &[String],
        include_globs: &[String],
        include_hidden: bool,
        preset_enabled: bool,
    ) -> AppResult<Self> {
        let (exclude_set, exclude_basename) = compile(exclude_globs)?;
        let (include_set, include_basename) = compile(include_globs)?;
        Ok(Self {
            include_hidden,
            preset_enabled,
            exclude_set,
            exclude_basename,
            has_includes: !include_set.is_empty() || !include_basename.is_empty(),
            include_set,
            include_basename,
        })
    }

    /// Decide whether the entry at source-relative path `rel` participates in
    /// the scan. `rel` is empty for the source root itself (always included).
    pub fn decide(&self, rel: &[u8], is_dir: bool) -> Decision {
        if rel.is_empty() {
            return Decision::Include;
        }
        let comps: Vec<&[u8]> = rel
            .split(|b| *b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        for comp in &comps {
            if FORCED_EXCLUDE_NAMES.contains(comp) {
                return Decision::Exclude(ExcludeReason::SystemForced);
            }
            if self.preset_enabled && PRESET_SYSTEM_NAMES.contains(comp) {
                return Decision::Exclude(ExcludeReason::SystemPreset);
            }
            if !self.include_hidden && comp.starts_with(b".") {
                return Decision::Exclude(ExcludeReason::Hidden);
            }
        }
        let display = String::from_utf8_lossy(rel);
        if self.exclude_set.is_match(display.as_ref()) {
            return Decision::Exclude(ExcludeReason::ExcludeGlob);
        }
        let basename = comps
            .last()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default();
        if self
            .exclude_basename
            .iter()
            .any(|m| m.is_match(basename.as_str()))
        {
            return Decision::Exclude(ExcludeReason::ExcludeGlob);
        }
        // Inclusion narrows files only; directories are always descended so
        // that matching descendants are still reachable.
        if !is_dir && self.has_includes {
            let included = self.include_set.is_match(display.as_ref())
                || self
                    .include_basename
                    .iter()
                    .any(|m| m.is_match(basename.as_str()));
            if !included {
                return Decision::Exclude(ExcludeReason::NotIncluded);
            }
        }
        Decision::Include
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(excl: &[&str], incl: &[&str], hidden: bool, preset: bool) -> RuleEngine {
        let excl: Vec<String> = excl.iter().map(|s| s.to_string()).collect();
        let incl: Vec<String> = incl.iter().map(|s| s.to_string()).collect();
        RuleEngine::build(&excl, &incl, hidden, preset).unwrap()
    }

    #[test]
    fn forced_exclusions_always_on() {
        // No toggle exists for these; even with the preset off and includes
        // matching, quarantine and app data dirs stay excluded.
        let e = engine(&[], &["**/*.txt"], true, false);
        assert_eq!(
            e.decide(b"a/.nas-analyzer-quarantine/x.txt", false),
            Decision::Exclude(ExcludeReason::SystemForced)
        );
        for dir in [
            "runs",
            "reports",
            "exports",
            "cache",
            "secrets",
            "config-backups",
        ] {
            let p = format!("deep/{dir}/f.bin");
            assert_eq!(
                e.decide(p.as_bytes(), false),
                Decision::Exclude(ExcludeReason::SystemForced),
                "{dir}"
            );
        }
        assert_eq!(
            e.decide(b".nas-analyzer-quarantine", true),
            Decision::Exclude(ExcludeReason::SystemForced)
        );
    }

    #[test]
    fn preset_toggle() {
        let on = engine(&[], &[], true, true);
        assert_eq!(
            on.decide(b"photos/@eaDir", true),
            Decision::Exclude(ExcludeReason::SystemPreset)
        );
        assert_eq!(
            on.decide(b"#recycle/old.txt", false),
            Decision::Exclude(ExcludeReason::SystemPreset)
        );
        assert_eq!(
            on.decide(b"$RECYCLE.BIN/x", false),
            Decision::Exclude(ExcludeReason::SystemPreset)
        );
        let off = engine(&[], &[], true, false);
        assert_eq!(off.decide(b"photos/@eaDir", true), Decision::Include);
        assert_eq!(off.decide(b"@eaDir/thumb.jpg", false), Decision::Include);
    }

    #[test]
    fn parent_excluded_prunes_child() {
        // The walk never descends into an excluded directory, so a child of
        // an excluded parent is never even evaluated; engine-level the child
        // path is excluded too because every component is checked.
        let e = engine(&["media"], &[], true, false);
        assert_eq!(
            e.decide(b"media", true),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
        let e2 = engine(&[], &[], true, true);
        assert_eq!(
            e2.decide(b"x/@eaDir/y/f.txt", false),
            Decision::Exclude(ExcludeReason::SystemPreset)
        );
    }

    #[test]
    fn include_globs_never_prune_dirs() {
        let e = engine(&[], &["**/*.txt"], true, false);
        // Directory does not match the include pattern but must be descended.
        assert_eq!(e.decide(b"plain", true), Decision::Include);
        assert_eq!(e.decide(b"plain/nested", true), Decision::Include);
        assert_eq!(e.decide(b"plain/a.txt", false), Decision::Include);
        assert_eq!(
            e.decide(b"plain/a.bin", false),
            Decision::Exclude(ExcludeReason::NotIncluded)
        );
        // Basename include pattern (no slash) matches at any depth.
        let e2 = engine(&[], &["*.md"], true, false);
        assert_eq!(
            e2.decide(b"deep/nested/readme.md", false),
            Decision::Include
        );
        assert_eq!(
            e2.decide(b"deep/nested/readme.txt", false),
            Decision::Exclude(ExcludeReason::NotIncluded)
        );
    }

    #[test]
    fn exclusion_wins_over_inclusion() {
        let e = engine(&["**/secret*"], &["**/*.txt"], true, false);
        assert_eq!(
            e.decide(b"docs/secret.txt", false),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
        assert_eq!(e.decide(b"docs/public.txt", false), Decision::Include);
    }

    #[test]
    fn glob_semantics_star_vs_globstar() {
        let e = engine(&["**/*.tmp"], &[], true, false);
        assert_eq!(
            e.decide(b"a/b/c.tmp", false),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
        // `**/` also matches zero components.
        assert_eq!(
            e.decide(b"top.tmp", false),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
        // Single `*` must not cross `/`.
        let e2 = engine(&["media/*.bin"], &[], true, false);
        assert_eq!(
            e2.decide(b"media/m.bin", false),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
        assert_eq!(e2.decide(b"media/sub/m.bin", false), Decision::Include);
        // Basename fallback: pattern without `/` matches at any depth.
        let e3 = engine(&["*.swp"], &[], true, false);
        assert_eq!(
            e3.decide(b"x/y/z.swp", false),
            Decision::Exclude(ExcludeReason::ExcludeGlob)
        );
    }

    #[test]
    fn hidden_toggle() {
        let off = engine(&[], &[], false, false);
        assert_eq!(
            off.decide(b".git/config", false),
            Decision::Exclude(ExcludeReason::Hidden)
        );
        assert_eq!(
            off.decide(b".env", false),
            Decision::Exclude(ExcludeReason::Hidden)
        );
        let on = engine(&[], &[], true, false);
        assert_eq!(on.decide(b".env", false), Decision::Include);
        assert_eq!(on.decide(b".git/config", false), Decision::Include);
    }

    #[test]
    fn invalid_glob_rejected() {
        assert!(RuleEngine::build(&["[unclosed".to_string()], &[], true, true).is_err());
    }
}
