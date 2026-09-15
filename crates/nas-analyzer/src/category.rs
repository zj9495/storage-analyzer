//! File classification rules (spec 8.2, F08).
//!
//! - nine fixed builtin category ids;
//! - extension → category mapping with longest multi-part suffix match
//!   (tar.gz beats gz), ASCII case-insensitive comparison, original file
//!   names never rewritten;
//! - admin edits create a NEW immutable ruleset version; historical reports
//!   keep their snapshot;
//! - extension syntax: lowercase letters, digits, '-', '+', '_' and dots as
//!   multi-part separators; no slash/backslash/whitespace/control chars;
//!   one extension belongs to exactly one category (conflict rejected).

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult, ErrorCode};

pub const CATEGORY_IDS: [&str; 9] = [
    "audio",
    "disk_images",
    "documents",
    "executables",
    "pictures",
    "videos",
    "web_and_code",
    "archives",
    "other",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategoryRuleset {
    /// Monotonic version, persisted in category_rulesets.
    pub version: u32,
    /// extension (lowercase, no leading dot, dots allowed inside) → category id.
    pub mapping: BTreeMap<String, String>,
}

impl CategoryRuleset {
    /// Default mapping per spec 8.2 (independent re-implementation of the
    /// nine-category scheme; not a byte-copy of any DSM version's list).
    pub fn default_v1() -> Self {
        let mut m = BTreeMap::new();
        let mut add = |cat: &str, exts: &[&str]| {
            for e in exts {
                m.insert(e.to_string(), cat.to_string());
            }
        };
        add(
            "audio",
            &["mp3", "flac", "wav", "m4a", "ape", "ogg", "aac", "dsf"],
        );
        add(
            "disk_images",
            &["iso", "img", "bin", "dmg", "vhd", "vhdx", "qcow2"],
        );
        add(
            "documents",
            &[
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "rtf", "odt",
            ],
        );
        add("executables", &["exe", "msi", "apk", "appimage"]);
        add(
            "pictures",
            &[
                "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "tif", "tiff", "svg", "raw",
                "dng", "psd",
            ],
        );
        add(
            "videos",
            &["mp4", "mkv", "avi", "mov", "ts", "m2ts", "webm", "rmvb"],
        );
        add(
            "web_and_code",
            &[
                "html", "css", "js", "ts", "vue", "json", "xml", "py", "go", "java", "c", "cpp",
            ],
        );
        add(
            "archives",
            &[
                "zip", "7z", "rar", "tar", "gz", "bz2", "xz", "tar.gz", "tar.xz",
            ],
        );
        Self {
            version: 1,
            mapping: m,
        }
    }

    pub fn validate(&self) -> AppResult<()> {
        for (ext, cat) in &self.mapping {
            validate_extension(ext)?;
            if !CATEGORY_IDS.contains(&cat.as_str()) {
                return Err(AppError::new(
                    ErrorCode::ValidationFailed,
                    format!("未知分类 id：{cat}"),
                ));
            }
        }
        Ok(())
    }

    /// Classify a file name (raw bytes already decoded to display form by the
    /// caller for rule matching only; classification never feeds back into
    /// identity). Rules:
    /// - comparison on ASCII-lowercased name;
    /// - longest matching multi-part extension wins (tar.gz > gz);
    /// - dotfiles like `.env` have no extension → other;
    /// - `.config.json` classifies by `json`;
    /// - no extension / unknown extension → other.
    pub fn classify(&self, file_name: &str) -> (&'static str, Option<String>) {
        let lower: String = file_name.to_ascii_lowercase();
        // Strip a single leading dot group: ".env" → no basename extension;
        // `.config.json` keeps its inner part.
        let name = lower.strip_prefix('.').unwrap_or(&lower);
        let Some(dot) = name.find('.') else {
            return ("other", None);
        };
        let ext_part = &name[dot + 1..];
        if ext_part.is_empty() {
            return ("other", None);
        }
        // Longest suffix match over mapping keys.
        let mut best: Option<(&String, &String)> = None;
        for (ext, cat) in &self.mapping {
            if (ext_part == ext || ext_part.ends_with(&format!(".{ext}")))
                && best.is_none_or(|(b, _)| ext.len() > b.len())
            {
                best = Some((ext, cat));
            }
        }
        match best {
            Some((ext, cat)) => (category_id_static(cat), Some(ext.clone())),
            None => ("other", None),
        }
    }
}

/// Load the currently effective persisted ruleset. A fresh installation has
/// no row until the first settings write, so the versioned builtin ruleset is
/// the initial ruleset rather than a field-level fallback.
pub fn load_current(conn: &Connection) -> AppResult<CategoryRuleset> {
    let row: Option<(u32, String)> = conn
        .query_row(
            "SELECT version, rules_json FROM category_rulesets
             WHERE is_default = 1 ORDER BY version DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("读取分类规则集失败: {e}")))?;
    let Some((version, rules_json)) = row else {
        return Ok(CategoryRuleset::default_v1());
    };
    let mapping = serde_json::from_str(&rules_json)
        .map_err(|e| AppError::new(ErrorCode::Internal, format!("分类规则集数据损坏: {e}")))?;
    let ruleset = CategoryRuleset { version, mapping };
    ruleset.validate()?;
    Ok(ruleset)
}

fn category_id_static(cat: &str) -> &'static str {
    CATEGORY_IDS
        .iter()
        .copied()
        .find(|c| *c == cat)
        .unwrap_or("other")
}

pub fn validate_extension(ext: &str) -> AppResult<()> {
    if ext.is_empty() || ext.len() > 64 {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "扩展名长度必须为 1–64 字符",
        ));
    }
    let bytes = ext.as_bytes();
    if bytes[0] == b'.' || bytes[bytes.len() - 1] == b'.' || ext.contains("..") {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            format!("扩展名格式非法：{ext:?}"),
        ));
    }
    for &b in bytes {
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'_' | b'.');
        if !ok {
            return Err(AppError::new(
                ErrorCode::ValidationFailed,
                format!("扩展名 {ext:?} 含非法字符（仅允许小写字母、数字、-、+、_ 与多段分隔点）"),
            ));
        }
    }
    Ok(())
}

/// Build a new ruleset from admin edits, rejecting cross-category conflicts.
/// `changes`: (extension, category) pairs to set; category "other" with an
/// empty mapping entry removes the override... removal is expressed by
/// `removals`.
pub fn derive_ruleset(
    base: &CategoryRuleset,
    changes: &[(String, String)],
    removals: &[String],
    new_version: u32,
) -> AppResult<CategoryRuleset> {
    let mut mapping = base.mapping.clone();
    for ext in removals {
        mapping.remove(&ext.to_ascii_lowercase());
    }
    for (ext, cat) in changes {
        let ext = ext.to_ascii_lowercase();
        validate_extension(&ext)?;
        if !CATEGORY_IDS.contains(&cat.as_str()) {
            return Err(AppError::new(
                ErrorCode::ValidationFailed,
                format!("未知分类 id：{cat}"),
            ));
        }
        mapping.insert(ext, cat.clone());
    }
    let rs = CategoryRuleset {
        version: new_version,
        mapping,
    };
    rs.validate()?;
    Ok(rs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mapping_covers_spec_minimum() {
        let rs = CategoryRuleset::default_v1();
        rs.validate().unwrap();
        let required: [(&str, &str); 12] = [
            ("mp3", "audio"),
            ("iso", "disk_images"),
            ("pdf", "documents"),
            ("exe", "executables"),
            ("jpg", "pictures"),
            ("mp4", "videos"),
            ("html", "web_and_code"),
            ("zip", "archives"),
            ("tar.gz", "archives"),
            ("tar.xz", "archives"),
            ("psd", "pictures"),
            ("dsf", "audio"),
        ];
        for (ext, cat) in required {
            assert_eq!(rs.mapping.get(ext).map(String::as_str), Some(cat), "{ext}");
        }
    }

    #[test]
    fn longest_match_and_case() {
        let rs = CategoryRuleset::default_v1();
        assert_eq!(rs.classify("archive.tar.gz").0, "archives");
        assert_eq!(rs.classify("archive.tar.gz").1.as_deref(), Some("tar.gz"));
        assert_eq!(rs.classify("UPPER.JPG").0, "pictures");
        assert_eq!(rs.classify("movie.bin").0, "disk_images");
        assert_eq!(rs.classify("a.TAR.GZ").0, "archives");
    }

    #[test]
    fn dotfile_rules() {
        let rs = CategoryRuleset::default_v1();
        assert_eq!(rs.classify(".env").0, "other");
        assert_eq!(rs.classify(".config.json").0, "web_and_code");
        assert_eq!(rs.classify("noext").0, "other");
        assert_eq!(rs.classify("trailing.").0, "other");
    }

    #[test]
    fn invalid_extensions_rejected() {
        for bad in ["a/b", "a\\b", "a b", "A", "a\tb", ".gz", "gz.", "a..b", ""] {
            assert!(validate_extension(bad).is_err(), "{bad:?}");
        }
        for good in ["gz", "tar.gz", "c++", "x-1", "a_b"] {
            assert!(validate_extension(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn conflict_and_unknown_category_rejected() {
        let base = CategoryRuleset::default_v1();
        assert!(derive_ruleset(&base, &[("mp4".into(), "nope".into())], &[], 2).is_err());
        let ok = derive_ruleset(&base, &[("mp3".into(), "other".into())], &[], 2).unwrap();
        assert_eq!(ok.classify("x.mp3").0, "other");
        let removed = derive_ruleset(&base, &[], &["mp3".into()], 3).unwrap();
        assert_eq!(removed.classify("x.mp3").0, "other");
    }
}
