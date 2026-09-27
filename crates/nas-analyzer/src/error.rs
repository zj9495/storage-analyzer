//! Stable business error codes shared by HTTP mapping and the frontend
//! (spec 17.1). Never match on Chinese message text; codes are the contract.

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    SetupRequired,
    ReadOnlyMode,
    PathOutsideRoot,
    SourceIdentityChanged,
    SourceUnavailable,
    DetailExpired,
    ReportIncompatible,
    FileChanged,
    HashIncomplete,
    PlanExpired,
    ProtectedFile,
    HardlinkNotAllowed,
    NoSurvivingCopy,
    QuarantineConflict,
    InsufficientDataSpace,
    UnsupportedCapability,
    JobStateConflict,
    PasswordChangeRequired,
    ResourceBusy,
    ResourceBudgetExceeded,
    ValidationFailed,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden,
    RateLimited,
    BadRequest,
    Internal,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SetupRequired => "SETUP_REQUIRED",
            Self::ReadOnlyMode => "READ_ONLY_MODE",
            Self::PathOutsideRoot => "PATH_OUTSIDE_ROOT",
            Self::SourceIdentityChanged => "SOURCE_IDENTITY_CHANGED",
            Self::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Self::DetailExpired => "DETAIL_EXPIRED",
            Self::ReportIncompatible => "REPORT_INCOMPATIBLE",
            Self::FileChanged => "FILE_CHANGED",
            Self::HashIncomplete => "HASH_INCOMPLETE",
            Self::PlanExpired => "PLAN_EXPIRED",
            Self::ProtectedFile => "PROTECTED_FILE",
            Self::HardlinkNotAllowed => "HARDLINK_NOT_ALLOWED",
            Self::NoSurvivingCopy => "NO_SURVIVING_COPY",
            Self::QuarantineConflict => "QUARANTINE_CONFLICT",
            Self::InsufficientDataSpace => "INSUFFICIENT_DATA_SPACE",
            Self::UnsupportedCapability => "UNSUPPORTED_CAPABILITY",
            Self::JobStateConflict => "JOB_STATE_CONFLICT",
            Self::PasswordChangeRequired => "PASSWORD_CHANGE_REQUIRED",
            Self::ResourceBusy => "RESOURCE_BUSY",
            Self::ResourceBudgetExceeded => "RESOURCE_BUDGET_EXCEEDED",
            Self::ValidationFailed => "VALIDATION_FAILED",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::RateLimited => "RATE_LIMITED",
            Self::BadRequest => "BAD_REQUEST",
            Self::Internal => "INTERNAL",
        }
    }

    pub fn http_status(&self) -> u16 {
        // Reconciled with api/openapi.yaml ErrorCode description (the API
        // contract). Exceptions pinned by spec 3.3 / 17.1: SETUP_REQUIRED and
        // PATH_OUTSIDE_ROOT keep their spec-mandated statuses and the openapi
        // description documents them accordingly.
        match self {
            Self::SetupRequired => 503,
            Self::ReadOnlyMode | Self::Forbidden | Self::PasswordChangeRequired => 403,
            Self::Unauthorized => 401,
            Self::NotFound => 404,
            Self::Conflict
            | Self::SourceIdentityChanged
            | Self::JobStateConflict
            | Self::FileChanged
            | Self::QuarantineConflict
            | Self::NoSurvivingCopy
            | Self::ReportIncompatible => 409,
            Self::DetailExpired | Self::PlanExpired => 410,
            Self::ValidationFailed
            | Self::ProtectedFile
            | Self::HardlinkNotAllowed
            | Self::HashIncomplete => 422,
            Self::PathOutsideRoot | Self::BadRequest => 400,
            Self::RateLimited | Self::ResourceBusy | Self::ResourceBudgetExceeded => 429,
            Self::InsufficientDataSpace | Self::SourceUnavailable | Self::UnsupportedCapability => {
                503
            }
            Self::Internal => 500,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub(crate) fn from_io(operation: impl Into<String>, error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
                ErrorCode::InsufficientDataSpace
            }
            _ => ErrorCode::Internal,
        };
        Self::new(code, format!("{}: {error}", operation.into()))
    }

    pub(crate) fn from_sqlite(operation: impl Into<String>, error: rusqlite::Error) -> Self {
        let code = if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
            ErrorCode::InsufficientDataSpace
        } else {
            ErrorCode::Internal
        };
        Self::new(code, format!("{}: {error}", operation.into()))
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;

impl From<rusqlite::Error> for AppError {
    fn from(error: rusqlite::Error) -> Self {
        AppError::from_sqlite("SQLite error", error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_full_io_maps_to_capacity_error_contract() {
        let error = AppError::from_io(
            "写入报告 manifest",
            std::io::Error::from(std::io::ErrorKind::StorageFull),
        );

        assert_eq!(error.code, ErrorCode::InsufficientDataSpace);
        assert_eq!(error.code.as_str(), "INSUFFICIENT_DATA_SPACE");
        assert_eq!(error.code.http_status(), 503);
    }

    #[test]
    fn sqlite_disk_full_maps_to_capacity_error_contract() {
        let sqlite_error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            None,
        );
        let error = AppError::from_sqlite("写入报告数据库", sqlite_error);

        assert_eq!(error.code, ErrorCode::InsufficientDataSpace);
        assert_eq!(error.code.http_status(), 503);
    }

    #[test]
    fn unrelated_io_remains_internal() {
        let error = AppError::from_io(
            "打开报告文件",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );

        assert_eq!(error.code, ErrorCode::Internal);
    }
}
