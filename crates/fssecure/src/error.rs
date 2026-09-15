use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsSecureError {
    #[error("path escapes the approved root")]
    PathOutsideRoot,
    #[error("path resolution would follow a symbolic link")]
    SymlinkNotAllowed,
    #[error("path resolution would cross a mount boundary")]
    MountCrossingNotAllowed,
    #[error("path component is invalid: {0}")]
    InvalidComponent(String),
    #[error("path is too long")]
    PathTooLong,
    #[error("entry is not a regular file")]
    NotRegularFile,
    #[error("entry is not a directory")]
    NotDirectory,
    #[error("entry does not exist")]
    NotFound,
    #[error("entry already exists")]
    AlreadyExists,
    #[error("operation would cross filesystems (EXDEV)")]
    CrossDevice,
    #[error("permission denied")]
    PermissionDenied,
    #[error("file identity changed between verification and use")]
    IdentityChanged,
    #[error("filesystem metadata value cannot be represented safely")]
    NumericOverflow,
    #[error(
        "kernel lacks required safe-resolution capability (openat2) and write operations are disabled"
    )]
    MissingCapability,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rustix error: {0}")]
    Rustix(#[from] rustix::io::Errno),
}

pub type Result<T> = std::result::Result<T, FsSecureError>;
