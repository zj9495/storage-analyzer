//! fssecure: all filesystem access to approved roots goes through this crate.
//!
//! Invariants enforced here:
//! - paths are resolved relative to an already-open approved root directory FD
//!   using openat2(RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV) when the kernel
//!   supports it, otherwise a tested per-component no-follow fallback;
//! - symlinks are never followed; mount boundaries are never crossed;
//! - raw path bytes (OsStr) are used, never lossy display strings;
//! - write operations (mkdir/rename/unlink) share the same resolution model.

pub mod entry;
pub mod error;
pub mod root;

pub use entry::{DirEntryInfo, EntryKind, FileIdentity, StatData};
pub use error::{FsSecureError, Result};
pub use root::{OpenOptions, OpenedFile, SecureRoot, SecurityCaps};
