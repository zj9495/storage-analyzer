use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};

use crate::entry::{DirEntryInfo, EntryKind, FileIdentity, StatData};
use crate::error::{FsSecureError, Result};

#[cfg(target_os = "linux")]
use rustix::fs::ResolveFlags;

#[cfg(target_os = "linux")]
const RESOLVE_SAFE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_MAGICLINKS);

// rustix 1.x names this flag CREATE on every platform (no CREAT/CREATE
// spelling split).
const O_CREATE: OFlags = OFlags::CREATE;

/// Kernel/runtime security capabilities detected once at startup.
#[derive(Debug, Clone, Copy)]
pub struct SecurityCaps {
    /// openat2(2) with RESOLVE_BENEATH/NO_SYMLINKS/NO_XDEV available.
    /// Always false on non-Linux development hosts.
    pub openat2: bool,
}

impl SecurityCaps {
    /// Write operations (quarantine/restore/purge) require the strong
    /// resolution path. Read-only analysis may use the tested per-component
    /// no-follow fallback when openat2 is unavailable.
    pub fn supports_safe_writes(&self) -> bool {
        self.openat2
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    /// Request O_NOATIME for content reads of regular files. If the kernel
    /// denies it (EPERM), the open is retried without the flag and the result
    /// reports `used_noatime == false`; callers must surface that the atime
    /// may have been updated and must never "restore" atime via utime.
    pub noatime: bool,
    /// Write access (only for the app's own directories; sources are opened
    /// read-only).
    pub write: bool,
    pub create: bool,
    pub exclusive: bool,
    pub truncate: bool,
}

#[derive(Debug)]
pub struct OpenedFile {
    pub fd: OwnedFd,
    pub stat: StatData,
    pub used_noatime: bool,
}

/// An approved root directory. Every path passed to this type is a raw-byte
/// relative path interpreted strictly beneath the root.
pub struct SecureRoot {
    dir: OwnedFd,
    dev: u64,
    caps: SecurityCaps,
    /// Canonicalized root path, used only by the non-Linux development-host
    /// read_dir fallback (fd-based listing is Linux getdents only).
    #[cfg(not(target_os = "linux"))]
    path: std::path::PathBuf,
}

impl SecureRoot {
    /// Open an approved root. `path` must be an absolute path selected from
    /// the deployment configuration allow-list by the caller; from here on
    /// only root-relative operations are possible.
    pub fn open(path: &OsStr) -> Result<Self> {
        let (dir, dev) = open_root_dir(path)?;
        let caps = SecurityCaps {
            openat2: probe_openat2(&dir),
        };
        Ok(Self {
            dir,
            dev,
            caps,
            #[cfg(not(target_os = "linux"))]
            path: std::fs::canonicalize(path)?,
        })
    }

    /// Test hook: construct a root with explicitly supplied capabilities so
    /// tests can exercise fail-closed write behavior on kernels that do
    /// provide openat2. Not part of the supported API.
    #[doc(hidden)]
    pub fn new_with_caps_for_test(path: &OsStr, caps: SecurityCaps) -> Result<Self> {
        let (dir, dev) = open_root_dir(path)?;
        Ok(Self {
            dir,
            dev,
            caps,
            #[cfg(not(target_os = "linux"))]
            path: std::fs::canonicalize(path)?,
        })
    }

    pub fn caps(&self) -> SecurityCaps {
        self.caps
    }

    /// Duplicate the already-approved root descriptor for a bounded worker.
    /// The duplicate keeps the same mount boundary, capability decision, and
    /// (on development hosts) pinned canonical listing path; it never
    /// re-opens the caller's display path.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            dir: self.dup_root()?,
            dev: self.dev,
            caps: self.caps,
            #[cfg(not(target_os = "linux"))]
            path: self.path.clone(),
        })
    }

    pub fn root_fd(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// Resolve `rel` beneath the root and open the resulting directory.
    /// `rel` may be empty to refer to the root itself.
    pub fn open_dir(&self, rel: &OsStr) -> Result<OwnedFd> {
        if rel.is_empty() {
            return self.dup_root();
        }
        self.resolve(
            rel,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    /// Resolve `rel` beneath the root and open a regular file. Symlinks and
    /// non-regular files are rejected; the returned stat is obtained from the
    /// already-open FD (no TOCTOU window between check and use).
    pub fn open_file(&self, rel: &OsStr, opts: OpenOptions) -> Result<OpenedFile> {
        let mut oflags = if opts.write {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        } | OFlags::CLOEXEC;
        if opts.create {
            oflags |= O_CREATE;
        }
        if opts.exclusive {
            oflags |= OFlags::EXCL;
        }
        if opts.truncate {
            oflags |= OFlags::TRUNC;
        }
        // openat2 rejects a nonzero creation mode unless O_CREAT is set
        // (EINVAL), so only pass a mode when actually creating.
        let mode = if opts.create {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let (fd, used_noatime) = if opts.noatime && !opts.write {
            match self.resolve(rel, oflags | OFlags::NOATIME, mode) {
                Ok(fd) => (fd, true),
                Err(FsSecureError::PermissionDenied) => (self.resolve(rel, oflags, mode)?, false),
                Err(e) => return Err(e),
            }
        } else {
            (self.resolve(rel, oflags, mode)?, false)
        };
        // O_NOATIME does not exist on non-Linux development hosts; content
        // reads there always report used_noatime = false.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let (fd, used_noatime) = (self.resolve(rel, oflags, mode)?, false);
        let st = rustix::fs::fstat(&fd).map_err(map_errno)?;
        let data = stat_to_data(st)?;
        if !opts.write && data.kind != EntryKind::RegularFile && !opts.create {
            return Err(FsSecureError::NotRegularFile);
        }
        Ok(OpenedFile {
            fd,
            stat: data,
            used_noatime,
        })
    }

    /// Stat `rel` without following symlinks (a symlink as the final
    /// component is reported, never followed). Intermediate components are
    /// resolved through the same no-follow path as opens, so a symlink
    /// planted in a parent directory cannot make stat escape the root.
    pub fn stat(&self, rel: &OsStr) -> Result<StatData> {
        validate_relative(rel)?;
        let comps = split_components(rel)?;
        let st = match comps.last() {
            None => rustix::fs::fstat(&self.dir).map_err(map_errno)?,
            Some(last) if comps.len() == 1 => {
                rustix::fs::statat(&self.dir, last.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(map_errno)?
            }
            Some(last) => {
                let mut parent = OsString::new();
                for c in &comps[..comps.len() - 1] {
                    if !parent.is_empty() {
                        parent.push("/");
                    }
                    parent.push(c);
                }
                let pfd = self.resolve(
                    parent.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                rustix::fs::statat(&pfd, last.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(map_errno)?
            }
        };
        let data = stat_to_data(st)?;
        if data.identity.device_id != self.dev {
            return Err(FsSecureError::MountCrossingNotAllowed);
        }
        Ok(data)
    }
    /// Iterate a directory opened through this root. Names are raw bytes;
    /// `.` and `..` are skipped. The kernel yields entries in batches; the
    /// caller controls memory by consuming the iterator incrementally.
    pub fn read_dir(&self, rel: &OsStr) -> Result<SecureDirIter> {
        // Resolve and open first: this enforces the boundary (no symlinks,
        // no mount crossings) regardless of which listing backend runs.
        let fd = self.open_dir(rel)?;
        #[cfg(target_os = "linux")]
        {
            SecureDirIter::from_fd(fd)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Development hosts cannot list a directory from an fd without
            // unsafe fdopendir(3); the boundary has already been enforced by
            // open_dir above, so list through the pinned canonical path.
            drop(fd);
            SecureDirIter::from_path(self.path.join(rel))
        }
    }

    /// Create a directory beneath the root (used for quarantine layout).
    /// Fails if the final component exists or any component is a symlink.
    pub fn mkdir(&self, rel: &OsStr, mode: u32) -> Result<()> {
        self.require_write_caps()?;
        let (parent, name) = self.parent_and_name(rel)?;
        rustix::fs::mkdirat(&parent, &name, Mode::from_bits_retain(mode as _)).map_err(map_errno)
    }

    /// Create a directory and all missing parents beneath the root, each
    /// resolved without following symlinks.
    pub fn mkdir_all(&self, rel: &OsStr, mode: u32) -> Result<()> {
        self.require_write_caps()?;
        let comps = split_components(rel)?;
        let mut cur = OsString::new();
        for c in comps {
            if !cur.is_empty() {
                cur.push("/");
            }
            cur.push(&c);
            match self.mkdir(cur.as_os_str(), mode) {
                Ok(()) | Err(FsSecureError::AlreadyExists) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Atomic rename within this root; never replaces an existing target.
    pub fn rename_noreplace(&self, from: &OsStr, to: &OsStr) -> Result<()> {
        self.require_write_caps()?;
        let (from_parent, from_name) = self.parent_and_name(from)?;
        let (to_parent, to_name) = self.parent_and_name(to)?;
        rename_noreplace(&from_parent, &from_name, &to_parent, &to_name)
    }

    /// Remove a single regular file beneath the root (never a directory).
    pub fn unlink_file(&self, rel: &OsStr) -> Result<()> {
        self.require_write_caps()?;
        let (parent, name) = self.parent_and_name(rel)?;
        let st =
            rustix::fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        self.ensure_same_device(&st)?;
        if file_type_to_kind(FileType::from_raw_mode(st.st_mode)) != EntryKind::RegularFile {
            return Err(FsSecureError::NotRegularFile);
        }
        #[cfg(target_os = "linux")]
        {
            self.verify_regular_file_at(&parent, &name, &st)?;
            self.verify_entry_at(&parent, &name, &st)?;
        }
        rustix::fs::unlinkat(&parent, &name, AtFlags::empty()).map_err(map_errno)
    }

    /// Recursively remove a directory beneath the root.
    ///
    /// The target and every descendant are resolved from already-open
    /// directory descriptors. The complete tree is first checked for
    /// symbolic links, mount crossings, and unsupported entry kinds so a
    /// malformed report tree is rejected before any child is removed. The
    /// deletion pass revalidates each name immediately before unlinking it;
    /// an identity change never causes the replacement object to be removed.
    /// The approved root itself cannot be removed because `rel` must name a
    /// non-empty relative path.
    pub fn remove_dir_all(&self, rel: &OsStr) -> Result<()> {
        self.require_write_caps()?;
        #[cfg(target_os = "linux")]
        {
            let (parent, name) = self.parent_and_name(rel)?;
            let expected =
                rustix::fs::statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
            self.ensure_same_device(&expected)?;
            if file_type_to_kind(FileType::from_raw_mode(expected.st_mode)) == EntryKind::Symlink {
                return Err(FsSecureError::SymlinkNotAllowed);
            }
            if file_type_to_kind(FileType::from_raw_mode(expected.st_mode)) != EntryKind::Directory
            {
                return Err(FsSecureError::NotDirectory);
            }

            let directory = self.open_directory_at(&parent, &name, &expected)?;
            self.validate_directory_tree(&directory)?;
            self.remove_directory_tree(&directory)?;
            self.open_directory_at(&parent, &name, &expected)?;
            rustix::fs::unlinkat(&parent, &name, AtFlags::REMOVEDIR).map_err(map_errno)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = rel;
            Err(FsSecureError::MissingCapability)
        }
    }

    pub fn fsync_dir(&self, rel: &OsStr) -> Result<()> {
        let fd = self.open_dir(rel)?;
        rustix::fs::fsync(fd).map_err(map_errno)
    }

    fn dup_root(&self) -> Result<OwnedFd> {
        rustix::fs::openat(
            &self.dir,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_errno)
    }

    fn require_write_caps(&self) -> Result<()> {
        if !self.caps.supports_safe_writes() {
            return Err(FsSecureError::MissingCapability);
        }
        Ok(())
    }

    #[allow(clippy::unnecessary_cast)]
    fn ensure_same_device(&self, st: &Stat) -> Result<()> {
        if st.st_dev as u64 != self.dev {
            return Err(FsSecureError::MountCrossingNotAllowed);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::unnecessary_cast)]
    fn ensure_same_entry(expected: &Stat, actual: &Stat) -> Result<()> {
        if FileType::from_raw_mode(actual.st_mode) == FileType::Symlink {
            return Err(FsSecureError::SymlinkNotAllowed);
        }
        if expected.st_dev as u64 != actual.st_dev as u64
            || expected.st_ino as u64 != actual.st_ino as u64
            || FileType::from_raw_mode(expected.st_mode) != FileType::from_raw_mode(actual.st_mode)
        {
            return Err(FsSecureError::IdentityChanged);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_directory_at(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        expected: &Stat,
    ) -> Result<OwnedFd> {
        let directory = rustix::fs::openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_SAFE,
        )
        .map_err(map_errno)?;
        let actual = rustix::fs::fstat(&directory).map_err(map_errno)?;
        self.ensure_same_device(&actual)?;
        Self::ensure_same_entry(expected, &actual)?;
        if FileType::from_raw_mode(actual.st_mode) != FileType::Directory {
            return Err(FsSecureError::NotDirectory);
        }
        Ok(directory)
    }

    #[cfg(target_os = "linux")]
    fn verify_regular_file_at(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        expected: &Stat,
    ) -> Result<()> {
        let file = rustix::fs::openat2(
            parent,
            name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_SAFE,
        )
        .map_err(map_errno)?;
        let actual = rustix::fs::fstat(&file).map_err(map_errno)?;
        self.ensure_same_device(&actual)?;
        Self::ensure_same_entry(expected, &actual)?;
        if FileType::from_raw_mode(actual.st_mode) != FileType::RegularFile {
            return Err(FsSecureError::NotRegularFile);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_entry_at(&self, parent: &OwnedFd, name: &OsStr, expected: &Stat) -> Result<()> {
        let actual =
            rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        self.ensure_same_device(&actual)?;
        Self::ensure_same_entry(expected, &actual)
    }

    #[cfg(target_os = "linux")]
    fn directory_names(&self, directory: &OwnedFd) -> Result<Vec<OsString>> {
        let mut stream = rustix::fs::Dir::read_from(directory).map_err(map_errno)?;
        let mut names = Vec::new();
        for entry in &mut stream {
            let entry = entry.map_err(map_errno)?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsString::from(OsStr::from_bytes(bytes)));
        }
        Ok(names)
    }

    #[cfg(target_os = "linux")]
    fn validate_directory_tree(&self, directory: &OwnedFd) -> Result<()> {
        for name in self.directory_names(directory)? {
            let entry = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(map_errno)?;
            self.ensure_same_device(&entry)?;
            match file_type_to_kind(FileType::from_raw_mode(entry.st_mode)) {
                EntryKind::Directory => {
                    let child = self.open_directory_at(directory, &name, &entry)?;
                    self.validate_directory_tree(&child)?;
                }
                EntryKind::RegularFile => {
                    self.verify_regular_file_at(directory, &name, &entry)?;
                }
                EntryKind::Symlink => return Err(FsSecureError::SymlinkNotAllowed),
                _ => return Err(FsSecureError::NotRegularFile),
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_directory_tree(&self, directory: &OwnedFd) -> Result<()> {
        for name in self.directory_names(directory)? {
            let entry = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(map_errno)?;
            self.ensure_same_device(&entry)?;
            match file_type_to_kind(FileType::from_raw_mode(entry.st_mode)) {
                EntryKind::Directory => {
                    let child = self.open_directory_at(directory, &name, &entry)?;
                    self.remove_directory_tree(&child)?;
                    self.open_directory_at(directory, &name, &entry)?;
                    rustix::fs::unlinkat(directory, &name, AtFlags::REMOVEDIR)
                        .map_err(map_errno)?;
                }
                EntryKind::RegularFile => {
                    self.verify_regular_file_at(directory, &name, &entry)?;
                    self.verify_entry_at(directory, &name, &entry)?;
                    rustix::fs::unlinkat(directory, &name, AtFlags::empty()).map_err(map_errno)?;
                }
                EntryKind::Symlink => return Err(FsSecureError::SymlinkNotAllowed),
                _ => return Err(FsSecureError::NotRegularFile),
            }
        }
        Ok(())
    }

    fn parent_and_name(&self, rel: &OsStr) -> Result<(OwnedFd, OsString)> {
        validate_relative(rel)?;
        let components = split_components(rel)?;
        let Some(name) = components.last().cloned() else {
            return Err(FsSecureError::InvalidComponent(
                "operation requires a non-empty relative path".to_string(),
            ));
        };
        let parent = if components.len() == 1 {
            self.dup_root()?
        } else {
            let mut parent_path = OsString::new();
            for component in &components[..components.len() - 1] {
                if !parent_path.is_empty() {
                    parent_path.push("/");
                }
                parent_path.push(component);
            }
            self.resolve(
                &parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?
        };
        Ok((parent, name))
    }

    fn resolve(&self, rel: &OsStr, oflags: OFlags, mode: Mode) -> Result<OwnedFd> {
        validate_relative(rel)?;
        #[cfg(target_os = "linux")]
        if self.caps.openat2 {
            return rustix::fs::openat2(&self.dir, rel, oflags, mode, RESOLVE_SAFE)
                .map_err(map_errno);
        }
        self.resolve_fallback(rel, oflags, mode)
    }

    /// Tested fallback when openat2 is unavailable (old kernels, non-Linux
    /// development hosts): resolve each component with O_NOFOLLOW and verify
    /// st_dev never changes. Never used for write operations
    /// (require_write_caps guards those).
    fn resolve_fallback(&self, rel: &OsStr, oflags: OFlags, mode: Mode) -> Result<OwnedFd> {
        let mut cur = self.dup_root()?;
        let comps = split_components(rel)?;
        let Some(last) = comps.len().checked_sub(1) else {
            return Ok(cur);
        };
        for (i, comp) in comps.iter().enumerate() {
            let st = rustix::fs::statat(&cur, comp.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(map_errno)?;
            if (st.st_dev as u64) != self.dev {
                return Err(FsSecureError::MountCrossingNotAllowed);
            }
            // The openat below enforces no-follow; reporting the symlink
            // explicitly keeps the error stable across kernels (macOS
            // returns ENOTDIR rather than ELOOP for O_NOFOLLOW|O_DIRECTORY).
            if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
                return Err(FsSecureError::SymlinkNotAllowed);
            }
            let flags = if i == last {
                oflags | OFlags::NOFOLLOW
            } else {
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
            };
            let next =
                rustix::fs::openat(&cur, comp.as_os_str(), flags, mode).map_err(map_errno)?;
            let st2 = rustix::fs::fstat(&next).map_err(map_errno)?;
            if (st2.st_dev as u64) != self.dev {
                return Err(FsSecureError::MountCrossingNotAllowed);
            }
            cur = next;
        }
        Ok(cur)
    }
}

#[cfg(target_os = "linux")]
fn probe_openat2(dir: &OwnedFd) -> bool {
    rustix::fs::openat2(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_SAFE,
    )
    .is_ok()
}

#[cfg(not(target_os = "linux"))]
fn probe_openat2(_dir: &OwnedFd) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    from_parent: &OwnedFd,
    from: &OsStr,
    to_parent: &OwnedFd,
    to: &OsStr,
) -> Result<()> {
    rustix::fs::renameat_with(
        from_parent,
        from,
        to_parent,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(map_errno)
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(
    from_parent: &OwnedFd,
    from: &OsStr,
    to_parent: &OwnedFd,
    to: &OsStr,
) -> Result<()> {
    // No RENAME_NOREPLACE off Linux; writes are disabled there anyway
    // (require_write_caps), so this path is unreachable in practice.
    let _ = (from_parent, from, to_parent, to);
    Err(FsSecureError::MissingCapability)
}

enum DirBackend {
    #[cfg(target_os = "linux")]
    Linux(rustix::fs::Dir),
    #[cfg(not(target_os = "linux"))]
    Compat(std::fs::ReadDir),
}

pub struct SecureDirIter {
    backend: DirBackend,
}

impl SecureDirIter {
    #[cfg(target_os = "linux")]
    fn from_fd(fd: OwnedFd) -> Result<Self> {
        Ok(Self {
            backend: DirBackend::Linux(rustix::fs::Dir::read_from(fd).map_err(map_errno)?),
        })
    }

    /// Development-host fallback: iterate via the canonicalized root path
    /// captured at open time. Only ever used on non-Linux hosts where write
    /// capability is disabled and the caller has already enforced the
    /// boundary with open_dir; production targets always take the getdents
    /// path.
    #[cfg(not(target_os = "linux"))]
    fn from_path(path: std::path::PathBuf) -> Result<Self> {
        let it = std::fs::read_dir(path)?;
        Ok(Self {
            backend: DirBackend::Compat(it),
        })
    }
}

impl Iterator for SecureDirIter {
    type Item = Result<DirEntryInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            DirBackend::Linux(dir) => loop {
                match dir.next()? {
                    Ok(ent) => {
                        let bytes = ent.file_name().to_bytes();
                        if bytes == b"." || bytes == b".." {
                            continue;
                        }
                        return Some(Ok(DirEntryInfo {
                            name: OsString::from(OsStr::from_bytes(bytes)),
                            kind: file_type_to_kind(ent.file_type()),
                            inode_id: ent.ino(),
                        }));
                    }
                    Err(e) => return Some(Err(map_errno(e))),
                }
            },
            #[cfg(not(target_os = "linux"))]
            DirBackend::Compat(it) => loop {
                match it.next()? {
                    Ok(ent) => {
                        let name = ent.file_name();
                        let bytes = name.as_bytes();
                        if bytes == b"." || bytes == b".." {
                            continue;
                        }
                        let kind = match ent.file_type() {
                            Ok(ft) => {
                                if ft.is_dir() {
                                    EntryKind::Directory
                                } else if ft.is_symlink() {
                                    EntryKind::Symlink
                                } else if ft.is_file() {
                                    EntryKind::RegularFile
                                } else {
                                    EntryKind::Unknown
                                }
                            }
                            Err(_) => EntryKind::Unknown,
                        };
                        let inode_id = std::os::unix::fs::MetadataExt::ino(&match ent.metadata() {
                            Ok(m) => m,
                            Err(e) => return Some(Err(FsSecureError::Io(e))),
                        });
                        return Some(Ok(DirEntryInfo {
                            name,
                            kind,
                            inode_id,
                        }));
                    }
                    Err(e) => return Some(Err(FsSecureError::Io(e))),
                }
            },
        }
    }
}

fn open_root_dir(path: &OsStr) -> Result<(OwnedFd, u64)> {
    let dir = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_errno)?;
    let st = rustix::fs::fstat(&dir).map_err(map_errno)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(FsSecureError::NotDirectory);
    }
    Ok((dir, st.st_dev as u64))
}

fn validate_relative(rel: &OsStr) -> Result<()> {
    let bytes = rel.as_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > 4096 {
        return Err(FsSecureError::PathTooLong);
    }
    if bytes.starts_with(b"/") {
        return Err(FsSecureError::PathOutsideRoot);
    }
    split_components(rel)?;
    Ok(())
}

fn split_components(rel: &OsStr) -> Result<Vec<OsString>> {
    let mut out = Vec::new();
    for part in rel.as_bytes().split(|b| *b == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            return Err(FsSecureError::PathOutsideRoot);
        }
        out.push(OsString::from(OsStr::from_bytes(part)));
    }
    Ok(out)
}

// rustix `Stat` field widths differ across platforms (i32/u64 on macOS vs
// u64/u64 on Linux etc.); the casts normalize them. Allow the lint so the
// same source is clippy-clean on both.
#[allow(clippy::unnecessary_cast)]
fn stat_to_data(st: Stat) -> Result<StatData> {
    let size_bytes =
        i64::try_from(st.st_size as i128).map_err(|_| FsSecureError::NumericOverflow)?;
    if size_bytes < 0 {
        return Err(FsSecureError::NumericOverflow);
    }
    let allocated_blocks = (st.st_blocks as i128)
        .checked_mul(512)
        .ok_or(FsSecureError::NumericOverflow)?;
    let allocated_bytes_estimate =
        i64::try_from(allocated_blocks).map_err(|_| FsSecureError::NumericOverflow)?;
    Ok(StatData {
        kind: file_type_to_kind(FileType::from_raw_mode(st.st_mode)),
        identity: FileIdentity {
            device_id: st.st_dev as u64,
            inode_id: st.st_ino as u64,
        },
        nlink: st.st_nlink as u64,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode as u32,
        size_bytes,
        allocated_bytes_estimate,
        mtime: (st.st_mtime as i64, st.st_mtime_nsec as i64),
        atime: (st.st_atime as i64, st.st_atime_nsec as i64),
        ctime: (st.st_ctime as i64, st.st_ctime_nsec as i64),
        // Linux birthtime requires statx(2); not yet wired through. We report
        // None rather than fabricating a creation time from ctime.
        birthtime: None,
    })
}

fn file_type_to_kind(ft: FileType) -> EntryKind {
    match ft {
        FileType::RegularFile => EntryKind::RegularFile,
        FileType::Directory => EntryKind::Directory,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Fifo => EntryKind::Fifo,
        FileType::Socket => EntryKind::Socket,
        FileType::BlockDevice => EntryKind::BlockDevice,
        FileType::CharacterDevice => EntryKind::CharDevice,
        _ => EntryKind::Unknown,
    }
}

fn map_errno(e: rustix::io::Errno) -> FsSecureError {
    match e {
        rustix::io::Errno::NOENT => FsSecureError::NotFound,
        rustix::io::Errno::EXIST => FsSecureError::AlreadyExists,
        E_ACCESS | rustix::io::Errno::PERM => FsSecureError::PermissionDenied,
        rustix::io::Errno::XDEV => FsSecureError::CrossDevice,
        rustix::io::Errno::LOOP => FsSecureError::SymlinkNotAllowed,
        rustix::io::Errno::NOTDIR => FsSecureError::NotDirectory,
        rustix::io::Errno::NAMETOOLONG => FsSecureError::PathTooLong,
        rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT => FsSecureError::Io(e.into()),
        other => FsSecureError::Rustix(other),
    }
}

// rustix 1.x names this constant ACCESS on every platform (it no longer
// follows the libc EACCES/EACCESS spelling split).
const E_ACCESS: rustix::io::Errno = rustix::io::Errno::ACCESS;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn capacity_errno_preserves_io_kind_and_raw_errno() {
        for (errno, kind) in [
            (rustix::io::Errno::NOSPC, ErrorKind::StorageFull),
            (rustix::io::Errno::DQUOT, ErrorKind::QuotaExceeded),
        ] {
            let FsSecureError::Io(error) = map_errno(errno) else {
                panic!("capacity errno must remain an IO error");
            };
            assert_eq!(error.kind(), kind);
            assert_eq!(error.raw_os_error(), Some(errno.raw_os_error()));
        }
    }

    #[test]
    fn ordinary_errno_mappings_keep_their_existing_semantics() {
        assert!(matches!(
            map_errno(rustix::io::Errno::NOENT),
            FsSecureError::NotFound
        ));
        assert!(matches!(
            map_errno(E_ACCESS),
            FsSecureError::PermissionDenied
        ));
        assert!(matches!(
            map_errno(rustix::io::Errno::NOTDIR),
            FsSecureError::NotDirectory
        ));
        assert!(matches!(
            map_errno(rustix::io::Errno::XDEV),
            FsSecureError::CrossDevice
        ));
    }
}
