//! Isolated filesystem fixture generator for tests (03_ACCEPTANCE.md §1–2).
//!
//! Safety contract:
//! - fixtures are only ever created inside a freshly created empty temporary
//!   directory owned by the test process; never in a user-supplied path;
//! - the root carries a marker file; operations refuse roots without it;
//! - callers place a KEEP sentinel file OUTSIDE the root and verify it is
//!   byte-identical after the test (`verify_keep_sentinel`).

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

pub const MARKER: &str = ".nas-analyzer-test-fixture";

pub struct FixtureRoot {
    pub root: PathBuf,
    _guard: tempfile::TempDir,
}

impl FixtureRoot {
    /// Create a new empty temporary fixture root with marker.
    pub fn new() -> std::io::Result<Self> {
        let guard = tempfile::Builder::new()
            .prefix("nas-analyzer-fixture-")
            .tempdir()?;
        let root = guard.path().to_path_buf();
        fs::write(root.join(MARKER), b"fixture\n")?;
        Ok(Self {
            root,
            _guard: guard,
        })
    }

    /// Wrap an existing directory as a fixture root, refusing anything that
    /// is not a marked, non-symlink directory created by `new`.
    pub fn open_existing(path: &Path) -> std::io::Result<Self> {
        let md = fs::symlink_metadata(path)?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(err("fixture root must be a real directory, not a symlink"));
        }
        if !path.join(MARKER).exists() {
            return Err(err("refusing unmarked directory as fixture root"));
        }
        Ok(Self {
            root: path.to_path_buf(),
            _guard: tempfile::Builder::new()
                .prefix("nas-analyzer-fixture-hold-")
                .tempdir()?,
        })
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

fn err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

fn write(root: &Path, rel: &str, content: &[u8]) -> std::io::Result<()> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(p, content)
}

/// Golden dataset from 03_ACCEPTANCE.md §2: two sources alpha and beta,
/// 8 regular paths, 7 physical objects (hard link), 50 bytes entry-logical,
/// 44 bytes unique-logical; alpha 38 / beta 12; documents 33 /
/// disk_images 17 / other 0.
pub fn create_golden(root: &Path) -> std::io::Result<()> {
    write(root, "alpha/docs/readme.txt", b"hello\n")?;
    write(root, "alpha/docs/copy.txt", b"hello\n")?;
    fs::hard_link(
        root.join("alpha/docs/readme.txt"),
        root.join("alpha/docs/hard.txt"),
    )?;
    write(root, "alpha/media/movie.bin", &[b'B'; 17])?;
    write(root, "alpha/empty.dat", b"")?;
    // File name contains a comma and a real newline.
    let weird = root
        .join("alpha")
        .join(OsStr::from_bytes("名称,\n换行.txt".as_bytes()));
    fs::write(weird, b"xyz")?;
    write(root, "beta/copy.txt", b"hello\n")?;
    write(root, "beta/changed.txt", b"HELLO\n")?;
    Ok(())
}

/// A 64 MiB sparse file with only a few blocks written.
pub fn create_sparse(root: &Path, rel: &str) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(p)?;
    f.write_all(b"start")?;
    f.seek(SeekFrom::Start(64 * 1024 * 1024 - 5))?;
    f.write_all(b"end  ")?;
    Ok(())
}

/// Two large files with identical head/middle/tail sample regions but
/// different bytes elsewhere (ACC-029).
pub fn create_sample_collision_pair(root: &Path, a: &str, b: &str) -> std::io::Result<()> {
    let size = 512 * 1024usize;
    let mut va = vec![0xAAu8; size];
    let mut vb = vec![0xAAu8; size];
    // Differ only in a region outside the head/mid/tail 64 KiB samples.
    va[100 * 1024] = 1;
    vb[100 * 1024] = 2;
    write(root, a, &va)?;
    write(root, b, &vb)?;
    Ok(())
}

pub fn create_symlink(root: &Path, rel: &str, target: &Path) -> std::io::Result<()> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    unix_fs::symlink(target, p)
}

/// Create the KEEP sentinel OUTSIDE any fixture root; verify after the test.
pub fn create_keep_sentinel(dir: &Path) -> std::io::Result<PathBuf> {
    let p = dir.join("KEEP-SENTINEL.txt");
    fs::write(&p, b"do-not-touch\n")?;
    Ok(p)
}

pub fn verify_keep_sentinel(p: &Path) -> std::io::Result<()> {
    let content = fs::read(p)?;
    if content != b"do-not-touch\n" {
        return Err(err("KEEP sentinel was modified"));
    }
    Ok(())
}
