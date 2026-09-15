use std::os::unix::fs::FileExt;
use std::os::unix::io::OwnedFd;

use sha2::{Digest, Sha256};

use super::ratelimit::TokenBucket;
use crate::error::{AppError, AppResult, ErrorCode};

/// Files larger than this get a head/middle/tail sample pre-filter (spec 9.2B).
pub const SAMPLE_THRESHOLD: u64 = 192 * 1024;
/// Each sample region reads at most this many bytes (non-overlapping).
pub const SAMPLE_REGION: u64 = 64 * 1024;
const FULL_HASH_BUF: usize = 1024 * 1024;
pub const HASH_ALGORITHM: &str = "sha256";
pub const HASH_ALGORITHM_VERSION: u32 = 1;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashVerdict {
    /// Full-file SHA-256 completed; hex digest.
    FullHash(String),
    /// The file changed or vanished between the pre-check and the read, or
    /// mid-read on retry — excluded from confirmed groups (spec 10.4).
    Unstable,
    /// Cancelled cooperatively at a chunk boundary.
    Cancelled,
    /// The configured content-read budget was exhausted before a complete
    /// hash could be produced.
    BudgetExceeded,
}

#[derive(Debug)]
pub struct HashOutcome {
    pub verdict: HashVerdict,
    /// Whether O_NOATIME was in effect for the read (false → atime may have
    /// been updated; callers surface this, never "repair" atime).
    pub used_noatime: bool,
    /// Bytes actually read.
    pub bytes_read: u64,
}

#[derive(Debug)]
pub struct SampleOutcome {
    pub fingerprint: Option<String>,
    pub bytes_read: u64,
    pub cancelled: bool,
}

fn identity_of(fd: &OwnedFd) -> AppResult<(u64, u64, i64, i64, i64, i64, i64)> {
    let st = rustix::fs::fstat(fd).map_err(|e| internal(format!("fstat: {e}")))?;
    #[allow(clippy::unnecessary_cast)] // field widths differ across platforms
    Ok((
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_size as i64,
        st.st_mtime as i64,
        st.st_mtime_nsec as i64,
        st.st_ctime as i64,
        st.st_ctime_nsec as i64,
    ))
}

/// Low-cost sample fingerprint (spec 9.2 stage B). Input covers algorithm
/// version, file length, region offsets and contents. Files at or below the
/// threshold are not sampled (they go straight to full hash).
pub fn sample_fingerprint(fd: &OwnedFd, size_bytes: u64) -> AppResult<Option<String>> {
    Ok(sample_fingerprint_limited(fd, size_bytes, &mut || false, None)?.fingerprint)
}

/// Read the bounded pre-filter used by the duplicate engine. The returned
/// byte count is part of the content-read budget; the caller still has to
/// perform a complete hash before it can confirm a duplicate.
pub fn sample_fingerprint_limited(
    fd: &OwnedFd,
    size_bytes: u64,
    cancel: &mut dyn FnMut() -> bool,
    mut limiter: Option<&mut TokenBucket>,
) -> AppResult<SampleOutcome> {
    let mut acquire = |bytes| {
        if let Some(limiter) = limiter.as_deref_mut() {
            limiter.acquire(bytes);
        }
        true
    };
    sample_fingerprint_limited_with_acquire(fd, size_bytes, cancel, &mut acquire)
}

/// Read the bounded pre-filter with a caller-owned acquisition callback.
/// This keeps the read limiter independent from the hash worker thread and
/// lets several workers share one global token bucket without sharing a
/// mutable borrow across threads.
pub fn sample_fingerprint_limited_with_acquire(
    fd: &OwnedFd,
    size_bytes: u64,
    cancel: &mut dyn FnMut() -> bool,
    acquire: &mut dyn FnMut(u64) -> bool,
) -> AppResult<SampleOutcome> {
    if size_bytes <= SAMPLE_THRESHOLD {
        return Ok(SampleOutcome {
            fingerprint: None,
            bytes_read: 0,
            cancelled: false,
        });
    }
    let mid_off = (size_bytes / 2)
        .checked_sub(SAMPLE_REGION / 2)
        .ok_or_else(|| internal("重复抽样中部偏移溢出"))?;
    let tail_off = size_bytes
        .checked_sub(SAMPLE_REGION)
        .ok_or_else(|| internal("重复抽样尾部偏移溢出"))?;
    let mut h = Sha256::new();
    h.update(HASH_ALGORITHM_VERSION.to_le_bytes());
    h.update(size_bytes.to_le_bytes());
    let mut buf = vec![0u8; SAMPLE_REGION as usize];
    let mut bytes_read = 0u64;
    for off in [0u64, mid_off, tail_off] {
        if cancel() {
            return Ok(SampleOutcome {
                fingerprint: None,
                bytes_read,
                cancelled: true,
            });
        }
        let n = read_exact_at(fd, &mut buf, off)?;
        bytes_read = bytes_read
            .checked_add(n as u64)
            .ok_or_else(|| internal("重复抽样字节数溢出"))?;
        if !acquire(n as u64) {
            return Ok(SampleOutcome {
                fingerprint: None,
                bytes_read,
                cancelled: true,
            });
        }
        h.update(off.to_le_bytes());
        h.update((n as u64).to_le_bytes());
        h.update(&buf[..n]);
    }
    Ok(SampleOutcome {
        fingerprint: Some(hex::encode(h.finalize())),
        bytes_read,
        cancelled: false,
    })
}

fn read_exact_at(fd: &OwnedFd, buf: &mut [u8], mut off: u64) -> AppResult<usize> {
    // FileExt::read_at lives on std File; clone the FD (same file
    // description, offset-independent pread semantics).
    let file = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| internal(format!("clone fd: {e}")))?,
    );
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read_at(&mut buf[filled..], off) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                off += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(internal(format!("pread: {e}"))),
        }
    }
    Ok(filled)
}

/// Full streaming SHA-256 (spec 9.2 stage C).
///
/// - `expected` is the (dev, ino, size, mtime_sec, mtime_nsec, ctime_sec,
///   ctime_nsec) tuple observed at candidate selection; the FD is fstat-ed
///   before and after the read and must match both times, with one internal
///   retry on pre-read mismatch (spec: 变化则重试一次).
/// - `cancel` is polled at every 1 MiB chunk boundary (cooperative).
/// - `limiter` enforces the global hash read budget (None = unlimited).
pub fn full_sha256(
    fd: &OwnedFd,
    expected: (u64, u64, i64, i64, i64, i64, i64),
    cancel: &mut dyn FnMut() -> bool,
    limiter: Option<&mut TokenBucket>,
) -> AppResult<HashOutcome> {
    full_sha256_limited(fd, expected, cancel, limiter, None)
}

/// Full streaming hash with an optional exact byte budget for this call.
/// The budget is checked before every read and across the single allowed
/// retry, so a changed file cannot silently consume bytes beyond the report's
/// configured limit.
pub fn full_sha256_limited(
    fd: &OwnedFd,
    expected: (u64, u64, i64, i64, i64, i64, i64),
    cancel: &mut dyn FnMut() -> bool,
    mut limiter: Option<&mut TokenBucket>,
    max_bytes: Option<u64>,
) -> AppResult<HashOutcome> {
    let mut acquire = |bytes| {
        if let Some(limiter) = limiter.as_deref_mut() {
            limiter.acquire(bytes);
        }
        true
    };
    full_sha256_limited_with_acquire(fd, expected, cancel, &mut acquire, max_bytes)
}

/// Full streaming hash with a caller-owned acquisition callback. The
/// callback is invoked once per completed read, so a shared limiter can be
/// locked only for token accounting rather than for the whole hash.
pub fn full_sha256_limited_with_acquire(
    fd: &OwnedFd,
    expected: (u64, u64, i64, i64, i64, i64, i64),
    cancel: &mut dyn FnMut() -> bool,
    acquire: &mut dyn FnMut(u64) -> bool,
    max_bytes: Option<u64>,
) -> AppResult<HashOutcome> {
    let expected_size =
        u64::try_from(expected.2).map_err(|_| internal("待哈希文件大小不能转换为 u64"))?;
    let mut attempt = 0;
    let mut bytes_read = 0u64;
    loop {
        attempt += 1;
        let before = identity_of(fd)?;
        if before != expected {
            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            return Ok(HashOutcome {
                verdict: HashVerdict::Unstable,
                used_noatime: false,
                bytes_read,
            });
        }

        let mut h = Sha256::new();
        let mut buf = vec![0u8; FULL_HASH_BUF];
        let mut off = 0u64;
        while off < expected_size {
            if cancel() {
                return Ok(HashOutcome {
                    verdict: HashVerdict::Cancelled,
                    used_noatime: false,
                    bytes_read,
                });
            }
            let remaining_file = expected_size
                .checked_sub(off)
                .ok_or_else(|| internal("完整哈希读取偏移溢出"))?;
            let n = remaining_file.min(FULL_HASH_BUF as u64);
            let n_usize =
                usize::try_from(n).map_err(|_| internal("完整哈希块大小不能转换为 usize"))?;
            if let Some(max) = max_bytes {
                let Some(remaining) = max.checked_sub(bytes_read) else {
                    return Ok(HashOutcome {
                        verdict: HashVerdict::BudgetExceeded,
                        used_noatime: false,
                        bytes_read,
                    });
                };
                if remaining < n {
                    return Ok(HashOutcome {
                        verdict: HashVerdict::BudgetExceeded,
                        used_noatime: false,
                        bytes_read,
                    });
                }
            }
            let read = read_exact_at(fd, &mut buf[..n_usize], off)?;
            bytes_read = bytes_read
                .checked_add(read as u64)
                .ok_or_else(|| internal("完整哈希累计字节数溢出"))?;
            if !acquire(read as u64) {
                return Ok(HashOutcome {
                    verdict: HashVerdict::Cancelled,
                    used_noatime: false,
                    bytes_read,
                });
            }
            if read != n_usize {
                return Ok(HashOutcome {
                    verdict: HashVerdict::Unstable,
                    used_noatime: false,
                    bytes_read,
                });
            }
            h.update(&buf[..n_usize]);
            off = off
                .checked_add(n)
                .ok_or_else(|| internal("完整哈希偏移溢出"))?;
        }
        let after = identity_of(fd)?;
        if after == expected {
            return Ok(HashOutcome {
                verdict: HashVerdict::FullHash(hex::encode(h.finalize())),
                used_noatime: false,
                bytes_read,
            });
        }
        if attempt >= 2 {
            return Ok(HashOutcome {
                verdict: HashVerdict::Unstable,
                used_noatime: false,
                bytes_read,
            });
        }
    }
}

/// Cache key per spec 9.3: source identity epoch + file identity + size +
/// mtime + ctime + algorithm and its version. Never inode or path alone.
pub fn cache_key_string(
    source_identity_epoch: u64,
    device_id: u64,
    inode_id: u64,
    size: i64,
    mtime: (i64, i64),
    ctime: (i64, i64),
) -> String {
    format!(
        "e{source_identity_epoch}:d{device_id}:i{inode_id}:s{size}:m{}.{}:c{}.{}:{HASH_ALGORITHM}v{HASH_ALGORITHM_VERSION}",
        mtime.0, mtime.1, ctime.0, ctime.1
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fd_of(path: &std::path::Path) -> OwnedFd {
        let f = std::fs::File::open(path).unwrap();
        OwnedFd::from(f)
    }

    fn write_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn small_files_are_not_sampled() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_file(&dir, "a.bin", b"hello\n");
        let fd = fd_of(&p);
        assert_eq!(sample_fingerprint(&fd, 6).unwrap(), None);
    }

    #[test]
    fn sample_regions_non_overlapping_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let size = 512 * 1024;
        let p = write_file(&dir, "b.bin", &vec![0x42u8; size]);
        let fd = fd_of(&p);
        let a = sample_fingerprint(&fd, size as u64).unwrap().unwrap();
        let b = sample_fingerprint(&fd, size as u64).unwrap().unwrap();
        assert_eq!(a, b);
        // Different content in an unsampled region keeps the SAME fingerprint
        // (that is why sampling can only pre-filter)...
        let p2 = write_file(&dir, "c.bin", &{
            let mut v = vec![0x42u8; size];
            v[100 * 1024] = 0x99;
            v
        });
        let fd2 = fd_of(&p2);
        let c = sample_fingerprint(&fd2, size as u64).unwrap().unwrap();
        assert_eq!(a, c);
        // (the full-hash difference is covered by full_hash_* tests)
    }

    #[test]
    fn full_hash_streams_and_matches_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let p = write_file(&dir, "d.bin", &content);
        let fd = fd_of(&p);
        let before = identity_of(&fd).unwrap();
        let out = full_sha256(&fd, before, &mut || false, None).unwrap();
        let expect = hex::encode(Sha256::digest(&content));
        match out.verdict {
            HashVerdict::FullHash(h) => assert_eq!(h, expect),
            other => panic!("unexpected verdict {other:?}"),
        }
        assert_eq!(out.bytes_read, content.len() as u64);
    }

    #[test]
    fn full_hash_detects_mid_read_change() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_file(&dir, "e.bin", &vec![7u8; 8 * 1024 * 1024]);
        let fd = fd_of(&p);
        let before = identity_of(&fd).unwrap();
        let p2 = p.clone();
        // Mutate after ~2 chunks.
        let mut calls = 0u32;
        let mut cancel = || {
            calls += 1;
            if calls == 2 {
                std::fs::write(&p2, b"changed!").unwrap();
            }
            false
        };
        let out = full_sha256(&fd, before, &mut cancel, None).unwrap();
        assert!(matches!(out.verdict, HashVerdict::Unstable));
    }

    #[test]
    fn full_hash_cancellation_at_chunk_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_file(&dir, "f.bin", &vec![9u8; 4 * 1024 * 1024]);
        let fd = fd_of(&p);
        let before = identity_of(&fd).unwrap();
        let out = full_sha256(&fd, before, &mut || true, None).unwrap();
        assert!(matches!(out.verdict, HashVerdict::Cancelled));
        assert_eq!(out.bytes_read, 0);
    }

    #[test]
    fn cache_key_covers_required_fields() {
        let k = cache_key_string(3, 10, 20, 100, (1, 2), (3, 4));
        assert!(k.contains("e3") && k.contains("d10") && k.contains("i20"));
        assert!(k.contains("sha256v1"));
        assert_ne!(
            cache_key_string(3, 10, 20, 100, (1, 2), (3, 4)),
            cache_key_string(3, 10, 20, 100, (1, 2), (3, 5))
        );
    }
}
