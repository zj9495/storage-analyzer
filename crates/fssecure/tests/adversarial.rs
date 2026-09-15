//! Adversarial and happy-path tests for the fssecure descriptor-relative
//! security boundary.
//!
//! Every test operates only inside tempdirs it creates; nothing outside a
//! tempdir is ever touched. Write operations require kernel openat2 support;
//! where it is unavailable (non-Linux dev hosts, ancient kernels) the crate
//! is fail-closed and the write tests skip with a printed note.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::process::Command;

use fssecure::{EntryKind, FsSecureError, OpenOptions, SecureRoot, SecurityCaps};

/// tempdir fixture: `hello.txt` (11 bytes), `sub/inner.txt` (5 bytes).
fn fixture() -> (tempfile::TempDir, SecureRoot) {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("hello.txt"), b"hello world").unwrap();
    fs::create_dir(tmp.path().join("sub")).unwrap();
    fs::write(tmp.path().join("sub").join("inner.txt"), b"inner").unwrap();
    let root = SecureRoot::open(tmp.path().as_os_str()).unwrap();
    (tmp, root)
}

/// True when writes are possible here; otherwise prints a skip note.
fn writes_available(root: &SecureRoot) -> bool {
    if root.caps().supports_safe_writes() {
        true
    } else {
        eprintln!("note: openat2 unavailable on this host; writes are fail-closed, skipping");
        false
    }
}

#[test]
fn happy_path_open_stat_read_dir() {
    let (_tmp, root) = fixture();

    let opened = root
        .open_file(OsStr::new("hello.txt"), OpenOptions::default())
        .unwrap();
    assert_eq!(opened.stat.kind, EntryKind::RegularFile);
    assert_eq!(opened.stat.size_bytes, 11);
    let mut buf = String::new();
    fs::File::from(opened.fd).read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "hello world");

    let st = root.stat(OsStr::new("sub/inner.txt")).unwrap();
    assert_eq!(st.kind, EntryKind::RegularFile);
    assert_eq!(st.size_bytes, 5);

    let mut names = Vec::new();
    for ent in root.read_dir(OsStr::new("")).unwrap() {
        names.push(ent.unwrap().name);
    }
    names.sort();
    assert_eq!(
        names,
        vec![OsString::from("hello.txt"), OsString::from("sub")]
    );

    // open_dir on a real directory works, including the root itself.
    root.open_dir(OsStr::new("sub")).unwrap();
    root.open_dir(OsStr::new("")).unwrap();
}

#[test]
fn rejects_dotdot_and_absolute_paths() {
    let (_tmp, root) = fixture();
    for p in [
        "..",
        "../outside",
        "sub/../../escape",
        "a/./../../b",
        "/etc/passwd",
        "/",
    ] {
        assert!(
            matches!(
                root.open_file(OsStr::new(p), OpenOptions::default()),
                Err(FsSecureError::PathOutsideRoot)
            ),
            "open_file({p:?}) must be rejected as PathOutsideRoot"
        );
        assert!(
            matches!(
                root.open_dir(OsStr::new(p)),
                Err(FsSecureError::PathOutsideRoot)
            ),
            "open_dir({p:?}) must be rejected as PathOutsideRoot"
        );
        assert!(
            matches!(
                root.stat(OsStr::new(p)),
                Err(FsSecureError::PathOutsideRoot)
            ),
            "stat({p:?}) must be rejected as PathOutsideRoot"
        );
    }
}

#[test]
fn symlink_in_middle_component_pointing_outside_rejected() {
    let (tmp, root) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"top secret").unwrap();
    symlink(outside.path(), tmp.path().join("evil")).unwrap();

    assert!(
        matches!(
            root.open_file(OsStr::new("evil/secret.txt"), OpenOptions::default()),
            Err(FsSecureError::SymlinkNotAllowed)
        ),
        "open through a middle symlink must be rejected"
    );
    assert!(
        matches!(
            root.open_dir(OsStr::new("evil")),
            Err(FsSecureError::SymlinkNotAllowed)
        ),
        "open_dir on a symlink must be rejected"
    );
    assert!(
        matches!(
            root.stat(OsStr::new("evil/secret.txt")),
            Err(FsSecureError::SymlinkNotAllowed)
        ),
        "stat must not follow an intermediate symlink out of the root"
    );
    // stat of the link itself reports the link, never the target.
    assert_eq!(
        root.stat(OsStr::new("evil")).unwrap().kind,
        EntryKind::Symlink
    );
}

#[test]
fn symlink_as_final_component_rejected() {
    let (tmp, root) = fixture();
    symlink("hello.txt", tmp.path().join("link_inside")).unwrap();
    symlink("/etc/passwd", tmp.path().join("link_outside")).unwrap();

    for p in ["link_inside", "link_outside"] {
        assert!(
            matches!(
                root.open_file(OsStr::new(p), OpenOptions::default()),
                Err(FsSecureError::SymlinkNotAllowed)
            ),
            "open_file({p:?}) must reject a final symlink even to a valid target"
        );
        assert!(
            matches!(
                root.open_dir(OsStr::new(p)),
                Err(FsSecureError::SymlinkNotAllowed)
            ),
            "open_dir({p:?}) must reject a final symlink"
        );
        assert_eq!(
            root.stat(OsStr::new(p)).unwrap().kind,
            EntryKind::Symlink,
            "stat({p:?}) reports the link itself"
        );
    }
}

#[test]
fn read_dir_reports_escape_symlink_but_it_is_never_traversed() {
    let (tmp, root) = fixture();
    symlink("/etc", tmp.path().join("sub").join("escape")).unwrap();

    let mut entries = Vec::new();
    for ent in root.read_dir(OsStr::new("sub")).unwrap() {
        entries.push(ent.unwrap());
    }
    let esc = entries
        .iter()
        .find(|e| e.name == OsStr::new("escape"))
        .expect("read_dir must report the planted symlink");
    assert_eq!(esc.kind, EntryKind::Symlink);
    assert!(
        entries.iter().any(|e| e.name == OsStr::new("inner.txt")),
        "legitimate entries still listed"
    );

    assert!(
        matches!(
            root.open_dir(OsStr::new("sub/escape")),
            Err(FsSecureError::SymlinkNotAllowed)
        ),
        "open_dir must never traverse the listed escape symlink"
    );
    assert!(
        matches!(
            root.open_file(OsStr::new("sub/escape/passwd"), OpenOptions::default()),
            Err(FsSecureError::SymlinkNotAllowed)
        ),
        "open_file beneath the escape symlink must be rejected"
    );
}

#[test]
fn open_file_rejects_fifo_and_other_non_regular() {
    let (tmp, root) = fixture();
    let fifo = tmp.path().join("pipe");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success(), "mkfifo failed");
    // Opening a FIFO O_RDONLY blocks until a writer appears; hold an O_RDWR
    // handle so the secure open returns and can be rejected on fstat.
    let _held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();

    assert!(
        matches!(
            root.open_file(OsStr::new("pipe"), OpenOptions::default()),
            Err(FsSecureError::NotRegularFile)
        ),
        "FIFO must be rejected as NotRegularFile"
    );
    assert_eq!(root.stat(OsStr::new("pipe")).unwrap().kind, EntryKind::Fifo);
    assert!(
        matches!(
            root.open_file(OsStr::new("sub"), OpenOptions::default()),
            Err(FsSecureError::NotRegularFile)
        ),
        "directory opened via open_file must be rejected as NotRegularFile"
    );
}

#[test]
fn kind_mismatch_and_missing_entries_rejected() {
    let (_tmp, root) = fixture();
    assert!(
        matches!(
            root.open_dir(OsStr::new("hello.txt")),
            Err(FsSecureError::NotDirectory)
        ),
        "open_dir on a regular file must be rejected"
    );
    assert!(
        matches!(
            root.open_file(OsStr::new("missing"), OpenOptions::default()),
            Err(FsSecureError::NotFound)
        ),
        "missing file must report NotFound"
    );
    assert!(
        matches!(
            root.stat(OsStr::new("missing")),
            Err(FsSecureError::NotFound)
        ),
        "missing path must report NotFound"
    );
}

#[test]
fn mkdir_all_creates_nested_dirs() {
    let (_tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    root.mkdir_all(OsStr::new("a/b/c"), 0o755).unwrap();
    assert_eq!(
        root.stat(OsStr::new("a/b/c")).unwrap().kind,
        EntryKind::Directory
    );
    // Idempotent over existing directories.
    root.mkdir_all(OsStr::new("a/b/c"), 0o755).unwrap();
    // Single mkdir on an existing entry fails.
    assert!(matches!(
        root.mkdir(OsStr::new("a"), 0o755),
        Err(FsSecureError::AlreadyExists)
    ));
    // Escape attempts are rejected before any creation happens.
    assert!(matches!(
        root.mkdir_all(OsStr::new("../x"), 0o755),
        Err(FsSecureError::PathOutsideRoot)
    ));
    // A symlink in the path is never traversed.
    assert!(root.mkdir(OsStr::new("link/new"), 0o755).is_err());
}

#[test]
fn write_operations_reject_symlinked_parent_directories() {
    let (tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("victim.txt"), b"outside").unwrap();
    symlink(outside.path(), tmp.path().join("link")).unwrap();

    assert!(root.mkdir(OsStr::new("link/new"), 0o700).is_err());
    assert!(
        root.rename_noreplace(OsStr::new("hello.txt"), OsStr::new("link/moved.txt"))
            .is_err()
    );
    assert!(root.unlink_file(OsStr::new("link/victim.txt")).is_err());
    assert!(tmp.path().join("hello.txt").exists());
    assert!(!outside.path().join("new").exists());
    assert!(!outside.path().join("moved.txt").exists());
    assert!(outside.path().join("victim.txt").exists());
}

#[test]
fn rename_noreplace_refuses_existing_target() {
    let (_tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    assert!(
        matches!(
            root.rename_noreplace(OsStr::new("hello.txt"), OsStr::new("sub/inner.txt")),
            Err(FsSecureError::AlreadyExists)
        ),
        "rename over an existing file must be refused"
    );
    // Source untouched by the failed rename.
    assert_eq!(root.stat(OsStr::new("hello.txt")).unwrap().size_bytes, 11);

    root.rename_noreplace(OsStr::new("hello.txt"), OsStr::new("moved.txt"))
        .unwrap();
    assert!(matches!(
        root.stat(OsStr::new("hello.txt")),
        Err(FsSecureError::NotFound)
    ));
    assert_eq!(root.stat(OsStr::new("moved.txt")).unwrap().size_bytes, 11);

    assert!(matches!(
        root.rename_noreplace(OsStr::new("../moved.txt"), OsStr::new("x")),
        Err(FsSecureError::PathOutsideRoot)
    ));
    assert!(matches!(
        root.rename_noreplace(OsStr::new("moved.txt"), OsStr::new("../x")),
        Err(FsSecureError::PathOutsideRoot)
    ));
}

#[test]
fn unlink_file_refuses_directories_and_symlinks() {
    let (tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    symlink("hello.txt", tmp.path().join("victim_link")).unwrap();

    assert!(
        matches!(
            root.unlink_file(OsStr::new("sub")),
            Err(FsSecureError::NotRegularFile)
        ),
        "unlink_file must refuse directories"
    );
    assert!(
        matches!(
            root.unlink_file(OsStr::new("victim_link")),
            Err(FsSecureError::NotRegularFile)
        ),
        "unlink_file must refuse symlinks (never unlink through identity confusion)"
    );
    // Neither refused entry was removed.
    assert!(tmp.path().join("sub").is_dir());
    assert!(tmp.path().join("victim_link").symlink_metadata().is_ok());

    root.unlink_file(OsStr::new("hello.txt")).unwrap();
    assert!(matches!(
        root.stat(OsStr::new("hello.txt")),
        Err(FsSecureError::NotFound)
    ));
}

#[test]
fn remove_dir_all_removes_nested_tree_and_keeps_siblings() {
    let (tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    fs::create_dir_all(tmp.path().join("tree/one/two")).unwrap();
    fs::write(tmp.path().join("tree/one/two/file.txt"), b"nested").unwrap();
    fs::write(tmp.path().join("tree/root.txt"), b"root").unwrap();

    root.remove_dir_all(OsStr::new("tree")).unwrap();

    assert!(!tmp.path().join("tree").exists());
    assert!(tmp.path().join("hello.txt").is_file());
    assert!(tmp.path().join("sub").is_dir());
}

#[test]
fn remove_dir_all_refuses_symlink_without_touching_target_or_tree() {
    let (tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("sentinel.txt"), b"outside").unwrap();
    fs::create_dir_all(tmp.path().join("tree/nested")).unwrap();
    fs::write(tmp.path().join("tree/keep.txt"), b"keep").unwrap();
    symlink(
        outside.path(),
        tmp.path().join("tree/nested").join("escape"),
    )
    .unwrap();

    assert!(matches!(
        root.remove_dir_all(OsStr::new("tree")),
        Err(FsSecureError::SymlinkNotAllowed)
    ));
    assert!(tmp.path().join("tree/keep.txt").is_file());
    assert!(
        tmp.path()
            .join("tree/nested/escape")
            .symlink_metadata()
            .is_ok()
    );
    assert_eq!(
        fs::read(outside.path().join("sentinel.txt")).unwrap(),
        b"outside"
    );
}

#[test]
fn remove_dir_all_refuses_special_file_without_partial_deletion() {
    let (tmp, root) = fixture();
    if !writes_available(&root) {
        return;
    }
    let tree = tmp.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("keep.txt"), b"keep").unwrap();
    let fifo = tree.join("pipe");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success(), "mkfifo failed");

    assert!(matches!(
        root.remove_dir_all(OsStr::new("tree")),
        Err(FsSecureError::NotRegularFile)
    ));
    assert!(tree.join("keep.txt").is_file());
    assert!(fifo.symlink_metadata().is_ok());
}

#[test]
fn writes_fail_closed_without_openat2_capability() {
    let (tmp, _root) = fixture();
    let weak =
        SecureRoot::new_with_caps_for_test(tmp.path().as_os_str(), SecurityCaps { openat2: false })
            .unwrap();

    assert!(matches!(
        weak.mkdir(OsStr::new("x"), 0o755),
        Err(FsSecureError::MissingCapability)
    ));
    assert!(matches!(
        weak.mkdir_all(OsStr::new("x/y"), 0o755),
        Err(FsSecureError::MissingCapability)
    ));
    assert!(matches!(
        weak.rename_noreplace(OsStr::new("hello.txt"), OsStr::new("z")),
        Err(FsSecureError::MissingCapability)
    ));
    assert!(matches!(
        weak.unlink_file(OsStr::new("hello.txt")),
        Err(FsSecureError::MissingCapability)
    ));
    assert!(matches!(
        weak.remove_dir_all(OsStr::new("sub")),
        Err(FsSecureError::MissingCapability)
    ));

    // Reads still work through the tested per-component no-follow fallback.
    assert_eq!(
        weak.stat(OsStr::new("hello.txt")).unwrap().kind,
        EntryKind::RegularFile
    );
    weak.open_file(OsStr::new("hello.txt"), OpenOptions::default())
        .unwrap();
    assert_eq!(weak.read_dir(OsStr::new("")).unwrap().count(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn mount_crossing_rejected_when_mount_is_permitted() {
    let (tmp, root) = fixture();
    let mnt = tmp.path().join("mnt");
    fs::create_dir(&mnt).unwrap();
    let mounted = Command::new("mount")
        .args(["-t", "tmpfs", "none"])
        .arg(&mnt)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !mounted {
        eprintln!(
            "note: mount(2) not permitted in this container; \
             skipping live mount-crossing check"
        );
        return;
    }

    // stat must report the device change rather than the mounted tree.
    assert!(
        matches!(
            root.stat(OsStr::new("mnt")),
            Err(FsSecureError::MountCrossingNotAllowed)
        ),
        "stat must refuse a mount point on another device"
    );
    // Opening must be refused by RESOLVE_NO_XDEV (EXDEV) on the openat2
    // path, or by the st_dev check (MountCrossingNotAllowed) on the
    // fallback path.
    assert!(
        matches!(
            root.open_dir(OsStr::new("mnt")),
            Err(FsSecureError::CrossDevice) | Err(FsSecureError::MountCrossingNotAllowed)
        ),
        "open_dir must never cross into the mounted filesystem"
    );
    assert!(
        matches!(
            root.remove_dir_all(OsStr::new("mnt")),
            Err(FsSecureError::CrossDevice) | Err(FsSecureError::MountCrossingNotAllowed)
        ),
        "recursive deletion must refuse a mounted directory"
    );
    assert!(mnt.is_dir(), "the mounted directory must remain untouched");

    // The no-openat2 fallback path must catch it too.
    let weak =
        SecureRoot::new_with_caps_for_test(tmp.path().as_os_str(), SecurityCaps { openat2: false })
            .unwrap();
    assert!(
        matches!(
            weak.open_dir(OsStr::new("mnt")),
            Err(FsSecureError::MountCrossingNotAllowed)
        ),
        "fallback resolution must detect the device change"
    );

    let _ = Command::new("umount").arg(&mnt).status();
}
