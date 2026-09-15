use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    RegularFile,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Unknown,
}

/// Stable identity of a physical file object within one filesystem instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub device_id: u64,
    pub inode_id: u64,
}

#[derive(Debug, Clone)]
pub struct StatData {
    pub kind: EntryKind,
    pub identity: FileIdentity,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub size_bytes: i64,
    pub allocated_bytes_estimate: i64,
    pub mtime: (i64, i64),
    pub atime: (i64, i64),
    pub ctime: (i64, i64),
    pub birthtime: Option<(i64, i64)>,
}

#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub name: OsString,
    pub kind: EntryKind,
    pub inode_id: u64,
}
