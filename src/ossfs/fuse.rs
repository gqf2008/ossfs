//! macOS / Linux FUSE mount adapter for the metadata-less object filesystem.
//!
//! Bridges the FUSE kernel protocol (via the `fuser` crate) to
//! [`ObjectFs`](super::ObjectFs). Writes are buffered in memory and flushed as
//! a whole-object `PutObject` on flush/release — the same "cloud drive"
//! semantics as the WinFsp adapter and ossfs/s3fs.
//!
//! Only compiled on non-Windows targets (macOS with FUSE-T/macFUSE, Linux with
//! libfuse). Windows uses the WinFsp adapter in [`super::winfsp`].
#![cfg(not(windows))]

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenAccMode, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, SessionACL, TimeOrNow, WriteFlags,
};
use tokio::runtime::Handle;
use tracing::{info, warn};

use super::{
    DirEntry, DirtyBudget, DirtyPermit, MountAttr, ObjectFs, StreamingUpload, effective_mode,
    effective_owner,
};

/// Attribute/entry cache lifetime. Object storage has no change notifications,
/// so a short TTL keeps the tree weakly consistent across machines.
const TTL: Duration = Duration::from_secs(1);
/// Root directory inode (stable).
const ROOT_INODE: u64 = 1;
/// Upper bound on the number of directories tracked for periodic kernel-cache
/// invalidation. Browsing a huge tree cannot grow this set without limit.
const MAX_TRACKED_DIRS: usize = 8192;
/// Hard upper bound on tracked inodes. FORGET normally releases entries as
/// the kernel drops its references, but accounting can drift (a READDIRPLUS
/// entry the kernel failed to link, a FUSE backend that counts lookups
/// differently), so the map also has a capacity ceiling like `dirs` — an
/// I/O storm such as `find /` over a million-object bucket must never grow
/// it without limit.
const MAX_TRACKED_INODES: usize = 65536;
/// Maximum supported path component length (POSIX NAME_MAX).
const NAME_MAX: u32 = 255;

/// Above this size a write handle spills its buffer to a temp file so a large
/// file copy cannot exhaust process memory.
const WRITE_SPOOL_THRESHOLD: usize = 8 * 1024 * 1024;

/// Stable per-path inode: FNV-1a 64-bit of the POSIX path. Deterministic so a
/// path always maps to the same inode, mirroring the WinFsp adapter's
/// index-from-path scheme. `"/"` is special-cased to `ROOT_INODE`.
fn inode_for_path(path: &str) -> u64 {
    if path == "/" {
        return ROOT_INODE;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Keep it non-zero and distinct from the root inode.
    if hash == 0 { 2 } else { hash | 1 }
}

/// True when `mode` denotes a regular file. `libc::S_IFMT`/`libc::S_IFREG`
/// are `u16` on macOS but `u32` on Linux, so both are cast to `u32`.
#[allow(clippy::unnecessary_cast)]
fn is_regular_file_mode(mode: u32) -> bool {
    mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
}

/// True when a CREATE with these open flags conflicts with an existing path:
/// `O_CREAT|O_EXCL` must fail `EEXIST` instead of silently opening (or, with
/// `O_TRUNC`, clobbering) the existing object. Without it, `open(O_EXCL)`
/// behaves like a plain `O_CREAT` open.
fn create_conflicts(flags: i32, existing: bool) -> bool {
    existing && flags & libc::O_EXCL != 0
}

/// Join a parent path and a name into a normalized POSIX path.
fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn epoch(secs: i64) -> SystemTime {
    if secs <= 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    }
}

/// Per-open-file state. Writes are buffered whole-file and pushed to the
/// object store on flush/release (matching the WinFsp adapter).
#[derive(Clone)]
struct OpenFile {
    path: String,
    is_dir: bool,
    /// `Some(buffer)` when the handle was opened for writing (or created);
    /// `None` for read-only handles. Reads prefer the buffer when present.
    write_buf: Option<Vec<u8>>,
    /// Whether `write_buf` holds the object's current content. Opened write
    /// handles start unloaded and fetch on the first write/truncate, so
    /// opening a file for write never downloads the whole object.
    loaded: bool,
    dirty: bool,
    /// High-water MiB units reserved from [`OssFs::dirty_budget`].
    budget_units: Arc<AtomicUsize>,
    /// RAII permits for every reservation made by this handle.
    budget_permits: Arc<Mutex<Vec<DirtyPermit>>>,
    /// Streaming multipart upload for large files (write-while-upload).
    stream: Arc<tokio::sync::Mutex<Option<StreamingUpload>>>,
    /// Set when a streaming multipart completion failed. `flush_open` then
    /// refuses to fall back to the whole-buffer PUT: the buffer was emptied
    /// into the stream, so that PUT would upload an empty object over the
    /// previous content.
    stream_failed: Arc<AtomicBool>,
    /// Current logical file size (set by setattr/truncate and write).
    logical_size: u64,
}

/// A tracked inode: its POSIX path plus how many lookup references the
/// kernel holds on it. Every entry-out reply (LOOKUP, MKNOD, MKDIR, CREATE
/// and each READDIRPLUS child) takes exactly one reference — mirroring the
/// kernel's `fi->nlookup++` — and FORGET releases them. Plain READDIR
/// entries and the "."/".." entries of READDIRPLUS are *not* counted by
/// the kernel (fs/fuse/readdir.c returns early for dots and never touches
/// `fi->nlookup` in the plain path), so they are registered reference-free
/// and stay evictable.
struct InodeRecord {
    path: String,
    nlookup: u64,
}

/// FUSE filesystem bridging kernel requests to [`ObjectFs`].
pub struct OssFs {
    fs: Arc<ObjectFs>,
    /// Tokio handle used to drive the async S3 client from FUSE threads.
    rt: Handle,
    /// inode -> tracked record (root is always `ROOT_INODE`).
    inodes: Mutex<HashMap<u64, InodeRecord>>,
    /// inodes of directories that have been listed; the periodic refresh task
    /// invalidates their kernel caches so remote changes show up.
    dirs: Arc<Mutex<HashSet<u64>>>,
    /// fh -> open file state.
    files: Mutex<HashMap<u64, OpenFile>>,
    next_fh: AtomicU64,
    /// uid/gid shown in attributes (the mounting user).
    uid: u32,
    gid: u32,
    /// Mount-level ownership / permission defaults from [`ObjectFs`].
    mount_attr: MountAttr,
    /// Whether FUSE fsync is a no-op (whole-file buffered write model).
    ignore_fsync: bool,
    /// Optional mount-wide dirty-buffer budget.
    dirty_budget: Option<DirtyBudget>,
}

impl OssFs {
    pub fn new(fs: Arc<ObjectFs>, rt: Handle, dirs: Arc<Mutex<HashSet<u64>>>) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            ROOT_INODE,
            InodeRecord {
                path: "/".to_string(),
                nlookup: 0,
            },
        );
        dirs.lock().unwrap().insert(ROOT_INODE);
        let mount_attr = fs.mount_attr();
        let uid = effective_owner(mount_attr.uid, unsafe { libc::getuid() });
        let gid = effective_owner(mount_attr.gid, unsafe { libc::getgid() });
        let ignore_fsync = fs.ignore_fsync();
        let dirty_budget = fs.dirty_budget();
        Self {
            fs,
            rt,
            inodes: Mutex::new(inodes),
            dirs,
            files: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            uid,
            gid,
            mount_attr,
            ignore_fsync,
            dirty_budget,
        }
    }

    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }

    /// Block on an async ObjectFs call from a FUSE worker thread.
    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: std::future::Future,
    {
        self.rt.block_on(fut)
    }

    /// Reserve dirty-buffer budget for `bytes`, if the mount configured one.
    /// Tracks the handle's high-water mark so later shrink does not need to
    /// release and reacquire permits.
    async fn reserve_dirty(&self, open: &OpenFile, bytes: usize) -> anyhow::Result<()> {
        let Some(budget) = &self.dirty_budget else {
            return Ok(());
        };
        let new_units = budget.units_for(bytes)?;
        let current = open.budget_units.load(Ordering::Acquire);
        if new_units <= current {
            return Ok(());
        }
        // try_acquire, not acquire: write/setattr run on the fuser session
        // thread (a single dispatcher on macOS), and a blocking wait would
        // park the only thread that can ever release the permits (handle
        // close / release), deadlocking the whole mount (#53). Same pattern
        // as reserve_rmw_budget below.
        let permit = budget
            .try_acquire_units(new_units - current)
            .await
            .ok_or_else(|| {
                anyhow::anyhow!("dirty-buffer budget busy: cannot grow handle to {bytes} bytes")
            })?;
        open.budget_permits.lock().unwrap().push(permit);
        open.budget_units.store(new_units, Ordering::Release);
        Ok(())
    }

    fn path_of(&self, ino: INodeNo) -> Option<String> {
        if ino.0 == ROOT_INODE {
            return Some("/".to_string());
        }
        self.inodes
            .lock()
            .unwrap()
            .get(&ino.0)
            .map(|rec| rec.path.clone())
    }

    /// Track `path` under its inode and take one lookup reference, matching
    /// the kernel's accounting for entry-out replies (LOOKUP / MKNOD / MKDIR
    /// / CREATE and READDIRPLUS children each count exactly one). FORGET
    /// later releases them.
    fn register_inode(&self, path: &str) -> u64 {
        let ino = inode_for_path(path);
        let mut inodes = self.inodes.lock().unwrap();
        inodes
            .entry(ino)
            .and_modify(|rec| rec.nlookup += 1)
            .or_insert(InodeRecord {
                path: path.to_string(),
                nlookup: 1,
            });
        Self::enforce_inode_budget(&mut inodes);
        ino
    }

    /// Track `path` without taking a lookup reference: plain READDIR
    /// entries and the "."/".." of READDIRPLUS. The kernel never sends
    /// FORGET for those, so they must not hold a reference; the mapping
    /// only serves name resolution until the capacity ceiling evicts it.
    fn note_inode(&self, path: &str) -> u64 {
        let ino = inode_for_path(path);
        let mut inodes = self.inodes.lock().unwrap();
        inodes.entry(ino).or_insert(InodeRecord {
            path: path.to_string(),
            nlookup: 0,
        });
        Self::enforce_inode_budget(&mut inodes);
        ino
    }

    /// Release `nlookup` kernel references on `ino` and drop the record once
    /// none remain (the kernel sends FORGET when it evicts the inode from
    /// its dentry/inode caches, so this is what keeps the map from growing
    /// for the lifetime of the mount). An underflow — or a forget for an
    /// inode we never counted or already evicted — simply drops the record.
    fn forget_inode(&self, ino: u64, nlookup: u64) {
        if ino == ROOT_INODE {
            // The root inode is pinned for the mount's lifetime; the kernel
            // never forgets it (and path_of resolves it without the map).
            return;
        }
        let mut inodes = self.inodes.lock().unwrap();
        match inodes.get_mut(&ino) {
            Some(rec) if rec.nlookup > nlookup => rec.nlookup -= nlookup,
            Some(_) => {
                inodes.remove(&ino);
            }
            None => {}
        }
    }

    /// Keep the inode map at its capacity ceiling. Reference-free records
    /// (pure name associations) are evicted first — the kernel holds nothing
    /// on them, so dropping them is always safe. If every record is still
    /// referenced, reset to just the root, the same escape hatch `dirs` uses
    /// at [`MAX_TRACKED_DIRS`]; a later LOOKUP re-registers evicted paths.
    fn enforce_inode_budget(inodes: &mut HashMap<u64, InodeRecord>) {
        if inodes.len() <= MAX_TRACKED_INODES {
            return;
        }
        inodes.retain(|ino, rec| *ino == ROOT_INODE || rec.nlookup > 0);
        if inodes.len() > MAX_TRACKED_INODES {
            inodes.clear();
            inodes.insert(
                ROOT_INODE,
                InodeRecord {
                    path: "/".to_string(),
                    nlookup: 0,
                },
            );
        }
    }

    /// Move an inode's path association after a rename. The kernel keeps the
    /// dentry (and thus the inode number) across the rename, so the old
    /// inode must resolve to the *new* path or every later getattr on the
    /// moved file stats a path that no longer exists; its lookup count
    /// carries over. The new path's own inode is registered reference-free
    /// (the kernel LOOKUPs it when it needs it).
    fn rename_inode(&self, old: &str, new: &str) {
        let old_ino = inode_for_path(old);
        let new_ino = inode_for_path(new);
        if old_ino == new_ino {
            // Same path (or a 64-bit hash collision): nothing to move.
            return;
        }
        let mut inodes = self.inodes.lock().unwrap();
        if let Some(rec) = inodes.get_mut(&old_ino) {
            rec.path = new.to_string();
        }
        inodes.entry(new_ino).or_insert(InodeRecord {
            path: new.to_string(),
            nlookup: 0,
        });
        Self::enforce_inode_budget(&mut inodes);
    }

    /// FileAttr for `entry` under a caller-supplied inode, without touching
    /// the inode map.
    fn attr_for(&self, entry: &DirEntry, ino: u64) -> FileAttr {
        let (kind, perm, nlink) = if entry.is_dir {
            (
                FileType::Directory,
                effective_mode(
                    true,
                    self.mount_attr.dir_mode,
                    self.mount_attr.file_mode,
                    self.mount_attr.umask,
                ),
                2u32,
            )
        } else {
            (
                FileType::RegularFile,
                effective_mode(
                    false,
                    self.mount_attr.dir_mode,
                    self.mount_attr.file_mode,
                    self.mount_attr.umask,
                ),
                1u32,
            )
        };
        let size = entry.size;
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.saturating_add(511) / 512,
            atime: epoch(entry.mtime_secs),
            mtime: epoch(entry.mtime_secs),
            ctime: epoch(entry.mtime_secs),
            crtime: epoch(entry.mtime_secs),
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// `attr_for` with the inode freshly registered (+1 lookup reference).
    /// Only for entry-out replies, which is what the kernel counts.
    fn attr_of(&self, path: &str, entry: &DirEntry) -> FileAttr {
        let ino = self.register_inode(path);
        self.attr_for(entry, ino)
    }

    /// Attr for `path`, preferring an in-flight write buffer size when an open
    /// write handle exists (so fstat after write sees the new size).
    ///
    /// Takes no lookup reference: getattr replies do not add one kernel-side,
    /// so registering here would leak the count.
    fn effective_attr(&self, path: &str, entry: &DirEntry) -> FileAttr {
        let mut entry = entry.clone();
        let buf_len = {
            let files = self.files.lock().unwrap();
            files
                .values()
                .find(|o| o.path == path && o.loaded)
                .map(|o| {
                    if o.logical_size > 0 {
                        Some(o.logical_size)
                    } else {
                        o.write_buf.as_ref().map(|b| b.len() as u64)
                    }
                })
                .flatten()
        };
        if let Some(len) = buf_len {
            entry.size = len;
        }
        let mut attr = self.attr_for(&entry, inode_for_path(path));
        // 单元 5(§5.1 ②):macOS `.Trashes` 目录层恒报 0700(覆盖
        // config.dir_mode)—— Finder 会把空 `.Trashes` 自置 0333(写权限
        // 陷阱 → 删除立即生效),虚拟目录无真实 inode,按 0700 呈现保证
        // 属主可写。[待验证] Finder 对虚拟目录权限的判定(实测项 D)。
        if let Some(perm) = self.trashes_perm(path, entry.is_dir) {
            attr.perm = perm;
        }
        attr
    }

    /// macOS `.Trashes` 目录层(macOS 平台形态)的 0700 覆盖。仅
    /// `MacOsTrashes` 平台的 Dir 层(level 0/1,uid 范围过滤随
    /// match_system_trash 生效,裁决 R17);条目层与 Windows 形态不覆盖。
    /// trash 关闭/非 macOS 平台恒 None(行为不变)。
    fn trashes_perm(&self, path: &str, is_dir: bool) -> Option<u16> {
        if !is_dir {
            return None;
        }
        let trash = self.fs.trash.as_ref()?;
        let sys = trash.system.as_ref()?;
        if sys.platform != super::trash::SystemTrashPlatform::MacOsTrashes {
            return None;
        }
        match trash.match_system_trash(path) {
            Some(super::trash::SystemTrashMatch::Dir { .. }) => Some(0o700),
            _ => None,
        }
    }

    /// Flush a dirty open file to the object store. A streaming handle
    /// completes its multipart upload; a small handle uploads its buffer.
    fn flush_open(&self, open: &OpenFile) -> anyhow::Result<()> {
        if !open.dirty {
            return Ok(());
        }
        if open.stream_failed.load(Ordering::Acquire) {
            anyhow::bail!(
                "streaming upload previously failed; refusing to overwrite the object with partial data"
            );
        }
        if let Some(up) = self.block_on(async { open.stream.lock().await.take() }) {
            if let Err(e) = self.block_on(up.finish()) {
                // The buffer was emptied into the stream, so a later retry
                // through the buffer path would PUT an empty object over the
                // previous content; remember that and refuse.
                open.stream_failed.store(true, Ordering::Release);
                return Err(e);
            }
            return Ok(());
        }
        if let Some(buf) = open.write_buf.as_ref() {
            self.block_on(self.fs.write(&open.path, buf))?;
        }
        Ok(())
    }

    /// Truncate/expand a file with no open write handle via a
    /// read-modify-write against the object store.
    fn truncate_unopened(&self, path: &str, new_size: u64) -> anyhow::Result<()> {
        self.block_on(self.truncate_unopened_async(path, new_size))
    }

    /// Async core of [`Self::truncate_unopened`] (kept separate so tests can
    /// drive it without a FUSE dispatcher thread to block on).
    async fn truncate_unopened_async(&self, path: &str, new_size: u64) -> anyhow::Result<()> {
        // The whole-object read-modify-write holds the object in memory; gate
        // it against the dirty-buffer budget BEFORE downloading so a huge
        // truncate fails cleanly instead of exhausting process memory. The
        // stat is only useful for sizing the reservation, so skip it when no
        // budget is configured (the default).
        let peak = if self.dirty_budget.is_some() {
            let remote_size = self.fs.stat(path).await?.map(|e| e.size).unwrap_or(0);
            remote_size.max(new_size) as usize
        } else {
            0
        };
        // Held for the whole read-modify-write (the download and the upload
        // both keep the object in memory).
        let _permit = self.reserve_rmw_budget(peak).await?;
        let mut data = self.fs.read_range(path, 0, usize::MAX).await?;
        data.resize(new_size as usize, 0);
        self.fs.write(path, &data).await
    }

    /// Reserve dirty-buffer budget for a transient whole-object
    /// read-modify-write whose peak memory is `bytes`. Returns a no-op permit
    /// when the mount has no budget configured.
    async fn reserve_rmw_budget(&self, bytes: usize) -> anyhow::Result<DirtyPermit> {
        let Some(budget) = &self.dirty_budget else {
            return Ok(DirtyPermit::noop());
        };
        let units = budget.units_for(bytes)?;
        // try_acquire, not acquire: truncate runs on the single fuser session
        // thread, and a blocking wait would park the only thread that can
        // ever release the permits (handle close), deadlocking the mount.
        budget.try_acquire_units(units).await.ok_or_else(|| {
            anyhow::anyhow!("truncate read-modify-write of {bytes} bytes: dirty-buffer budget busy")
        })
    }

    /// Map an [`ObjectFs`] failure to the errno closest to its meaning
    /// instead of a blanket `EIO`:
    ///
    /// - on a read-only mount, mutating operations fail with `EROFS`
    ///   (POSIX requires writes to a read-only filesystem to fail EROFS;
    ///   `ObjectFs::ensure_writable` is what rejects them);
    /// - S3 permission errors (`AccessDenied`, `SignatureDoesNotMatch`, ...)
    ///   map to `EACCES`;
    /// - everything else stays `EIO`.
    ///
    /// Marker matching walks the whole `anyhow` chain: ObjectFs contexts
    /// sometimes embed the object path (`bail!("directory {old} ...")`), so a
    /// path that itself contains a marker word (e.g. a directory named
    /// `forbidden`) can be misclassified as `EACCES`. S3 service errors carry
    /// the error code rather than the key, so in practice the markers fire on
    /// real 403s; the residual risk only shifts the errno class of an
    /// operation that failed anyway.
    fn errno_for(&self, e: &anyhow::Error, mutation: bool) -> Errno {
        if mutation && self.fs.read_only() {
            return Errno::EROFS;
        }
        let mut text = e.to_string();
        for cause in e.chain().skip(1) {
            text.push(' ');
            text.push_str(&cause.to_string());
        }
        let text = text.to_ascii_lowercase();
        const ACCESS_DENIED_MARKERS: [&str; 5] = [
            "accessdenied",
            "access denied",
            "forbidden",
            "invalidaccesskeyid",
            "signaturedoesnotmatch",
        ];
        if ACCESS_DENIED_MARKERS.iter().any(|m| text.contains(m)) {
            return Errno::EACCES;
        }
        // 可恢复错误(超时/断网/5xx/限流,issue #83):EAGAIN 让工具重试
        // 而非 EIO 直接放弃(与 WinFsp 的 STATUS_IO_TIMEOUT 同口径)。
        if super::is_retryable_error(e) {
            return Errno::EAGAIN;
        }
        Errno::EIO
    }
}

impl Filesystem for OssFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        match self.block_on(self.fs.stat(&path)) {
            Ok(Some(entry)) => {
                let attr = self.attr_of(&path, &entry);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs lookup failed");
                reply.error(self.errno_for(&e, false));
            }
        }
    }

    /// Release kernel lookup references on an inode. Without this the inode
    /// map only ever grows — `find /` over a large bucket would accumulate
    /// one record per visited path for the mount's lifetime. The kernel
    /// sends FORGET exactly when it stops holding the references it gained
    /// from entry-out replies, so releasing them here keeps the map in
    /// lockstep with the kernel's own (memory-bounded) inode cache.
    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.forget_inode(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.block_on(self.fs.stat(&path)) {
            Ok(Some(entry)) => {
                let attr = self.effective_attr(&path, &entry);
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs getattr failed");
                reply.error(self.errno_for(&e, false));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(new_size) = size {
            // Prefer resizing an open write handle; otherwise do a
            // read-modify-write so truncate() on an unopened file works.
            let mut handled = false;
            if let Some(fh) = fh {
                // Lazily load original content before truncating an open
                // write handle. Truncating to 0 needs no original bytes at
                // all (the empty buffer is authoritative), so skip the fetch
                // -- this is the open(O_WRONLY|O_TRUNC) save flow.
                let needs_load = {
                    let guard = self.files.lock().unwrap();
                    guard
                        .get(&fh.0)
                        .map(|o| {
                            o.path == path && o.write_buf.is_some() && !o.loaded && new_size != 0
                        })
                        .unwrap_or(false)
                };
                if needs_load {
                    // Pre-reserve the dirty-buffer budget from the stat'd size
                    // BEFORE downloading (same gate as write()): the download
                    // itself allocates the whole object, so a post-hoc reserve
                    // cannot stop an oversized object from exhausting process
                    // memory. Only meaningful when a budget is configured.
                    if self.dirty_budget.is_some() {
                        let remote_size = self
                            .block_on(self.fs.stat(&path))
                            .ok()
                            .flatten()
                            .map(|e| e.size as usize)
                            .unwrap_or(0);
                        let reserve_open = {
                            let guard = self.files.lock().unwrap();
                            guard
                                .get(&fh.0)
                                .filter(|o| o.path == path && o.write_buf.is_some())
                                .cloned()
                        };
                        if let Some(open) = reserve_open
                            && let Err(e) = self.block_on(self.reserve_dirty(&open, remote_size))
                        {
                            warn!(path = %path, error = ?e, "ossfs setattr dirty budget failed");
                            reply.error(self.errno_for(&e, true));
                            return;
                        }
                    }
                    let data = match self.block_on(self.fs.read_range(&path, 0, usize::MAX)) {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(path = %path, error = ?e, "ossfs setattr lazy-load failed");
                            reply.error(self.errno_for(&e, true));
                            return;
                        }
                    };
                    let mut guard = self.files.lock().unwrap();
                    if let Some(open) = guard.get_mut(&fh.0) {
                        if !open.loaded
                            && let Some(buf) = open.write_buf.as_mut()
                        {
                            *buf = data;
                            open.loaded = true;
                        }
                    }
                }
                // Truncate-to-zero on an unloaded handle: mark the empty
                // buffer authoritative without any S3 round trip.
                if new_size == 0 {
                    let mut guard = self.files.lock().unwrap();
                    if let Some(open) = guard.get_mut(&fh.0)
                        && open.path == path
                        && open.write_buf.is_some()
                        && !open.loaded
                    {
                        if let Some(buf) = open.write_buf.as_mut() {
                            buf.clear();
                        }
                        open.loaded = true;
                    }
                }
                let reserve_target = {
                    let guard = self.files.lock().unwrap();
                    guard
                        .get(&fh.0)
                        .filter(|o| o.path == path && o.write_buf.is_some())
                        .cloned()
                };
                if let Some(open) = reserve_target
                    && let Err(e) = self.block_on(self.reserve_dirty(&open, new_size as usize))
                {
                    warn!(path = %path, error = ?e, "ossfs setattr dirty budget failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
                {
                    let mut guard = self.files.lock().unwrap();
                    if let Some(open) = guard.get_mut(&fh.0)
                        && open.path == path
                        && open.write_buf.is_some()
                    {
                        open.logical_size = new_size;
                        open.dirty = true;
                        handled = true;
                    }
                }
            }
            if !handled && let Err(e) = self.truncate_unopened(&path, new_size) {
                warn!(path = %path, error = ?e, "ossfs setattr truncate failed");
                reply.error(self.errno_for(&e, true));
                return;
            }
        }
        // Object storage has no settable mode/timestamps; reply current attrs.
        match self.block_on(self.fs.stat(&path)) {
            Ok(Some(entry)) => {
                let attr = self.effective_attr(&path, &entry);
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs setattr stat failed");
                reply.error(self.errno_for(&e, false));
            }
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // Object storage has no device nodes/fifos/sockets; support regular
        // files only (created lazily, empty).
        if !is_regular_file_mode(mode) {
            reply.error(Errno::EPERM);
            return;
        }
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        let exists = match self.block_on(self.fs.stat(&path)) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs mknod stat failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        };
        if !exists && let Err(e) = self.block_on(self.fs.write(&path, &[])) {
            warn!(path = %path, error = ?e, "ossfs mknod failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        let attr = self.attr_of(
            &path,
            &DirEntry {
                name: name.to_string(),
                is_dir: false,
                size: 0,
                mtime_secs: 0,
            },
        );
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        if let Err(e) = self.block_on(self.fs.mkdir(&path)) {
            warn!(path = %path, error = ?e, "ossfs mkdir failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        let attr = self.attr_of(
            &path,
            &DirEntry {
                name: name.to_string(),
                is_dir: true,
                size: 0,
                mtime_secs: 0,
            },
        );
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        // Refuse to unlink a directory (POSIX requires rmdir).
        match self.block_on(self.fs.stat(&path)) {
            Ok(Some(entry)) if entry.is_dir => {
                reply.error(Errno::EISDIR);
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                reply.error(Errno::ENOENT);
                return;
            }
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs unlink stat failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        }
        if let Err(e) = self.block_on(self.fs.delete(&path)) {
            warn!(path = %path, error = ?e, "ossfs unlink failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        reply.ok();
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        // POSIX rmdir only succeeds on an empty directory. The kernel empties
        // each level before the final rmdir of `rm -rf`, and Finder deletes
        // children first too, so this does not regress either. A non-empty
        // directory must fail ENOTEMPTY instead of silently wiping the whole
        // subtree (review P1: a plain `rmdir dir` in a script was an
        // unrecoverable recursive delete).
        //
        // The emptiness probe and the recursive delete are two non-atomic S3
        // operations: a child created in between is still wiped (metadata-less
        // object-store semantics; far narrower than the pre-fix unconditional
        // wipe), and a child deleted in between yields a spurious ENOTEMPTY.
        if self.block_on(self.fs.dir_has_children(&path)) {
            reply.error(Errno::ENOTEMPTY);
            return;
        }
        if let Err(e) = self.block_on(self.fs.delete_dir_recursive(&path)) {
            warn!(path = %path, error = ?e, "ossfs rmdir failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        reply.ok();
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (Some(parent_path), Some(newparent_path)) =
            (self.path_of(parent), self.path_of(newparent))
        else {
            reply.error(Errno::ENOENT);
            return;
        };
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let old = join_path(&parent_path, name);
        let new = join_path(&newparent_path, newname);
        // RENAME_NOREPLACE only exists on Linux (renameat2); macOS rename
        // always replaces the target.
        let replace_if_exists = {
            #[cfg(target_os = "linux")]
            {
                !flags.contains(RenameFlags::RENAME_NOREPLACE)
            }
            #[cfg(not(target_os = "linux"))]
            {
                true
            }
        };
        if let Err(e) = self.block_on(self.fs.rename(&old, &new, replace_if_exists)) {
            warn!(old = %old, new = %new, error = ?e, "ossfs rename failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        // The kernel keeps the dentry (and its inode number) across the
        // rename; repoint that inode to the new path so later getattr on the
        // moved file resolves correctly, and register the new path's own
        // inode. Neither takes a lookup reference: RENAME replies carry no
        // entry-out.
        self.rename_inode(&old, &new);
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let entry = match self.block_on(self.fs.stat(&path)) {
            Ok(Some(e)) => e,
            Ok(None) => {
                reply.error(Errno::ENOENT);
                return;
            }
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs open stat failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        };
        let write = matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        );
        // POSIX: opening for write on a read-only filesystem fails with
        // EROFS at open time, not later on flush. The kernel enforces this
        // itself when mounted with `MountOption::RO`; keep the explicit
        // check so backends that do not honor RO (FUSE-T) behave the same.
        if write && self.fs.read_only() {
            reply.error(Errno::EROFS);
            return;
        }
        let write_buf = if !entry.is_dir && write {
            // Lazy: existing content is fetched on the first write/truncate
            // that needs it, so opening for write never downloads the object.
            Some(Vec::new())
        } else {
            None
        };
        let fh = self.alloc_fh();
        self.files.lock().unwrap().insert(
            fh,
            OpenFile {
                path: path.clone(),
                is_dir: entry.is_dir,
                write_buf,
                loaded: false,
                dirty: false,
                budget_units: Arc::new(AtomicUsize::new(0)),
                budget_permits: Arc::new(Mutex::new(Vec::new())),
                stream: Arc::new(tokio::sync::Mutex::new(None)),
                stream_failed: Arc::new(AtomicBool::new(false)),
                logical_size: 0,
            },
        );
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = join_path(&parent_path, name);
        if self.fs.read_only() {
            // create is always a write intent; reject up front with EROFS.
            reply.error(Errno::EROFS);
            return;
        }
        let truncate = flags & libc::O_TRUNC != 0;
        let existing = match self.block_on(self.fs.stat(&path)) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs create stat failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        };
        if create_conflicts(flags, existing.is_some()) {
            // POSIX: O_CREAT|O_EXCL on an existing path is EEXIST, not a
            // silent open (or truncate) of the existing object.
            reply.error(Errno::EEXIST);
            return;
        }
        if let Some(entry) = &existing
            && entry.is_dir
        {
            reply.error(Errno::EISDIR);
            return;
        }
        let needs_existing = existing.is_some() && !truncate;
        // A brand-new file has no S3 object yet; create the empty object now
        // so that subsequent GETATTR (e.g. the NFS/FUSE client stat after
        // create) finds it instead of ENOENT. (TOCTOU: a concurrent rename
        // could land on this path between the stat and the PUT and be
        // clobbered by the empty object; closing that needs a conditional
        // PutObject — If-None-Match:* — which ObjectFs does not expose yet.)
        if existing.is_none()
            && let Err(e) = self.block_on(self.fs.write(&path, &[]))
        {
            warn!(path = %path, error = ?e, "ossfs create initial put failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        let write_buf = Some(Vec::new());
        let attr = self.attr_of(
            &path,
            &DirEntry {
                name: name.to_string(),
                is_dir: false,
                // Existing content is kept but loaded lazily; report the real
                // size so the kernel's initial attr is not 0.
                size: if needs_existing {
                    existing.as_ref().map(|e| e.size).unwrap_or(0)
                } else {
                    0
                },
                mtime_secs: 0,
            },
        );
        let fh = self.alloc_fh();
        self.files.lock().unwrap().insert(
            fh,
            OpenFile {
                path: path.clone(),
                is_dir: false,
                write_buf,
                // New/truncated: empty buffer is authoritative. O_CREAT on an
                // existing file without O_TRUNC: original content is fetched
                // lazily on first write.
                loaded: !needs_existing,
                dirty: false,
                budget_units: Arc::new(AtomicUsize::new(0)),
                budget_permits: Arc::new(Mutex::new(Vec::new())),
                stream: Arc::new(tokio::sync::Mutex::new(None)),
                stream_failed: Arc::new(AtomicBool::new(false)),
                logical_size: 0,
            },
        );
        reply.created(
            &TTL,
            &attr,
            Generation(0),
            FileHandle(fh),
            FopenFlags::empty(),
        );
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let open = self.files.lock().unwrap().get(&fh.0).cloned();
        let Some(open) = open else {
            reply.error(Errno::EBADF);
            return;
        };
        if let Some(buf) = open.write_buf
            && open.loaded
        {
            let start = offset.min(buf.len() as u64) as usize;
            let n = (buf.len() - start).min(size as usize);
            reply.data(&buf[start..start + n]);
            return;
        }
        match self.block_on(self.fs.read_range(&open.path, offset, size as usize)) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                warn!(path = %open.path, offset = offset, error = ?e, "ossfs read failed");
                reply.error(self.errno_for(&e, false));
            }
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        // Snapshot the handle so we can reserve dirty-buffer budget without
        // holding the files lock across the S3 round trip or the budget wait.
        let open_snapshot = {
            let guard = self.files.lock().unwrap();
            match guard.get(&fh.0) {
                Some(o) => o.clone(),
                None => {
                    drop(guard);
                    reply.error(Errno::EBADF);
                    return;
                }
            }
        };
        let path = open_snapshot.path.clone();
        let needs_load = open_snapshot.write_buf.is_some() && !open_snapshot.loaded;
        if needs_load {
            // Reserve the dirty-buffer budget from the stat'd size BEFORE
            // downloading: the download itself allocates the whole object, so
            // a post-hoc reserve cannot stop an oversized object from
            // exhausting process memory. Only meaningful when the mount has a
            // budget configured (without one the stat would be dead work).
            if self.dirty_budget.is_some() {
                let remote_size = self
                    .block_on(self.fs.stat(&path))
                    .ok()
                    .flatten()
                    .map(|e| e.size as usize)
                    .unwrap_or(0);
                if let Err(e) = self.block_on(self.reserve_dirty(&open_snapshot, remote_size)) {
                    warn!(path = %path, error = ?e, "ossfs write dirty budget failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
            }
            let data = match self.block_on(self.fs.read_range(&path, 0, usize::MAX)) {
                Ok(d) => d,
                Err(e) => {
                    warn!(path = %path, error = ?e, "ossfs write lazy-load failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
            };
            // The object may have grown since stat; top up the reservation.
            if self.dirty_budget.is_some()
                && let Err(e) = self.block_on(self.reserve_dirty(&open_snapshot, data.len()))
            {
                warn!(path = %path, error = ?e, "ossfs write dirty budget failed");
                reply.error(self.errno_for(&e, true));
                return;
            }
            let mut guard = self.files.lock().unwrap();
            if let Some(o) = guard.get_mut(&fh.0) {
                // Only seed if nobody loaded meanwhile (e.g. a concurrent
                // truncate); their content wins.
                if !o.loaded
                    && let Some(buf) = o.write_buf.as_mut()
                {
                    *buf = data;
                    o.loaded = true;
                }
            }
        }
        let new_size = (offset as usize).saturating_add(data.len());
        if let Err(e) = self.block_on(self.reserve_dirty(&open_snapshot, new_size)) {
            warn!(path = %path, error = ?e, "ossfs write dirty budget failed");
            reply.error(self.errno_for(&e, true));
            return;
        }

        // Streaming multipart already active: feed it directly.
        {
            let mut guard = self.block_on(async { open_snapshot.stream.lock().await });
            if let Some(up) = guard.as_mut() {
                if let Err(e) = self.block_on(up.write(data)) {
                    warn!(path = %path, error = ?e, "ossfs stream write failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
                let end = offset.saturating_add(data.len() as u64);
                let mut files = self.files.lock().unwrap();
                if let Some(o) = files.get_mut(&fh.0) {
                    if end > o.logical_size {
                        o.logical_size = end;
                    }
                    o.dirty = true;
                }
                reply.written(data.len() as u32);
                return;
            }
        }

        // Switch to streaming multipart once the buffer exceeds the in-memory
        // threshold.
        if new_size > WRITE_SPOOL_THRESHOLD {
            let existing = open_snapshot.write_buf.clone();
            let mut up = match self.block_on(self.fs.begin_streaming_upload(&path)) {
                Ok(u) => u,
                Err(e) => {
                    warn!(path = %path, error = ?e, "ossfs begin streaming failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
            };
            if let Some(existing) = &existing
                && !existing.is_empty()
            {
                if let Err(e) = self.block_on(up.write(existing)) {
                    warn!(path = %path, error = ?e, "ossfs stream write failed");
                    reply.error(self.errno_for(&e, true));
                    return;
                }
            }
            if let Err(e) = self.block_on(up.write(data)) {
                warn!(path = %path, error = ?e, "ossfs stream write failed");
                reply.error(self.errno_for(&e, true));
                return;
            }
            let stream = open_snapshot.stream.clone();
            self.block_on(async move { *stream.lock().await = Some(up) });
            let mut files = self.files.lock().unwrap();
            if let Some(o) = files.get_mut(&fh.0) {
                o.write_buf = Some(Vec::new());
                o.loaded = true;
                o.logical_size = new_size as u64;
                o.dirty = true;
            }
            reply.written(data.len() as u32);
            return;
        }

        {
            let mut guard = self.files.lock().unwrap();
            let Some(open) = guard.get_mut(&fh.0) else {
                drop(guard);
                reply.error(Errno::EBADF);
                return;
            };
            let Some(buf) = open.write_buf.as_mut() else {
                drop(guard);
                reply.error(Errno::EACCES);
                return;
            };
            let start = offset as usize;
            if start.saturating_add(data.len()) > buf.len() {
                buf.resize(start + data.len(), 0);
            }
            buf[start..start + data.len()].copy_from_slice(data);
            open.dirty = true;
        }
        reply.written(data.len() as u32);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let open = self.files.lock().unwrap().get(&fh.0).cloned();
        let Some(open) = open else {
            reply.error(Errno::EBADF);
            return;
        };
        if let Err(e) = self.flush_open(&open) {
            warn!(path = %open.path, error = ?e, "ossfs flush failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        if let Some(o) = self.files.lock().unwrap().get_mut(&fh.0) {
            o.dirty = false;
            if o.write_buf.is_some() {
                o.write_buf = Some(Vec::new());
                o.loaded = false;
                o.logical_size = 0;
            }
        }
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let open = self.files.lock().unwrap().get(&fh.0).cloned();
        if let Some(open) = open {
            // Errors on release are not surfaced to the caller; log them.
            if let Err(e) = self.flush_open(&open) {
                warn!(path = %open.path, error = ?e, "ossfs release flush failed");
            }
            self.files.lock().unwrap().remove(&fh.0);
        }
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.ignore_fsync {
            reply.ok();
            return;
        }
        let open = self.files.lock().unwrap().get(&fh.0).cloned();
        let Some(open) = open else {
            reply.error(Errno::EBADF);
            return;
        };
        if let Err(e) = self.flush_open(&open) {
            warn!(path = %open.path, error = ?e, "ossfs fsync failed");
            reply.error(self.errno_for(&e, true));
            return;
        }
        if let Some(o) = self.files.lock().unwrap().get_mut(&fh.0) {
            o.dirty = false;
            if o.write_buf.is_some() {
                o.write_buf = Some(Vec::new());
                o.loaded = false;
                o.logical_size = 0;
            }
        }
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let entries = match self.block_on(self.fs.list(&path)) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs readdir failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        };
        // Remember this directory so the periodic refresh can invalidate it.
        // Bounded: when the tracked set exceeds MAX_TRACKED_DIRS we reset to
        // just the root so a pathological tree cannot grow memory or the
        // per-tick invalidation loop without limit.
        {
            let mut dirs = self.dirs.lock().unwrap();
            dirs.insert(ino.0);
            if dirs.len() > MAX_TRACKED_DIRS {
                dirs.clear();
                dirs.insert(ROOT_INODE);
            }
        }
        // "." and ".." first (Finder expects them), then children sorted by
        // name for a stable readdir cursor. Plain READDIR entries carry no
        // kernel lookup reference (fs/fuse/readdir.c never bumps nlookup on
        // this path), so register them reference-free: they resolve paths
        // but stay evictable and are never "forgotten".
        let mut items: Vec<(String, u64, FileType)> = Vec::with_capacity(entries.len() + 2);
        items.push((".".to_string(), ino.0, FileType::Directory));
        let parent_ino = if ino.0 == ROOT_INODE {
            ROOT_INODE
        } else {
            let parent = super::parent_path(&path);
            self.note_inode(&parent)
        };
        items.push(("..".to_string(), parent_ino, FileType::Directory));
        for entry in entries {
            let child = join_path(&path, &entry.name);
            let kind = if entry.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            items.push((entry.name, self.note_inode(&child), kind));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, (name, ino, kind)) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let entries = match self.block_on(self.fs.list(&path)) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %path, error = ?e, "ossfs readdirplus failed");
                reply.error(self.errno_for(&e, false));
                return;
            }
        };

        // Keep the same bounded directory tracking as `readdir`.
        {
            let mut dirs = self.dirs.lock().unwrap();
            dirs.insert(ino.0);
            if dirs.len() > MAX_TRACKED_DIRS {
                dirs.clear();
                dirs.insert(ROOT_INODE);
            }
        }

        let parent_path = if ino.0 == ROOT_INODE {
            "/".to_string()
        } else {
            super::parent_path(&path)
        };
        // READDIRPLUS children each take one lookup reference (the kernel
        // links them into the dentry cache and bumps fi->nlookup), but the
        // "." and ".." entries are explicitly skipped by the kernel
        // (fuse_direntplus_link returns early for dots), so they are
        // registered reference-free.
        let dot_ino = self.note_inode(&path);
        let dot_attr = self.attr_for(
            &DirEntry {
                name: ".".to_string(),
                is_dir: true,
                size: 0,
                mtime_secs: 0,
            },
            dot_ino,
        );
        let parent_ino = self.note_inode(&parent_path);
        let parent_attr = self.attr_for(
            &DirEntry {
                name: "..".to_string(),
                is_dir: true,
                size: 0,
                mtime_secs: 0,
            },
            parent_ino,
        );

        let mut items: Vec<(String, FileAttr)> = Vec::with_capacity(entries.len() + 2);
        items.push((".".to_string(), dot_attr));
        items.push(("..".to_string(), parent_attr));
        for entry in entries {
            let child = join_path(&path, &entry.name);
            let attr = self.attr_of(&child, &entry);
            items.push((entry.name, attr));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, (name, attr)) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(attr.ino, (i + 1) as u64, name, &TTL, attr, Generation(0)) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // Object storage has no fixed capacity; report a large synthetic pool.
        let total = 1 << 50; // 1 PiB
        reply.statfs(
            total,
            total,
            total,
            u64::MAX / 2,
            u64::MAX / 2,
            4096,
            NAME_MAX,
            4096,
        );
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // Permission checks are best-effort on a network drive; allow all.
        reply.ok();
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        reply.error(Errno::NO_XATTR);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::NO_XATTR);
    }
}

/// Runtime record the desktop tray app uses to list and stop `ossmount`
/// instances. Kept in `$TMPDIR/ossfs-oss` so it never mixes with the OSSFS
/// control-plane registry (`$TMPDIR/ossfs`), matching the Windows adapter.
fn runtime_record_path(pid: u32) -> PathBuf {
    std::env::temp_dir()
        .join("ossfs-oss")
        .join(format!("{pid}.json"))
}

fn write_runtime_record(mount_point: &Path) {
    let dir = std::env::temp_dir().join("ossfs-oss");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(error = ?e, "ossfs failed to create runtime record dir");
        return;
    }
    let record = serde_json::json!({
        "pid": std::process::id(),
        "mount_point": mount_point.display().to_string(),
        "socket_path": "",
        "started_at": chrono::Utc::now().to_rfc3339(),
    });
    let data = serde_json::to_vec_pretty(&record).unwrap_or_default();
    if let Err(e) = std::fs::write(runtime_record_path(std::process::id()), data) {
        warn!(error = ?e, "ossfs failed to write runtime record");
    }
}

fn remove_runtime_record() {
    let _ = std::fs::remove_file(runtime_record_path(std::process::id()));
}

/// Detect which user-space FUSE backend is available on macOS: macFUSE
/// (kext-based; on Apple Silicon it requires lowering the security policy in
/// Recovery Mode) or FUSE-T (kext-less NFS bridge, works with the default
/// Full Security policy).
#[cfg(target_os = "macos")]
fn macos_fuse_backend() -> Option<&'static str> {
    if Path::new("/Library/Filesystems/macfuse.fs").exists() {
        Some("macfuse")
    } else if Path::new("/Library/Application Support/fuse-t").exists()
        || Path::new("/usr/local/lib/libfuse-t.dylib").exists()
        || Path::new(&std::env::var("HOME").unwrap_or_default())
            .join(".fuse-t")
            .exists()
        || Path::new(&std::env::var("HOME").unwrap_or_default())
            .join("Library/Application Support/fuse-t")
            .exists()
    {
        Some("fuse-t")
    } else {
        None
    }
}

/// 系统回收站开启时(macOS)的挂载选项(裁决 R12):macFUSE 分支追加
/// `local`(gocryptfs `-ko local` / encfs `-olocal` 先例 —— 挂为本地卷位
/// Finder 才启用卷级废纸篓);FUSE-T 挂为 NFS 网络卷不支持 Finder 废纸篓,
/// 打 warning 并返回 None(不追加选项)。subtype 由 [`macos_fuse_backend`]
/// 探测注入;抽成纯函数便于测试确定性断言两个分支。
#[cfg(target_os = "macos")]
fn system_trash_mount_option(subtype: &str) -> Option<MountOption> {
    if subtype == "fuse-t" {
        warn!(
            "系统回收站已开启,但 FUSE-T 挂载为 NFS 网络卷,Finder 废纸篓不可用,删除将立即生效;请改用 macFUSE 以启用 Finder 废纸篓"
        );
        None
    } else {
        Some(MountOption::CUSTOM("local".to_string()))
    }
}

fn build_config(allow_other: bool, read_only: bool, system_trash: bool) -> Config {
    let mut cfg = Config::default();
    cfg.mount_options = vec![MountOption::FSName("OSSFS-OSS".to_string())];
    if read_only {
        // Mount the kernel volume read-only so open-for-write fails with
        // EROFS up front instead of every mutation failing late; without it
        // the kernel treats a --read-only mount as read-write.
        cfg.mount_options.push(MountOption::RO);
    }
    if allow_other {
        cfg.mount_options
            .push(MountOption::CUSTOM("allow_other".to_string()));
    }
    #[cfg(target_os = "macos")]
    {
        let subtype = match macos_fuse_backend() {
            Some("fuse-t") => "fuse-t",
            _ => "macfuse",
        };
        cfg.mount_options
            .push(MountOption::Subtype(subtype.to_string()));
        // 单元 5(裁决 R12):系统回收站开启时,macFUSE 追加 local;FUSE-T
        // 告警。关闭时行为不变。
        if system_trash && let Some(opt) = system_trash_mount_option(subtype) {
            cfg.mount_options.push(opt);
        }
    }
    cfg.acl = SessionACL::Owner;
    // fuser's multi-threaded event loop is Linux-only; macOS (macFUSE /
    // FUSE-T) must run with a single reader thread (Config default is 1).
    if !cfg!(target_os = "macos") {
        cfg.n_threads = Some(4);
    }
    cfg
}

/// True when `path` is already a kernel-level mount point (parses `mount`).
/// Prevents stacking a second FUSE/NFS mount on the same directory when a
/// previous ossmount left its mount behind (e.g. after a crash or when the
/// tray's process registry lost track of it).
#[cfg(not(windows))]
fn path_is_mount_point(path: &std::path::Path) -> bool {
    let Ok(out) = std::process::Command::new("mount").output() else {
        return false;
    };
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    String::from_utf8_lossy(&out.stdout).lines().any(|line| {
        let mut it = line.split_whitespace();
        let _dev = it.next();
        let _on = it.next();
        match it.next() {
            Some(mp) => {
                let mp_c =
                    std::fs::canonicalize(mp).unwrap_or_else(|_| std::path::PathBuf::from(mp));
                mp_c == canon
            }
            None => false,
        }
    })
}

/// Mount an [`ObjectFs`] at `mount_point` via FUSE (macFUSE or FUSE-T on
/// macOS, libfuse on Linux). Runs until Ctrl+C / SIGTERM / external unmount,
/// then tears down gracefully.
pub async fn mount_oss_fuse(
    fs: Arc<ObjectFs>,
    mount_point: &Path,
    refresh_secs: u64,
) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if macos_fuse_backend().is_none() {
            anyhow::bail!(
                "未检测到 FUSE 后端：请安装 FUSE-T（推荐，无需修改系统安全策略：brew install --cask fuse-t，或 https://www.fuse-t.org/）或 macFUSE（https://macfuse.github.io/），OSS 直挂需要其中之一"
            );
        }
    }

    // Fail fast: verify the bucket is reachable before mounting, so we never
    // present a mount that every operation errors on.
    fs.list("/").await?;

    // 回收站:挂载启动全量建索引(bootstrap 失败仅 warn + 计数,不阻塞挂载;
    // 索引空则已删文件短暂可见,周期刷新自愈)+ 启动周期刷新循环(与下方
    // 目录 refresh 任务同生命周期,随进程退出)。
    if fs.trash_enabled() {
        let _ = fs.trash_bootstrap().await;
        fs.trash_refresh_start();
    }

    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point).map_err(|e| {
            anyhow::anyhow!(
                "挂载点 {} 不存在且无法创建：{e}（/Volumes 需要管理员权限，请在托盘挂载时按提示创建）",
                mount_point.display()
            )
        })?;
    }
    // Non-root FUSE/NFS mounts require the mountpoint to belong to the
    // mounting user; a root-owned directory (e.g. created with sudo) fails
    // with EPERM. Give a clear hint instead of a generic I/O error.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata(mount_point) {
            let my_uid = unsafe { libc::getuid() };
            if md.uid() != my_uid {
                anyhow::bail!(
                    "挂载点 {} 的所有者不是当前用户（uid {} ≠ {}），非 root 挂载需要挂载点属于当前用户；请执行 sudo chown {}:{} {} 或让托盘自动创建",
                    mount_point.display(),
                    md.uid(),
                    my_uid,
                    my_uid,
                    unsafe { libc::getgid() },
                    mount_point.display()
                );
            }
        }
    }
    // Exclusive per-mountpoint lock: even if two ossmount processes are
    // started at the same instant (double click / auto-restart race), only
    // the first one may mount; the second bails out deterministically.
    #[cfg(unix)]
    let _mount_lock = {
        use std::os::unix::io::AsRawFd;
        let lock_dir = std::env::temp_dir().join("ossfs-oss").join(".locks");
        std::fs::create_dir_all(&lock_dir).ok();
        let safe: String = mount_point
            .display()
            .to_string()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let lock_path = lock_dir.join(format!("{safe}.lock"));
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("创建挂载锁失败：{e}"))?;
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!(
                "{} 正在被另一个 ossmount 挂载/已挂载，请勿重复挂载同一目录",
                mount_point.display()
            );
        }
        lock_file
    };

    #[cfg(not(windows))]
    if path_is_mount_point(mount_point) {
        anyhow::bail!(
            "{} 已是一个挂载点，请先卸载再挂载（避免同一目录被重复挂载）",
            mount_point.display()
        );
    }

    let allow_other = fs.allow_other();
    let read_only = fs.read_only();
    // 单元 5(裁决 R12):系统回收站开启(macOS 平台形态由 build_trash_state
    // 按 cfg 注入)决定 local 挂载选项 / FUSE-T 告警。
    let system_trash_enabled = fs.trash.as_ref().and_then(|t| t.system.as_ref()).is_some();
    let handle = Handle::current();
    let dirs = Arc::new(Mutex::new(HashSet::new()));
    let oss_fs = OssFs::new(fs, handle, Arc::clone(&dirs));
    let session = fuser::spawn_mount2(
        oss_fs,
        mount_point,
        &build_config(allow_other, read_only, system_trash_enabled),
    )
    .map_err(|e| anyhow::anyhow!("failed to mount at {}: {e}", mount_point.display()))?;

    // FUSE-T performs the real NFS mount asynchronously after the FUSE
    // session is negotiated. Poll until the mount actually shows up in the
    // kernel mount table; if it never does (e.g. the target directory is
    // already occupied by a stale mount, so the server's `mount` fails with
    // EX_UNAVAILABLE), fail fast instead of reporting a phantom "mounted"
    // state that disappears seconds later.
    #[cfg(not(windows))]
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut mounted = false;
        while std::time::Instant::now() < deadline {
            if path_is_mount_point(mount_point) {
                mounted = true;
                break;
            }
            if session.guard.is_finished() {
                // The backend gave up (mount failed and it closed the
                // connection), or the user unmounted while we were waiting.
                let err = session
                    .join()
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "FUSE 后端在挂载完成前退出了".to_string());
                anyhow::bail!("挂载失败：{err}（目标目录可能已被占用）");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if !mounted {
            let _ = session.umount_and_join();
            anyhow::bail!(
                "挂载失败：FUSE 后端未能在 {} 完成挂载（目录可能已被占用或 FUSE-T 服务异常）",
                mount_point.display()
            );
        }
    }

    info!(mount_point = %mount_point.display(), "ossfs-oss mounted via FUSE");
    println!("mounted at {}", mount_point.display());
    write_runtime_record(mount_point);

    // Periodic directory refresh: invalidate the kernel caches of every
    // directory that has been listed so changes made by other machines show
    // up without a manual refresh. The kernel re-lists lazily on the next
    // access, so this costs an S3 list only when the user actually browses.
    // macFUSE does not support kernel notifications; the errors are ignored
    // there (the 1s TTL still keeps attribute reads fresh).
    if refresh_secs > 0 {
        let notifier = session.notifier();
        let dirs = Arc::clone(&dirs);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; consume it so the first
            // refresh waits one full interval.
            interval.tick().await;
            loop {
                interval.tick().await;
                let inodes: Vec<u64> = dirs.lock().unwrap().iter().copied().collect();
                for ino in inodes {
                    let _ = notifier.inval_inode(INodeNo(ino), 0, 0);
                }
            }
        });
    }

    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    let mut session = Some(session);
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
            _ = async {
                #[cfg(unix)]
                if let Some(sig) = sigterm.as_mut() {
                    sig.recv().await;
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => { break; }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if let Some(s) = session.as_ref() {
                    if s.guard.is_finished() {
                        // The session ended on its own (e.g. user ejected the
                        // volume in Finder / ran `umount`, or the FUSE
                        // backend closed the connection). Surface the real
                        // result instead of guessing, then best-effort clean
                        // up any mount the backend left behind.
                        let s = session.take().unwrap();
                        let joined = s.join();
                        #[cfg(not(windows))]
                        {
                            let _ = std::process::Command::new("umount")
                                .arg(mount_point.as_os_str())
                                .status();
                        }
                        match joined {
                            Ok(()) => {
                                println!("filesystem session ended (unmounted externally)");
                            }
                            Err(e) => {
                                eprintln!("filesystem session ended with error: {e}");
                            }
                        }
                        remove_runtime_record();
                        return Ok(());
                    }
                }
            }
        }
    }

    println!("unmounting...");
    let result = match session.take() {
        Some(s) => s.umount_and_join(),
        None => Ok(()),
    };
    remove_runtime_record();
    if cfg!(target_os = "macos") {
        // On macOS the FUSE-T/macFUSE server may already have detached the
        // volume by the time we shut down, which makes the final join return
        // EIO/ENOENT even though the mount is gone. Treat that as noise.
        if let Err(e) = result {
            eprintln!("unmount warning: {e}");
        }
        Ok(())
    } else {
        result.map_err(anyhow::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossfs::{MockS3, test_fs_with_budget};

    #[test]
    fn inode_for_path_is_stable_and_distinct() {
        let a = inode_for_path("/docs/report.txt");
        let b = inode_for_path("/docs/report.txt");
        assert_eq!(a, b, "same path must map to the same inode");
        assert_ne!(a, ROOT_INODE, "non-root paths must not collide with root");
        assert_ne!(a, inode_for_path("/docs/report2.txt"));
        assert_eq!(inode_for_path("/"), ROOT_INODE);
        assert_ne!(inode_for_path("/"), 0);
    }

    #[test]
    fn join_path_handles_root_and_nested() {
        assert_eq!(join_path("/", "a.txt"), "/a.txt");
        assert_eq!(join_path("/docs", "a.txt"), "/docs/a.txt");
        assert_eq!(join_path("/a/b", "c"), "/a/b/c");
    }

    #[test]
    fn is_regular_file_mode_detects_regular_files() {
        assert!(is_regular_file_mode(0o100644));
        assert!(!is_regular_file_mode(0o040755)); // directory
        assert!(!is_regular_file_mode(0o120777)); // symlink
    }

    #[test]
    fn create_o_excl_conflicts_only_with_existing_path() {
        let excl = libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL;
        assert!(
            create_conflicts(excl, true),
            "O_CREAT|O_EXCL on an existing path must fail EEXIST"
        );
        assert!(!create_conflicts(excl, false));
        assert!(
            !create_conflicts(libc::O_CREAT | libc::O_WRONLY, true),
            "plain O_CREAT still opens an existing file"
        );
    }

    #[test]
    fn epoch_maps_nonpositive_to_unix_epoch() {
        assert_eq!(epoch(0), UNIX_EPOCH);
        assert_eq!(epoch(-5), UNIX_EPOCH);
        assert_eq!(
            epoch(1_700_000_000),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );
    }

    // -------------------------------------------------------------------
    // Whole-object read-modify-write budget tests (in-process S3 mock)
    // -------------------------------------------------------------------

    fn test_oss(mock_port: u16, max_dirty_bytes: Option<usize>) -> OssFs {
        let fs = Arc::new(test_fs_with_budget(mock_port, 32, max_dirty_bytes));
        OssFs::new(fs, Handle::current(), Arc::new(Mutex::new(HashSet::new())))
    }

    /// OssFs over a caller-built [`ObjectFs`] (e.g. with `read_only` set).
    fn test_oss_with(fs: ObjectFs) -> OssFs {
        OssFs::new(
            Arc::new(fs),
            Handle::current(),
            Arc::new(Mutex::new(HashSet::new())),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn truncate_unopened_rejects_oversized_rmw_before_download() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        // 5 MiB object under a 1 MiB dirty budget: the read-modify-write peak
        // exceeds the budget, so truncate must fail before downloading.
        mock.set_object("f", vec![0u8; 5 * 1024 * 1024]);
        let oss = test_oss(port, Some(1 << 20));
        let err = oss
            .truncate_unopened_async("/f", 1024)
            .await
            .expect_err("oversized truncate must fail");
        assert!(
            err.to_string().contains("max-dirty-bytes"),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            mock.get_count.load(Ordering::SeqCst),
            0,
            "oversized truncate must not download the object"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn truncate_unopened_within_budget_reads_modifies_writes() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        mock.set_object("f", vec![0x11u8; 1024 * 1024]);
        let oss = test_oss(port, Some(64 << 20));
        oss.truncate_unopened_async("/f", 512)
            .await
            .expect("truncate within budget");
        assert_eq!(mock.get_count.load(Ordering::SeqCst), 1, "one GET");
        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(
            recorded.iter().filter(|r| r.method == "PUT").count(),
            1,
            "one PUT"
        );
    }

    /// #53: when the dirty budget is exhausted, write/setattr budget growth
    /// must fail fast instead of blocking — a blocking acquire would park the
    /// single FUSE dispatcher thread forever (nothing else can release the
    /// permits: release() also needs that thread).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reserve_dirty_fails_fast_when_budget_exhausted() {
        let (_mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        // 1 MiB budget, already fully held by another handle.
        let oss = test_oss(port, Some(1 << 20));
        let budget = oss.dirty_budget.as_ref().expect("budget configured");
        let hog = budget
            .try_acquire_units(budget.units_for(1 << 20).unwrap())
            .await
            .expect("initial hog acquisition");
        let open = OpenFile {
            path: "/f".to_string(),
            is_dir: false,
            write_buf: Some(Vec::new()),
            loaded: false,
            dirty: false,
            budget_units: Arc::new(AtomicUsize::new(0)),
            budget_permits: Arc::new(Mutex::new(Vec::new())),
            stream: Arc::new(tokio::sync::Mutex::new(None)),
            stream_failed: Arc::new(AtomicBool::new(false)),
            logical_size: 0,
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            oss.reserve_dirty(&open, 1 << 20),
        )
        .await;
        drop(hog);
        let err = result
            .expect("reserve_dirty must not block when the budget is exhausted")
            .expect_err("reserve_dirty must fail when the budget is exhausted");
        assert!(
            err.to_string().contains("budget busy"),
            "unexpected error: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Inode tracking: FORGET reference decay + bounded map (#51)
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn forget_releases_lookup_references() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        // One LOOKUP reply = one kernel lookup reference.
        let ino = oss.register_inode("/docs/a.txt");
        assert_eq!(oss.path_of(INodeNo(ino)).as_deref(), Some("/docs/a.txt"));
        // The kernel sends FORGET(1) when it drops the dentry.
        oss.forget_inode(ino, 1);
        assert!(
            oss.path_of(INodeNo(ino)).is_none(),
            "FORGET must drop the record once its references are gone"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn repeated_lookups_need_repeated_forgets() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        let ino = oss.register_inode("/f");
        let ino2 = oss.register_inode("/f");
        assert_eq!(ino, ino2, "same path maps to the same inode");
        oss.forget_inode(ino, 1);
        assert!(
            oss.path_of(INodeNo(ino)).is_some(),
            "one reference must remain after one FORGET"
        );
        oss.forget_inode(ino, 1);
        assert!(oss.path_of(INodeNo(ino)).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn forget_underflow_or_unknown_inode_is_tolerated() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        let ino = oss.register_inode("/f"); // count 1
        // Kernel accounting drift: forget more than we tracked -> drop.
        oss.forget_inode(ino, 5);
        assert!(oss.path_of(INodeNo(ino)).is_none());
        // Forgetting an inode we never tracked must not panic.
        oss.forget_inode(999_999, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn note_inode_takes_no_reference() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        // Plain READDIR / dot-dot entries are never counted by the kernel.
        let ino = oss.note_inode("/dir/child");
        assert_eq!(oss.path_of(INodeNo(ino)).as_deref(), Some("/dir/child"));
        // A later registered lookup still balances against one forget.
        oss.register_inode("/dir/child");
        oss.forget_inode(ino, 1);
        assert!(oss.path_of(INodeNo(ino)).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inode_map_stays_bounded_under_lookup_storm() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        // Simulates `find /` walking far more paths than the ceiling.
        for i in 0..(MAX_TRACKED_INODES + 8192) {
            oss.note_inode(&format!("/deep/f{i}"));
        }
        let len = oss.inodes.lock().unwrap().len();
        assert!(
            len <= MAX_TRACKED_INODES,
            "inode map must stay bounded, has {len} records"
        );
        // The root always survives eviction.
        assert!(oss.path_of(INodeNo(ROOT_INODE)).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_repoints_inode_to_new_path() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        // The kernel holds a lookup on the file being renamed.
        let ino = oss.register_inode("/old.txt");
        oss.rename_inode("/old.txt", "/new.txt");
        assert_eq!(
            oss.path_of(INodeNo(ino)).as_deref(),
            Some("/new.txt"),
            "the moved inode must resolve to the new path, not the stale one"
        );
        // Its reference survives the rename and is still FORGET-releasable.
        oss.forget_inode(ino, 1);
        assert!(oss.path_of(INodeNo(ino)).is_none());
        // The new path's own inode also resolves.
        let new_ino = inode_for_path("/new.txt");
        assert_eq!(oss.path_of(INodeNo(new_ino)).as_deref(), Some("/new.txt"));
    }

    // -------------------------------------------------------------------
    // Error-code mapping: EROFS / EACCES instead of a blanket EIO (#54)
    // -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn errno_for_read_only_mutation_is_erofs() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let mut fs = test_fs_with_budget(port, 32, None);
        fs.read_only = true;
        let oss = test_oss_with(fs);
        // ensure_writable()'s rejection on a mutating op must be EROFS.
        let err = anyhow::anyhow!("filesystem is mounted read-only");
        assert_eq!(
            i32::from(oss.errno_for(&err, true)),
            i32::from(Errno::EROFS)
        );
        // Read operations keep EIO — the mount itself is fine.
        assert_eq!(i32::from(oss.errno_for(&err, false)), i32::from(Errno::EIO));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn errno_for_access_denied_is_eacces() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        let err = anyhow::anyhow!("service error: PutObject: AccessDenied (400)");
        assert_eq!(
            i32::from(oss.errno_for(&err, false)),
            i32::from(Errno::EACCES)
        );
        assert_eq!(
            i32::from(oss.errno_for(&err, true)),
            i32::from(Errno::EACCES)
        );
        // Nested causes are searched too (AWS SDK wraps the service error).
        let wrapped = anyhow::anyhow!("upload failed").context(err);
        assert_eq!(
            i32::from(oss.errno_for(&wrapped, true)),
            i32::from(Errno::EACCES)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn errno_for_retryable_errors_is_eagain() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        // 可恢复错误(issue #83):EAGAIN 让工具重试,而非 EIO 直接放弃。
        for msg in [
            "connection reset by peer",
            "timeout after 60s",
            "failed to connect to endpoint",
            "server returned 503 Service Unavailable",
            "too many requests (429)",
        ] {
            assert_eq!(
                i32::from(oss.errno_for(&anyhow::anyhow!(msg), true)),
                i32::from(Errno::EAGAIN),
                "retryable error should map to EAGAIN: {msg}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn errno_for_other_errors_stay_eio() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let oss = test_oss(port, None);
        assert_eq!(
            i32::from(oss.errno_for(&anyhow::anyhow!("object not found"), true)),
            i32::from(Errno::EIO)
        );
        assert_eq!(
            i32::from(oss.errno_for(&anyhow::anyhow!("internal logic error"), false)),
            i32::from(Errno::EIO)
        );
    }

    #[test]
    fn build_config_mounts_ro_when_read_only() {
        let ro = build_config(false, true, false);
        assert!(
            ro.mount_options.contains(&MountOption::RO),
            "--read-only must mount the kernel volume RO"
        );
        let rw = build_config(false, false, false);
        assert!(!rw.mount_options.contains(&MountOption::RO));
    }

    // -------------------------------------------------------------------
    // 单元 5:macOS 系统回收站挂载选项(裁决 R12)+ .Trashes 目录 mode
    // -------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn system_trash_mount_option_macfuse_appends_local() {
        // macFUSE 分支:追加 local(本地卷位,Finder 启用卷级废纸篓)。
        let opt = system_trash_mount_option("macfuse").expect("macFUSE 分支必有 local");
        assert_eq!(opt, MountOption::CUSTOM("local".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_trash_mount_option_fuse_t_none_and_warms() {
        // FUSE-T 分支:不追加任何选项(Finder 废纸篓不可用,告警由
        // tracing::warn 发出——分支判定在此,告警内容见实现)。
        assert_eq!(system_trash_mount_option("fuse-t"), None);
    }

    #[test]
    fn build_config_never_appends_local_when_system_trash_off() {
        // 关闭时行为不变:任何后端都不含 local(环境无关断言)。
        let cfg = build_config(false, false, false);
        assert!(
            !cfg.mount_options
                .iter()
                .any(|o| *o == MountOption::CUSTOM("local".to_string())),
            "系统回收站关闭不得追加 local: {:?}",
            cfg.mount_options
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_config_with_system_trash_still_has_subtype() {
        // 开启时:subtype 仍在(后端探测结果注入;local 分支由
        // system_trash_mount_option 单测覆盖,此处不断言后端相关项)。
        let cfg = build_config(false, false, true);
        assert!(
            cfg.mount_options
                .iter()
                .any(|o| matches!(o, MountOption::Subtype(_))),
            "subtype 必须始终存在: {:?}",
            cfg.mount_options
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trashes_perm_returns_0700_for_macos_trash_dirs_only() {
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let mut fs = test_fs_with_budget(port, 32, None);
        let mut state = crate::ossfs::trash::TrashState::new(
            ".trash/".to_string(),
            crate::ossfs::TrashRefreshMode::Lazy,
            Duration::from_secs(30),
            Duration::from_secs(600),
            Duration::from_secs(86400),
            crate::ossfs::TRASH_RETENTION_DAYS,
        );
        Arc::get_mut(&mut state)
            .expect("freshly created arc is uniquely owned")
            .system = Some(crate::ossfs::trash::SystemTrash {
            dir_name: ".Trashes".into(),
            platform: crate::ossfs::trash::SystemTrashPlatform::MacOsTrashes,
            macos_uid_dirs: vec![501],
        });
        fs.trash = Some(state);
        let oss = test_oss_with(fs);

        let dir = DirEntry {
            name: ".Trashes".into(),
            is_dir: true,
            size: 0,
            mtime_secs: 0,
        };
        // .Trashes 与 .Trashes/<uid> 目录层 → 0700
        assert_eq!(oss.trashes_perm("/.Trashes", true), Some(0o700));
        assert_eq!(oss.trashes_perm("/.Trashes/501", true), Some(0o700));
        // 条目层不覆盖
        assert_eq!(oss.trashes_perm("/.Trashes/501/a.txt", true), None);
        assert_eq!(oss.trashes_perm("/.Trashes/501/a.txt", false), None);
        // 范围外 uid(R17)与普通路径不覆盖
        assert_eq!(oss.trashes_perm("/.Trashes/999", true), None);
        assert_eq!(oss.trashes_perm("/docs", true), None);
        // effective_attr 全链路:getattr 语义(覆盖 config.dir_mode)
        let attr = oss.effective_attr("/.Trashes", &dir);
        assert_eq!(attr.perm, 0o700, "getattr 路径必须报 0700");
        assert_eq!(attr.kind, FileType::Directory);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trashes_perm_none_when_trash_off_or_windows_platform() {
        // 非 macOS 平台形态($Recycle.Bin)与 trash 关闭:恒 None(行为不变)
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let mut fs = test_fs_with_budget(port, 32, None);
        let mut state = crate::ossfs::trash::TrashState::new(
            ".trash/".to_string(),
            crate::ossfs::TrashRefreshMode::Lazy,
            Duration::from_secs(30),
            Duration::from_secs(600),
            Duration::from_secs(86400),
            crate::ossfs::TRASH_RETENTION_DAYS,
        );
        Arc::get_mut(&mut state)
            .expect("freshly created arc is uniquely owned")
            .system = Some(crate::ossfs::trash::SystemTrash {
            dir_name: "$Recycle.Bin".into(),
            platform: crate::ossfs::trash::SystemTrashPlatform::WindowsRecycleBin,
            macos_uid_dirs: vec![],
        });
        fs.trash = Some(state);
        let oss = test_oss_with(fs);
        assert_eq!(oss.trashes_perm("/$Recycle.Bin", true), None);
        assert_eq!(oss.trashes_perm("/$Recycle.Bin/S-1-5-21-1", true), None);
        drop(oss);
        // trash 关闭(system = None)
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        let fs = test_fs_with_budget(port, 32, None);
        let oss = test_oss_with(fs);
        assert_eq!(oss.trashes_perm("/.Trashes", true), None);
    }

    /// POSIX rmdir on a non-empty directory must fail with ENOTEMPTY instead
    /// of recursively deleting the whole subtree (review P1: a plain
    /// `rmdir dir` silently wiped the entire tree because the adapter
    /// delegated to delete_dir_recursive). `rm -rf` still works: the kernel
    /// empties each directory before issuing the final rmdir.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rmdir_nonempty_dir_returns_enotempty() {
        let (mock, port) =
            MockS3::start(vec![("dir/sub/a.txt".to_string(), false)], Duration::ZERO).await;
        mock.set_object("dir/sub/a.txt", b"data".to_vec());
        let oss = test_oss(port, None);
        // Register the inode so path_of(parent) resolves to "/dir".
        oss.register_inode("/dir");
        let parent = INodeNo(crate::ossfs::fuse::inode_for_path("/dir"));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let reply = ReplyEmpty {
            reply: fuser::ReplyRaw {
                unique: fuser::RequestId(0xdeadbeef),
                sender: Some(fuser::ReplySender::Sync(tx)),
            },
        };
        let header = Box::leak(Box::new(fuser::fuse_in_header {
            len: 0,
            opcode: 0,
            unique: 0,
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        }));
        let req = fuser::Request::ref_cast(header);
        // rmdir calls block_on internally; drive it off the tokio test
        // runtime thread like a real FUSE dispatcher would.
        let oss2 = std::sync::Arc::new(oss);
        let oss3 = std::sync::Arc::clone(&oss2);
        let name = std::ffi::OsString::from("sub");
        let handle = std::thread::spawn(move || {
            oss3.rmdir(req, parent, name.as_os_str(), reply);
        });
        let code = rx.recv().expect("rmdir must always reply");
        handle.join().expect("rmdir thread must not panic");
        // The Sync test-hook channel carries the wire-header errno (negative).
        assert_eq!(code, -(libc::ENOTEMPTY as i32));
        assert!(
            mock.recorded
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.method == "GET" && r.target.contains("list-type=2")),
            "the emptiness probe LIST must have run before ENOTEMPTY"
        );
        assert!(
            !mock
                .recorded
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.method == "DELETE" || r.method == "POST"),
            "ENOTEMPTY must not delete anything"
        );
    }

    /// Review C1: rmdir on an EMPTY directory (only its zero-byte marker
    /// object exists) must succeed and delete the marker — the probe must
    /// not count the directory's own marker as a child.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rmdir_empty_dir_succeeds_and_deletes_marker() {
        let (mock, port) = MockS3::start(vec![("dir/".to_string(), false)], Duration::ZERO).await;
        mock.set_object("dir/", b"".to_vec());
        let oss = test_oss(port, None);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let reply = ReplyEmpty {
            reply: fuser::ReplyRaw {
                unique: fuser::RequestId(0xdeadbeef),
                sender: Some(fuser::ReplySender::Sync(tx)),
            },
        };
        let header = Box::leak(Box::new(fuser::fuse_in_header {
            len: 0,
            opcode: 0,
            unique: 0,
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            padding: 0,
        }));
        let req = fuser::Request::ref_cast(header);
        let oss2 = std::sync::Arc::new(oss);
        let oss3 = std::sync::Arc::clone(&oss2);
        let name = std::ffi::OsString::from("dir");
        let handle = std::thread::spawn(move || {
            oss3.rmdir(req, INodeNo(1), name.as_os_str(), reply);
        });
        let code = rx.recv().expect("rmdir must always reply");
        handle.join().expect("rmdir thread must not panic");
        assert_eq!(code, 0, "empty dir rmdir must succeed, got {code}");
        assert!(
            !mock.objects.lock().unwrap().contains_key("dir/"),
            "empty dir marker must be deleted"
        );
    }
}
