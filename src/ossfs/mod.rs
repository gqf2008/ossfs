//! Metadata-less object-store filesystem.
//!
//! Mounts an S3-compatible bucket (Aliyun OSS, MinIO, ...) directly as a
//! filesystem: file paths are encoded into object keys and the bucket itself
//! is the single source of truth. There is **no local metadata database**, so
//! any number of machines can mount the same bucket and see the same tree —
//! exactly what `ossfs`/s3fs do. The trade-off is weak consistency (no locks,
//! no atomic rename): it is meant for "cloud drive" usage where machines do
//! not concurrently edit the same file.
//!
//! Layout (s3fs-style):
//! - `/docs/report.txt` -> object key `docs/report.txt`
//! - directory `/docs` -> implicit via prefix, plus a zero-byte marker
//!   object `docs/` so empty directories survive listing.
//!
//! This module is cross-platform; the platform mount adapters live in
//! [`crate::ossfs::winfsp`] (Windows only) and [`crate::ossfs::fuse`] (macOS/Linux).

pub mod admin;
pub mod trash;

#[cfg(all(not(windows), feature = "fuse"))]
pub mod fuse;
#[cfg(windows)]
pub mod winfsp;

use anyhow::{Context as _, Result};
use aws_config::credential_process::CredentialProcessProvider;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier, StorageClass,
};
use aws_sdk_s3::{Client, config::BehaviorVersion};
use aws_smithy_runtime_api::client::interceptors::{
    Intercept,
    context::{BeforeDeserializationInterceptorContextRef, BeforeTransmitInterceptorContextMut},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Remote trash refresh mode (唯一定义在本模块;单元 3 起启用 eager)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrashRefreshMode {
    /// 周期刷新(默认):本端删除即时隐藏,远端变更 ≤ 刷新周期感知。
    #[default]
    Lazy,
    /// 每次 list/stat 前先增量刷一遍 `.trash`,窗口缩到 OSS 最终一致量级,
    /// 代价是枚举类请求的远程成本翻倍。
    Eager,
}

/// S3-compatible object store configuration.
#[derive(Debug, Clone)]
pub struct OssConfig {
    pub bucket: String,
    pub region: String,
    /// Custom endpoint URL (Aliyun OSS, MinIO, ...). None = AWS.
    pub endpoint: Option<String>,
    /// Force path-style addressing (MinIO, Aliyun access points usually need
    /// virtual-hosted style, so default false).
    pub force_path_style: bool,
    /// Optional namespace prefix under the bucket (e.g. `ossfs/`). All keys
    /// are stored under it. Must be empty or end with `/`.
    pub prefix: String,
    /// Optional in-flight S3 request cap. `None` (or `Some(0)`) uses the
    /// default [`MAX_CONCURRENT_S3_REQUESTS`]; explicit values let high-RTT
    /// or low-memory mounts tune the bound (0/None = default, never disable).
    pub max_concurrent_requests: Option<usize>,
    /// Cap on directory-enumeration (`ListObjects`) rate in calls/second
    /// (mirrors a readdir soft-limit). `None`/`Some(0)` disables it.
    pub list_rate_limit: Option<f64>,
    /// Mount the filesystem read-only: reject write / mkdir / delete / rename.
    pub read_only: bool,
    /// POSIX ownership / permission defaults applied to every object by the
    /// FUSE adapters. Objects are metadata-less, so these are mount-level
    /// defaults (like aliyun/ossfs `uid` / `gid` / `dir_mode` / `file_mode`).
    /// `uid`/`gid` of 0 mean "use the mounting user".
    pub uid: u32,
    pub gid: u32,
    pub dir_mode: u32,
    pub file_mode: u32,
    /// Open the FUSE mount to all users (mirrors aliyun/ossfs
    /// `allow_other`). FUSE-only.
    pub allow_other: bool,
    /// Additional permission mask applied on top of `dir_mode`/`file_mode`
    /// (mirrors aliyun/ossfs `umask`). `0` applies no extra mask.
    pub umask: u32,
    /// Allow directory renames. Directory rename is implemented as a
    /// recursive copy + delete; disabling it avoids unbounded tree copies
    /// (mirrors aliyun/ossfs `allow_rename_dir`).
    pub allow_rename_dir: bool,
    /// Maximum number of objects copied by a single directory rename.
    /// `None` (or `Some(0)`) means unlimited. Mirrors aliyun/ossfs
    /// `rename_dir_limit`.
    pub rename_dir_limit: Option<u64>,
    /// Cap on aggregate bytes of in-flight object writes (whole-object PUT
    /// and multipart uploads). `None` (or `Some(0)`) means unlimited.
    /// Rounded up to 1 MiB units internally. Mirrors aliyun/ossfs
    /// `total_mem_limit` (the write-upload portion).
    pub max_upload_bytes: Option<usize>,
    /// Sequential-read prefetch window in bytes. When set, consecutive
    /// reads (next offset == previous end) fetch this many bytes ahead and
    /// cache them so the following small reads are served locally (mirrors
    /// aliyun/ossfs `prefetch_chunk_size`). `None`/`Some(0)` disables it.
    pub read_ahead_bytes: Option<usize>,
    /// Ignore FUSE fsync requests instead of flushing the whole-file write
    /// buffer on every sync (mirrors aliyun/ossfs `ignore_fsync`). The write
    /// is still pushed on flush/release.
    pub ignore_fsync: bool,
    /// Cap on aggregate dirty whole-file write-buffer bytes held by the
    /// mount adapters. `None`/`Some(0)` disables the cap. Rounded up to 1 MiB
    /// units. Mirrors aliyun/ossfs `total_mem_limit` (the dirty-buffer part).
    pub max_dirty_bytes: Option<usize>,
    /// External `credential_process` command (mirrors aliyun/ossfs). The
    /// command is executed on credential refresh and must emit the standard
    /// AWS credential-process JSON. Takes precedence over env/profile creds.
    pub credential_process: Option<String>,
    /// Socket connect timeout in seconds (mirrors aliyun/ossfs
    /// `connect_timeout`). `None` uses `DEFAULT_CONNECT_TIMEOUT_SECS`.
    pub connect_timeout_secs: Option<u64>,
    /// Read timeout in seconds (mirrors aliyun/ossfs `readwrite_timeout`).
    /// Bounds each S3 request — including the time to send its body — so a
    /// stalled connection errors out and retries instead of hanging the
    /// mount. `None` uses `DEFAULT_READWRITE_TIMEOUT_SECS`.
    pub readwrite_timeout_secs: Option<u64>,
    /// Additional retry attempts after the initial request (mirrors
    /// aliyun/ossfs `retries`). `None` keeps the SDK default.
    pub retries: Option<u32>,
    /// Verify each uploaded object's integrity against the `x-oss-hash-crc64ecma`
    /// header returned by OSS (mirrors aliyun/ossfs `enable_crc64`). The
    /// CRC64-ECMA-182 checksum is computed locally on every object / multipart
    /// write and compared to the value OSS reports back after the upload.
    pub verify_crc64: bool,
    /// Set the `Content-MD5` header on single PUT and each multipart part
    /// (mirrors aliyun/ossfs `enable_content_md5`).
    pub content_md5: bool,
    /// Skip legacy `_$folder$` directory-marker objects in listings
    /// (mirrors aliyun/ossfs `notsup_compat_dir`).
    pub notsup_compat_dir: bool,
    /// Storage class applied to newly written objects (mirrors aliyun/ossfs
    /// `storage_class`). Common values: `Standard`, `IA`, `Archive` (OSS) or
    /// `STANDARD` / `STANDARD_IA` / `GLACIER` (S3). `None` keeps the bucket
    /// default.
    pub storage_class: Option<String>,
    /// Multipart upload part size in bytes (mirrors aliyun/ossfs
    /// `multipart_size`). `None` uses [`MULTIPART_PART_SIZE`]; values below
    /// 5 MiB are clamped up to the S3 minimum.
    pub multipart_size: Option<usize>,
    /// Number of concurrent part uploads within one multipart write (mirrors
    /// aliyun/ossfs `parallel_count`). `None` uses
    /// [`MULTIPART_UPLOAD_CONCURRENCY`].
    pub multipart_concurrency: Option<usize>,
    /// Local disk cache directory for object-range blocks. When set, read
    /// ranges that are not served from the in-memory read-ahead cache are
    /// written here and reused on later reads (even across remounts).
    /// Mirrors aliyun/ossfs disk cache.
    pub disk_cache_dir: Option<PathBuf>,
    /// Total process memory budget for read/write buffers. When set, it
    /// overrides the read-cache / upload / dirty budgets with a fixed
    /// 2:1:1 split (read cache : upload : dirty). Mirrors aliyun/ossfs
    /// `total_mem_limit`. `Some(0)` disables the override.
    pub total_mem_limit: Option<usize>,
    /// Fraction of [`Self::total_mem_limit`] reserved for the in-memory read
    /// cache (aliyun/ossfs `rw_ratio` semantics). Valid range `(0, 1)`.
    /// The remaining memory is split equally between upload and dirty buffers.
    pub total_mem_read_ratio: f64,
    /// Upper bound on the in-memory read-ahead cache in bytes. `None`
    /// uses the default [`READ_CACHE_MAX_BYTES`].
    pub read_cache_max_bytes: Option<usize>,
    /// Upper bound on disk-cache bytes; evicts oldest blocks when exceeded.
    /// `0` disables the disk cache. Rounded up to 1 MiB units.
    pub disk_cache_max_bytes: usize,
    /// Disk-cache block size in bytes. `Some(0)` / `None` uses
    /// [`DISK_CACHE_BLOCK_SIZE`].
    pub disk_cache_block_size: Option<usize>,
    /// Keep at least this many bytes free on the disk cache's filesystem.
    /// When a cache write would drop free space below this floor the block
    /// is skipped (mirrors aliyun/ossfs `ensure_diskfree`).
    pub disk_cache_reserve_diskfree: u64,
    /// Keep at least this fraction of the cache filesystem free. Combined
    /// with [`Self::disk_cache_reserve_diskfree`] via `max` (mirrors
    /// aliyun/ossfs `free_space_ratio`).
    pub disk_cache_free_space_ratio: Option<f64>,
    /// Number of consecutive blocks to prefetch in the background after a
    /// sequential disk-cache read. `0` disables prefetch.
    pub disk_cache_prefetch_blocks: usize,
    /// Maximum concurrent background disk-cache prefetch tasks.
    /// `Some(0)` / `None` uses [`DISK_CACHE_PREFETCH_CONCURRENCY`].
    pub disk_cache_prefetch_concurrency: usize,
    /// Verify object ETag with a HEAD before serving disk-cache blocks.
    /// Detects remote changes made by other writers.
    pub disk_cache_verify_etag: bool,
    /// ETag re-check TTL in seconds (default 10).
    pub disk_cache_etag_ttl_secs: u64,
    /// Negative-stat cache TTL in seconds (default 5).
    pub negative_cache_ttl_secs: u64,
    /// Maximum negative-stat cache entries (default 4096).
    pub negative_cache_max_entries: usize,
    /// Positive-stat cache TTL in seconds (default 3).
    pub stat_cache_ttl_secs: u64,
    /// Maximum positive-stat cache entries (default 4096).
    pub stat_cache_max_entries: usize,
    /// Trash (soft delete) directory name relative to the namespace root.
    /// `Some(".trash")` enables the trash; `None` disables it (hard delete).
    /// The CLI defaults to `Some`; the library API to `None` — `normalize`
    /// never fills it, so the gate is never overridden by defaulting.
    pub trash_dir: Option<String>,
    /// Retention days before the GC may clear a tombstone (unit 4 lands the
    /// default; `None` = unset for now).
    pub trash_retention_days: Option<u32>,
    /// Remote trash refresh interval in seconds (unit 3 lands the default).
    pub trash_refresh_interval_secs: Option<u64>,
    /// `Lazy` (default) | `Eager` remote trash refresh (unit 3 enables eager).
    pub trash_refresh_mode: Option<TrashRefreshMode>,
    /// GC interval in seconds (unit 4 lands the default).
    pub trash_gc_interval_secs: Option<u64>,
    /// 系统回收站虚拟视图(issue #80)。None = 关闭。
    /// 默认:Windows/Linux 跟随 trash_dir 开启(平台默认目录名 $Recycle.Bin);
    /// macOS 默认关闭(需显式 --system-trash-dir,裁决 R1)。normalize 不填
    /// 该字段(门控不被默认值覆盖,同 trash_dir 注释模式);平台默认与默认
    /// 开/关在 CLI 与 build_trash_state 按 cfg!(target_os = "macos") 注入。
    pub system_trash: Option<trash::SystemTrashConfig>,
}

/// POSIX ownership / permission defaults applied to every object by the FUSE
/// adapters. See [`OssConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountAttr {
    pub uid: u32,
    pub gid: u32,
    pub dir_mode: u32,
    pub file_mode: u32,
    pub umask: u32,
}

impl Default for MountAttr {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            umask: 0,
        }
    }
}

/// Resolve a configured owner id: `0` means "use the mounting user".
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn effective_owner(configured: u32, current: u32) -> u32 {
    if configured == 0 { current } else { configured }
}

/// Resolve the FUSE permission bits for an object: directory vs file.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn effective_mode(is_dir: bool, dir_mode: u32, file_mode: u32, umask: u32) -> u16 {
    let base = if is_dir { dir_mode } else { file_mode };
    (base & !umask) as u16
}

/// 重试上限:超过后最终放弃并 error 日志(数据未上传,spool 保留供人工
/// 定位)。退避 5s * 3^n 封顶 5 分钟 → 10 次 ≈ 25 分钟。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const RETRY_MAX_ATTEMPTS: u32 = 10;

/// 指数退避:5s * 3^min(attempts,5),封顶 5 分钟。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn retry_backoff(attempts: u32) -> Duration {
    Duration::from_secs(5 * 3u64.pow(attempts.min(5)))
}

/// 失败上传后台重试的共享状态(issue #85):cleanup/close 上传失败(弱网
/// 超时等)时数据入队,worker 指数退避重试,网络恢复后自动补传 —— 文件
/// 系统回调(如 WinFsp cleanup)无错误返回通道,静默丢弃即数据丢失(实测:
/// 21.44G 源复制后桶里仅 8.33G)。重试成功前 spool 缓冲保留不删。
/// 平台无关:winfsp.rs 只负责入队挂点与 close 的 spool 保留检查。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct RetryState {
    pub(crate) queue: Mutex<VecDeque<RetryUpload>>,
    /// 唤醒重试 worker 的信号(入队后 notify_one)。
    pub(crate) notify: tokio::sync::Notify,
}

/// 一次失败的上传:数据源为 spool 文件或内存缓冲,二选一。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct RetryUpload {
    /// 目标 POSIX 路径(挂载视图形态,如 "/临时/a.txt")。
    pub(crate) path: String,
    /// spool 读回缓冲文件(流式/大文件路径);重试成功后由 worker 删除。
    pub(crate) spool: Option<PathBuf>,
    /// 内存缓冲(小文件路径,clone 自 write_buf 固化)。
    pub(crate) buf: Option<Vec<u8>>,
    /// 已重试次数(指数退避,超过 [`RETRY_MAX_ATTEMPTS`] 最终放弃并告警)。
    pub(crate) attempts: u32,
}

/// 后台重试 worker 主体(平台无关):监听入队通知,指数退避重试失败上传。
/// 与挂载生命周期解耦(fs + retry 均为 Arc),由适配器(mount)spawn。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) async fn run_retry_worker(fs: Arc<ObjectFs>, retry: Arc<RetryState>) {
    loop {
        retry.notify.notified().await;
        let item = retry.queue.lock().unwrap().pop_front();
        let Some(mut item) = item else { continue };
        tokio::time::sleep(retry_backoff(item.attempts)).await;
        let result = if let Some(spool) = &item.spool {
            fs.write_from_file(&item.path, spool).await
        } else if let Some(buf) = &item.buf {
            fs.write(&item.path, buf).await
        } else {
            Ok(())
        };
        match result {
            Ok(()) => {
                if let Some(spool) = item.spool.take() {
                    let _ = std::fs::remove_file(&spool);
                }
                tracing::info!(path = %item.path, "retry upload succeeded");
            }
            Err(e) => {
                item.attempts += 1;
                if item.attempts >= RETRY_MAX_ATTEMPTS {
                    tracing::error!(
                        path = %item.path,
                        error = ?e,
                        "retry upload gave up after {RETRY_MAX_ATTEMPTS} attempts; \
                         data NOT uploaded (spool kept at {:?})",
                        item.spool
                    );
                } else {
                    retry.queue.lock().unwrap().push_back(item);
                    retry.notify.notify_one();
                }
            }
        }
    }
}

/// 可恢复错误分类(issue #83):超时/连接失败/网络不可达/HTTP 5xx/限流
/// 属于「用户重试可能成功」的错误 —— WinFsp 映射为 STATUS_IO_TIMEOUT
/// (Explorer 弹"重试/取消"由用户决定),FUSE 映射为 EAGAIN(工具重试);
/// 其余(404/403/签名错误/本地逻辑错误)为致命错误,保持设备错误映射。
/// 基于错误链全文特征匹配(aws-sdk 错误文本跨版本稳定),宁可多判可重试
/// (超时最坏后果 = 用户点重试),不可把致命错误判为可重试(会导致死循环)。
pub(crate) fn is_retryable_error(e: &anyhow::Error) -> bool {
    let mut text = e.to_string();
    for cause in e.chain().skip(1) {
        text.push(' ');
        text.push_str(&cause.to_string());
    }
    let t = text.to_ascii_lowercase();
    const RETRYABLE_MARKERS: [&str; 16] = [
        "timeout",
        "timed out",
        "timedout",
        "connect",
        "connection",
        "network",
        "reset by peer",
        "broken pipe",
        "unreachable",
        "slow down",
        "throttl",
        "too many requests",
        "request rate limit",
        " 5", // " 500"/" 502"/" 503" 等 5xx(带前导空格防误伤文件名)
        "service unavailable",
        "internal server error",
    ];
    RETRYABLE_MARKERS.iter().any(|m| t.contains(m))
}

/// Compute the CRC-64/ECMA-182 checksum used by Aliyun OSS
/// (`x-oss-hash-crc64ecma`). The reflected polynomial is `0xC96C5795D7870F42`,
/// init `0xFFFF_FFFF_FFFF_FFFF`, xorout `0xFFFF_FFFF_FFFF_FFFF`, identical to
/// CRC-64/XZ and to aliyun/ossfs's PhotonLibOS `crc64ecma`.
pub(crate) fn crc64ecma(data: &[u8]) -> u64 {
    const POLY: u64 = 0xC96C_5795_D787_0F42;
    let mut crc: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    for &b in data {
        crc ^= b as u64;
        for _ in 0..8 {
            crc = (crc >> 1) ^ ((crc & 1).wrapping_neg() & POLY);
        }
    }
    crc ^ 0xFFFF_FFFF_FFFF_FFFF
}

/// Incremental CRC-64/ECMA-182 hasher, so a multipart upload can be verified
/// while streaming a file from disk (see [`ObjectFs::write_from_file`]).
struct Crc64Ecma {
    crc: u64,
}

impl Crc64Ecma {
    fn new() -> Self {
        Self {
            crc: 0xFFFF_FFFF_FFFF_FFFF,
        }
    }

    fn update(&mut self, data: &[u8]) {
        const POLY: u64 = 0xC96C_5795_D787_0F42;
        for &b in data {
            self.crc ^= b as u64;
            for _ in 0..8 {
                self.crc = (self.crc >> 1) ^ ((self.crc & 1).wrapping_neg() & POLY);
            }
        }
    }

    fn finalize(self) -> u64 {
        self.crc ^ 0xFFFF_FFFF_FFFF_FFFF
    }
}

/// Captures the `x-oss-hash-crc64ecma` response header before the SDK
/// deserializes the output, so the write path can compare it to the locally
/// computed checksum after the call returns.
#[derive(Debug)]
struct Crc64ResponseCapture {
    slot: Arc<Mutex<Option<u64>>>,
}

impl Intercept for Crc64ResponseCapture {
    fn name(&self) -> &'static str {
        "Crc64ResponseCapture"
    }

    fn read_before_deserialization(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _runtime_components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        _cfg: &mut aws_smithy_types::config_bag::ConfigBag,
    ) -> std::result::Result<(), aws_smithy_runtime_api::box_error::BoxError> {
        let value = context
            .response()
            .headers()
            .get("x-oss-hash-crc64ecma")
            .and_then(|v| v.parse::<u64>().ok());
        *self.slot.lock().unwrap() = value;
        Ok(())
    }
}

/// Makes the DeleteObjects batch request carry `Content-MD5` (base64 MD5 of
/// the serialized body), which Aliyun OSS's DeleteMultipleObjects mandates
/// (#74). With `behavior-version-latest` the SDK treats DeleteObjects as
/// checksum-required and adds `x-amz-checksum-crc32` +
/// `x-amz-sdk-checksum-algorithm: CRC32` itself — headers OSS neither
/// expects nor validates — so without this the batch was rejected with 400
/// `InvalidDigest` and directory markers survived ("新建文件夹删不掉").
///
/// `customize().interceptor()` registers in a config-override plugin the SDK
/// appends after the operation's own interceptors, so the checksum
/// computation runs first and `modify_before_signing` below strips those
/// headers and substitutes the real digest. The placeholder planted in
/// `modify_before_retry_loop` is defensive only: the SDK's checksum
/// interceptor skips when any user-set `x-amz-checksum-*` header is present,
/// which protects the opposite (hypothetical) registration order. Both the
/// ordering and the placeholder are SDK implementation details, not
/// contracts — `delete_dir_recursive_sends_oss_content_md5` asserts the wire
/// shape and turns red on an SDK upgrade that changes either.
#[derive(Debug, Default)]
pub(crate) struct DeleteObjectsContentMd5;

impl Intercept for DeleteObjectsContentMd5 {
    fn name(&self) -> &'static str {
        "DeleteObjectsContentMd5"
    }

    /// Defensive (see struct docs): in the current SDK this runs after the
    /// checksum decision and the value is overwritten by the SDK's real
    /// CRC32; if registration order ever puts us first, it makes the SDK's
    /// checksum interceptor skip instead of computing.
    fn modify_before_retry_loop(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        _cfg: &mut aws_smithy_types::config_bag::ConfigBag,
    ) -> std::result::Result<(), aws_smithy_runtime_api::box_error::BoxError> {
        context
            .request_mut()
            .headers_mut()
            .insert("x-amz-checksum-crc32", "placeholder");
        Ok(())
    }

    /// Drop whatever automatic checksum headers the SDK produced (the prefix
    /// scan survives a future default-algorithm change, e.g. CRC64NVME) and
    /// add the Content-MD5 OSS actually validates, computed over the exact
    /// serialized body. Runs after the SDK's checksum interceptor in the
    /// current registration order.
    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        _cfg: &mut aws_smithy_types::config_bag::ConfigBag,
    ) -> std::result::Result<(), aws_smithy_runtime_api::box_error::BoxError> {
        let request = context.request_mut();
        let checksum_headers: Vec<String> = request
            .headers()
            .iter()
            .map(|(name, _)| name.to_string())
            .filter(|name| {
                name.starts_with("x-amz-checksum-") || name == "x-amz-sdk-checksum-algorithm"
            })
            .collect();
        for name in checksum_headers {
            request.headers_mut().remove(&name);
        }
        let Some(body) = request.body().bytes() else {
            return Err("DeleteObjects body must be in-memory to compute Content-MD5".into());
        };
        let digest = content_md5(body);
        request.headers_mut().insert("content-md5", digest);
        Ok(())
    }
}

/// Verify that `expected` matches the CRC64 value returned by OSS. The header
/// is captured as a side effect of [`Crc64ResponseCapture`] on the operation
/// that just completed.
fn check_crc64_response(
    slot: Arc<Mutex<Option<u64>>>,
    expected: u64,
    metrics: &Metrics,
) -> Result<()> {
    let actual = slot.lock().unwrap().take();
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => {
            metrics.crc64_mismatches.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!(
                "crc64 mismatch: expected {expected}, got {actual} from x-oss-hash-crc64ecma"
            )
        }
        None => anyhow::bail!("x-oss-hash-crc64ecma header missing from upload response"),
    }
}

/// Base64-encoded MD5 of `data`, for the S3 `Content-MD5` header
/// (aliyun/ossfs `enable_content_md5`).
fn content_md5(data: &[u8]) -> String {
    use base64::Engine as _;
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

impl OssConfig {
    pub fn normalize(mut self) -> Self {
        if !self.prefix.is_empty() && !self.prefix.ends_with('/') {
            self.prefix.push('/');
        }
        // Timeouts default ON. The SDK ships only a 3.1s connect timeout and
        // no read timeout for the request-to-response-HEAD wait (fully
        // stalled response bodies are covered by the SDK's default
        // StalledStreamProtection, but response-HEAD waits and request-send
        // stalls are not). A connection that silently stalls there (NAT/
        // firewall drop, OSS throttling) parks the request forever, and a
        // wedged request holds an S3 limiter permit — and, for multipart
        // parts, a part slot plus the write feeder's stream lock — which
        // froze Explorer copies mid-file and silently swallowed
        // deferred-close uploads under heavy multi-file copy load. `Some(0)`
        // is treated as unset so the CLI's `--*-timeout 0` keeps meaning
        // "use the default".
        if self.connect_timeout_secs.unwrap_or(0) == 0 {
            self.connect_timeout_secs = Some(DEFAULT_CONNECT_TIMEOUT_SECS);
        }
        if self.readwrite_timeout_secs.unwrap_or(0) == 0 {
            self.readwrite_timeout_secs = Some(DEFAULT_READWRITE_TIMEOUT_SECS);
        }
        if self.retries.is_none() {
            // Default to ONE retry (2 attempts): the SDK's default of 3
            // attempts triples how long a wedged request parks its WinFsp
            // callback / Explorer. Retries only help transient errors; the
            // first attempt already distinguishes those from a dead link.
            self.retries = Some(1);
        }
        // Trash refresh scheduling defaults (C4b: 阈值默认值随消费单元落地,
        // 此处只填 refresh/mode —— trash_dir 绝不填,None = 回收站关闭)。
        if self.trash_refresh_interval_secs.is_none() {
            self.trash_refresh_interval_secs = Some(TRASH_REFRESH_INTERVAL_SECS);
        }
        if self.trash_refresh_mode.is_none() {
            self.trash_refresh_mode = Some(TrashRefreshMode::Lazy);
        }
        // 单元 4 默认值(C4b):GC 保留期/周期在消费单元落地;trash_dir 仍
        // 绝不填(门控不被默认值覆盖)。
        if self.trash_retention_days.is_none() {
            self.trash_retention_days = Some(TRASH_RETENTION_DAYS);
        }
        if self.trash_gc_interval_secs.is_none() {
            self.trash_gc_interval_secs = Some(TRASH_GC_INTERVAL_SECS);
        }
        self
    }
}

/// A directory entry returned by [`ObjectFs::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_secs: i64,
}

/// Object-store-backed filesystem handle (no local metadata).
/// How long a `stat` result is cached locally. Explorer issues several
/// sequential attribute queries (get_file_info / get_security_by_name / open)
/// per click, and each used to cost an S3 round trip (10ms warm, 200-800ms
/// cold). A short cache absorbs the repeats while keeping remote changes
/// visible within a few seconds, consistent with the 1s WinFsp attr TTL.
const STAT_TTL: Duration = Duration::from_secs(3);
/// Upper bound on cached stat entries; the cache is cleared when exceeded.
const MAX_STAT_ENTRIES: usize = 4096;
/// TTL for the negative-stat cache (paths known to not exist). Avoids
/// repeated remote HEAD/probe round trips when callers repeatedly stat
/// missing paths.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);
/// Upper bound on negative-cache entries; cleared when exceeded so memory
/// stays bounded (mirrors [`MAX_STAT_ENTRIES`]).
const MAX_NEGATIVE_ENTRIES: usize = 4096;
/// Upper bound on in-flight S3 requests issued by one mount. Bounds peak
/// memory (every list/head materializes full results) and remote pressure
/// during I/O storms such as `find /` recursing into the mounted network
/// drive; without it the process can OOM-abort (0xc0000409).
const MAX_CONCURRENT_S3_REQUESTS: usize = 32;
/// Default socket connect timeout (mirrors aliyun/ossfs `connect_timeout`).
/// See [`OssConfig::normalize`] for why a default is applied at all: the SDK
/// default is 3.1s connect / no read timeout, and a request that hangs on a
/// silently-stalled connection parks its limiter permit (and multipart part
/// slot) forever, wedging the mount's write path.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default request read timeout. The smithy "read timeout" bounds sending the
/// request (including its body) plus waiting for the **response headers** —
/// it does NOT bound streaming the response body, so large downloads are
/// never cut off mid-stream. The default must tolerate the largest single
/// request body over a slow uplink: 8 MiB multipart parts (~14 KB/s floor)
/// and up to the 16 MiB whole-object PUT threshold (~27 KB/s floor). Raising
/// `--multipart-size` beyond 8 MiB must co-raise this value (a part needs
/// part_size / 600s of uplink). 600 s guarantees a stalled request errors
/// out (and the SDK retries) instead of hanging the mount forever.
/// Response-HEAD idle timeout: how long a request may wait for ANY bytes
/// from the peer. Slow-but-flowing transfers are NOT cut by this (response
/// bodies are governed by StalledStreamProtection); only a fully silent
/// peer is — and 60s of total silence is plenty on any network. Kept short
/// because a wedged request parks its WinFsp callback — and with it
/// Explorer — until it gives up (#43).
const DEFAULT_READWRITE_TIMEOUT_SECS: u64 = 60;

/// Overall budget floor for streaming one GET response body (see
/// [`read_body_budget`]).
const READ_BODY_MIN_TOTAL: Duration = Duration::from_secs(60);
/// Sustained throughput (bytes/sec) a response body must maintain to finish
/// inside its overall budget. Deliberately far below any healthy link so only
/// trickling / wedged streams are cut off.
const READ_BODY_MIN_THROUGHPUT_BPS: f64 = 8.0 * 1024.0;
/// Cap on the expected-length term so the budget for an unbounded read
/// (`usize::MAX` lazy loads) stays finite.
const READ_BODY_BUDGET_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Overall time budget for collecting one GET response body. The smithy read
/// timeout only bounds sending the request and waiting for the response
/// headers; the body stream is otherwise protected solely by the SDK's
/// StalledStreamProtection (fully-stalled, <1 B/s). A response trickling
/// faster than that could otherwise pin the read's limiter permit
/// indefinitely. The budget scales with the expected length up to a cap, so
/// the bounded read-ahead/cache reads always fit; the unbounded whole-object
/// lazy-load (`usize::MAX`) is capped at 64 MiB of budget (8192 s) — large
/// objects on a slow link can be cut mid-read there, which is acceptable
/// because the whole-object lazy load is itself the pathological case.
fn read_body_budget(expected_len: usize) -> Duration {
    let expected = (expected_len as u64).min(READ_BODY_BUDGET_CAP_BYTES);
    let by_throughput = (expected as f64 / READ_BODY_MIN_THROUGHPUT_BPS) as u64;
    READ_BODY_MIN_TOTAL.max(Duration::from_secs(by_throughput))
}
/// Above this size, `write` uploads via S3 multipart (bounded-concurrency
/// parts) instead of a single PUT. A single PUT is capped at 5 GiB by OSS/S3
/// and is more sensitive to timeouts / retries on large objects.
const MULTIPART_THRESHOLD: u64 = 16 * 1024 * 1024;
/// S3's single CopyObject limit: objects at or above this size must be
/// copied via multipart copy (#60).
pub(crate) const MULTIPART_COPY_THRESHOLD: u64 = 5 * 1024 * 1024 * 1024;
/// DeleteObjects batches at most this many keys per request (#60).
/// pub(crate):trash GC 批删复用(trash.rs)。
pub(crate) const MAX_DELETE_OBJECTS_PER_REQUEST: usize = 1000;
/// 回收站(soft delete)增量刷新周期秒:lazy 模式下本端感知远端删除的
/// 延迟上界(规格 C5 阈值,独立 commit 落地 + 断言防漂移;变更必须独立
/// commit 写明新旧值与理由)。
pub const TRASH_REFRESH_INTERVAL_SECS: u64 = 30;
/// 回收站全量重建周期秒:兜底「被恢复 / 被 GC 移除的墓碑」—— 增量游标
/// 只增不减,全量重建 diff 解决索引只增不减的问题(规格 C5 阈值,同上)。
pub const TRASH_REBUILD_INTERVAL_SECS: u64 = 600;
/// 回收站索引条目数告警阈值:超过此值 → 仅 warn、行为不变(full_rebuild
/// 的 diff 内存尖峰可见,缓解手段是 GC/trash-clean,见裁决 #6)。
/// 规格 C5 新阈值落地(无旧值);变更必须独立 commit 写明新旧值与理由。
pub const TRASH_INDEX_ALERT_THRESHOLD: usize = 500_000;
/// 回收站保留天数:墓碑日期早于 `today - TRASH_RETENTION_DAYS` 的分区才可
/// 被 GC 清理(规格 C5 阈值,独立 commit 落地 + 断言;新阈值,无旧值 ——
/// 设计稿 §9 默认 30 天)。变更必须独立 commit 写明新旧值与理由。
pub const TRASH_RETENTION_DAYS: u32 = 30;
/// 回收站 GC 周期秒:挂载时立即 GC 一次后按此周期后台清理过期墓碑
/// (规格 C5 阈值,独立 commit 落地 + 断言;新阈值,无旧值 —— 设计稿 §9
/// 默认 24h)。变更必须独立 commit 写明新旧值与理由。
pub const TRASH_GC_INTERVAL_SECS: u64 = 86_400;
/// Part size for multipart uploads (>= 5 MiB required by AWS; Aliyun OSS
/// allows >= 100 KiB, so 8 MiB is safe for both).
const MULTIPART_PART_SIZE: u64 = 8 * 1024 * 1024;
/// S3's hard cap on the number of parts per multipart upload.
const MAX_MULTIPART_PARTS: u64 = 10_000;
/// Concurrent in-flight part uploads within a single multipart write. Each
/// part also takes a global request-limit permit, so global in-flight stays
/// bounded.
const MULTIPART_UPLOAD_CONCURRENCY: usize = 4;
/// Unit size for the in-flight write-byte budget. The semaphore counts
/// whole MiB units, so the bound is accurate to within one MiB while keeping
/// permit counts small.
const UPLOAD_BUDGET_UNIT: usize = 1 << 20;
/// Upper bound on bytes held by the read-ahead cache. Keeps prefetch from
/// turning a sequential scan into an OOM (the same failure class the global
/// request limiter already guards against).
const READ_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Default share of `total_mem_limit` reserved for the read cache when the
/// configured ratio is unusable (NaN). Mirrors the CLI default.
const DEFAULT_TOTAL_MEM_READ_RATIO: f64 = 0.5;
/// Upper bound on read-ahead cache entries.
const READ_CACHE_MAX_ENTRIES: usize = 256;
/// Upper bound on tracked sequential-read hints; cleared when exceeded.
const MAX_READ_SEQ_ENTRIES: usize = 4096;
/// Unit size for the dirty-buffer budget (whole MiB permits).
const DIRTY_BUDGET_UNIT: usize = 1 << 20;
/// Block size for the disk cache. Reads are fetched and stored in these
/// fixed-size chunks, mirroring aliyun/ossfs cache_block_size.
const DISK_CACHE_BLOCK_SIZE: u64 = 4 * 1024 * 1024;
/// Version for the disk-cache on-disk format (block checksum layout).
const DISK_CACHE_META_VERSION: u64 = 2;
/// Default maximum number of concurrent disk-cache prefetch tasks.
const DISK_CACHE_PREFETCH_CONCURRENCY: usize = 4;
/// How long an object ETag check is considered fresh before re-HEADing.
const ETAG_CHECK_TTL: Duration = Duration::from_secs(10);
/// Unit size for the disk-cache byte budget (whole MiB permits).
const DISK_CACHE_BUDGET_UNIT: usize = 1 << 20;

/// `(total_capacity_bytes, available_bytes)` for the filesystem containing
/// `dir`. Best-effort: returns `None` when the OS query is unavailable, in
/// which case free-space protection is skipped.
#[cfg(windows)]
fn disk_space(dir: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut available = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            &mut total,
            &mut free,
        )
    };
    if ok == 0 {
        None
    } else {
        Some((total, available))
    }
}

#[cfg(not(windows))]
fn disk_space(dir: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize.max(1) as u64;
    Some((
        (stat.f_blocks as u64).saturating_mul(frsize),
        (stat.f_bavail as u64).saturating_mul(frsize),
    ))
}

/// Effective free-space floor: `max(reserve_bytes, ratio * total_bytes)`.
fn min_free_bytes(reserve: u64, ratio: Option<f64>, total: u64) -> u64 {
    let ratio_bytes = ratio
        .map(|r| (total as f64 * r.clamp(0.0, 0.99)) as u64)
        .unwrap_or(0);
    reserve.max(ratio_bytes)
}

/// Map `retries` (aliyun/ossfs semantics: additional attempts after the first)
/// to the AWS SDK `max_attempts` (total attempts: initial + retries).
fn s3_max_attempts(retries: u32) -> u32 {
    retries.saturating_add(1).max(1)
}

/// Build the SDK timeout config for the mount. `None` fields fall back to
/// the [`DEFAULT_*_TIMEOUT_SECS`] defaults (normalize() already guarantees
/// this; the fallback exists so a direct construction can never silently
/// regress to the SDK's no-read-timeout default).
fn s3_timeout_config(
    connect_secs: Option<u64>,
    read_secs: Option<u64>,
) -> aws_smithy_types::timeout::TimeoutConfig {
    let read = Duration::from_secs(read_secs.unwrap_or(DEFAULT_READWRITE_TIMEOUT_SECS));
    aws_smithy_types::timeout::TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(
            connect_secs.unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS),
        ))
        .read_timeout(read)
        // End-to-end budget for the whole operation, *including retries*:
        // without it the SDK's retry chain (default 3 attempts) lets one
        // request hold its limiter permit / part slot for attempts × read
        // timeout (3 × 600s) before giving up. A wedged request parks that
        // permit the whole time, which froze copies and deferred-close
        // uploads under load. Tying the operation budget to the configured
        // read timeout keeps the semantics simple: one operation — however
        // many attempts it needs — never outlives `readwrite-timeout` (#43).
        .operation_timeout(read)
        .build()
}

/// Resolve [`OssConfig::max_upload_bytes`] into a number of MiB permits.
/// Returns `None` when the budget is disabled. Values above what a single
/// acquire call can represent are clamped.
/// Derive effective memory budgets. When `total_mem_limit` is set it wins: the
/// read cache takes `total_mem_read_ratio`, and the rest splits equally between
/// upload bytes and dirty bytes. Otherwise the individual options win.
fn effective_memory_budgets(
    total_mem_limit: Option<usize>,
    total_mem_read_ratio: f64,
    max_upload_bytes: Option<usize>,
    max_dirty_bytes: Option<usize>,
    read_cache_max_bytes: Option<usize>,
) -> (Option<usize>, Option<usize>, usize) {
    match total_mem_limit {
        Some(total) if total > 0 => {
            // `NaN.clamp(..)` stays NaN and `(total * NaN) as usize` collapses
            // to 0, silently zeroing the read-cache budget — fall back to the
            // documented default split instead (#60).
            let ratio = if total_mem_read_ratio.is_nan() {
                DEFAULT_TOTAL_MEM_READ_RATIO
            } else {
                total_mem_read_ratio.clamp(0.01, 0.99)
            };
            let read = ((total as f64) * ratio) as usize;
            let rest = total.saturating_sub(read);
            (Some(rest / 2), Some(rest / 2), read)
        }
        _ => (
            max_upload_bytes,
            max_dirty_bytes,
            read_cache_max_bytes.unwrap_or(READ_CACHE_MAX_BYTES),
        ),
    }
}
fn upload_budget_units(max_bytes: Option<usize>) -> Option<usize> {
    let bytes = max_bytes?;
    if bytes == 0 {
        return None;
    }
    let units = bytes.div_ceil(UPLOAD_BUDGET_UNIT).min(u32::MAX as usize);
    Some(units.max(1))
}

/// Shared, bounded budget for whole-file dirty write buffers held by the
/// WinFsp/FUSE adapters. The budget is a semaphore of whole-MiB permits; each
/// open write handle keeps permits for its high-water buffer size and releases
/// them when the handle is closed.
#[derive(Clone)]
pub struct DirtyBudget {
    sem: Arc<Semaphore>,
    unit: usize,
    max_units: usize,
}

impl DirtyBudget {
    pub fn new(max_bytes: usize) -> Option<Self> {
        if max_bytes == 0 {
            return None;
        }
        let unit = DIRTY_BUDGET_UNIT;
        let max_units = max_bytes.div_ceil(unit).min(u32::MAX as usize).max(1);
        Some(Self {
            sem: Arc::new(Semaphore::new(max_units)),
            unit,
            max_units,
        })
    }

    pub fn unit(&self) -> usize {
        self.unit
    }

    pub fn max_units(&self) -> usize {
        self.max_units
    }

    /// Number of whole-unit permits for `bytes`, erroring when the amount
    /// exceeds the budget's total capacity.
    pub(crate) fn units_for(&self, bytes: usize) -> Result<usize> {
        let units = bytes.div_ceil(self.unit);
        if units > self.max_units {
            anyhow::bail!("{bytes} bytes exceeds max-dirty-bytes budget");
        }
        Ok(units)
    }

    /// Acquire `units` MiB permits. Returns an RAII permit that releases them
    /// on drop. `units == 0` returns an empty permit.
    pub async fn acquire_units(&self, units: usize) -> Result<DirtyPermit> {
        if units == 0 {
            return Ok(DirtyPermit::noop());
        }
        let permit = self
            .sem
            .clone()
            .acquire_many_owned(units as u32)
            .await
            .map_err(|_| anyhow::anyhow!("dirty buffer budget closed"))?;
        Ok(DirtyPermit {
            _permit: Some(permit),
        })
    }

    /// Like [`Self::acquire_units`] but fails immediately when fewer than
    /// `units` permits are available instead of waiting. Callers on
    /// single-threaded dispatch loops (e.g. FUSE truncate) must use this: a
    /// blocking acquire would park the only thread that can ever release the
    /// permits (handle close), deadlocking the whole mount.
    pub(crate) async fn try_acquire_units(&self, units: usize) -> Option<DirtyPermit> {
        if units == 0 {
            return Some(DirtyPermit::noop());
        }
        self.sem
            .clone()
            .try_acquire_many_owned(units as u32)
            .ok()
            .map(|permit| DirtyPermit {
                _permit: Some(permit),
            })
    }
}

/// RAII permit returned by [`DirtyBudget::acquire_units`]. Dropping it
/// releases the reserved MiB permits back to the budget.
pub struct DirtyPermit {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl DirtyPermit {
    /// An empty permit that holds no budget units (used when the mount has
    /// no budget configured or `units == 0`).
    pub(crate) fn noop() -> Self {
        Self { _permit: None }
    }
}

/// Token-bucket rate limiter for directory enumerations. Bounds how
/// fast a recursive scan (`find /`) can drive `ListObjects` calls while a
/// single normal directory read is served immediately (burst capacity).
struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: f64) -> Self {
        let burst = rate.max(1.0);
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    /// Refill and reserve one token. `None` means a token is available now;
    /// `Some(dur)` is how long to wait before retrying.
    fn reserve(&mut self, now: Instant) -> Option<Duration> {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            None
        } else {
            Some(Duration::from_secs_f64((1.0 - self.tokens) / self.rate))
        }
    }
}

/// One cached read-ahead window for a path.
struct ReadCacheEntry {
    start: u64,
    data: Vec<u8>,
    last_used: Instant,
}

/// Block-oriented on-disk cache for object ranges. Blocks are keyed by
/// FNV-1a hash of the object key plus block index; each block file starts
/// with the raw key so a hash collision is detected and treated as a miss.
#[derive(Debug)]
struct DiskCache {
    dir: PathBuf,
    max_bytes: u64,
    block_size: u64,
    used: AtomicU64,
    /// In-process LRU order of cached blocks: `(key, block)` with the most
    /// recently used entry at the back. Populated lazily on read/write; a
    /// cold-start eviction falls back to mtime.
    order: Mutex<VecDeque<(String, u64)>>,
    /// Free-space floor on the cache filesystem; writes are skipped below it.
    min_free_bytes: u64,
}

impl DiskCache {
    fn new(
        dir: PathBuf,
        max_bytes: usize,
        block_size: usize,
        reserve_diskfree: u64,
        free_space_ratio: Option<f64>,
    ) -> Result<Self> {
        let max_bytes =
            max_bytes.div_ceil(DISK_CACHE_BUDGET_UNIT) as u64 * DISK_CACHE_BUDGET_UNIT as u64;
        std::fs::create_dir_all(&dir).context("create disk cache dir")?;
        let min_free_bytes = {
            let (total, _avail) = disk_space(&dir).unwrap_or((0, 0));
            min_free_bytes(reserve_diskfree, free_space_ratio, total)
        };
        let block_size = Self::load_or_init_block_size(&dir, block_size)?;
        let cache = Self {
            dir,
            max_bytes,
            block_size,
            used: AtomicU64::new(0),
            order: Mutex::new(VecDeque::new()),
            min_free_bytes,
        };
        cache.load_order();
        if cache.order.lock().unwrap().is_empty() {
            cache.rebuild_order_from_mtime();
        }
        cache.rescan_used();
        Ok(cache)
    }

    fn load_or_init_block_size(dir: &Path, requested: usize) -> Result<u64> {
        let requested = requested.max(1) as u64;
        let meta = dir.join("cache.meta");
        let existing = std::fs::read_to_string(&meta).ok().and_then(|raw| {
            let mut version = None;
            let mut block_size = None;
            for line in raw.lines() {
                if let Some(v) = line.strip_prefix("version=") {
                    version = v.parse::<u64>().ok();
                } else if let Some(v) = line.strip_prefix("block_size=") {
                    block_size = v.parse::<u64>().ok();
                }
            }
            Some((version, block_size))
        });

        let reuse = matches!(
            existing,
            Some((Some(DISK_CACHE_META_VERSION), Some(block))) if block == requested
        );
        if !reuse {
            Self::clear_blocks(dir);
            std::fs::write(
                &meta,
                format!("version={DISK_CACHE_META_VERSION}\nblock_size={requested}\n"),
            )?;
        }
        Ok(requested)
    }

    fn clear_blocks(dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str());
                if ext == Some("blk")
                    || ext == Some("etag")
                    || path.file_name().and_then(|n| n.to_str()) == Some("lru.order")
                {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    fn etag_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.etag", fnv1a64(key)))
    }

    fn read_etag(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.etag_path(key)).ok()
    }

    fn store_etag(&self, key: &str, etag: &str) {
        let _ = std::fs::write(self.etag_path(key), etag);
    }

    fn order_path(&self) -> PathBuf {
        self.dir.join("lru.order")
    }

    fn load_order(&self) {
        let Ok(raw) = std::fs::read_to_string(self.order_path()) else {
            return;
        };
        let mut order = self.order.lock().unwrap();
        for line in raw.lines() {
            let Some((block, hex)) = line.split_once(' ') else {
                continue;
            };
            let Ok(block) = block.parse::<u64>() else {
                continue;
            };
            let Some(key) = hex_decode(hex) else {
                continue;
            };
            order.push_back((key, block));
        }
    }

    fn save_order(&self) {
        let order = self.order.lock().unwrap();
        let mut out = String::new();
        for (key, block) in order.iter() {
            out.push_str(&format!("{block} {}\n", hex_encode(key)));
        }
        let _ = std::fs::write(self.order_path(), out);
    }

    fn path_for(&self, key: &str, block: u64) -> PathBuf {
        self.dir.join(format!("{}-{:08x}.blk", fnv1a64(key), block))
    }

    fn read_block(&self, key: &str, block: u64) -> Option<Vec<u8>> {
        let path = self.path_for(key, block);
        let raw = std::fs::read(&path).ok()?;
        if raw.len() < 4 + 8 {
            return None;
        }
        let klen = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        if raw.len() < 4 + klen + 8 || &raw[4..4 + klen] != key.as_bytes() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        let crc = u64::from_le_bytes(raw[4 + klen..4 + klen + 8].try_into().unwrap());
        let data = raw[4 + klen + 8..].to_vec();
        if crc64ecma(&data) != crc {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        self.touch(key, block);
        Some(data)
    }

    fn write_block(&self, key: &str, block: u64, data: &[u8]) -> Result<()> {
        let header_len = (4 + key.len() + 8 + data.len()) as u64;
        if self.min_free_bytes > 0
            && let Some((_, avail)) = disk_space(&self.dir)
            && avail.saturating_sub(header_len) < self.min_free_bytes
        {
            // Refusing to cache keeps the disk above the free-space floor.
            // The read still succeeds; it is just not persisted locally.
            return Ok(());
        }
        let mut header = Vec::with_capacity(4 + key.len() + 8 + data.len());
        header.extend_from_slice(&(key.len() as u32).to_le_bytes());
        header.extend_from_slice(key.as_bytes());
        let crc = crc64ecma(data);
        header.extend_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(data);
        let final_path = self.path_for(key, block);
        // Size of the block being replaced, if any: `used` must track the
        // delta, not the new size, or an overwritten block inflates the
        // budget monotonically and evicts live blocks early (#60).
        let replaced = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
        // The tmp name is keyed by (key hash, block) exactly like the final
        // path, so two different blocks can never share a tmp file (#60).
        let tmp = self
            .dir
            .join(format!(".tmp-{:x}-{:08x}", fnv1a64(key), block));
        std::fs::write(&tmp, &header).context("write disk cache block")?;
        std::fs::rename(&tmp, &final_path).context("commit disk cache block")?;
        self.touch(key, block);
        let bytes = header.len() as u64;
        // Account for the size delta when overwriting, so `used` tracks the
        // on-disk total instead of growing monotonically (#60).
        let delta = bytes as i64 - replaced as i64;
        if delta > 0 {
            self.used.fetch_add(delta as u64, Ordering::Relaxed);
        } else if delta < 0 {
            self.used.fetch_sub(delta.unsigned_abs(), Ordering::Relaxed);
        }
        if self.used.load(Ordering::Relaxed) > self.max_bytes {
            self.evict();
        }
        self.save_order();
        Ok(())
    }

    fn touch(&self, key: &str, block: u64) {
        let mut order = self.order.lock().unwrap();
        if let Some(pos) = order.iter().position(|(k, b)| k == key && *b == block) {
            if let Some(entry) = order.remove(pos) {
                order.push_back(entry);
            }
        } else {
            order.push_back((key.to_string(), block));
        }
    }

    fn evict(&self) {
        let mut used = self.used.load(Ordering::Relaxed);
        while used > self.max_bytes {
            let (key, block) = {
                let mut order = self.order.lock().unwrap();
                let Some(entry) = order.pop_front() else {
                    break;
                };
                entry
            };
            let path = self.path_for(&key, block);
            if let Ok(meta) = std::fs::metadata(&path) {
                let len = meta.len();
                if std::fs::remove_file(&path).is_ok() {
                    used = used.saturating_sub(len);
                }
            }
        }
        self.used.store(used, Ordering::Relaxed);

        // Cold start (or stale order) fallback: if the in-memory LRU did not
        // bring us under budget, fall back to oldest-mtime eviction.
        if self.used.load(Ordering::Relaxed) > self.max_bytes {
            self.evict_by_mtime();
        }
    }

    fn evict_by_mtime(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "blk").unwrap_or(false))
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                Some((e.path(), meta.modified().ok()?, meta.len()))
            })
            .collect();
        files.sort_by(|a, b| b.1.cmp(&a.1)); // newest first
        let mut used = self.used.load(Ordering::Relaxed);
        for (path, _mtime, len) in files.iter().rev() {
            if used <= self.max_bytes {
                break;
            }
            if std::fs::remove_file(path).is_ok() {
                used = used.saturating_sub(*len);
            }
        }
        self.used.store(used, Ordering::Relaxed);
    }
    fn rebuild_order_from_mtime(&self) {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("blk") {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let stem = name.strip_suffix(".blk").unwrap_or(name);
                let Some(block) = stem
                    .rsplit_once('-')
                    .and_then(|(_, h)| u64::from_str_radix(h, 16).ok())
                else {
                    continue;
                };
                let Ok(raw) = std::fs::read(&path) else {
                    continue;
                };
                if raw.len() < 4 {
                    continue;
                }
                let klen = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
                if raw.len() < 4 + klen {
                    continue;
                }
                let key = String::from_utf8_lossy(&raw[4..4 + klen]).to_string();
                let mtime = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                files.push((mtime, key, block));
            }
        }
        files.sort_by_key(|(mtime, _, _)| *mtime);
        let mut order = self.order.lock().unwrap();
        for (_, key, block) in files {
            order.push_back((key, block));
        }
    }

    fn rescan_used(&self) {
        let mut used = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|x| x.to_str()) != Some("blk") {
                    continue;
                }
                if let Ok(meta) = e.metadata() {
                    used += meta.len();
                }
            }
        }
        self.used.store(used, Ordering::Relaxed);
    }

    fn invalidate(&self, key: &str) {
        let _ = std::fs::remove_file(self.etag_path(key));
        self.order.lock().unwrap().retain(|(k, _)| k != key);
        self.save_order();
        let prefix = format!("{}-", fnv1a64(key));
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|x| x.to_str()) != Some("blk") {
                    continue;
                }
                let path = e.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with(&prefix) {
                    if let Ok(meta) = e.metadata() {
                        let len = meta.len();
                        if std::fs::remove_file(&path).is_ok() {
                            self.used.fetch_sub(len, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    fn clear(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) == Some("etag") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|x| x.to_str()) != Some("blk") {
                    continue;
                }
                let _ = std::fs::remove_file(e.path());
            }
        }
        self.order.lock().unwrap().clear();
        self.save_order();
        self.used.store(0, Ordering::Relaxed);
    }
}

impl Drop for DiskCache {
    fn drop(&mut self) {
        self.save_order();
    }
}

/// FNV-1a 64-bit hash used for disk-cache block file names.
fn hex_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Option<String> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    String::from_utf8(out).ok()
}

fn fnv1a64(s: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Bounded read-ahead cache shared by all paths in one mount.
#[derive(Default)]
struct ReadCache {
    entries: HashMap<String, ReadCacheEntry>,
    bytes: usize,
}

/// Monotonic operation counters exposed by [`ObjectFs::metrics`].
#[derive(Default)]
pub struct Metrics {
    reads: AtomicU64,
    writes: AtomicU64,
    s3_gets: AtomicU64,
    s3_heads: AtomicU64,
    s3_stat_heads: AtomicU64,
    stat_cache_hits: AtomicU64,
    stat_positive_cache_hits: AtomicU64,
    stat_negative_cache_hits: AtomicU64,
    s3_etag_heads: AtomicU64,
    s3_lists: AtomicU64,
    s3_puts: AtomicU64,
    s3_errors: AtomicU64,
    s3_get_errors: AtomicU64,
    s3_list_errors: AtomicU64,
    s3_put_errors: AtomicU64,
    s3_delete_errors: AtomicU64,
    s3_multipart_errors: AtomicU64,
    upload_bytes_total: AtomicU64,
    download_bytes_total: AtomicU64,
    read_cache_hits: AtomicU64,
    read_cache_misses: AtomicU64,
    disk_cache_hits: AtomicU64,
    disk_cache_misses: AtomicU64,
    prefetch_started: AtomicU64,
    prefetch_skipped: AtomicU64,
    prefetch_failed: AtomicU64,
    list_throttled: AtomicU64,
    crc64_mismatches: AtomicU64,
    trash_tombstones_written: AtomicU64,
    trash_refresh_incrementals: AtomicU64,
    trash_refresh_rebuilds: AtomicU64,
    trash_refresh_errors: AtomicU64,
    trash_start_after_ignored: AtomicU64,
    trash_bootstrap_failures: AtomicU64,
    trash_gc_etag_skips: AtomicU64,
}

/// Point-in-time snapshot of [`Metrics`] counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub reads: u64,
    pub writes: u64,
    pub s3_gets: u64,
    pub s3_heads: u64,
    pub s3_stat_heads: u64,
    pub stat_cache_hits: u64,
    pub stat_positive_cache_hits: u64,
    pub stat_negative_cache_hits: u64,
    pub s3_etag_heads: u64,
    pub s3_lists: u64,
    pub s3_puts: u64,
    pub s3_errors: u64,
    pub s3_get_errors: u64,
    pub s3_list_errors: u64,
    pub s3_put_errors: u64,
    pub s3_delete_errors: u64,
    pub s3_multipart_errors: u64,
    pub upload_bytes_total: u64,
    pub download_bytes_total: u64,
    pub read_cache_hits: u64,
    pub read_cache_misses: u64,
    pub disk_cache_hits: u64,
    pub disk_cache_misses: u64,
    pub prefetch_started: u64,
    pub prefetch_inflight: usize,
    pub prefetch_skipped: u64,
    pub prefetch_failed: u64,
    pub list_throttled: u64,
    pub crc64_mismatches: u64,
    pub trash_tombstones_written: u64,
    /// 回收站索引条目数 gauge(TrashState.index_entries 注入,prefetch_inflight 先例)。
    pub trash_index_entries: usize,
    /// 增量拉取完成次数(§0.3)。
    pub trash_refresh_incrementals: u64,
    /// 全量重建完成次数(含 start-after 降级,§0.3)。
    pub trash_refresh_rebuilds: u64,
    /// 刷新/重建失败次数(§0.3)。
    pub trash_refresh_errors: u64,
    /// start-after 探测判定被忽略次数(§0.3)。
    pub trash_start_after_ignored: u64,
    /// 挂载时 bootstrap 失败次数(§0.3)。
    pub trash_bootstrap_failures: u64,
    /// GC etag 不一致跳过次数(§0.3)。
    pub trash_gc_etag_skips: u64,
}

impl Metrics {
    fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            reads: self.reads.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            s3_gets: self.s3_gets.load(Ordering::Relaxed),
            s3_heads: self.s3_heads.load(Ordering::Relaxed),
            s3_stat_heads: self.s3_stat_heads.load(Ordering::Relaxed),
            stat_cache_hits: self.stat_cache_hits.load(Ordering::Relaxed),
            stat_positive_cache_hits: self.stat_positive_cache_hits.load(Ordering::Relaxed),
            stat_negative_cache_hits: self.stat_negative_cache_hits.load(Ordering::Relaxed),
            s3_etag_heads: self.s3_etag_heads.load(Ordering::Relaxed),
            s3_lists: self.s3_lists.load(Ordering::Relaxed),
            s3_puts: self.s3_puts.load(Ordering::Relaxed),
            s3_errors: self.s3_errors.load(Ordering::Relaxed),
            s3_get_errors: self.s3_get_errors.load(Ordering::Relaxed),
            s3_list_errors: self.s3_list_errors.load(Ordering::Relaxed),
            s3_put_errors: self.s3_put_errors.load(Ordering::Relaxed),
            s3_delete_errors: self.s3_delete_errors.load(Ordering::Relaxed),
            s3_multipart_errors: self.s3_multipart_errors.load(Ordering::Relaxed),
            upload_bytes_total: self.upload_bytes_total.load(Ordering::Relaxed),
            download_bytes_total: self.download_bytes_total.load(Ordering::Relaxed),
            read_cache_hits: self.read_cache_hits.load(Ordering::Relaxed),
            read_cache_misses: self.read_cache_misses.load(Ordering::Relaxed),
            disk_cache_hits: self.disk_cache_hits.load(Ordering::Relaxed),
            disk_cache_misses: self.disk_cache_misses.load(Ordering::Relaxed),
            prefetch_started: self.prefetch_started.load(Ordering::Relaxed),
            prefetch_inflight: 0,
            prefetch_skipped: self.prefetch_skipped.load(Ordering::Relaxed),
            prefetch_failed: self.prefetch_failed.load(Ordering::Relaxed),
            list_throttled: self.list_throttled.load(Ordering::Relaxed),
            crc64_mismatches: self.crc64_mismatches.load(Ordering::Relaxed),
            trash_tombstones_written: self.trash_tombstones_written.load(Ordering::Relaxed),
            trash_index_entries: 0, // gauge 由 metrics() 注入(TrashState.index_entries)
            trash_refresh_incrementals: self.trash_refresh_incrementals.load(Ordering::Relaxed),
            trash_refresh_rebuilds: self.trash_refresh_rebuilds.load(Ordering::Relaxed),
            trash_refresh_errors: self.trash_refresh_errors.load(Ordering::Relaxed),
            trash_start_after_ignored: self.trash_start_after_ignored.load(Ordering::Relaxed),
            trash_bootstrap_failures: self.trash_bootstrap_failures.load(Ordering::Relaxed),
            trash_gc_etag_skips: self.trash_gc_etag_skips.load(Ordering::Relaxed),
        }
    }
}

/// A streaming multipart upload handle. Bytes are fed via [`StreamingUpload::write`]
/// and uploaded as [`StreamingUpload::part_size`] parts in the background (bounded
/// by `part_sem`), so upload overlaps with the local write and the process never
/// holds the whole object in memory.
pub struct StreamingUpload {
    client: Client,
    bucket: String,
    key: String,
    upload_id: String,
    next_part: i32,
    parts: Vec<(i32, String)>,
    pending: Vec<u8>,
    /// Total bytes fed through [`Self::write`] — the size the completed
    /// object must have, used to verify a raced completion on NoSuchUpload.
    total_bytes: u64,
    hasher: Crc64Ecma,
    verify_crc64: bool,
    content_md5: bool,
    part_sem: Arc<Semaphore>,
    limiter: Arc<Semaphore>,
    tasks: tokio::task::JoinSet<anyhow::Result<(i32, String)>>,
    metrics: Arc<Metrics>,
    /// Multipart part size in bytes (from `OssConfig::multipart_size`; the
    /// default is [`MULTIPART_PART_SIZE`]). The user-visible knob was
    /// previously ignored on this path (#55).
    part_size: usize,
    /// In-flight write-byte budget (MiB-unit semaphore); `None` = unlimited.
    /// Permits are acquired incrementally in [`Self::write`] and released
    /// when the upload finishes, aborts or drops.
    budget_sem: Option<Arc<Semaphore>>,
    /// MiB units of `budget_sem` currently held (high-water mark).
    budget_units: usize,
    /// RAII permits backing [`Self::budget_units`]; dropped together with the
    /// handle (finish/abort/drop), releasing the budget.
    budget_permits: Vec<tokio::sync::OwnedSemaphorePermit>,
    /// Set once the upload reached a terminal state (completed or aborted).
    /// [`Drop`] then skips its best-effort abort — otherwise dropping a
    /// finished handle would abort the very object it just completed.
    aborted: bool,
    /// Tokio runtime captured at [`ObjectFs::begin_streaming_upload`] (which
    /// always runs in a runtime context). The adapter may drop the handle on
    /// a plain synchronous thread (e.g. a FUSE release callback), where
    /// `Handle::try_current` would fail; the captured handle lets [`Drop`]
    /// still spawn its best-effort abort (#55).
    rt: tokio::runtime::Handle,
}

impl StreamingUpload {
    /// Object key this upload writes to (immutable once started). Adapters
    /// compare it against the handle's current path so a rename cannot make
    /// a flush resurrect the deleted old object (#46).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Feed `data` into the upload. Buffers until a full part is ready, then
    /// uploads it in the background.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        let new_total = self.total_bytes.saturating_add(data.len() as u64);
        // S3 caps multipart at 10,000 parts; fail before uploading a part
        // that can never complete, instead of discovering it at
        // CompleteMultipartUpload after the whole object was uploaded (#55).
        let max_bytes = (self.part_size as u64).saturating_mul(MAX_MULTIPART_PARTS);
        if new_total > max_bytes {
            anyhow::bail!(
                "streaming write exceeds S3 multipart limit of {MAX_MULTIPART_PARTS} parts \
                 ({max_bytes} bytes at part size {})",
                self.part_size
            );
        }
        // Grow the upload-budget reservation for the newly fed bytes.
        // try_acquire, not acquire: the FUSE adapter feeds stream writes on
        // its single dispatcher thread, where a blocking wait could hang the
        // whole mount (same reasoning as the dirty-budget fix, #53/#55).
        if !data.is_empty() {
            if let Some(sem) = &self.budget_sem {
                let units = new_total.div_ceil(UPLOAD_BUDGET_UNIT as u64) as usize;
                if units > self.budget_units {
                    let permit = sem
                        .clone()
                        .try_acquire_many_owned((units - self.budget_units) as u32)
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "write of {new_total} bytes exceeds max-upload-bytes budget"
                            )
                        })?;
                    // Holding the permit(s) until finish/abort/drop bounds
                    // total in-flight streaming bytes at max-upload-bytes.
                    self.budget_units = units;
                    self.budget_permits.push(permit);
                }
            }
        }
        self.hasher.update(data);
        self.total_bytes = new_total;
        self.pending.extend_from_slice(data);
        while self.pending.len() >= self.part_size {
            let chunk: Vec<u8> = self.pending.drain(..self.part_size).collect();
            self.upload_part(chunk).await?;
        }
        Ok(())
    }

    async fn upload_part(&mut self, chunk: Vec<u8>) -> Result<()> {
        let part_no = self.next_part;
        self.next_part += 1;
        let slot = self
            .part_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("multipart concurrency closed"))?;
        let md5 = self.content_md5.then(|| content_md5(&chunk));
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();
        let limiter = Arc::clone(&self.limiter);
        self.tasks.spawn(async move {
            let _permit = limiter
                .acquire_owned()
                .await
                .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))?;
            let mut part = client
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .part_number(part_no)
                .body(ByteStream::from(chunk));
            if let Some(md5) = md5 {
                part = part.content_md5(md5);
            }
            let resp = part.send().await.context("s3 upload part")?;
            let etag = resp.e_tag().unwrap_or_default().to_string();
            drop(slot);
            Ok((part_no, etag))
        });
        Ok(())
    }

    /// Flush the final partial part, await all parts, and complete the upload.
    pub async fn finish(mut self) -> Result<()> {
        if !self.pending.is_empty() {
            let chunk = std::mem::take(&mut self.pending);
            self.upload_part(chunk).await?;
            // upload_part error: self is dropped here — [`Drop`] aborts the
            // upload so no multipart is left behind (#55).
        }
        let mut upload_error = None;
        while let Some(joined) = self.tasks.join_next().await {
            match joined {
                Ok(Ok((part_no, etag))) => self.parts.push((part_no, etag)),
                Ok(Err(e)) => upload_error = Some(e),
                Err(e) => upload_error = Some(anyhow::anyhow!("multipart task panicked: {e}")),
            }
        }
        if let Some(e) = upload_error {
            let _ = self.abort_send().await;
            self.aborted = true;
            return Err(e);
        }
        self.parts.sort_by_key(|p| p.0);
        // `hasher.finalize()` below moves only `self.hasher`, so client /
        // bucket / key remain borrowable for the completion builder and (on
        // the rare error branch) the HEAD verify — no eager clone needed.
        let parts = std::mem::take(&mut self.parts);
        // Replace, not move: `StreamingUpload` implements Drop, so a field
        // may not be moved out of `self`; the finished hasher is swapped for
        // a fresh no-op one (#55).
        let hasher = std::mem::replace(&mut self.hasher, Crc64Ecma::new());
        let expected_crc = self.verify_crc64.then(|| hasher.finalize());
        let crc_slot = Arc::new(Mutex::new(None));
        let mut complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(
                        parts
                            .into_iter()
                            .map(|(n, etag)| {
                                CompletedPart::builder().part_number(n).e_tag(etag).build()
                            })
                            .collect(),
                    ))
                    .build(),
            )
            .customize();
        if expected_crc.is_some() {
            complete = complete.interceptor(Crc64ResponseCapture {
                slot: Arc::clone(&crc_slot),
            });
        }
        let _permit = self
            .limiter
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))?;
        if let Err(e) = complete.send().await {
            // A failed CompleteMultipartUpload may still have completed the
            // object server-side: a retried complete racing the first attempt
            // reports NoSuchUpload, and a timeout / 5xx / connection reset can
            // land after the request was issued. Aborting would then target a
            // consumed upload (a no-op) and the caller would wrongly see
            // failure. HEAD-verify: when the key exists with exactly the fed
            // byte count the write succeeded (the complete response never
            // arrived, so the whole-object CRC64 header cannot be captured —
            // size-verified success is the best guarantee for this path).
            drop(_permit);
            if matches!(
                head_reports_size(
                    &self.client,
                    &self.bucket,
                    &self.key,
                    self.total_bytes,
                    &self.metrics,
                    &self.limiter,
                )
                .await,
                Some(true)
            ) {
                // `self.hasher` was moved into the crc closure above, so
                // count via direct field access (field access on a partially
                // moved value is fine).
                self.metrics.s3_puts.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .upload_bytes_total
                    .fetch_add(self.total_bytes, Ordering::Relaxed);
                self.aborted = true;
                return Ok(());
            }
            let _ = self.abort_send().await;
            self.aborted = true;
            return Err(e).context("s3 complete multipart upload");
        }
        if let Some(expected) = expected_crc {
            if let Err(e) = check_crc64_response(crc_slot, expected, &self.metrics) {
                // The object completed server-side; a Drop abort would be a
                // no-op. Mark terminal so Drop skips the wasted request even
                // on this error path (#55 review).
                self.aborted = true;
                return Err(e);
            }
        }
        // One completed streamed object: a single PUT-equivalent upload of
        // `total_bytes` (#60 — streaming uploads used to be invisible to the
        // put/byte counters).
        self.metrics.s3_puts.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .upload_bytes_total
            .fetch_add(self.total_bytes, Ordering::Relaxed);
        self.aborted = true;
        Ok(())
    }

    /// Best-effort AbortMultipartUpload under a limiter permit. Callers use
    /// it on their error paths and set `aborted` themselves.
    async fn abort_send(&self) -> anyhow::Result<()> {
        let _permit = self
            .limiter
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))?;
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .send()
            .await
            .map(|_| ())
            .context("s3 abort multipart upload")
    }

    /// Abort the multipart upload and discard any uploaded parts, keeping
    /// the object's previous content (or absence). Used when a truncate /
    /// overwrite invalidates the in-flight stream (#47).
    pub async fn abort(mut self) {
        self.aborted = true;
        self.tasks.abort_all();
        let _ = self.abort_send().await;
    }
}

impl Drop for StreamingUpload {
    /// Best-effort abort of an abandoned upload: adapter error paths and
    /// dropped handles would otherwise orphan the multipart upload, leaving
    /// uploaded parts billed as invisible storage until a bucket lifecycle
    /// rule cleans them up (#55). Completed (`finish`) and explicitly aborted
    /// (`abort`) handles set `aborted` and are untouched.
    fn drop(&mut self) {
        if self.aborted {
            return;
        }
        self.aborted = true;
        self.tasks.abort_all();
        // Drop can run on a plain sync thread (a FUSE release callback
        // outside block_on); the runtime handle captured at begin() lets us
        // still spawn the abort from anywhere.
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();
        let limiter = self.limiter.clone();
        self.rt.spawn(async move {
            let _permit = match limiter.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let _ = client
                .abort_multipart_upload()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .send()
                .await;
        });
    }
}

/// HEAD `key`; return `Some(true)` when it exists with exactly
/// `expected_bytes`. Used to confirm a multipart upload that completed
/// server-side before a racing CompleteMultipartUpload failed (e.g. with
/// NoSuchUpload), so the caller treats the write as success instead of
/// aborting or erroring on a possibly-complete object. `metrics`, when
/// provided, counts the HEAD against `s3_heads` (it is invisible to the
/// adapters' other HEAD paths otherwise). Takes a limiter permit so the
/// verification HEAD stays inside `MAX_CONCURRENT_S3_REQUESTS` (#55).
async fn head_reports_size(
    client: &Client,
    bucket: &str,
    key: &str,
    expected_bytes: u64,
    metrics: &Metrics,
    limiter: &Arc<Semaphore>,
) -> Option<bool> {
    metrics.s3_heads.fetch_add(1, Ordering::Relaxed);
    let _permit = limiter.clone().acquire_owned().await.ok()?;
    let resp = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .ok()?;
    Some(resp.content_length()? as u64 == expected_bytes)
}

pub struct ObjectFs {
    client: Client,
    bucket: String,
    prefix: String,
    /// Short-TTL attribute cache: path -> (cached_at, entry).
    stats: Mutex<HashMap<String, (Instant, DirEntry)>>,
    /// Negative stat cache: path -> cached_at (path known missing).
    negative: Mutex<HashMap<String, Instant>>,
    /// Trash (soft-delete) index; `None` = trash disabled (hard delete).
    /// pub(crate):单元 4 winfsp.rs 内联消费(裁决 R16:match_system_trash /
    /// set_recycle_i 经此字段直调 TrashState 方法,不加 ObjectFs 包装)。
    pub(crate) trash: Option<Arc<trash::TrashState>>,
    /// 回收站后台刷新循环已启动标记(挂载钩子调用 trash_refresh_start 的
    /// 防重入;compare_exchange/swap 语义,重复调用 no-op)。
    trash_refresh_started: AtomicBool,
    /// Bounds in-flight S3 requests (see [`MAX_CONCURRENT_S3_REQUESTS`]).
    limiter: Arc<Semaphore>,
    /// Optional directory-enumeration rate limiter (see [OssConfig::list_rate_limit]).
    list_rate: Option<Mutex<TokenBucket>>,
    /// Read-only mount: reject all mutations.
    read_only: bool,
    /// Open the FUSE mount to all users (see [OssConfig::allow_other]).
    allow_other: bool,
    /// POSIX ownership / permission defaults for the FUSE adapters.
    mount_attr: MountAttr,
    /// Whether directory renames are allowed at all.
    allow_rename_dir: bool,
    /// Max object count for one directory rename; `None` = unlimited.
    rename_dir_limit: Option<u64>,
    /// In-flight write-byte budget (MiB-unit semaphore); `None` = unlimited.
    upload_budget: Option<Arc<Semaphore>>,
    /// Total MiB units available when [`Self::upload_budget`] is set.
    upload_budget_units: usize,
    /// Sequential-read prefetch window; 0 disables read-ahead.
    read_ahead_window: usize,
    /// Bounded read-ahead cache.
    read_cache: Mutex<ReadCache>,
    /// Upper bound on in-memory read-ahead cache bytes.
    read_cache_max_bytes: usize,
    /// Optional block-oriented on-disk read cache.
    disk_cache: Option<Arc<DiskCache>>,
    /// Background prefetch depth for sequential disk-cache reads.
    disk_cache_prefetch_blocks: usize,
    /// In-flight prefetch dedup: `(key, block)` currently being prefetched.
    prefetch_inflight: Arc<Mutex<HashSet<(String, u64)>>>,
    /// Caps concurrent background prefetch tasks.
    prefetch_sem: Arc<Semaphore>,
    /// Verify object ETag with HEAD before serving disk-cache blocks.
    disk_cache_verify_etag: bool,
    /// path -> last successful ETag check (short TTL, see [`ETAG_CHECK_TTL`]).
    etag_checked: Mutex<HashMap<String, Instant>>,
    /// TTL for cached ETag checks.
    etag_ttl: Duration,
    negative_ttl: Duration,
    stat_ttl: Duration,
    negative_max_entries: usize,
    stat_max_entries: usize,

    /// Prefetch dedup skips and failures are tracked inside [`Metrics`].
    /// path -> end offset of its previous read (sequential-read hint).
    read_seq: Mutex<HashMap<String, u64>>,
    /// Whether FUSE fsync should be a no-op (whole-file buffered writes).
    ignore_fsync: bool,
    /// Verify uploaded objects via x-oss-hash-crc64ecma (see [OssConfig::verify_crc64]).
    verify_crc64: bool,
    /// Storage class for newly written objects (see [OssConfig::storage_class]).
    storage_class: Option<StorageClass>,
    /// Set Content-MD5 on uploads (see [OssConfig::content_md5]).
    content_md5: bool,
    /// Skip legacy `_$folder$` directory markers (see [OssConfig::notsup_compat_dir]).
    notsup_compat_dir: bool,
    /// Multipart upload part size in bytes.
    multipart_part_size: usize,
    /// Concurrent in-flight part uploads within a single multipart write.
    multipart_concurrency: usize,
    /// Monotonic operation counters.
    metrics: Arc<Metrics>,
    /// Dirty-buffer budget for the adapters; None when unlimited.
    dirty_budget: Option<DirtyBudget>,
    /// Upper bound for a single adapter operation (flush/cleanup uploads):
    /// a network request hanging beyond this must fail the operation instead
    /// of parking the WinFsp callback — and with it Explorer — forever
    /// (#43). Mirrors `readwrite_timeout`.
    operation_timeout: std::time::Duration,
}

/// Build the trash state from config: `trash_dir` is a single path segment
/// (rejecting empty / '/' / '.' / '..'), and the tombstone prefix is
/// `{prefix}{trash_dir}/` (`prefix` is normalized to end with '/'; an empty
/// prefix yields `.trash/`). `None` → trash disabled, no state.
/// 启动重建(rebuild_trash_index)不在此处 spawn —— 由挂载钩子在单元 3 落地
/// (connect 内无 Arc<ObjectFs>,后台任务无法 invalidate 缓存)。
fn build_trash_state(config: &OssConfig) -> Result<Option<Arc<trash::TrashState>>> {
    let Some(dir) = &config.trash_dir else {
        return Ok(None);
    };
    if dir.is_empty() || dir.contains('/') || dir == "." || dir == ".." {
        anyhow::bail!("trash-dir must be a single path segment (no '/', '.' or '..'): got `{dir}`");
    }
    // 调度字段读 normalized config(常量兜底;normalize 已填默认值,双保险)。
    let mode = config.trash_refresh_mode.unwrap_or(TrashRefreshMode::Lazy);
    let refresh_interval = Duration::from_secs(
        config
            .trash_refresh_interval_secs
            .unwrap_or(TRASH_REFRESH_INTERVAL_SECS),
    );
    let rebuild_interval = Duration::from_secs(TRASH_REBUILD_INTERVAL_SECS);
    let gc_interval = Duration::from_secs(
        config
            .trash_gc_interval_secs
            .unwrap_or(TRASH_GC_INTERVAL_SECS),
    );
    // 保留期消费点(H1):--trash-retention-days 经 normalize 已填默认,
    // 兜底常量防直接构造未 normalize 的 config。
    let retention_days = config.trash_retention_days.unwrap_or(TRASH_RETENTION_DAYS);
    let mut state = trash::TrashState::new(
        format!("{}{}/", config.prefix, dir),
        mode,
        refresh_interval,
        rebuild_interval,
        gc_interval,
        retention_days,
    );
    // 系统回收站虚拟视图注入(裁决 R1):纯消费 Some/None —— 默认开/关由
    // CLI 按平台决定(--no-system-trash 显式关必须可区分「未配置」,故
    // 默认值不在此处补齐,否则 --no-system-trash 会被默认开覆盖)。
    // 平台形态:macOS = MacOsTrashes(.Trashes),其余 = WindowsRecycleBin
    // ($Recycle.Bin,$R/$I 成对);dir_name 平台默认在此落地。
    if let Some(sys) = &config.system_trash {
        let dir_name = sys.dir_name.clone().unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                ".Trashes".to_string()
            } else {
                "$Recycle.Bin".to_string()
            }
        });
        let platform = if cfg!(target_os = "macos") {
            trash::SystemTrashPlatform::MacOsTrashes
        } else {
            trash::SystemTrashPlatform::WindowsRecycleBin
        };
        Arc::get_mut(&mut state)
            .expect("freshly created arc is uniquely owned")
            .system = Some(trash::SystemTrash {
            platform,
            macos_uid_dirs: sys.macos_uid_dirs.clone(),
            dir_name,
        });
    }
    Ok(Some(state))
}

impl ObjectFs {
    /// Build the S3 client from environment credentials
    /// (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` or the shared config
    /// file), which is how the desktop tray app spawns mounts.
    pub async fn connect(config: OssConfig) -> Result<Self> {
        // Pre-normalize value: normalize() fills the default 600s, but the
        // adapter-operation timeout wants its own (shorter) default when the
        // user did not configure one.
        let configured_readwrite = config.readwrite_timeout_secs;
        let config = config.normalize();
        let loader = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&loader);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        if config.force_path_style {
            builder = builder.force_path_style(true);
        }
        if let Some(command) = &config.credential_process {
            builder = builder.credentials_provider(CredentialProcessProvider::new(command.clone()));
        }
        // Request timeouts are always set: post-normalize both fields are
        // Some, and falling back to the loader's timeout config would
        // reintroduce the SDK's no-read-timeout default — the wedge this
        // guards against. See `s3_timeout_config`.
        builder = builder.timeout_config(s3_timeout_config(
            config.connect_timeout_secs,
            config.readwrite_timeout_secs,
        ));
        if let Some(retries) = config.retries {
            builder = builder.retry_config(
                aws_smithy_types::retry::RetryConfig::standard()
                    .with_max_attempts(s3_max_attempts(retries)),
            );
        }
        let client = Client::from_conf(builder.build());
        let (max_upload_bytes, max_dirty_bytes, read_cache_max_bytes) = effective_memory_budgets(
            config.total_mem_limit,
            config.total_mem_read_ratio,
            config.max_upload_bytes,
            config.max_dirty_bytes,
            config.read_cache_max_bytes,
        );
        let upload_budget_units = upload_budget_units(max_upload_bytes);
        let read_ahead_window = config.read_ahead_bytes.unwrap_or(0);
        let ignore_fsync = config.ignore_fsync;
        let dirty_budget = DirtyBudget::new(max_dirty_bytes.unwrap_or(0));
        // 回收站状态必须在 struct 字面量之前构建(config 字段随后被 move)。
        let trash = build_trash_state(&config)?;
        let disk_cache = match &config.disk_cache_dir {
            Some(dir) if config.disk_cache_max_bytes > 0 => Some(Arc::new(DiskCache::new(
                dir.clone(),
                config.disk_cache_max_bytes,
                config
                    .disk_cache_block_size
                    .unwrap_or(DISK_CACHE_BLOCK_SIZE as usize),
                config.disk_cache_reserve_diskfree,
                config.disk_cache_free_space_ratio,
            )?)),
            _ => None,
        };
        let fs = Self {
            client,
            bucket: config.bucket,
            prefix: config.prefix,
            stats: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            limiter: Arc::new(Semaphore::new(effective_max_concurrent_requests(
                config.max_concurrent_requests,
            ))),
            list_rate: config
                .list_rate_limit
                .filter(|r| *r > 0.0)
                .map(|r| Mutex::new(TokenBucket::new(r))),
            read_only: config.read_only,
            allow_other: config.allow_other,
            mount_attr: MountAttr {
                uid: config.uid,
                gid: config.gid,
                dir_mode: config.dir_mode,
                file_mode: config.file_mode,
                umask: config.umask,
            },
            allow_rename_dir: config.allow_rename_dir,
            rename_dir_limit: config.rename_dir_limit,
            upload_budget: upload_budget_units.map(|units| Arc::new(Semaphore::new(units))),
            upload_budget_units: upload_budget_units.unwrap_or(0),
            read_ahead_window,
            read_cache: Mutex::new(ReadCache::default()),
            read_cache_max_bytes,
            disk_cache,
            disk_cache_prefetch_blocks: config.disk_cache_prefetch_blocks,
            prefetch_inflight: Arc::new(Mutex::new(HashSet::new())),
            prefetch_sem: Arc::new(Semaphore::new(
                config.disk_cache_prefetch_concurrency.max(1),
            )),
            disk_cache_verify_etag: config.disk_cache_verify_etag,
            etag_checked: Mutex::new(HashMap::new()),
            etag_ttl: Duration::from_secs(config.disk_cache_etag_ttl_secs.max(1)),
            negative_ttl: Duration::from_secs(config.negative_cache_ttl_secs.max(1)),
            stat_ttl: Duration::from_secs(config.stat_cache_ttl_secs.max(1)),
            negative_max_entries: config.negative_cache_max_entries.max(1),
            stat_max_entries: config.stat_cache_max_entries.max(1),
            read_seq: Mutex::new(HashMap::new()),
            ignore_fsync,
            verify_crc64: config.verify_crc64,
            storage_class: config.storage_class.map(|s| StorageClass::from(s.as_str())),
            content_md5: config.content_md5,
            notsup_compat_dir: config.notsup_compat_dir,
            multipart_part_size: config
                .multipart_size
                .unwrap_or(MULTIPART_PART_SIZE as usize)
                .max(5 * 1024 * 1024),
            multipart_concurrency: config
                .multipart_concurrency
                .unwrap_or(MULTIPART_UPLOAD_CONCURRENCY)
                .max(1),
            metrics: Arc::new(Metrics::default()),
            dirty_budget,
            operation_timeout: std::time::Duration::from_secs(
                configured_readwrite.unwrap_or(DEFAULT_READWRITE_TIMEOUT_SECS),
            ),
            trash,
            trash_refresh_started: AtomicBool::new(false),
        };
        // Fail fast on a missing bucket: every later request would 404, which
        // is indistinguishable from "empty bucket" and would surface as a
        // silently empty drive instead of a configuration error (#60).
        fs.ensure_bucket_exists().await?;
        Ok(fs)
    }

    /// Verify the configured bucket exists (mount-time configuration check).
    pub async fn ensure_bucket_exists(&self) -> Result<()> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => Ok(()),
            Err(e) if is_s3_not_found(&e) => {
                anyhow::bail!(
                    "bucket `{}` does not exist at the configured endpoint/region",
                    self.bucket
                );
            }
            Err(e) => {
                // 403 (valid credentials lacking s3:ListBucket on an existing
                // bucket) and 5xx (transient) must not fail the mount — the
                // bucket very likely exists and later operations will surface
                // real permission problems (review B1).
                tracing::warn!(
                    bucket = %self.bucket,
                    error = ?e,
                    "head-bucket check failed (not a 404); continuing — the bucket may exist \
                     but the credentials may lack s3:ListBucket, or the endpoint is transiently down"
                );
                Ok(())
            }
        }
    }

    /// Read-only state of this mount.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Whether FUSE fsync should be ignored (whole-file buffered write model).
    pub fn ignore_fsync(&self) -> bool {
        self.ignore_fsync
    }

    /// Shared dirty-buffer budget for the adapters, when configured.
    /// Snapshot of monotonic operation counters (for an admin/metrics endpoint).
    pub fn metrics(&self) -> MetricsSnapshot {
        let mut snapshot = self.metrics.snapshot();
        snapshot.prefetch_inflight = self.prefetch_inflight.lock().unwrap().len();
        // gauge 注入:TrashState 持计数(prefetch_inflight 先例),None → 0。
        snapshot.trash_index_entries = self
            .trash
            .as_ref()
            .map_or(0, |t| t.index_entries.load(Ordering::Relaxed) as usize);
        snapshot
    }

    pub fn dirty_budget(&self) -> Option<DirtyBudget> {
        self.dirty_budget.clone()
    }

    /// Adapter-operation timeout (see the `operation_timeout` field).
    pub fn operation_timeout(&self) -> std::time::Duration {
        self.operation_timeout
    }

    /// POSIX ownership / permission defaults applied by the FUSE adapters.
    pub fn mount_attr(&self) -> MountAttr {
        self.mount_attr
    }

    /// Whether the FUSE mount is opened to all users (`allow_other`).
    pub fn allow_other(&self) -> bool {
        self.allow_other
    }

    /// Acquire the in-flight write-byte budget for `data_len` bytes.
    /// Returns a permit that must be held for the whole upload.
    ///
    /// try_acquire, not acquire: on macOS the whole-object write runs on the
    /// single fuser dispatcher thread (flush_open), and a blocking wait can
    /// hang the mount forever — streaming handles hold their budget permits
    /// across operations and release them only from a later dispatcher
    /// callback (#55). A full budget therefore fails the write instead of
    /// parking the only thread that could ever free it.
    async fn acquire_upload_budget(
        &self,
        data_len: usize,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        let Some(sem) = &self.upload_budget else {
            return Ok(None);
        };
        let units = data_len.div_ceil(UPLOAD_BUDGET_UNIT);
        if units > self.upload_budget_units {
            anyhow::bail!(
                "write of {data_len} bytes exceeds max-upload-bytes budget ({})",
                self.upload_budget_units.saturating_mul(UPLOAD_BUDGET_UNIT)
            );
        }
        if units == 0 {
            return Ok(None);
        }
        Ok(Some(
            sem.clone()
                .try_acquire_many_owned(units as u32)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "write of {data_len} bytes exceeds max-upload-bytes budget: \
                         in-flight streaming uploads hold all of it"
                    )
                })?,
        ))
    }

    /// Reject mutations when mounted read-only.
    fn ensure_writable(&self) -> Result<()> {
        if self.read_only {
            anyhow::bail!("filesystem is mounted read-only");
        }
        Ok(())
    }

    /// Acquire a permit bounding in-flight S3 operations. Every public
    /// S3-facing method takes exactly one permit for its whole body (mkdir
    /// takes one indirectly via write); internal `*_impl` helpers never
    /// acquire, so cross-calls cannot deadlock even when the pool is
    /// saturated. Helpers that issue their *own* S3 request on top of a
    /// caller's permit must use `try_acquire` (see `verify_disk_cache_etag`)
    /// — never block on a second permit, or a saturated pool deadlocks.
    /// Helpers that issue their own request with no outer permit (verification
    /// HEADs, aborts — see `head_reports_size` / `abort_upload`) acquire one
    /// permit for that request, so the in-flight count never exceeds
    /// `MAX_CONCURRENT_S3_REQUESTS` even stacked on a public method (#55).
    /// Keep this invariant: public methods acquire, `*_impl` helpers never do.
    async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.limiter
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))
    }

    /// Full object key for a normalized POSIX path (see module docs).
    pub fn key_for(&self, path: &str) -> String {
        let rel = rel_key(path);
        if rel.is_empty() {
            self.prefix.trim_end_matches('/').to_string()
        } else {
            format!("{}{}", self.prefix, rel)
        }
    }

    /// S3 list prefix for the children of `dir` (always ends with `/`).
    fn list_prefix(&self, dir: &str) -> String {
        if dir == "/" {
            self.prefix.clone()
        } else {
            format!("{}{}/", self.prefix, rel_key(dir))
        }
    }

    /// 统一过滤入口(私有,同步,不 await)。None 时只多一次判空 → 零行为变化。
    /// .trash 自隐藏双形态:`key.starts_with(prefix)` 覆盖 ".trash/..." 与根 list 的
    /// common_prefix;`key == prefix.trim_end_matches('/')` 覆盖 stat("/.trash") 的裸 key
    /// 形态(否则经 marker HEAD 复活)。尾斜杠边界保证 ".trashx" 不误伤。
    fn hidden_key(&self, key: &str) -> bool {
        let Some(trash) = &self.trash else {
            return false;
        };
        let p = trash.prefix.as_str();
        if key.starts_with(p) || key == p.trim_end_matches('/') {
            return true;
        }
        trash.index.read().unwrap().is_covered(key)
    }

    /// 分页过滤专用(裁决 #12):调用方持**每页一次**读锁快照,本方法不再
    /// 取锁。语义与 [`Self::hidden_key`] 相同(.trash 自隐藏双形态 + 索引
    /// 覆盖);前提是过滤循环内无 await —— 见 `list_impl` 快照注释。
    fn hidden_key_with(&self, snapshot: &trash::TombstoneIndex, key: &str) -> bool {
        let Some(trash) = &self.trash else {
            return false;
        };
        let p = trash.prefix.as_str();
        key.starts_with(p) || key == p.trim_end_matches('/') || snapshot.is_covered(key)
    }

    /// 挂载启动全量建索引(回收站开启时由 [`Self::trash_bootstrap`] 转发
    /// —— 契约 C7,裁决 #11):全量列表统一走 `trash::fetch_all_tombstones`
    /// (bootstrap/全量重建共用,消除三处全量逻辑并存);离线构建新集合、
    /// 短写锁整体换入(遍历期间不持写锁,否则刷新/GC 与挂载 list 相互
    /// 饿死);推进增量游标与全量重建时刻(bootstrap 即一次全量重建);
    /// 末尾全清 stat/negative 缓存;全程持一个 limiter permit(并发上限
    /// 不可回归)。返回条目数(测试/指标用)。
    pub(crate) async fn rebuild_trash_index(&self) -> Result<usize> {
        let Some(trash) = &self.trash else {
            return Ok(0);
        };
        let _permit = self.acquire().await?;
        // 代际捕获(L3/L4):挂载期周期 GC 与 bootstrap 并发时,本快照可能
        // 含 GC 刚删的墓碑 —— 换入前检测代际变化则整体丢弃(索引空 →
        // 周期刷新自愈,绝不把已删墓碑重新隐藏进索引)。
        let gen_snapshot = trash.generation.load(Ordering::SeqCst);
        let (index, last_key) = trash::fetch_all_tombstones(self, trash).await?;
        if trash.generation.load(Ordering::SeqCst) != gen_snapshot {
            return Ok(0); // GC 并发完成:丢弃陈旧快照,下轮刷新自愈
        }
        let count = index.len();
        // 短写锁整体换入:离线构建期间读路径继续用旧索引
        *trash.index.write().unwrap() = index;
        // gauge 统一落点(裁决 #6/#9):整体换入后刷新条目数 + 超阈值告警
        trash.store_index_entries(trash.index.read().unwrap().len());
        *trash.cursor.lock().unwrap() = last_key;
        *trash.last_full_rebuild.lock().unwrap() = Instant::now();
        self.stats.lock().unwrap().clear();
        self.negative.lock().unwrap().clear();
        Ok(count)
    }

    /// 索引变更后的缓存失效接缝(单元 2 的调用点;本单元由其测试驱动):
    /// 内部:key_for → index.write().insert → gauge 同步(裁决 #9:测试
    /// 用 trash_insert 建索引后断言 trash_index_entries 此前会得 0)→
    /// 失效目标路径(目录墓碑额外按 `path.trim_end_matches('/') + "/"`
    /// 前缀扫掉 stats/negative 后代条目,有界 map ≤4096 一次扫描可忽略)。
    /// 同步,不 await。仅测试驱动(生产写入路径走 TrashState 方法)。
    pub(crate) fn trash_insert(&self, path: &str, is_dir: bool) {
        let Some(trash) = &self.trash else {
            return;
        };
        let key = self.key_for(path);
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert(
                &key,
                is_dir,
                trash::date_partition_utc(std::time::SystemTime::now()),
            );
            trash.store_index_entries(idx.len());
        }
        self.invalidate_trash_cached(path, is_dir);
    }

    /// 墓碑索引变更的缓存失效:精确路径 + 目录后代前缀扫描。
    fn invalidate_trash_cached(&self, path: &str, is_dir: bool) {
        self.invalidate_stat(path);
        if is_dir {
            let dir = format!("{}/", path.trim_end_matches('/'));
            self.stats
                .lock()
                .unwrap()
                .retain(|p, _| !p.starts_with(&dir));
            self.negative
                .lock()
                .unwrap()
                .retain(|p, _| !p.starts_with(&dir));
        }
    }

    /// 回收站是否开启(挂载钩子 / 管理命令门控)。
    pub fn trash_enabled(&self) -> bool {
        self.trash.is_some()
    }

    /// 挂载启动全量建索引:转发 [`Self::rebuild_trash_index`](契约 C7,
    /// 裁决 #11 —— 内部即全量重建 + 游标/全量周期推进 + 缓存清空,
    /// permit 由其内部持有,此处不重复 acquire)。失败仅 warn +
    /// trash_bootstrap_failures,**不阻塞挂载** —— 索引空则已删文件短暂
    /// 可见,周期刷新自愈(warn + continue,无重试)。
    pub async fn trash_bootstrap(&self) -> Result<()> {
        if self.trash.is_none() {
            return Ok(());
        }
        if let Err(e) = self.rebuild_trash_index().await {
            self.metrics
                .trash_bootstrap_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %e, "trash bootstrap failed; 周期刷新将自愈");
        }
        Ok(())
    }

    /// 启动后台刷新循环:trash 开启且未启动(AtomicBool swap 防重入)时
    /// `tokio::spawn(refresh_loop)`;重复调用 no-op。挂载钩子
    /// (fuse.rs / winfsp.rs fail-fast 后)调用;循环与既有目录刷新任务
    /// 同生命周期(随进程退出)。
    pub fn trash_refresh_start(self: &Arc<Self>) {
        if self.trash.is_none() || self.trash_refresh_started.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::spawn(Self::refresh_loop(Arc::clone(self)));
    }

    /// 一轮调度(测试与 refresh_loop 共用):距上次全量 >= rebuild_interval
    /// → 全量重建 diff,否则 start-after 游标增量。全程持一个 limiter
    /// permit(并发上限不可回归);失败 → trash_refresh_errors +1 后原样
    /// 返回 Err(上层循环仅 warn,下一轮重试)。
    pub async fn trash_refresh_once(&self) -> Result<()> {
        let Some(trash) = &self.trash else {
            return Ok(());
        };
        let _permit = self.acquire().await?;
        match trash.refresh_once(self).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.metrics
                    .trash_refresh_errors
                    .fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// 后台周期刷新:interval(refresh_interval)循环,MissedTickBehavior::Skip,
    /// 首 tick 消费(挂载启动已 bootstrap);每轮 refresh_once,错误仅
    /// warn + trash_refresh_errors(下一轮重试,不 panic)。
    async fn refresh_loop(fs: Arc<ObjectFs>) {
        let Some(trash) = &fs.trash else {
            return;
        };
        let mut interval = tokio::time::interval(trash.refresh_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // 首 tick 立即触发;消费掉,第一次刷新等一个完整周期
        interval.tick().await;
        loop {
            interval.tick().await;
            // 失败计数已在 trash_refresh_once 内完成;此处仅 warn,下一轮重试
            if let Err(e) = fs.trash_refresh_once().await {
                tracing::warn!(error = %e, "trash refresh failed; will retry next cycle");
            }
        }
    }

    // ---------- 单元 4:管理命令与周期 GC ----------

    /// trash-list 管理命令:分页列出墓碑(CLI 流式打印)。trash 关闭
    /// (--no-trash)时无墓碑可列 → bail(CLI 层已拦,双保险)。
    pub async fn trash_list(
        &self,
        on_page: impl FnMut(Vec<trash::TrashEntry>) -> Result<()>,
    ) -> Result<()> {
        let Some(trash) = &self.trash else {
            anyhow::bail!("trash is disabled (--no-trash); no trash to list");
        };
        trash.trash_list(self, on_page).await
    }

    /// trash-restore 管理命令(三分支见 [`trash::RestoreOutcome`])。
    pub async fn trash_restore(
        &self,
        path: &str,
        date: Option<chrono::NaiveDate>,
    ) -> Result<trash::RestoreOutcome> {
        let Some(trash) = &self.trash else {
            anyhow::bail!("trash is disabled (--no-trash); nothing to restore");
        };
        trash.trash_restore(self, path, date).await
    }

    /// trash-clean 管理命令 / 周期 GC。trash 关闭 → 无事可做,返回空报告。
    pub async fn trash_gc(&self, opts: trash::GcOptions) -> Result<trash::GcReport> {
        let Some(trash) = &self.trash else {
            return Ok(trash::GcReport::default());
        };
        trash.trash_gc(self, opts).await
    }

    /// 后台 GC 周期秒(trash 关闭 → None);main 据此 spawn 周期任务,
    /// 0 或 None 不 spawn(TRASH_GC_INTERVAL_SECS 兜底在调用方)。
    pub fn trash_gc_interval_secs(&self) -> Option<u64> {
        self.trash.as_ref().map(|t| t.gc_interval.as_secs())
    }

    /// List the immediate children of `dir`.
    pub async fn list(&self, dir: &str) -> Result<Vec<DirEntry>> {
        self.acquire_list_permit().await;
        let _permit = self.acquire().await?;
        self.list_impl(dir).await
    }

    /// Await a token from the directory-enumeration rate limiter, if set.
    async fn acquire_list_permit(&self) {
        let Some(rate) = &self.list_rate else { return };
        loop {
            let wait = rate.lock().unwrap().reserve(Instant::now());
            let Some(wait) = wait else { return };
            self.metrics.list_throttled.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(wait).await;
        }
    }

    async fn list_impl(&self, dir: &str) -> Result<Vec<DirEntry>> {
        // eager 挂点:仅 eager 档生效(lazy 零开销);放过滤之前 —— 先拉后滤,
        // 远端新墓碑当轮即隐藏。不 acquire permit(调用方 list() 已持,
        // 饱和池二次 acquire 会死锁;poll_inflight 天然限 1)。
        if let Some(trash) = &self.trash {
            trash.poll_incremental_eager(self).await;
        }
        // 单元 1:系统回收站目录层标记 —— S3 分页循环照常执行(合并真实
        // 对象:macOS .DS_Store、桶中真实用户数据;hidden_key_with 不滤
        // 系统前缀,勿加过滤),返回前合并合成条目(同名去重,真实优先)。
        let system_dir_match = self.trash.as_ref().and_then(|t| t.match_system_trash(dir));
        let is_system_dir = matches!(system_dir_match, Some(trash::SystemTrashMatch::Dir { .. }));
        self.metrics.s3_lists.fetch_add(1, Ordering::Relaxed);
        let prefix = self.list_prefix(dir);
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix)
                .delimiter("/");
            if let Some(tok) = token.as_deref() {
                req = req.continuation_token(tok);
            }
            let resp = match req.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                    self.metrics.s3_list_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e).context("s3 list");
                }
            };
            // 回收站过滤(裁决 #12):每页一次读锁快照包整页两个过滤循环
            // —— 10 万条目页面由逐条目 10 万次锁往返降为每页 1 次(读锁
            // 与增量刷新写锁互斥,锁往返是热路径常数因子)。快照只覆盖
            // 本页循环:循环内无 await(纯内存比较、零远程),读守卫不得
            // 跨 await 存活(阻塞写者且使 future !Send),随页释放。
            let snapshot = self.trash.as_ref().map(|t| t.index.read().unwrap());
            for cp in resp.common_prefixes() {
                if let Some(p) = cp.prefix() {
                    if let Some(snap) = &snapshot {
                        // 目录墓碑覆盖的 common_prefix 一并跳过;在分页
                        // 循环内过滤,continuation token 不受影响。
                        if self.hidden_key_with(snap, p) {
                            continue;
                        }
                    }
                    let name = p
                        .strip_prefix(&prefix)
                        .unwrap_or(p)
                        .trim_end_matches('/')
                        .to_string();
                    if !name.is_empty() {
                        out.push(DirEntry {
                            name,
                            is_dir: true,
                            size: 0,
                            mtime_secs: 0,
                        });
                    }
                }
            }
            for obj in resp.contents() {
                let Some(key) = obj.key() else { continue };
                // The directory marker (key == list prefix) is the dir itself.
                if key == prefix {
                    continue;
                }
                if let Some(snap) = &snapshot {
                    // 回收站过滤:marker 跳过之后、裁剪之前 —— 隐藏 key
                    // 免一次裁剪分配。
                    if self.hidden_key_with(snap, key) {
                        continue;
                    }
                }
                let Some(name) = key.strip_prefix(&prefix) else {
                    continue;
                };
                if name.is_empty() || name.ends_with('/') {
                    continue;
                }
                if self.notsup_compat_dir && name.ends_with("_$folder$") {
                    continue;
                }
                out.push(DirEntry {
                    name: name.to_string(),
                    is_dir: false,
                    size: obj.size().unwrap_or(0).max(0) as u64,
                    mtime_secs: obj.last_modified().map(|d| d.secs()).unwrap_or(0),
                });
            }
            drop(snapshot);
            match next_page_token(&resp)? {
                Some(tok) => token = Some(tok),
                None => break,
            }
        }
        // 返回前合并(单元 1):系统回收站目录层合成条目(Windows 冷路径
        // 允许 ≤ 未命中条目数的墓碑 body GET,天然有界,裁决 P1);根目录
        // 追加系统虚拟目录条目(裁决 P2:零额外请求)。
        if let Some(trash) = &self.trash {
            if is_system_dir {
                let synthesized = trash.synthesize_dir_entries(self, dir).await?;
                let mut seen: std::collections::HashSet<String> =
                    out.iter().map(|e| e.name.clone()).collect();
                for e in synthesized {
                    if seen.insert(e.name.clone()) {
                        out.push(e);
                    }
                }
            }
            if dir == "/" {
                if let Some(sys) = &trash.system
                    && !out.iter().any(|e| e.name == sys.dir_name)
                {
                    out.push(DirEntry {
                        name: sys.dir_name.clone(),
                        is_dir: true,
                        size: 0,
                        mtime_secs: 0,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Stat a path. Returns `None` when the path does not exist.
    ///
    /// Results are cached for [`STAT_TTL`] so the repeated attribute queries
    /// Explorer makes on a click (get_file_info / get_security_by_name / open)
    /// do not each pay an S3 round trip.
    pub async fn stat(&self, path: &str) -> Result<Option<DirEntry>> {
        {
            let cache = self.stats.lock().unwrap();
            if let Some((at, entry)) = cache.get(path) {
                if at.elapsed() < self.stat_ttl {
                    self.metrics.stat_cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .stat_positive_cache_hits
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(entry.clone()));
                }
            }
        }
        if self.negative_hit(path) {
            self.metrics.stat_cache_hits.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .stat_negative_cache_hits
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let _permit = self.acquire().await?;
        let result = self.stat_uncached_impl(path).await?;
        if let Some(entry) = &result {
            self.cache_insert(path, entry.clone());
        } else {
            self.negative_insert(path);
        }
        Ok(result)
    }

    fn negative_hit(&self, path: &str) -> bool {
        matches!(
            self.negative.lock().unwrap().get(path),
            Some(at) if at.elapsed() < self.negative_ttl
        )
    }

    /// Record `path` as missing (bounded; evicts the oldest entry when full).
    /// positive cache).
    fn negative_insert(&self, path: &str) {
        let mut cache = self.negative.lock().unwrap();
        if cache.len() >= self.negative_max_entries && !cache.contains_key(path) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, at)| *at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                cache.remove(&k);
            }
        }
        cache.insert(path.to_string(), Instant::now());
    }

    fn cache_insert(&self, path: &str, entry: DirEntry) {
        let mut cache = self.stats.lock().unwrap();
        if cache.len() >= self.stat_max_entries && !cache.contains_key(path) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                cache.remove(&k);
            }
        }
        cache.insert(path.to_string(), (Instant::now(), entry));
    }

    /// Drop any cached attribute (positive or negative) for `path`, called
    /// after local mutations.
    fn invalidate_stat(&self, path: &str) {
        self.stats.lock().unwrap().remove(path);
        self.negative.lock().unwrap().remove(path);
    }

    /// The actual S3 lookup behind [`Self::stat`] (HEAD, then directory-marker
    /// HEAD, then prefix probe as a last resort). Caller must hold a limiter
    /// permit.
    async fn stat_uncached_impl(&self, path: &str) -> Result<Option<DirEntry>> {
        // eager 挂点(与 list_impl 同理由):放过滤之前,先拉后滤。
        if let Some(trash) = &self.trash {
            trash.poll_incremental_eager(self).await;
        }
        if path == "/" {
            return Ok(Some(DirEntry {
                name: String::new(),
                is_dir: true,
                size: 0,
                mtime_secs: 0,
            }));
        }
        // 单元 1:系统回收站前缀 stat 合成(裁决 P3:Dir 零远程;Entry 层
        // ≤1 次 body GET,stat 缓存 3s 吸收)。位于 hidden_key 过滤之前 ——
        // 系统视图条目必须可见(单元 1 阶段被普通软删墓碑覆盖的视图条目
        // 也以合成结果为准)。合成失败(桶中真实对象无墓碑对应 —— macOS
        // .DS_Store、Windows 历史遗留真实条目)落到普通 stat 链,真实
        // 对象可见;仅无真实对象时由普通链返回 None(ENOENT)。
        // F10(low):修复前 Windows 分支合成失败直接 return None —— 列出
        // 与可访问性不一致(列表合并真实对象而 stat 返回 None = 幽灵
        // 条目),与 macOS 回退不对称。
        if let Some(trash) = &self.trash
            && trash.is_system_trash_path(path)
            && let Some(entry) = trash.synthesize_stat(self, path).await?
        {
            return Ok(Some(entry));
        }
        // 回收站过滤:根路径守卫之后、HEAD 计数之前 —— 被删路径的 stat
        // 零远程请求(head 都不发);None 经 `stat()` 走 negative 缓存。
        let key = self.key_for(path);
        if self.hidden_key(&key) {
            return Ok(None);
        }
        // One request counted per request actually issued below: the initial
        // HEAD, plus the marker HEAD / prefix probe on the miss path.
        self.metrics.s3_heads.fetch_add(1, Ordering::Relaxed);
        self.metrics.s3_stat_heads.fetch_add(1, Ordering::Relaxed);
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(resp) => {
                let is_dir = path.ends_with('/') || key.ends_with('/');
                Ok(Some(DirEntry {
                    name: basename(path),
                    is_dir,
                    size: resp.content_length().unwrap_or(0).max(0) as u64,
                    mtime_secs: resp.last_modified().map(|d| d.secs()).unwrap_or(0),
                }))
            }
            Err(e) if is_s3_not_found(&e) => {
                // A directory marker lives at `path + "/"`; check it before
                // falling back to a prefix scan.
                if !key.ends_with('/') {
                    self.metrics.s3_heads.fetch_add(1, Ordering::Relaxed);
                    self.metrics.s3_stat_heads.fetch_add(1, Ordering::Relaxed);
                    let marker_key = format!("{key}/");
                    match self
                        .client
                        .head_object()
                        .bucket(&self.bucket)
                        .key(&marker_key)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            return Ok(Some(DirEntry {
                                name: basename(path),
                                is_dir: true,
                                size: resp.content_length().unwrap_or(0).max(0) as u64,
                                mtime_secs: resp.last_modified().map(|d| d.secs()).unwrap_or(0),
                            }));
                        }
                        Err(e2) if is_s3_not_found(&e2) => {}
                        Err(e2) => return Err(e2).context("s3 head marker"),
                    }
                }
                // Implied directory (children exist under the prefix).
                // Probe with max_keys=1 instead of materializing a full
                // listing: stat storms on missing paths otherwise allocate a
                // whole directory just to learn "has children". The probe
                // strips a trailing slash so `stat("/a")` and `stat("/a/")`
                // resolve the same implied directory (#60).
                let probe_dir = path.trim_end_matches('/');
                if !probe_dir.is_empty() && self.has_children_impl(probe_dir).await? {
                    return Ok(Some(DirEntry {
                        name: basename(path),
                        is_dir: true,
                        size: 0,
                        mtime_secs: 0,
                    }));
                }
                Ok(None)
            }
            Err(e) => Err(e).context("s3 head"),
        }
    }

    /// Public empty-check for the mount adapters' `rmdir`: POSIX requires
    /// ENOTEMPTY on a non-empty directory, and the adapters have no other way
    /// to distinguish "delete this tree" (WinFsp cleanup) from "the user
    /// called rmdir" (FUSE). One `max_keys=1` probe; the limiter permit is
    /// taken internally because adapter call sites run on dispatcher threads
    /// that must not block on a busy limiter.
    pub async fn dir_has_children(&self, dir: &str) -> bool {
        let probe = dir.trim_end_matches('/');
        if probe.is_empty() {
            // The root always has children unless the bucket is empty; let
            // delete_dir_recursive decide — rmdir("/") is rejected by the
            // kernel before it reaches us anyway.
            return true;
        }
        match self.acquire().await {
            Ok(_permit) => self.has_children_impl(probe).await.unwrap_or(true),
            Err(_) => true,
        }
    }

    /// Cheap existence probe: does `dir` have any child object? Uses
    /// `max_keys = 1` so a missing implied directory costs one tiny request
    /// instead of a full listing. Caller must hold a limiter permit.
    async fn has_children_impl(&self, dir: &str) -> Result<bool> {
        self.metrics.s3_lists.fetch_add(1, Ordering::Relaxed);
        let prefix = self.list_prefix(dir);
        let resp = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .max_keys(1)
            .send()
            .await
            .context("s3 probe children")?;
        Ok(!resp.contents().is_empty())
    }

    /// Read `len` bytes starting at `offset`. Returns fewer bytes near EOF,
    /// empty when `offset` is at/behind EOF.
    ///
    /// When [`Self::read_ahead_window`] is enabled and the read continues the
    /// previous read (`offset == last_end`), the object is fetched in
    /// window-sized chunks and cached so subsequent sequential small reads do
    /// not pay an S3 round trip each.
    pub async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.metrics.reads.fetch_add(1, Ordering::Relaxed);
        if len == 0 {
            return Ok(Vec::new());
        }
        let window = self.read_ahead_window;
        let mut key = self.key_for(path);
        // 单元 1:系统回收站条目 → 原 key(转发既有读取链;窗口缓存键沿用
        // 视图 path —— 同一视图路径 → 同一原 key,缓存一致)。$I 形态合成
        // 切片返回(捕获字节优先,合成回退,裁决 R8)。解析/合成可能发
        // body GET(冷路径),scope 内持 permit;暖路径零远程,缓存命中
        // 路径不受影响(scope 结束即释放,不与既有读取 permit 叠加)。
        if let Some(trash) = &self.trash
            && let Some(trash::SystemTrashMatch::Entry { entry_name }) =
                trash.match_system_trash(path)
        {
            let _permit = self.acquire().await?;
            let is_windows = trash
                .system
                .as_ref()
                .is_some_and(|s| s.platform == trash::SystemTrashPlatform::WindowsRecycleBin);
            if is_windows && trash::is_i_entry(&entry_name) {
                // $I:合成切片返回(捕获字节优先,合成回退),零远程
                let bytes = trash
                    .synthesize_i_file(self, &entry_name)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("read: $I entry not found"))?;
                let start = offset.min(bytes.len() as u64) as usize;
                return Ok(bytes[start..].iter().take(len).copied().collect());
            }
            if let Some(orig) = trash.resolve_entry_original(self, &entry_name).await? {
                key = orig;
            }
            // F10(low):未解析(桶中真实对象)保持视图 key —— 有真实对象
            // 则按真实对象读;无墓碑也无真实对象时由 S3 404 自然报错
            // (与 macOS 回退同构;修复前 Windows 分支 bail,真实
            // $Recycle.Bin 条目列出但打不开 = 幽灵)。
        }

        if window > 0
            && let Some(data) = self.read_cache_hit(path, offset, len)
        {
            self.metrics.read_cache_hits.fetch_add(1, Ordering::Relaxed);
            self.note_read_end(path, offset.saturating_add(data.len() as u64));
            return Ok(data);
        }

        if window > 0 {
            self.metrics
                .read_cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }
        let sequential = if window > 0 {
            let seq = self.read_seq.lock().unwrap();
            seq.get(path) == Some(&offset)
        } else {
            false
        };

        // Warm the sequential hint so the next contiguous read can trigger
        // prefetch even if this one is served directly.
        if window > 0 {
            self.note_read_end(path, offset.saturating_add(len as u64));
        }

        let fetch_len = read_fetch_len(len, window, sequential);

        let _permit = self.acquire().await?;
        let data = if self.disk_cache.is_some() {
            self.read_range_disk(&key, offset, fetch_len, sequential)
                .await?
        } else {
            self.read_range_uncached(&key, offset, fetch_len).await?
        };

        if window > 0 && fetch_len > len {
            self.insert_read_cache(path, offset, data.clone());
        }
        if window > 0 {
            self.note_read_end(path, offset.saturating_add(data.len() as u64));
        }

        Ok(data[..len.min(data.len())].to_vec())
    }

    /// Read `fetch_len` bytes at `offset`, sourcing each `DISK_CACHE_BLOCK_SIZE`
    /// block from the on-disk cache when present and otherwise fetching and
    /// storing it. Returns at most `fetch_len` bytes (fewer near EOF).
    async fn read_range_disk(
        &self,
        key: &str,
        offset: u64,
        fetch_len: usize,
        prefetch_next: bool,
    ) -> Result<Vec<u8>> {
        if self.disk_cache_verify_etag {
            self.verify_disk_cache_etag(key).await;
        }
        let cache = self.disk_cache.as_ref().expect("disk cache enabled");
        let block_size = cache.block_size;
        let end = offset.saturating_add(fetch_len as u64);
        let first_block = offset / block_size;
        let last_block = end.saturating_sub(1) / block_size;
        let mut out = Vec::with_capacity(fetch_len);
        let mut pos = offset;
        let mut eof = false;

        for block in first_block..=last_block {
            let block_start = block * block_size;
            let within = (pos - block_start) as usize;
            let want = (end - pos).min(block_size - within as u64) as usize;

            if let Some(block_data) = cache.read_block(key, block) {
                self.metrics.disk_cache_hits.fetch_add(1, Ordering::Relaxed);
                if within >= block_data.len() {
                    eof = true;
                    break;
                }
                let take = want.min(block_data.len() - within);
                out.extend_from_slice(&block_data[within..within + take]);
                pos += take as u64;
                if block_data.len() < block_size as usize || take < want {
                    eof = true;
                    break;
                }
                continue;
            }

            self.metrics
                .disk_cache_misses
                .fetch_add(1, Ordering::Relaxed);
            let fetched = self
                .read_range_uncached(key, block_start, block_size as usize)
                .await?;
            if fetched.is_empty() {
                eof = true;
                break;
            }
            let _ = cache.write_block(key, block, &fetched);

            if within >= fetched.len() {
                eof = true;
                break;
            }
            let take = want.min(fetched.len() - within);
            out.extend_from_slice(&fetched[within..within + take]);
            pos += take as u64;
            if fetched.len() < block_size as usize || take < want {
                eof = true;
                break;
            }
        }

        if prefetch_next && !eof && self.disk_cache_prefetch_blocks > 0 {
            self.metrics
                .prefetch_started
                .fetch_add(1, Ordering::Relaxed);
            let cache = Arc::clone(cache);
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let limiter = Arc::clone(&self.limiter);
            let key = key.to_string();
            let inflight = Arc::clone(&self.prefetch_inflight);
            let prefetch_sem = Arc::clone(&self.prefetch_sem);
            let metrics = Arc::clone(&self.metrics);
            let first_next = last_block + 1;
            let count = self.disk_cache_prefetch_blocks;
            tokio::spawn(async move {
                let Ok(_prefetch_guard) = prefetch_sem.acquire_owned().await else {
                    return;
                };
                for block in first_next..first_next + count as u64 {
                    {
                        let mut set = inflight.lock().unwrap();
                        if !set.insert((key.clone(), block)) {
                            metrics.prefetch_skipped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    let Ok(_permit) = limiter.clone().acquire_owned().await else {
                        inflight.lock().unwrap().remove(&(key.clone(), block));
                        return;
                    };
                    let start = block * cache.block_size;
                    let range = format!("bytes={}-{}", start, start + cache.block_size - 1);
                    let Ok(resp) = client
                        .get_object()
                        .bucket(&bucket)
                        .key(&key)
                        .range(&range)
                        .send()
                        .await
                    else {
                        metrics.prefetch_failed.fetch_add(1, Ordering::Relaxed);
                        inflight.lock().unwrap().remove(&(key.clone(), block));
                        return;
                    };
                    // Same trickle guard as read_range_uncached: the prefetch
                    // task holds a limiter permit while streaming the body.
                    let collected = match tokio::time::timeout(
                        read_body_budget(cache.block_size as usize),
                        resp.body.collect(),
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(_) => {
                            metrics.prefetch_failed.fetch_add(1, Ordering::Relaxed);
                            metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                            inflight.lock().unwrap().remove(&(key.clone(), block));
                            return;
                        }
                    };
                    if let Ok(body) = collected {
                        let bytes = body.to_vec();
                        if bytes.is_empty() {
                            inflight.lock().unwrap().remove(&(key.clone(), block));
                            return;
                        }
                        let _ = cache.write_block(&key, block, &bytes);
                    } else {
                        metrics.prefetch_failed.fetch_add(1, Ordering::Relaxed);
                        inflight.lock().unwrap().remove(&(key.clone(), block));
                    }
                    inflight.lock().unwrap().remove(&(key.clone(), block));
                }
            });
        }

        Ok(out)
    }

    /// HEAD `key`; return `Some(true)` when it exists with exactly
    /// `expected_bytes` (see [`head_reports_size`] for the rationale).
    async fn verify_completed_object(&self, key: &str, expected_bytes: u64) -> Option<bool> {
        head_reports_size(
            &self.client,
            &self.bucket,
            key,
            expected_bytes,
            &self.metrics,
            &self.limiter,
        )
        .await
    }

    /// Best-effort AbortMultipartUpload under a limiter permit. The abort
    /// request itself is an S3 request and must stay inside
    /// `MAX_CONCURRENT_S3_REQUESTS` (#55); failures are swallowed on purpose
    /// (the caller is already on an error path).
    async fn abort_upload(&self, key: &str, upload_id: &str) {
        let Ok(_permit) = self.acquire().await else {
            return;
        };
        let _ = self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await;
    }

    async fn verify_disk_cache_etag(&self, key: &str) {
        {
            let checked = self.etag_checked.lock().unwrap();
            if let Some(at) = checked.get(key) {
                if at.elapsed() < self.etag_ttl {
                    // TTL suppressed the re-check: no HEAD is issued, so no
                    // HEAD may be counted (#60).
                    return;
                }
            }
        }
        self.metrics.s3_heads.fetch_add(1, Ordering::Relaxed);
        self.metrics.s3_etag_heads.fetch_add(1, Ordering::Relaxed);
        let cache = self.disk_cache.as_ref().expect("disk cache enabled");
        // The verification HEAD is a second in-flight S3 request on top of
        // the read_range that called us. try_acquire: this runs while the
        // caller already holds a permit, and a blocking wait when the pool is
        // saturated (all readers stuck re-verifying) could deadlock; skipping
        // the verification under load is equivalent to the HEAD failing (#55).
        let Ok(_permit) = self.limiter.clone().try_acquire_owned() else {
            return;
        };
        let Ok(resp) = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        else {
            return;
        };
        let Some(etag) = resp.e_tag().map(str::to_string) else {
            return;
        };
        if etag.is_empty() {
            return;
        }
        if cache.read_etag(key).as_deref() != Some(etag.as_str()) {
            cache.invalidate(key);
            cache.store_etag(key, &etag);
            self.etag_checked
                .lock()
                .unwrap()
                .insert(key.to_string(), Instant::now());
        }
    }

    /// Actual S3 GET for `len` bytes at `offset`. Caller holds a limiter
    /// permit.
    async fn read_range_uncached(&self, key: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.metrics.s3_gets.fetch_add(1, Ordering::Relaxed);
        let end = offset.saturating_add(len as u64);
        let range = if offset == 0 && len == usize::MAX {
            "bytes=0-".to_string()
        } else {
            format!("bytes={}-{}", offset, end.saturating_sub(1))
        };
        let resp = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(&range)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) if is_s3_invalid_range(&e) => return Ok(Vec::new()),
            Err(e) => {
                self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                self.metrics.s3_get_errors.fetch_add(1, Ordering::Relaxed);
                return Err(e).context("s3 get");
            }
        };
        let body = tokio::time::timeout(read_body_budget(len), resp.body.collect()).await;
        let bytes = match body {
            Ok(Ok(collected)) => collected.to_vec(),
            Ok(Err(e)) => {
                // Mid-body stream error (reset, hyper I/O, the SDK's own
                // StalledStreamProtection) — same counters as the budget miss.
                self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                self.metrics.s3_get_errors.fetch_add(1, Ordering::Relaxed);
                return Err(e).context("s3 get body");
            }
            Err(_) => {
                self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                self.metrics.s3_get_errors.fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("s3 get body stalled past its budget ({len} bytes requested)");
            }
        };
        self.metrics
            .download_bytes_total
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(bytes)
    }

    /// Return a fully-cached window slice when `[offset, offset+len)` is
    /// entirely inside it.
    fn read_cache_hit(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut cache = self.read_cache.lock().unwrap();
        let entry = cache.entries.get_mut(path)?;
        let end = entry.start.checked_add(entry.data.len() as u64)?;
        if offset < entry.start || offset.saturating_add(len as u64) > end {
            return None;
        }
        let start = (offset - entry.start) as usize;
        entry.last_used = Instant::now();
        Some(entry.data[start..start + len].to_vec())
    }

    /// Insert a read-ahead window into the bounded cache, evicting arbitrary
    /// entries when the byte/entry budgets are exceeded.
    fn insert_read_cache(&self, path: &str, start: u64, data: Vec<u8>) {
        if data.is_empty() || data.len() > self.read_cache_max_bytes {
            return;
        }
        let mut cache = self.read_cache.lock().unwrap();
        if let Some(old) = cache.entries.remove(path) {
            cache.bytes = cache.bytes.saturating_sub(old.data.len());
        }
        while cache.bytes + data.len() > self.read_cache_max_bytes
            || cache.entries.len() >= READ_CACHE_MAX_ENTRIES
        {
            let key = cache
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            let Some(key) = key else { break };
            if let Some(evicted) = cache.entries.remove(&key) {
                cache.bytes = cache.bytes.saturating_sub(evicted.data.len());
            }
        }
        cache.bytes += data.len();
        cache.entries.insert(
            path.to_string(),
            ReadCacheEntry {
                start,
                data,
                last_used: Instant::now(),
            },
        );
    }

    /// Track the end of the most recent read for sequential-prefetch
    /// detection. The hint map is bounded like the stat/negative caches.
    fn note_read_end(&self, path: &str, end: u64) {
        let mut seq = self.read_seq.lock().unwrap();
        if seq.len() >= MAX_READ_SEQ_ENTRIES {
            seq.clear();
        }
        seq.insert(path.to_string(), end);
    }

    /// Drop cached read-ahead data for one path after a local mutation.
    fn invalidate_read_cache(&self, path: &str) {
        if let Some(cache) = &self.disk_cache {
            cache.invalidate(&self.key_for(path));
        }
        let mut cache = self.read_cache.lock().unwrap();
        if let Some(old) = cache.entries.remove(path) {
            cache.bytes = cache.bytes.saturating_sub(old.data.len());
        }
        self.read_seq.lock().unwrap().remove(path);
    }

    /// Drop all cached read-ahead data (used by recursive delete/rename).
    fn clear_read_cache(&self) {
        if let Some(cache) = &self.disk_cache {
            cache.clear();
        }
        let mut cache = self.read_cache.lock().unwrap();
        cache.entries.clear();
        cache.bytes = 0;
        self.read_seq.lock().unwrap().clear();
    }

    /// Overwrite an object with `data` (whole-object write). Large objects
    /// are uploaded via S3 multipart so they are not limited by the single-PUT
    /// object-size cap and can be retried per part.
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.ensure_writable()?;
        // Counted only after the read-only gate: a rejected write issued no
        // request and must not inflate the write/put counters (#60).
        self.metrics.writes.fetch_add(1, Ordering::Relaxed);
        self.metrics.s3_puts.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .upload_bytes_total
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.invalidate_stat(path);
        self.invalidate_read_cache(path);
        let _budget = self.acquire_upload_budget(data.len()).await?;
        if data.len() as u64 > MULTIPART_THRESHOLD {
            self.write_multipart(path, data).await?;
        } else {
            let _permit = self.acquire().await?;
            self.put_whole_object(path, data).await?;
        }
        // 清墓碑挂点(C9 裁决):FUSE create / WinFsp create 均收敛到
        // write() —— 同名重建 = 覆盖语义。清墓碑在提交写之后(裁决 #3):
        // PUT 失败 → 墓碑保留(软删除不被静默撤销,已删文件不复活);
        // 清墓碑失败 → Err,重试自愈。未覆盖时零远程请求(性能守卫)。
        // 双形态门控(F1):rmdir /e 后再写文件 /e —— 目录墓碑 e/ 前缀
        // 覆盖新文件 key,只清文件形态会静默不可见;此处 is_covered
        // 裸 key 门控 + 文件/目录两形态一并清除。
        if let Some(trash) = &self.trash {
            trash.clear_tombstones_if_covered(self, path).await?;
        }
        Ok(())
    }

    async fn put_whole_object(&self, path: &str, data: &[u8]) -> Result<()> {
        let key = self.key_for(path);
        let expected_crc = self.verify_crc64.then(|| crc64ecma(data));
        let crc_slot = Arc::new(Mutex::new(None));

        let mut put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(data.to_vec()));
        if let Some(sc) = &self.storage_class {
            put = put.storage_class(sc.clone());
        }
        if self.content_md5 {
            put = put.content_md5(content_md5(data));
        }
        let mut put = put.customize();
        if expected_crc.is_some() {
            put = put.interceptor(Crc64ResponseCapture {
                slot: Arc::clone(&crc_slot),
            });
        }
        if let Err(e) = put.send().await {
            self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
            self.metrics.s3_put_errors.fetch_add(1, Ordering::Relaxed);
            return Err(e).context("s3 put");
        }

        if let Some(expected) = expected_crc {
            check_crc64_response(crc_slot, expected, &self.metrics)?;
        }
        Ok(())
    }

    /// Multipart upload: initiate -> upload parts (bounded concurrency, one
    /// global permit per part) -> complete. Any failure aborts the upload so
    /// no unfinished multipart upload is left behind on the bucket.
    async fn write_multipart(&self, path: &str, data: &[u8]) -> Result<()> {
        let key = self.key_for(path);
        let expected_crc = self.verify_crc64.then(|| crc64ecma(data));
        let crc_slot = Arc::new(Mutex::new(None));

        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key);
        if let Some(sc) = &self.storage_class {
            create = create.storage_class(sc.clone());
        }
        let create = {
            // Scoped to the request: part uploads below need the pool's
            // remaining permits (#55).
            let _permit = self.acquire().await?;
            create
                .send()
                .await
                .inspect_err(|_| {
                    self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                })
                .inspect_err(|_| {
                    self.metrics
                        .s3_multipart_errors
                        .fetch_add(1, Ordering::Relaxed);
                })
                .context("s3 create multipart upload")?
        };
        let upload_id = create
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("s3 create multipart upload returned no upload id"))?
            .to_string();

        let local = Arc::new(Semaphore::new(self.multipart_concurrency));
        let mut handles = tokio::task::JoinSet::new();
        let mut part_number = 1i32;
        let mut offset = 0usize;

        while offset < data.len() {
            let end = (offset + self.multipart_part_size).min(data.len());
            // Wait for a local slot so at most self.multipart_concurrency
            // part chunks are materialized in memory at once.
            let slot = local
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| anyhow::anyhow!("multipart upload concurrency closed"))?;
            let chunk = data[offset..end].to_vec();
            let part_md5 = self.content_md5.then(|| content_md5(&chunk));
            let part_no = part_number;
            let upload_id = upload_id.clone();
            let key = key.clone();
            let bucket = self.bucket.clone();
            let client = self.client.clone();
            let limiter = Arc::clone(&self.limiter);
            handles.spawn(async move {
                // Bound in-flight part uploads against the global limit too.
                let _permit = limiter
                    .acquire_owned()
                    .await
                    .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))?;
                let mut part = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .part_number(part_no)
                    .body(ByteStream::from(chunk));
                if let Some(md5) = part_md5 {
                    part = part.content_md5(md5);
                }
                let resp = part.send().await.context("s3 upload part")?;
                let etag = resp.e_tag().unwrap_or_default().to_string();
                drop(slot);
                Ok::<(i32, String), anyhow::Error>((part_no, etag))
            });
            part_number += 1;
            offset = end;
        }

        let mut parts = Vec::new();
        let mut upload_error = None;
        while let Some(joined) = handles.join_next().await {
            match joined {
                Ok(Ok((part_no, etag))) => {
                    parts.push(
                        CompletedPart::builder()
                            .part_number(part_no)
                            .e_tag(etag)
                            .build(),
                    );
                }
                Ok(Err(e)) => upload_error = Some(e),
                Err(e) => {
                    upload_error = Some(anyhow::anyhow!("multipart upload task panicked: {e}"))
                }
            }
        }

        if let Some(e) = upload_error {
            self.abort_upload(&key, &upload_id).await;
            return Err(e);
        }

        parts.sort_by_key(|p| p.part_number);
        let mut complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(&upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .customize();
        if expected_crc.is_some() {
            complete = complete.interceptor(Crc64ResponseCapture {
                slot: Arc::clone(&crc_slot),
            });
        }
        let complete_result = {
            // Scoped to the request (#55).
            let _permit = self.acquire().await?;
            complete.send().await
        };
        if let Err(e) = complete_result {
            // Any failed CompleteMultipartUpload may have completed server-side
            // (NoSuchUpload race, timeout, 5xx, reset). HEAD-verify before
            // aborting/erroring (see StreamingUpload::finish).
            if matches!(
                self.verify_completed_object(&key, data.len() as u64).await,
                Some(true)
            ) {
                return Ok(());
            }
            self.abort_upload(&key, &upload_id).await;
            return Err(e).context("s3 complete multipart upload");
        }
        if let Some(expected) = expected_crc {
            check_crc64_response(crc_slot, expected, &self.metrics)?;
        }
        Ok(())
    }

    /// Overwrite an object from a local file, streaming large files through
    /// multipart so the process never holds the whole object in memory. Used
    /// by the WinFsp adapter once a write buffer spills to disk.
    pub async fn write_from_file(&self, path: &str, src: &Path) -> Result<()> {
        let size = std::fs::metadata(src).context("stat spool file")?.len();
        self.ensure_writable()?;
        // Counted only after the read-only gate (see [`Self::write`], #60).
        self.metrics.writes.fetch_add(1, Ordering::Relaxed);
        self.metrics.s3_puts.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .upload_bytes_total
            .fetch_add(size, Ordering::Relaxed);
        self.invalidate_stat(path);
        self.invalidate_read_cache(path);
        let _budget = self.acquire_upload_budget(size as usize).await?;
        if size > MULTIPART_THRESHOLD {
            self.write_multipart_from_file(path, src, size).await?;
        } else {
            let data = tokio::fs::read(src).await.context("read spool file")?;
            let _permit = self.acquire().await?;
            self.put_whole_object(path, &data).await?;
        }
        // 清墓碑挂点(C9 裁决修正):WinFsp overwrite 回调经
        // write_from_file()(winfsp.rs:518),是独立方法不走 write() ——
        // 与 write() 共享同一语义(同名重建清墓碑,且清墓碑在提交写之后,
        // 裁决 #3:写失败时墓碑保留)。双形态门控同 write()(F1)。
        if let Some(trash) = &self.trash {
            trash.clear_tombstones_if_covered(self, path).await?;
        }
        Ok(())
    }

    /// Multipart upload reading part chunks directly from `src`, bounded by
    /// [`Self::multipart_concurrency`] so memory stays at a few part sizes.
    async fn write_multipart_from_file(&self, path: &str, src: &Path, size: u64) -> Result<()> {
        let key = self.key_for(path);
        let crc_slot = Arc::new(Mutex::new(None));
        let mut hasher = self.verify_crc64.then(Crc64Ecma::new);

        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key);
        if let Some(sc) = &self.storage_class {
            create = create.storage_class(sc.clone());
        }
        let create = {
            // Scoped to the request: part uploads below need the pool's
            // remaining permits (#55).
            let _permit = self.acquire().await?;
            create
                .send()
                .await
                .inspect_err(|_| {
                    self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
                })
                .inspect_err(|_| {
                    self.metrics
                        .s3_multipart_errors
                        .fetch_add(1, Ordering::Relaxed);
                })
                .context("s3 create multipart upload")?
        };
        let upload_id = create
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("s3 create multipart upload returned no upload id"))?
            .to_string();

        let local = Arc::new(Semaphore::new(self.multipart_concurrency));
        let mut handles = tokio::task::JoinSet::new();
        let mut file = tokio::fs::File::open(src)
            .await
            .context("open spool file")?;
        let part_size = self.multipart_part_size as u64;
        let mut remaining = size;
        let mut part_number = 1i32;

        while remaining > 0 {
            let chunk_len = part_size.min(remaining) as usize;
            let slot = local
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| anyhow::anyhow!("multipart upload concurrency closed"))?;
            let mut chunk = vec![0u8; chunk_len];
            tokio::io::AsyncReadExt::read_exact(&mut file, &mut chunk)
                .await
                .context("read spool file chunk")?;
            if let Some(h) = &mut hasher {
                h.update(&chunk);
            }
            let part_md5 = self.content_md5.then(|| content_md5(&chunk));
            let part_no = part_number;
            let upload_id = upload_id.clone();
            let key = key.clone();
            let bucket = self.bucket.clone();
            let client = self.client.clone();
            let limiter = Arc::clone(&self.limiter);
            handles.spawn(async move {
                let _permit = limiter
                    .acquire_owned()
                    .await
                    .map_err(|_| anyhow::anyhow!("s3 request limiter closed"))?;
                let mut part = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .part_number(part_no)
                    .body(ByteStream::from(chunk));
                if let Some(md5) = part_md5 {
                    part = part.content_md5(md5);
                }
                let resp = part.send().await.context("s3 upload part")?;
                let etag = resp.e_tag().unwrap_or_default().to_string();
                drop(slot);
                Ok::<(i32, String), anyhow::Error>((part_no, etag))
            });
            part_number += 1;
            remaining -= chunk_len as u64;
        }

        let mut parts = Vec::new();
        let mut upload_error = None;
        while let Some(joined) = handles.join_next().await {
            match joined {
                Ok(Ok((part_no, etag))) => {
                    parts.push(
                        CompletedPart::builder()
                            .part_number(part_no)
                            .e_tag(etag)
                            .build(),
                    );
                }
                Ok(Err(e)) => upload_error = Some(e),
                Err(e) => {
                    upload_error = Some(anyhow::anyhow!("multipart upload task panicked: {e}"))
                }
            }
        }

        if let Some(e) = upload_error {
            self.abort_upload(&key, &upload_id).await;
            return Err(e);
        }

        parts.sort_by_key(|p| p.part_number);
        let expected_crc = hasher.map(Crc64Ecma::finalize);
        let mut complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(&upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .customize();
        if expected_crc.is_some() {
            complete = complete.interceptor(Crc64ResponseCapture {
                slot: Arc::clone(&crc_slot),
            });
        }
        let complete_result = {
            // Scoped to the request (#55).
            let _permit = self.acquire().await?;
            complete.send().await
        };
        if let Err(e) = complete_result {
            // Any failed CompleteMultipartUpload may have completed server-side
            // (see StreamingUpload::finish). HEAD-verify before aborting.
            if matches!(self.verify_completed_object(&key, size).await, Some(true)) {
                return Ok(());
            }
            self.abort_upload(&key, &upload_id).await;
            return Err(e).context("s3 complete multipart upload");
        }
        if let Some(expected) = expected_crc {
            check_crc64_response(crc_slot, expected, &self.metrics)?;
        }
        Ok(())
    }

    /// Begin a streaming multipart upload for `path`. Bytes are fed via
    /// [`StreamingUpload::write`] and uploaded as parts in the background, so
    /// upload overlaps with the local write. Call [`StreamingUpload::finish`]
    /// on close.
    pub async fn begin_streaming_upload(&self, path: &str) -> Result<StreamingUpload> {
        self.ensure_writable()?;
        self.invalidate_stat(path);
        // A streaming handle counts as one write up front (the create request
        // is issued here); the completed object's bytes are counted once the
        // final size is known, in [`StreamingUpload::finish`] (#60).
        self.metrics.writes.fetch_add(1, Ordering::Relaxed);
        let key = self.key_for(path);
        let _permit = self.acquire().await?;
        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key);
        if let Some(sc) = &self.storage_class {
            create = create.storage_class(sc.clone());
        }
        let create = create
            .send()
            .await
            .inspect_err(|_| {
                self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
            })
            .inspect_err(|_| {
                self.metrics
                    .s3_multipart_errors
                    .fetch_add(1, Ordering::Relaxed);
            })
            .context("s3 create multipart upload")?;
        let upload_id = create
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("s3 create multipart upload returned no upload id"))?
            .to_string();
        Ok(StreamingUpload {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key,
            upload_id,
            next_part: 1,
            parts: Vec::new(),
            pending: Vec::new(),
            total_bytes: 0,
            hasher: Crc64Ecma::new(),
            verify_crc64: self.verify_crc64,
            content_md5: self.content_md5,
            part_sem: Arc::new(Semaphore::new(self.multipart_concurrency.max(1))),
            limiter: Arc::clone(&self.limiter),
            tasks: tokio::task::JoinSet::new(),
            metrics: Arc::clone(&self.metrics),
            part_size: self.multipart_part_size,
            budget_sem: self.upload_budget.clone(),
            budget_units: 0,
            budget_permits: Vec::new(),
            aborted: false,
            rt: tokio::runtime::Handle::current(),
        })
    }

    /// Create an empty directory marker object.
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.ensure_writable()?;
        if is_root_path(path) {
            // The mount root always exists; creating it would PUT an empty
            // (or prefix-only) key the server rejects (#60).
            anyhow::bail!("directory / already exists");
        }
        // 单元 1:系统回收站虚拟目录 mkdir no-op —— 不写 marker(否则
        // write 会 PUT 真实垃圾对象);Windows 记录 SID 段(裁决 R14)。
        // 只读挂载的 ensure_writable 在拦截之前,写拒绝语义不变。
        if let Some(trash) = &self.trash
            && let Some(trash::SystemTrashMatch::Dir { .. }) = trash.match_system_trash(path)
        {
            trash.record_seen_sid(path);
            return Ok(());
        }
        self.invalidate_stat(path);
        let dir = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
        // marker 写提交在前,清墓碑在后(裁决 #3 / F2):marker 写失败 →
        // 墓碑保留,软删除不被静默撤销(修复前:先清墓碑再写 marker,
        // 写失败后已删目录复活、trash 追踪丢失)。清双形态(F1):unlink
        // /e 后再 mkdir /e 的文件墓碑同样被清 —— stat("/e") 立即可用。
        // write() 内部挂点已对目录 key 清过一次,此处门控 false 即零远程
        // (幂等,双保险)。
        self.write(&dir, &[]).await?;
        if let Some(trash) = &self.trash {
            trash.clear_tombstones_if_covered(self, path).await?;
        }
        Ok(())
    }

    /// Delete a single object.
    pub async fn delete(&self, path: &str) -> Result<()> {
        self.ensure_writable()?;
        if is_root_path(path) {
            // `key_for("/")` is empty; a DELETE against the bucket URL would
            // attempt to delete the bucket itself (#60).
            anyhow::bail!("cannot delete the mount root /");
        }
        // 回收站开启 → 软删除:HEAD 原对象 + 写墓碑,原对象不删
        // (soft_delete_file 内部 acquire 一个 permit,镜像 delete)。
        if let Some(trash) = &self.trash {
            if trash.is_system_trash_path(path) {
                // 回收站内删除 = 永久删(裁决 R6):先原对象后墓碑;$I 形态
                // no-op(捕获字节随对应 $R 的永久删一并清除)。
                return trash.permanent_delete_entry(self, path).await;
            }
            // F16(裁决 R17):系统回收站目录名下但匹配未命中(范围外 uid
            // / 非数字 uid 段 / >2 层深层路径)的 delete 按硬删除 —— 修复
            // 前走普通软删产生墓碑,经 level-1 全索引遍历以 basename 渲染
            // 进范围内 uid 视图(跨 uid 数据可见,与 R17「范围外按普通
            // 路径、不产生无视图对应的墓碑」冲突)。
            if trash.is_system_trash_named_path(path) {
                let _permit = self.acquire().await?;
                return self.delete_impl(path).await;
            }
            return trash.soft_delete_file(self, path, None).await;
        }
        // 回收站未开启:直接永久删除(0.4.0 默认)——明确记录提醒,
        // 删除不可恢复(可查日志追溯)。
        tracing::warn!(
            path = %path,
            "permanent delete (trash disabled): this deletion is NOT recoverable"
        );
        let _permit = self.acquire().await?;
        self.delete_impl(path).await
    }

    async fn delete_impl(&self, path: &str) -> Result<()> {
        self.invalidate_stat(path);
        self.invalidate_read_cache(path);
        let key = self.key_for(path);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .inspect_err(|_| {
                self.metrics.s3_errors.fetch_add(1, Ordering::Relaxed);
            })
            .inspect_err(|_| {
                self.metrics
                    .s3_delete_errors
                    .fetch_add(1, Ordering::Relaxed);
            })
            .context("s3 delete")?;
        Ok(())
    }

    /// Recursively delete a directory tree (objects under the dir prefix).
    pub async fn delete_dir_recursive(&self, dir: &str) -> Result<()> {
        self.ensure_writable()?;
        // 回收站开启 → 系统回收站路径拦截(单元 3):清空/rmdir SID/条目
        // 永久删;其余目录软删(只写一个目录墓碑,不枚举、不 DeleteObjects,
        // 子树由前缀覆盖隐藏)。
        if let Some(trash) = &self.trash {
            match trash.match_system_trash(dir) {
                // 清空整个系统回收站:只清"有墓碑的条目"对应的原对象+墓碑,
                // 不触碰桶中真实(非墓碑)对象(风险 6 口径)
                Some(trash::SystemTrashMatch::Dir { level: 0 }) => {
                    return trash.purge_all(self).await;
                }
                // rmdir SID/uid 目录:有残余墓碑 → ENOTEMPTY;空 → Ok。
                // F13(low):空判定加 max_keys=1 真实对象探测 —— 索引只看
                // 墓碑,桶中真实对象(.DS_Store 等)残留时 rmdir 必须
                // ENOTEMPTY(修复前 Ok 但对象残留,下次列表重现)。跨
                // SID/uid 共享同一墓碑集(裁决 R14),别 SID/uid 有条目时
                // 本段 rmdir 误报 ENOTEMPTY(共享语义,文档化)。
                Some(trash::SystemTrashMatch::Dir { level: 1 }) => {
                    if trash.index.read().unwrap().is_empty() {
                        let _permit = self.acquire().await?;
                        if !self.has_children_impl(dir.trim_end_matches('/')).await? {
                            return Ok(());
                        }
                    }
                    return Err(anyhow::anyhow!("directory not empty"));
                }
                Some(trash::SystemTrashMatch::Entry { .. }) => {
                    return trash.permanent_delete_entry(self, dir).await;
                }
                // level ≥2 实际不可达(match_system_trash 只产 0/1/Entry),
                // 编译器穷尽性兜底:按普通路径处理(与"更深不拦截"一致)。
                _ => {}
            }
            return trash.soft_delete_dir(self, dir, None).await;
        }
        // 回收站未开启:递归永久删除(0.4.0 默认)——记录提醒,不可恢复。
        tracing::warn!(
            dir = %dir,
            "permanent recursive delete (trash disabled): this deletion is NOT recoverable"
        );
        let _permit = self.acquire().await?;
        self.delete_dir_recursive_impl(dir).await
    }

    async fn delete_dir_recursive_impl(&self, dir: &str) -> Result<()> {
        self.invalidate_stat(dir);
        self.clear_read_cache();
        let prefix = self.list_prefix(dir);
        let mut token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(tok) = token.as_deref() {
                req = req.continuation_token(tok);
            }
            let resp = req.send().await.context("s3 list for delete")?;
            let keys: Vec<String> = resp
                .contents()
                .iter()
                .filter_map(|o| o.key().map(str::to_string))
                .collect();
            // Batch deletes (1000 keys/request) instead of one DELETE per
            // object — deleting a large tree was O(n) round trips (#60).
            for chunk in keys.chunks(MAX_DELETE_OBJECTS_PER_REQUEST) {
                let objects = chunk
                    .iter()
                    .map(|k| ObjectIdentifier::builder().key(k).build())
                    .collect::<Result<Vec<_>, _>>()
                    .context("build delete object identifiers")?;
                let delete = Delete::builder()
                    .set_objects(Some(objects))
                    .build()
                    .context("build batch delete request")?;
                let resp = self
                    .client
                    .delete_objects()
                    .bucket(&self.bucket)
                    .delete(delete)
                    // Aliyun OSS requires Content-MD5 on DeleteMultipleObjects
                    // (#74); the SDK's default CRC32 checksum would be
                    // rejected with 400 InvalidDigest.
                    .customize()
                    .interceptor(DeleteObjectsContentMd5)
                    .send()
                    .await
                    .context("s3 batch delete")?;
                let failed = resp.errors();
                if !failed.is_empty() {
                    let sample: Vec<&str> = failed.iter().filter_map(|e| e.key()).take(5).collect();
                    anyhow::bail!(
                        "s3 batch delete failed for {} of {} keys (e.g. {:?})",
                        failed.len(),
                        chunk.len(),
                        sample
                    );
                }
            }
            match next_page_token(&resp)? {
                Some(tok) => token = Some(tok),
                None => break,
            }
        }
        // Remove the marker itself (it is included in the prefix listing).
        let marker_path = if dir.ends_with('/') {
            dir.to_string()
        } else {
            format!("{dir}/")
        };
        let marker = self.key_for(&marker_path);
        let _ = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(&marker)
            .send()
            .await;
        Ok(())
    }

    /// Rename a file or directory. Directories are copied recursively; the
    /// operation is intentionally non-atomic (object storage semantics).
    /// `replace_if_exists` is honored against the current target state.
    pub async fn rename(&self, old: &str, new: &str, replace_if_exists: bool) -> Result<()> {
        self.ensure_writable()?;
        let _permit = self.acquire().await?;
        self.rename_impl(old, new, replace_if_exists).await
    }

    async fn rename_impl(&self, old: &str, new: &str, replace_if_exists: bool) -> Result<()> {
        self.invalidate_stat(old);
        self.invalidate_stat(new);
        self.clear_read_cache();

        // POSIX rename(a, a) is a successful no-op. rename(a, a/b) must fail
        // (EINVAL): copying the tree then recursively deleting the source
        // prefix would re-list the freshly copied `a/b/*` and wipe both.
        // The reverse direction (moving a directory into its own ancestor)
        // would likewise scramble the tree, so both are rejected.
        if old == new {
            return Ok(());
        }
        if new.starts_with(&format!("{old}/")) || old.starts_with(&format!("{new}/")) {
            anyhow::bail!("rename: cannot move a path into its own subtree");
        }

        // ---- 系统回收站拦截(单元 2,issue #80):位于 (a) 源覆盖检查与
        // replace_if_exists 检查之前 —— 否则 stat(new) 命中合成条目会误报
        // "目标已存在"。目标在回收站条目层 = 软删除(零 copy);源在回收站
        // 条目层 = 还原;回收站目录层本身不可 rename。现有 (a) 用
        // is_covered(old_key) —— 系统前缀 key 不在索引,天然不误伤;
        // (b) clear_target_tombstones(new_key) 对系统前缀 no-op,无需改。
        if let Some(trash) = &self.trash
            && let Some(_sys) = &trash.system
        {
            let src = trash.match_system_trash(old);
            let dst = trash.match_system_trash(new);
            match (src, dst) {
                // 目标在回收站条目层、源不在 → 软删除(先于 (a)/(b),零 copy)
                (None, Some(trash::SystemTrashMatch::Entry { entry_name })) => {
                    // 裁决 R14:Windows 记录 SID 段(视图根渲染;幂等)
                    trash.record_seen_sid(new);
                    return trash.soft_delete_via_system(self, old, &entry_name).await;
                }
                // F3(medium):涉及回收站目录层本身的 rename(源或目标为
                // $Recycle.Bin / SID 目录)一律拒绝 —— 必须位于还原分支
                // 之前:修复前 (Some(Entry), Some(Dir)) 被 (Some(Entry), _)
                // 还原分支吞掉,restore_via_system 把原对象 copy 到
                // "$Recycle.Bin" 真实键,根列表以真实文件形态覆盖合成目录,
                // Explorer 回收站探测失效(实现与规格 §2.1 同款 bug,裁决 F3)。
                (Some(trash::SystemTrashMatch::Dir { .. }), _)
                | (_, Some(trash::SystemTrashMatch::Dir { .. })) => {
                    anyhow::bail!("rename: cannot move the system recycle bin directory");
                }
                // 源在回收站条目层 → 还原(目标也在回收站 = WithinRecycle,
                // 裁决 R5:虚拟视图内 rename 不改变任何状态,no-op 成功)
                (
                    Some(trash::SystemTrashMatch::Entry { entry_name }),
                    Some(trash::SystemTrashMatch::Entry { .. }),
                ) => {
                    // F14(low):no-op 前校验源条目存在(cold_scan=false,
                    // 零远程 —— Windows by_name 命中即存在、未知条目零
                    // 远程判定;macOS basename 扫描同样零远程)—— 幽灵
                    // 源 rename 丢失 POSIX ENOENT 语义(修复前返回 Ok
                    // 且零请求,调用方误以为移动成功)。
                    if trash
                        .resolve_entry(self, &entry_name, false)
                        .await?
                        .is_none()
                    {
                        anyhow::bail!("rename: source not found: {old}");
                    }
                    return Ok(());
                }
                (Some(trash::SystemTrashMatch::Entry { .. }), None) => {
                    // 还原(Result<RestoreOutcome> 丢弃 —— rename 契约是
                    // Result<()>,失败语义已含于 Err)
                    return trash.restore_via_system(self, old, new).await.map(|_| ());
                }
                (None, None) => {}
            }
        }

        let old_key = self.key_for(old);
        let new_key = self.key_for(new);

        // (a) 源被墓碑覆盖 → 拒绝。stat 已被 hidden_key 过滤返回 None,
        // 不拦会被当"不存在"走 copy —— 隐藏对象被搬出 = 数据泄漏。
        // is_covered 双形态覆盖文件精确与目录前缀两种情况。
        if let Some(trash) = &self.trash {
            if trash.index.read().unwrap().is_covered(&old_key) {
                anyhow::bail!("rename: source path is in the trash");
            }
        }

        if !replace_if_exists && self.stat_uncached_impl(new).await?.is_some() {
            anyhow::bail!("rename: target already exists");
        }

        let source = s3_copy_source(&self.bucket, &old_key);

        // Determine directory-ness from S3 instead of assuming a trailing
        // slash: WinFsp/FUSE rename paths for directories arrive without a
        // trailing slash. The size also decides whether the object copy must
        // be chunked (> 5 GiB, #60).
        let stat = self.stat_uncached_impl(old).await?;
        let is_dir = stat.as_ref().map(|e| e.is_dir).unwrap_or(false);
        let size = stat.map(|e| e.size).unwrap_or(0);

        // (0) 目录 rename 的全部失败检查前移到清墓碑之前(裁决 #3):
        // 超限检查失败时目标墓碑必须原样保留 —— 修复前「先清墓碑再
        // count」,超限 bail 后已删目录子树永久复活、trash 追踪丢失。
        if is_dir {
            if !self.allow_rename_dir {
                anyhow::bail!("directory rename is disabled");
            }
            if let Some(limit) = self.rename_dir_limit {
                let count = self.count_tree_entries(&old_key, limit).await?;
                if count > limit {
                    anyhow::bail!(
                        "directory {old} has {count} entries, exceeding rename-dir-limit {limit}"
                    );
                }
            }
        }

        if is_dir {
            // Directory: copy the marker + every child recursively.
            self.copy_tree(&old_key, &new_key).await?;
            // (b) 目标被墓碑覆盖 → copy 成功后清墓碑(rename = 覆盖语义)。
            // 清墓碑在 copy 之后(裁决 #3):copy 失败 → 墓碑保留(软删除
            // 不被静默撤销);清墓碑失败 → rename 失败,重试自愈。清双形态
            // (F1):unlink /e 后 rename 目录到 /e 的文件墓碑同样被清。
            if let Some(trash) = &self.trash {
                trash.clear_target_tombstones(self, &new_key).await?;
            }
            self.delete_dir_recursive_impl(old).await
        } else {
            if size >= MULTIPART_COPY_THRESHOLD {
                // A single CopyObject is capped at 5 GiB; the file rename
                // must chunk-copy like directory children do (#60 review).
                self.multipart_copy_object(&old_key, &new_key, size).await?;
            } else {
                let mut copy = self
                    .client
                    .copy_object()
                    .bucket(&self.bucket)
                    .key(&new_key)
                    .copy_source(&source);
                if let Some(sc) = &self.storage_class {
                    copy = copy.storage_class(sc.clone());
                }
                copy.send().await.context("s3 copy")?;
            }
            // (b) 文件目标:copy 成功后清墓碑(与目录分支同语义,裁决 #3;
            // 双形态 F1:rmdir /e 后 rename 文件到 /e 的目录墓碑被清)。
            if let Some(trash) = &self.trash {
                trash.clear_target_tombstones(self, &new_key).await?;
            }
            self.delete_impl(old).await
        }
    }

    /// Count objects under the `old_key` directory prefix, failing as soon as
    /// the count exceeds `limit` so an oversized rename is rejected before any
    /// copy work starts.
    async fn count_tree_entries(&self, old_key: &str, limit: u64) -> Result<u64> {
        let prefix = dir_object_prefix(old_key);
        let mut count = 0u64;
        let mut token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(tok) = token.as_deref() {
                req = req.continuation_token(tok);
            }
            let resp = req.send().await.context("s3 list for rename count")?;
            count += resp.contents().len() as u64;
            if count > limit {
                anyhow::bail!(
                    "directory exceeds rename-dir-limit {limit} ({count} entries so far)"
                );
            }
            match next_page_token(&resp)? {
                Some(tok) => token = Some(tok),
                None => break,
            }
        }
        Ok(count)
    }

    async fn copy_tree(&self, old_key: &str, new_key: &str) -> Result<()> {
        let prefix = dir_object_prefix(old_key);
        let mut token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(tok) = token.as_deref() {
                req = req.continuation_token(tok);
            }
            let resp = req.send().await.context("s3 list for rename")?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    let suffix = key.strip_prefix(&prefix).unwrap_or(key);
                    let dst = format!("{}/{suffix}", new_key.trim_end_matches('/'));
                    let size = obj.size().unwrap_or(0);
                    if size >= MULTIPART_COPY_THRESHOLD as i64 {
                        // A single CopyObject is capped at 5 GiB; larger
                        // objects must be chunk-copied (#60).
                        self.multipart_copy_object(key, &dst, size as u64).await?;
                    } else {
                        let mut copy = self
                            .client
                            .copy_object()
                            .bucket(&self.bucket)
                            .key(&dst)
                            .copy_source(s3_copy_source(&self.bucket, key));
                        if let Some(sc) = &self.storage_class {
                            copy = copy.storage_class(sc.clone());
                        }
                        copy.send().await.context("s3 copy")?;
                    }
                }
            }
            match next_page_token(&resp)? {
                Some(tok) => token = Some(tok),
                None => break,
            }
        }
        // Copy the dir marker.
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .key(format!("{}/", new_key.trim_end_matches('/')))
            .copy_source(s3_copy_source(
                &self.bucket,
                &format!("{}/", old_key.trim_end_matches('/')),
            ))
            .send()
            .await
            .context("s3 copy marker")?;
        Ok(())
    }

    /// Copy one object via multipart copy. S3 caps a single CopyObject at
    /// 5 GiB; larger objects are chunk-copied with `upload_part_copy` parts
    /// of [`Self::multipart_part_size`] (floored at the 5 MiB AWS minimum
    /// for non-final copy parts). Any failure aborts the upload (#60).
    async fn multipart_copy_object(&self, src_key: &str, dst_key: &str, size: u64) -> Result<()> {
        let part_size = (self.multipart_part_size as u64).max(5 * 1024 * 1024);
        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(dst_key);
        if let Some(sc) = &self.storage_class {
            create = create.storage_class(sc.clone());
        }
        let upload_id = create
            .send()
            .await
            .context("s3 create multipart copy")?
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("multipart copy returned no upload id"))?
            .to_string();
        let source = s3_copy_source(&self.bucket, src_key);
        let mut parts = Vec::new();
        let mut part_number = 1i32;
        let mut offset = 0u64;
        loop {
            let end = (offset + part_size).min(size);
            let range = format!("bytes={}-{}", offset, end.saturating_sub(1));
            let resp = self
                .client
                .upload_part_copy()
                .bucket(&self.bucket)
                .key(dst_key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .copy_source(&source)
                .copy_source_range(&range)
                .send()
                .await;
            let etag = match resp {
                Ok(r) => r
                    .copy_part_result()
                    .and_then(|c| c.e_tag().map(str::to_string))
                    .unwrap_or_default(),
                Err(e) => {
                    self.abort_upload(dst_key, &upload_id).await;
                    return Err(e).context("s3 copy part");
                }
            };
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(etag)
                    .build(),
            );
            if end >= size {
                break;
            }
            offset = end;
            part_number += 1;
        }
        let complete = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(dst_key)
            .upload_id(&upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await;
        if let Err(e) = complete {
            self.abort_upload(dst_key, &upload_id).await;
            return Err(e).context("s3 complete multipart copy");
        }
        Ok(())
    }
}

/// True when an AWS SDK error is a 404 (used to distinguish missing objects).
fn is_s3_not_found(
    e: &aws_sdk_s3::error::SdkError<impl std::fmt::Debug + std::fmt::Display>,
) -> bool {
    match e {
        aws_sdk_s3::error::SdkError::ServiceError(err) => err.raw().status().as_u16() == 404,
        _ => false,
    }
}

/// Next continuation token of a paginated ListObjectsV2 response.
///
/// A response that reports `IsTruncated` without a `NextContinuationToken`
/// cannot be paged any further. Returning the partial result as success would
/// silently drop the rest of the listing — missing readdir entries, or
/// objects left behind by a "successful" recursive delete — so it is
/// surfaced as an error instead (#60).
fn next_page_token(
    resp: &aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output,
) -> Result<Option<String>> {
    if resp.is_truncated() != Some(true) {
        return Ok(None);
    }
    match resp.next_continuation_token() {
        Some(tok) => Ok(Some(tok.to_string())),
        None => anyhow::bail!(
            "s3 list truncated without a continuation token; refusing to return a partial listing"
        ),
    }
}

/// True when an AWS SDK error is an out-of-range read (416 InvalidRange).
/// Reads at/behind EOF are treated as "return 0 bytes", so this is not an
/// error.
fn is_s3_invalid_range(
    e: &aws_sdk_s3::error::SdkError<impl std::fmt::Debug + std::fmt::Display>,
) -> bool {
    match e {
        aws_sdk_s3::error::SdkError::ServiceError(err) => {
            let status = err.raw().status().as_u16();
            if status == 416 {
                return true;
            }
            // Some S3-compatible services return 400 with a body code.
            if status == 400 {
                let body = String::from_utf8_lossy(err.raw().body().bytes().unwrap_or_default());
                return body.contains("InvalidRange");
            }
            false
        }
        _ => false,
    }
}

/// Size of the S3 GET for one read, factoring in the read-ahead window and
/// whether this read continues the previous one. Extracted so the prefetch
/// decision is unit-testable.
fn read_fetch_len(len: usize, window: usize, sequential: bool) -> usize {
    if window > 0 && (len as u64) < window as u64 && sequential {
        window
    } else {
        len
    }
}

/// Normalize an object key so its directory prefix is `<base>/`, never
/// `<base>//`. Used by directory rename copy/count paths.
fn dir_object_prefix(key: &str) -> String {
    let base = key.trim_end_matches('/');
    format!("{base}/")
}

/// Strip the leading slashes from a normalized path; `"/"` -> `""`.
///
/// Only leading `/` are stripped: a trailing slash is significant (directory
/// markers live at `path + "/"`) and leading/trailing whitespace is a legal
/// part of a POSIX file name, so trimming it here would map `"a"` and `"a "`
/// to the same object key (silent mutual overwrite).
pub fn rel_key(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

/// True when `path` denotes the mount root (`"/"`, `"//"`, `""`): everything
/// that reduces to the empty relative key. The root has no object of its
/// own, so key-producing mutations on it are rejected by the callers (#60).
fn is_root_path(path: &str) -> bool {
    path.trim_start_matches('/').is_empty()
}

/// Build an S3 `x-amz-copy-source` header value (`/bucket/key`) with the key
/// percent-encoded per RFC 3986. Slashes inside the key are preserved (they
/// are object-key separators, not encoded by S3 in copy-source); everything
/// else that is not an unreserved character is encoded. Without this, keys
/// containing spaces / `+` / `#` / `%` / non-ASCII break rename and copy.
pub(crate) fn s3_copy_source(bucket: &str, key: &str) -> String {
    let mut out = String::with_capacity(bucket.len() + key.len() + 2);
    out.push('/');
    out.push_str(bucket);
    out.push('/');
    for b in key.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique temp-file path for a streaming write handle's read-back spool
/// (#47): while a multipart upload is in flight the parts are invisible to
/// reads, so the handle spills the bytes written so far to a temp file and
/// serves reads from it until the upload completes.
fn spool_file_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ossfs-spool-{}-{}",
        std::process::id(),
        SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Last path component of a normalized POSIX path. `/` stays `/`.
pub fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        None => trimmed.to_string(),
        Some(0) => trimmed[1..].to_string(),
        Some(idx) => trimmed[idx + 1..].to_string(),
    }
}

/// Parent of a normalized POSIX path. `/` stays `/`.
pub fn parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(idx) => trimmed[..idx].to_string(),
    }
}

/// Effective in-flight S3 request cap: explicit config wins, `None`/`0`
/// fall back to the default bound (0 never means "unlimited", which would
/// reintroduce the unbounded-concurrency OOM this limiter prevents).
fn effective_max_concurrent_requests(configured: Option<usize>) -> usize {
    configured
        .filter(|&n| n > 0)
        .unwrap_or(MAX_CONCURRENT_S3_REQUESTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_retryable_error_classifies() {
        // 可恢复(issue #83):超时/连接/网络/5xx/限流 → true
        for msg in [
            "request timed out after 60s",
            "connect timed out",
            "failed to connect to endpoint",
            "network is unreachable",
            "connection reset by peer",
            "broken pipe",
            "server returned 500 Internal Server Error",
            "status 503 Service Unavailable",
            "slow down (throttling)",
            "too many requests (429)",
        ] {
            let e = anyhow::anyhow!(msg);
            assert!(is_retryable_error(&e), "should be retryable: {msg}");
        }
        // 致命:权限/不存在/签名/本地逻辑 → false
        for msg in [
            "AccessDenied (403)",
            "NoSuchKey (404)",
            "SignatureDoesNotMatch",
            "InvalidAccessKeyId",
            "target already exists",
            "cannot delete the mount root /",
        ] {
            let e = anyhow::anyhow!(msg);
            assert!(!is_retryable_error(&e), "should NOT be retryable: {msg}");
        }
        // 嵌套 cause 也搜索(aws-sdk 包装链)。
        let nested = anyhow::anyhow!("upload failed").context("request timed out");
        assert!(is_retryable_error(&nested));
    }

    #[test]
    fn retry_backoff_scales_and_caps() {
        // 退避 5s * 3^min(attempts,5),封顶 5 分钟(issue #85)。
        assert_eq!(retry_backoff(0), Duration::from_secs(5));
        assert_eq!(retry_backoff(1), Duration::from_secs(15));
        assert_eq!(retry_backoff(2), Duration::from_secs(45));
        assert_eq!(retry_backoff(5), Duration::from_secs(5 * 3u64.pow(5)));
        assert_eq!(retry_backoff(9), retry_backoff(5), "封顶");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn retry_worker_recovers_after_transient_failure() {
        // issue #85:失败上传入队 → 网络恢复 → worker 退避后重试成功,
        // 对象最终存在、队列清空。平台无关核心(macOS 可跑)。
        let (mock, port) = MockS3::start(vec![], Duration::ZERO).await;
        mock.fail_put.store(1, Ordering::SeqCst); // 第一次 PUT 失败
        let fs = Arc::new(test_fs_with_budget(port, 32, None));
        let retry = Arc::new(RetryState {
            queue: Mutex::new(VecDeque::new()),
            notify: tokio::sync::Notify::new(),
        });
        {
            let mut q = retry.queue.lock().unwrap();
            q.push_back(RetryUpload {
                path: "/f.txt".to_string(),
                spool: None,
                buf: Some(b"hello retry".to_vec()),
                attempts: 0,
            });
        }
        retry.notify.notify_one();
        let worker_fs = Arc::clone(&fs);
        let worker_retry = Arc::clone(&retry);
        tokio::spawn(async move {
            run_retry_worker(worker_fs, worker_retry).await;
        });
        // worker 退避 5s 后才重试:期间恢复网络(mock 放行)。
        mock.fail_put.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert!(retry.queue.lock().unwrap().is_empty(), "重试成功后退队");
        let obj = mock.objects.lock().unwrap().get("f.txt").cloned();
        assert_eq!(
            obj.as_deref(),
            Some(b"hello retry".as_slice()),
            "对象最终必须存在且内容正确"
        );
    }

    #[test]
    fn rel_key_maps_paths() {
        assert_eq!(rel_key("/"), "");
        assert_eq!(rel_key("/a"), "a");
        assert_eq!(rel_key("/a/b.txt"), "a/b.txt");
        assert_eq!(rel_key("/a/"), "a/");
        assert_eq!(rel_key("//a//b"), "a//b");
    }

    #[test]
    fn rel_key_preserves_significant_whitespace() {
        // Regression (#60): `trim()` used to collapse `"a "` and `"a"` (and
        // ` /a` vs `/a`) onto the same object key, silently overwriting one
        // with the other. Whitespace is a legal POSIX name character.
        assert_eq!(rel_key("/a "), "a ");
        assert_eq!(rel_key("/ a"), " a");
        assert_eq!(rel_key("/a\n"), "a\n");
        assert_eq!(rel_key(" /a"), " /a");
        assert_eq!(rel_key("/ a/"), " a/");
    }

    #[test]
    fn basename_and_parent() {
        assert_eq!(basename("/a/b.txt"), "b.txt");
        assert_eq!(basename("/a/"), "a");
        assert_eq!(basename("/"), "/");
        assert_eq!(parent_path("/a/b"), "/a");
        assert_eq!(parent_path("/a"), "/");
        assert_eq!(parent_path("/"), "/");
    }

    /// Minimal [`ObjectFs`] with default config and no S3 client. Tests that
    /// need a live mock call [`super::s3_mock_tests::test_fs`] instead. A
    /// single builder keeps the ~40-line literal from being duplicated per
    /// test — adding a field must not mean editing ten sites (#59).
    fn test_fs() -> ObjectFs {
        ObjectFs {
            client: Client::from_conf(aws_sdk_s3::config::Config::builder().build()),
            bucket: "b".into(),
            stats: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_S3_REQUESTS)),
            read_only: false,
            allow_other: false,
            list_rate: None,
            mount_attr: MountAttr::default(),
            allow_rename_dir: true,
            rename_dir_limit: None,
            upload_budget: None,
            upload_budget_units: 0,
            read_ahead_window: 0,
            read_cache: Mutex::new(ReadCache::default()),
            read_cache_max_bytes: READ_CACHE_MAX_BYTES,
            disk_cache: None,
            disk_cache_prefetch_blocks: 1,
            prefetch_inflight: Arc::new(Mutex::new(HashSet::new())),
            prefetch_sem: Arc::new(Semaphore::new(DISK_CACHE_PREFETCH_CONCURRENCY)),
            disk_cache_verify_etag: false,
            etag_checked: Mutex::new(HashMap::new()),
            etag_ttl: ETAG_CHECK_TTL,
            negative_ttl: NEGATIVE_CACHE_TTL,
            stat_ttl: STAT_TTL,
            negative_max_entries: MAX_NEGATIVE_ENTRIES,
            stat_max_entries: MAX_STAT_ENTRIES,
            read_seq: Mutex::new(HashMap::new()),
            ignore_fsync: true,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            multipart_part_size: MULTIPART_PART_SIZE as usize,
            multipart_concurrency: MULTIPART_UPLOAD_CONCURRENCY,
            metrics: Arc::new(Metrics::default()),
            dirty_budget: None,
            operation_timeout: std::time::Duration::from_secs(60),
            prefix: String::new(),
            trash: None,
            trash_refresh_started: AtomicBool::new(false),
        }
    }

    #[test]
    fn key_for_applies_prefix() {
        let mut fs = test_fs();
        fs.prefix = "ossfs/".into();
        assert_eq!(fs.key_for("/docs/a.txt"), "ossfs/docs/a.txt");
        assert_eq!(fs.key_for("/docs/"), "ossfs/docs/");
        assert_eq!(fs.key_for("/"), "ossfs");

        let fs2 = test_fs();
        assert_eq!(fs2.key_for("/docs/a.txt"), "docs/a.txt");
        assert_eq!(fs2.list_prefix("/docs"), "docs/");
        assert_eq!(fs2.list_prefix("/"), "");
    }

    #[test]
    fn hidden_key_gate() {
        let trash_state = |prefix: &str| {
            trash::TrashState::new(
                prefix.to_string(),
                TrashRefreshMode::Lazy,
                Duration::from_secs(TRASH_REFRESH_INTERVAL_SECS),
                Duration::from_secs(TRASH_REBUILD_INTERVAL_SECS),
                Duration::from_secs(TRASH_GC_INTERVAL_SECS),
                TRASH_RETENTION_DAYS,
            )
        };
        // trash None → 恒 false(零行为变化)
        let fs = test_fs();
        assert!(!fs.hidden_key(".trash"));
        assert!(!fs.hidden_key(".trash/2026-08-16/a.txt"));
        assert!(!fs.hidden_key("docs/a.txt"));
        // ".trash" 裸形态与 ".trash/" 前缀
        let mut fs = test_fs();
        fs.trash = Some(trash_state(".trash/"));
        assert!(fs.hidden_key(".trash"));
        assert!(fs.hidden_key(".trash/"));
        assert!(fs.hidden_key(".trash/2026-08-16/a.txt"));
        assert!(!fs.hidden_key(".trashx"), "尾斜杠边界:.trashx 不误伤");
        assert!(!fs.hidden_key(".trashx/a.txt"));
        // prefix 变体
        let mut fs = test_fs();
        fs.prefix = "ossfs/".into();
        fs.trash = Some(trash_state("ossfs/.trash/"));
        assert!(fs.hidden_key("ossfs/.trash"));
        assert!(fs.hidden_key("ossfs/.trash/2026-08-16/a.txt"));
        assert!(!fs.hidden_key("ossfs/docs/a.txt"));
        // 索引覆盖(files + dirs)
        let mut fs = test_fs();
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/a.txt", false);
        assert!(fs.hidden_key("a.txt"));
        assert!(!fs.hidden_key("b.txt"));
        fs.trash_insert("/docs", true);
        assert!(fs.hidden_key("docs/x.txt"));
        assert!(!fs.hidden_key("docsx/x.txt"));
    }

    #[test]
    fn effective_owner_and_mode_resolve_defaults() {
        assert_eq!(effective_owner(0, 1000), 1000);
        assert_eq!(effective_owner(42, 1000), 42);
        assert_eq!(effective_mode(true, 0o755, 0o644, 0), 0o755);
        assert_eq!(effective_mode(false, 0o755, 0o644, 0), 0o644);
        assert_eq!(effective_mode(false, 0o755, 0o644, 0o022), 0o644);
        assert_eq!(effective_mode(true, 0o777, 0o666, 0o022), 0o755);
    }

    #[tokio::test]
    async fn read_only_rejects_all_mutations() {
        let mut fs = test_fs();
        fs.read_only = true;
        assert!(fs.ensure_writable().is_err());
        assert!(fs.write("/a", b"x").await.is_err());
        assert!(fs.mkdir("/d").await.is_err());
        assert!(fs.delete("/a").await.is_err());
        assert!(fs.delete_dir_recursive("/d").await.is_err());
        assert!(fs.rename("/a", "/b", true).await.is_err());
    }

    #[tokio::test]
    async fn upload_budget_rejects_object_larger_than_limit() {
        let mut fs = test_fs();
        fs.upload_budget = Some(Arc::new(Semaphore::new(1)));
        fs.upload_budget_units = 1;
        let data = vec![0u8; 2 * UPLOAD_BUDGET_UNIT];
        let err = fs.write("/large.bin", &data).await.unwrap_err();
        assert!(err.to_string().contains("max-upload-bytes budget"));
    }

    #[test]
    fn read_fetch_len_prefetches_only_on_sequential_reads() {
        assert_eq!(read_fetch_len(4096, 8 * 1024, false), 4096);
        assert_eq!(read_fetch_len(4096, 8 * 1024, true), 8 * 1024);
        assert_eq!(read_fetch_len(8 * 1024, 8 * 1024, true), 8 * 1024);
        assert_eq!(read_fetch_len(4096, 0, true), 4096);
    }

    #[test]
    fn read_cache_hit_and_invalidation() {
        let mut fs = test_fs();
        fs.read_ahead_window = 1024;
        fs.insert_read_cache("/a", 0, (0..1024u32).map(|v| v as u8).collect::<Vec<_>>());
        assert_eq!(fs.read_cache_hit("/a", 10, 4), Some(vec![10, 11, 12, 13]));
        assert_eq!(fs.read_cache_hit("/a", 2048, 4), None);
        fs.invalidate_read_cache("/a");
        assert_eq!(fs.read_cache_hit("/a", 10, 4), None);
    }

    #[test]
    fn dirty_budget_rounds_up_and_disables_on_zero() {
        assert!(DirtyBudget::new(0).is_none());
        let budget = DirtyBudget::new(DIRTY_BUDGET_UNIT + 1).unwrap();
        assert_eq!(budget.max_units(), 2);
    }

    #[test]
    fn total_mem_limit_derives_budgets() {
        assert_eq!(
            effective_memory_budgets(Some(64 * 1024 * 1024), 0.5, None, None, None),
            (
                Some(16 * 1024 * 1024),
                Some(16 * 1024 * 1024),
                32 * 1024 * 1024
            )
        );
        assert_eq!(
            effective_memory_budgets(None, 0.5, Some(5), Some(7), Some(9)),
            (Some(5), Some(7), 9)
        );
        assert_eq!(
            effective_memory_budgets(None, 0.5, None, None, None),
            (None, None, READ_CACHE_MAX_BYTES)
        );
    }

    #[test]
    fn s3_max_attempts_maps_retries_to_total_attempts() {
        assert_eq!(s3_max_attempts(0), 1);
        assert_eq!(s3_max_attempts(1), 2);
        assert_eq!(s3_max_attempts(2), 3);
        assert_eq!(s3_max_attempts(u32::MAX), u32::MAX);
    }

    #[test]
    fn min_free_bytes_uses_max_of_reserve_and_ratio() {
        assert_eq!(min_free_bytes(0, None, 1000), 0);
        assert_eq!(min_free_bytes(100, None, 1000), 100);
        assert_eq!(min_free_bytes(0, Some(0.1), 1000), 100);
        assert_eq!(min_free_bytes(50, Some(0.1), 1000), 100);
        assert_eq!(min_free_bytes(200, Some(0.1), 1000), 200);
    }

    #[test]
    fn disk_cache_skips_write_below_free_space_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            u64::MAX,
            None,
        )
        .expect("cache");
        cache.write_block("k", 0, b"data").expect("write");

        let blocks = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "blk").unwrap_or(false))
            .count();
        assert_eq!(
            blocks, 0,
            "write must be skipped below the free-space floor"
        );
    }

    #[test]
    fn disk_cache_lru_evicts_least_recently_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            5 * 1024 * 1024,
            DISK_CACHE_BLOCK_SIZE as usize,
            0,
            None,
        )
        .expect("cache");
        let two_mib = vec![0xA5u8; 2 * 1024 * 1024];

        cache.write_block("k", 0, &two_mib).expect("write A");
        cache.write_block("k", 1, &two_mib).expect("write B");
        cache.read_block("k", 0); // touch A
        cache
            .write_block("k", 2, &two_mib)
            .expect("write C triggers evict");

        assert!(cache.path_for("k", 0).exists(), "A must survive");
        assert!(cache.path_for("k", 2).exists(), "C must survive");
        assert!(!cache.path_for("k", 1).exists(), "B must be evicted as LRU");
    }

    #[test]
    fn disk_cache_lru_order_persists_across_remount() {
        let dir = tempfile::tempdir().expect("tempdir");
        let two_mib = vec![0xB5u8; 2 * 1024 * 1024];

        {
            let cache = DiskCache::new(
                dir.path().to_path_buf(),
                5 * 1024 * 1024,
                DISK_CACHE_BLOCK_SIZE as usize,
                0,
                None,
            )
            .expect("cache");
            cache.write_block("k", 0, &two_mib).expect("write A");
            cache.write_block("k", 1, &two_mib).expect("write B");
            cache.read_block("k", 0); // touch A
        }

        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            5 * 1024 * 1024,
            DISK_CACHE_BLOCK_SIZE as usize,
            0,
            None,
        )
        .expect("reopen");
        cache
            .write_block("k", 2, &two_mib)
            .expect("write C triggers evict");
        assert!(
            cache.path_for("k", 0).exists(),
            "A must survive across remount"
        );
        assert!(cache.path_for("k", 2).exists(), "C must survive");
        assert!(!cache.path_for("k", 1).exists(), "B must be evicted as LRU");
    }

    #[test]
    fn disk_cache_block_size_mismatch_rebuilds() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let cache = DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                2 * 1024 * 1024,
                0,
                None,
            )
            .expect("cache");
            assert_eq!(cache.block_size, 2 * 1024 * 1024);
        }
        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            64 * 1024 * 1024,
            1 * 1024 * 1024,
            0,
            None,
        )
        .expect("reopen");
        assert_eq!(cache.block_size, 1 * 1024 * 1024);
    }

    #[test]
    fn disk_cache_detects_corrupt_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            64 * 1024 * 1024,
            4 * 1024 * 1024,
            0,
            None,
        )
        .expect("cache");
        cache
            .write_block("k", 0, &vec![0x5Au8; 1024])
            .expect("write");

        let path = cache.path_for("k", 0);
        let mut raw = std::fs::read(&path).expect("read block");
        let n = raw.len();
        raw[n - 1] ^= 0xFF;
        std::fs::write(&path, raw).expect("corrupt block");

        assert_eq!(cache.read_block("k", 0), None);
        assert!(!path.exists(), "corrupt block should be removed");
    }

    #[test]
    fn token_bucket_limits_burst_and_refills() {
        let mut b = TokenBucket::new(10.0);
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(b.reserve(t0).is_none(), "burst allows 10 immediate tokens");
        }
        assert!(b.reserve(t0).is_some(), "11th token must wait");
        let t1 = t0 + Duration::from_secs_f64(0.2);
        assert!(b.reserve(t1).is_none());
        assert!(b.reserve(t1).is_none());
        assert!(b.reserve(t1).is_some());
    }

    #[tokio::test]
    async fn dirty_budget_acquire_and_drop_releases_permits() {
        let budget = DirtyBudget::new(2 * DIRTY_BUDGET_UNIT).unwrap();
        assert_eq!(budget.max_units(), 2);
        let permit = budget.acquire_units(2).await.unwrap();
        assert_eq!(budget.sem.available_permits(), 0);
        drop(permit);
        assert_eq!(budget.sem.available_permits(), 2);
    }

    #[test]
    fn config_normalizes_prefix() {
        let cfg = OssConfig {
            bucket: "b".into(),
            region: "cn-shanghai".into(),
            endpoint: None,
            force_path_style: false,
            prefix: "ossfs".into(),
            max_concurrent_requests: None,
            list_rate_limit: None,
            read_only: false,
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            allow_other: false,
            umask: 0,
            allow_rename_dir: true,
            rename_dir_limit: Some(2_000_000),
            max_upload_bytes: None,
            read_ahead_bytes: None,
            ignore_fsync: true,
            max_dirty_bytes: None,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            connect_timeout_secs: None,
            readwrite_timeout_secs: None,
            retries: None,
            multipart_size: None,
            multipart_concurrency: None,
            disk_cache_reserve_diskfree: 0,
            disk_cache_free_space_ratio: None,
            disk_cache_dir: None,
            disk_cache_max_bytes: 0,
            disk_cache_block_size: None,
            disk_cache_prefetch_blocks: 1,
            disk_cache_prefetch_concurrency: 4,
            disk_cache_verify_etag: false,
            disk_cache_etag_ttl_secs: 10,
            negative_cache_ttl_secs: 5,
            negative_cache_max_entries: 4096,
            stat_cache_ttl_secs: 3,
            stat_cache_max_entries: 4096,
            total_mem_limit: None,
            total_mem_read_ratio: 0.5,
            read_cache_max_bytes: None,
            credential_process: None,
            trash_dir: None,
            trash_retention_days: None,
            trash_refresh_interval_secs: None,
            trash_refresh_mode: None,
            trash_gc_interval_secs: None,
            system_trash: None,
        }
        .normalize();
        assert_eq!(cfg.prefix, "ossfs/");
        assert!(
            cfg.trash_dir.is_none(),
            "normalize 绝不填 trash_dir(None = 回收站关闭,门控不被默认值覆盖)"
        );
    }

    #[test]
    fn s3_timeout_config_always_sets_timeouts() {
        // The SDK's own default has no read timeout; any path that lets a
        // None through to the client builder would reintroduce the
        // permanent-wedge bug. Explicit values win, None falls back to the
        // defaults. The operation timeout (same value as read; it bounds the
        // whole request including retries, #43) has no getter and is covered
        // by operation_timeout_cuts_off_retry_chain.
        let explicit = s3_timeout_config(Some(3), Some(120));
        assert_eq!(explicit.connect_timeout(), Some(Duration::from_secs(3)));
        assert_eq!(explicit.read_timeout(), Some(Duration::from_secs(120)));

        let fallback = s3_timeout_config(None, None);
        assert_eq!(
            fallback.connect_timeout(),
            Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        );
        assert_eq!(
            fallback.read_timeout(),
            Some(Duration::from_secs(DEFAULT_READWRITE_TIMEOUT_SECS))
        );
    }

    #[test]
    fn normalize_defaults_request_timeouts() {
        // Regression: the SDK ships no read timeout, so a silently-stalled
        // connection held its limiter permit / part slot forever and froze
        // writes under heavy copy load. Unset must fall back to real
        // defaults while an explicit value is preserved (`Some(0)` is only
        // constructible directly — CLI flags and the config file both map 0
        // to unset — and is treated as unset too).
        let base = || OssConfig {
            bucket: "b".into(),
            region: "cn-shanghai".into(),
            endpoint: None,
            force_path_style: false,
            prefix: String::new(),
            max_concurrent_requests: None,
            list_rate_limit: None,
            read_only: false,
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            allow_other: false,
            umask: 0,
            allow_rename_dir: true,
            rename_dir_limit: Some(2_000_000),
            max_upload_bytes: None,
            read_ahead_bytes: None,
            ignore_fsync: true,
            max_dirty_bytes: None,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            connect_timeout_secs: None,
            readwrite_timeout_secs: None,
            retries: None,
            multipart_size: None,
            multipart_concurrency: None,
            disk_cache_reserve_diskfree: 0,
            disk_cache_free_space_ratio: None,
            disk_cache_dir: None,
            disk_cache_max_bytes: 0,
            disk_cache_block_size: None,
            disk_cache_prefetch_blocks: 1,
            disk_cache_prefetch_concurrency: 4,
            disk_cache_verify_etag: false,
            disk_cache_etag_ttl_secs: 10,
            negative_cache_ttl_secs: 5,
            negative_cache_max_entries: 4096,
            stat_cache_ttl_secs: 3,
            stat_cache_max_entries: 4096,
            total_mem_limit: None,
            total_mem_read_ratio: 0.5,
            read_cache_max_bytes: None,
            credential_process: None,
            trash_dir: None,
            trash_retention_days: None,
            trash_refresh_interval_secs: None,
            trash_refresh_mode: None,
            trash_gc_interval_secs: None,
            system_trash: None,
        };
        let cfg = base().normalize();
        assert_eq!(cfg.connect_timeout_secs, Some(DEFAULT_CONNECT_TIMEOUT_SECS));
        assert_eq!(
            cfg.readwrite_timeout_secs,
            Some(DEFAULT_READWRITE_TIMEOUT_SECS)
        );
        assert_eq!(
            cfg.retries,
            Some(1),
            "default to one retry so a wedged request parks its callback at most 2x the read timeout"
        );

        let mut cfg = base();
        cfg.connect_timeout_secs = Some(0);
        cfg.readwrite_timeout_secs = Some(0);
        let cfg = cfg.normalize();
        assert_eq!(cfg.connect_timeout_secs, Some(DEFAULT_CONNECT_TIMEOUT_SECS));
        assert_eq!(
            cfg.readwrite_timeout_secs,
            Some(DEFAULT_READWRITE_TIMEOUT_SECS)
        );

        let mut cfg = base();
        cfg.connect_timeout_secs = Some(3);
        cfg.readwrite_timeout_secs = Some(120);
        let cfg = cfg.normalize();
        assert_eq!(cfg.connect_timeout_secs, Some(3));
        assert_eq!(cfg.readwrite_timeout_secs, Some(120));
    }

    #[test]
    fn normalize_never_fills_system_trash() {
        // 裁决 R1:normalize 绝不填 system_trash(门控不被默认值覆盖,
        // 同 trash_dir 注释模式;默认开/关由 CLI 与 build_trash_state 注入)。
        let base = || OssConfig {
            bucket: "b".into(),
            region: "cn-shanghai".into(),
            endpoint: None,
            force_path_style: false,
            prefix: String::new(),
            max_concurrent_requests: None,
            list_rate_limit: None,
            read_only: false,
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            allow_other: false,
            umask: 0,
            allow_rename_dir: true,
            rename_dir_limit: Some(2_000_000),
            max_upload_bytes: None,
            read_ahead_bytes: None,
            ignore_fsync: true,
            max_dirty_bytes: None,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            connect_timeout_secs: None,
            readwrite_timeout_secs: None,
            retries: None,
            multipart_size: None,
            multipart_concurrency: None,
            disk_cache_reserve_diskfree: 0,
            disk_cache_free_space_ratio: None,
            disk_cache_dir: None,
            disk_cache_max_bytes: 0,
            disk_cache_block_size: None,
            disk_cache_prefetch_blocks: 1,
            disk_cache_prefetch_concurrency: 4,
            disk_cache_verify_etag: false,
            disk_cache_etag_ttl_secs: 10,
            negative_cache_ttl_secs: 5,
            negative_cache_max_entries: 4096,
            stat_cache_ttl_secs: 3,
            stat_cache_max_entries: 4096,
            total_mem_limit: None,
            total_mem_read_ratio: 0.5,
            read_cache_max_bytes: None,
            credential_process: None,
            trash_dir: None,
            trash_retention_days: None,
            trash_refresh_interval_secs: None,
            trash_refresh_mode: None,
            trash_gc_interval_secs: None,
            system_trash: None,
        };
        assert!(
            base().normalize().system_trash.is_none(),
            "normalize 绝不填 system_trash"
        );
        let mut cfg = base();
        cfg.system_trash = Some(trash::SystemTrashConfig {
            dir_name: Some("Custom".into()),
            macos_uid_dirs: vec![501],
        });
        let cfg = cfg.normalize();
        assert_eq!(
            cfg.system_trash.unwrap().dir_name.as_deref(),
            Some("Custom"),
            "显式配置不被 normalize 覆盖"
        );
    }

    #[test]
    fn build_trash_state_injects_system_view() {
        // 裁决 R1:build_trash_state 是纯消费 Some/None —— 默认开/关由
        // CLI 决定(--no-system-trash 必须可区分「未配置」);平台形态与
        // 目录名默认在此按 cfg!(target_os) 落地。
        let mut cfg = OssConfig {
            bucket: "b".into(),
            region: "cn-shanghai".into(),
            endpoint: None,
            force_path_style: false,
            prefix: "ossfs/".into(),
            max_concurrent_requests: None,
            list_rate_limit: None,
            read_only: false,
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            allow_other: false,
            umask: 0,
            allow_rename_dir: true,
            rename_dir_limit: Some(2_000_000),
            max_upload_bytes: None,
            read_ahead_bytes: None,
            ignore_fsync: true,
            max_dirty_bytes: None,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            connect_timeout_secs: None,
            readwrite_timeout_secs: None,
            retries: None,
            multipart_size: None,
            multipart_concurrency: None,
            disk_cache_reserve_diskfree: 0,
            disk_cache_free_space_ratio: None,
            disk_cache_dir: None,
            disk_cache_max_bytes: 0,
            disk_cache_block_size: None,
            disk_cache_prefetch_blocks: 1,
            disk_cache_prefetch_concurrency: 4,
            disk_cache_verify_etag: false,
            disk_cache_etag_ttl_secs: 10,
            negative_cache_ttl_secs: 5,
            negative_cache_max_entries: 4096,
            stat_cache_ttl_secs: 3,
            stat_cache_max_entries: 4096,
            total_mem_limit: None,
            total_mem_read_ratio: 0.5,
            read_cache_max_bytes: None,
            credential_process: None,
            trash_dir: Some(".trash".into()),
            trash_retention_days: Some(TRASH_RETENTION_DAYS),
            trash_refresh_interval_secs: Some(TRASH_REFRESH_INTERVAL_SECS),
            trash_refresh_mode: None,
            trash_gc_interval_secs: Some(TRASH_GC_INTERVAL_SECS),
            system_trash: None,
        };
        // system_trash 未配置 → 无系统视图(默认开/关是 CLI 的职责)
        let state = build_trash_state(&cfg).unwrap().unwrap();
        assert!(state.system.is_none(), "未配置 system_trash → 不渲染");
        // 显式配置 → 平台形态与目录名默认注入
        cfg.system_trash = Some(trash::SystemTrashConfig {
            dir_name: None,
            macos_uid_dirs: vec![],
        });
        let state = build_trash_state(&cfg).unwrap().unwrap();
        let sys = state.system.as_ref().expect("配置后必须注入系统视图");
        if cfg!(target_os = "macos") {
            assert_eq!(sys.dir_name, ".Trashes");
            assert_eq!(
                sys.platform,
                trash::SystemTrashPlatform::MacOsTrashes,
                "macOS = MacOsTrashes(.Trashes)"
            );
        } else {
            assert_eq!(sys.dir_name, "$Recycle.Bin");
            assert_eq!(
                sys.platform,
                trash::SystemTrashPlatform::WindowsRecycleBin,
                "Windows/Linux = WindowsRecycleBin($Recycle.Bin)"
            );
        }
        // 目录名覆盖
        cfg.system_trash = Some(trash::SystemTrashConfig {
            dir_name: Some("CustomBin".into()),
            macos_uid_dirs: vec![501],
        });
        let state = build_trash_state(&cfg).unwrap().unwrap();
        let sys = state.system.as_ref().unwrap();
        assert_eq!(sys.dir_name, "CustomBin");
        assert_eq!(sys.macos_uid_dirs, vec![501]);
        // 平台形态随目标平台;路径识别按注入后的目录名(裁决 R17:macOS
        // 用数字 uid 段;Windows SID 段任意接受 —— 数字 uid 双平台皆中)
        assert_eq!(
            state.match_system_trash("/CustomBin/501"),
            Some(trash::SystemTrashMatch::Dir { level: 1 })
        );
        // 裁决 R17:macOS 非数字 uid 段不拦截;Windows SID 段任意接受
        if cfg!(target_os = "macos") {
            assert_eq!(state.match_system_trash("/CustomBin/S-1"), None);
        }
        assert_eq!(state.match_system_trash("/$Recycle.Bin"), None);
        // trash 关闭 → 无状态(系统视图无从谈起)
        cfg.trash_dir = None;
        assert!(build_trash_state(&cfg).unwrap().is_none());
    }

    #[test]
    fn refresh_constants_pinned() {
        // 阈值独立 commit 规范:TRASH_* 默认值变更必须独立 commit 写明新旧值
        // 与理由;此断言引用常量本身防漂移。
        assert_eq!(TRASH_REFRESH_INTERVAL_SECS, 30, "增量刷新周期 30s");
        assert_eq!(TRASH_REBUILD_INTERVAL_SECS, 600, "全量重建周期 10min");
        assert_eq!(
            TRASH_INDEX_ALERT_THRESHOLD, 500_000,
            "索引规模告警阈值 500k(裁决 #6 新阈值,无旧值)"
        );
        assert_eq!(
            TRASH_RETENTION_DAYS, 30,
            "回收站保留期 30 天(规格 C5,新阈值,无旧值)"
        );
        assert_eq!(
            TRASH_GC_INTERVAL_SECS, 86_400,
            "GC 周期 24h(规格 C5,新阈值,无旧值)"
        );
        assert_eq!(
            trash::TRASH_EAGER_MIN_POLL_INTERVAL,
            Duration::from_secs(1),
            "eager 最小轮询间隔 1s"
        );
    }

    #[test]
    fn normalize_refresh_defaults() {
        // C4b:阈值默认值在消费单元落地 —— 单元 3 填 refresh_interval=30 /
        // mode=Lazy;显式值不被覆盖;trash_dir 绝不填(门控不被默认值覆盖)。
        let base = || OssConfig {
            bucket: "b".into(),
            region: "cn-shanghai".into(),
            endpoint: None,
            force_path_style: false,
            prefix: String::new(),
            max_concurrent_requests: None,
            list_rate_limit: None,
            read_only: false,
            uid: 0,
            gid: 0,
            dir_mode: 0o755,
            file_mode: 0o644,
            allow_other: false,
            umask: 0,
            allow_rename_dir: true,
            rename_dir_limit: Some(2_000_000),
            max_upload_bytes: None,
            read_ahead_bytes: None,
            ignore_fsync: true,
            max_dirty_bytes: None,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            connect_timeout_secs: None,
            readwrite_timeout_secs: None,
            retries: None,
            multipart_size: None,
            multipart_concurrency: None,
            disk_cache_reserve_diskfree: 0,
            disk_cache_free_space_ratio: None,
            disk_cache_dir: None,
            disk_cache_max_bytes: 0,
            disk_cache_block_size: None,
            disk_cache_prefetch_blocks: 1,
            disk_cache_prefetch_concurrency: 4,
            disk_cache_verify_etag: false,
            disk_cache_etag_ttl_secs: 10,
            negative_cache_ttl_secs: 5,
            negative_cache_max_entries: 4096,
            stat_cache_ttl_secs: 3,
            stat_cache_max_entries: 4096,
            total_mem_limit: None,
            total_mem_read_ratio: 0.5,
            read_cache_max_bytes: None,
            credential_process: None,
            trash_dir: None,
            trash_retention_days: None,
            trash_refresh_interval_secs: None,
            trash_refresh_mode: None,
            trash_gc_interval_secs: None,
            system_trash: None,
        };
        let cfg = base().normalize();
        assert_eq!(
            cfg.trash_refresh_interval_secs,
            Some(TRASH_REFRESH_INTERVAL_SECS),
            "None → 默认 30s"
        );
        assert_eq!(
            cfg.trash_refresh_mode,
            Some(TrashRefreshMode::Lazy),
            "None → 默认 Lazy"
        );
        assert!(
            cfg.trash_dir.is_none(),
            "normalize 绝不填 trash_dir(None = 回收站关闭)"
        );
        // 单元 4 默认值(C4b):retention_days=30 / gc_interval_secs=86400
        assert_eq!(
            cfg.trash_retention_days,
            Some(TRASH_RETENTION_DAYS),
            "None → 默认 30 天保留期"
        );
        assert_eq!(
            cfg.trash_gc_interval_secs,
            Some(TRASH_GC_INTERVAL_SECS),
            "None → 默认 86400s GC 周期"
        );
        // 显式值不被覆盖
        let mut cfg = base();
        cfg.trash_refresh_interval_secs = Some(7);
        cfg.trash_refresh_mode = Some(TrashRefreshMode::Eager);
        cfg.trash_retention_days = Some(7);
        cfg.trash_gc_interval_secs = Some(3600);
        let cfg = cfg.normalize();
        assert_eq!(cfg.trash_refresh_interval_secs, Some(7));
        assert_eq!(cfg.trash_refresh_mode, Some(TrashRefreshMode::Eager));
        assert_eq!(cfg.trash_retention_days, Some(7), "显式保留期不被覆盖");
        assert_eq!(
            cfg.trash_gc_interval_secs,
            Some(3600),
            "显式 GC 周期不被覆盖"
        );
    }

    #[tokio::test]
    async fn stat_returns_cached_entry_without_s3() {
        let fs = test_fs();
        let entry = DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 5,
            mtime_secs: 1,
        };
        // Seed the cache: stat() must return this without touching S3 (the
        // unconfigured client would error if it did).
        fs.stats
            .lock()
            .unwrap()
            .insert("/a.txt".into(), (Instant::now(), entry.clone()));
        let got = fs.stat("/a.txt").await.expect("cached stat");
        assert_eq!(got, Some(entry));
    }

    #[tokio::test]
    async fn stat_misses_cache_and_caches_result() {
        // A missing object returns None and does not cache a hit (stat only
        // caches Some). The unconfigured client returns an error for the
        // HEAD, which surfaces as Err rather than None; this is fine as long
        // as it does not panic. Here we only assert the plumbing: after
        // seeding a stale (expired) entry, stat must not return it and must
        // not leave the cache holding the stale entry past a successful call.
        let fs = test_fs();
        let old = DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 5,
            mtime_secs: 1,
        };
        // Expired entry (cached 1 hour ago).
        fs.stats.lock().unwrap().insert(
            "/a.txt".into(),
            (Instant::now() - Duration::from_secs(3600), old),
        );
        // stat will try S3 and fail (unconfigured client) -> Err, but the
        // expired entry must be ignored, not returned.
        assert!(fs.stat("/a.txt").await.is_err());
    }

    #[test]
    fn stat_cache_invalidate_removes_entry() {
        let fs = test_fs();
        let entry = DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 5,
            mtime_secs: 1,
        };
        fs.stats
            .lock()
            .unwrap()
            .insert("/a.txt".into(), (Instant::now(), entry));
        fs.invalidate_stat("/a.txt");
        assert!(!fs.stats.lock().unwrap().contains_key("/a.txt"));
        fs.invalidate_stat("/never-cached"); // must not panic
    }

    #[test]
    fn stat_cache_evicts_all_when_over_bound() {
        let fs = test_fs();
        let entry = DirEntry {
            name: "f".into(),
            is_dir: false,
            size: 1,
            mtime_secs: 1,
        };
        // Fill the cache to the bound through the real insertion helper.
        for i in 0..MAX_STAT_ENTRIES {
            fs.cache_insert(&format!("/f{i}"), entry.clone());
        }
        assert_eq!(fs.stats.lock().unwrap().len(), MAX_STAT_ENTRIES);
        // One more insert hits the bound branch in cache_insert (clear +
        // keep only the new entry), exactly what stat() would do.
        fs.cache_insert("/overflow", entry.clone());
        let cache = fs.stats.lock().unwrap();
        assert_eq!(cache.len(), MAX_STAT_ENTRIES);
        assert!(!cache.contains_key("/f0"));
        assert!(cache.contains_key("/overflow"));
    }

    #[test]
    fn max_concurrent_requests_default_and_override() {
        assert_eq!(
            effective_max_concurrent_requests(None),
            MAX_CONCURRENT_S3_REQUESTS
        );
        assert_eq!(
            effective_max_concurrent_requests(Some(0)),
            MAX_CONCURRENT_S3_REQUESTS
        );
        assert_eq!(effective_max_concurrent_requests(Some(4)), 4);
    }
}

#[cfg(test)]
mod s3_mock_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Poll `mock.recorded` until `pred` matches or 2s elapse. The abort
    /// issued from a [`StreamingUpload`] drop is spawned async, so assertions
    /// must poll instead of sleeping a fixed interval (#55 review).
    async fn wait_for_recorded(mock: &MockS3, pred: impl Fn(&MockRequest) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if mock.recorded.lock().unwrap().iter().any(&pred) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Minimal in-process S3 mock: counts concurrent in-flight requests,
    /// records request targets + bodies, and serves canned responses so the
    /// AWS SDK can round-trip (ListBucketResult and multipart uploads).
    #[derive(Clone, Debug)]
    pub(crate) struct MockRequest {
        pub(crate) method: String,
        pub(crate) target: String,
        pub(crate) body: Vec<u8>,
        pub(crate) storage_class: Option<String>,
        pub(crate) content_md5: Option<String>,
        pub(crate) copy_source: Option<String>,
        /// `x-amz-checksum-*` / `x-amz-sdk-checksum-algorithm` headers (the
        /// AWS SDK's automatic CRC32 additions, which Aliyun OSS neither
        /// expects nor accepts as a substitute for Content-MD5, #74).
        pub(crate) checksum_headers: Vec<(String, String)>,
    }

    pub(crate) struct MockS3 {
        pub(crate) active: Arc<AtomicUsize>,
        pub(crate) max_concurrent: Arc<AtomicUsize>,
        pub(crate) requests: Arc<Mutex<Vec<String>>>,
        pub(crate) recorded: Arc<Mutex<Vec<MockRequest>>>,
        pub(crate) delay: Duration,
        pub(crate) entries: Arc<Mutex<Vec<(String, bool)>>>,
        pub(crate) objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        /// Per-key sizes for listing (defaults to 5 when absent); lets tests
        /// model objects too large to materialize (e.g. > 5 GiB copies, #60).
        pub(crate) sizes: Arc<Mutex<HashMap<String, u64>>>,
        pub(crate) get_count: Arc<AtomicUsize>,
        pub(crate) head_count: Arc<AtomicUsize>,
        /// Number of GET requests to fail with 500 before succeeding (used
        /// to exercise the SDK retry chain, #43).
        pub(crate) fail_get: AtomicUsize,
        /// Number of DeleteObjects requests to fail with 500 before
        /// succeeding (exercises Content-MD5 recompute across retries, #74).
        pub(crate) fail_delete: AtomicUsize,
        /// Keys reported as failed by DeleteObjects responses (exercises the
        /// partial-failure error path, #60).
        pub(crate) delete_errors: Arc<Mutex<Vec<String>>>,
        pub(crate) crc64: Mutex<u64>,
        pub(crate) head_etag: Mutex<String>,
        /// Per-key etag 覆盖(单元 4:restore/GC 的 etag 一致性判定需要
        /// 模拟「其他端覆盖同名 key」;缺省回退全局 head_etag)。
        pub(crate) etags: Arc<Mutex<HashMap<String, String>>>,
        /// Per-key LastModified(单元 4:目录 GC 的 mtime 启发式需要按对象
        /// 区分 last_modified;PUT/COPY 落地即写当前时间,list/HEAD 分支
        /// 返回,无记录对象缺省当前时间(C1 生产对齐))。
        pub(crate) last_modified: Arc<Mutex<HashMap<String, String>>>,
        /// When non-zero, every HEAD answers with this status (used to
        /// simulate 403/5xx bucket checks; 0 = normal object lookup).
        pub(crate) head_status: std::sync::atomic::AtomicU16,
        /// When set, CompleteMultipartUpload answers 404 NoSuchUpload —
        /// simulating a retry racing an already-completed upload.
        pub(crate) complete_no_such_upload: std::sync::atomic::AtomicBool,
        /// When set, ListObjectsV2 answers `IsTruncated=true` without a
        /// `NextContinuationToken` — the unpaggable partial listing the
        /// client must refuse (#60).
        pub(crate) list_truncated_no_token: std::sync::atomic::AtomicBool,
        /// Number of plain PUT requests to fail with 500 before succeeding
        /// (exercises trash tombstone write failure semantics).
        pub(crate) fail_put: AtomicUsize,
        /// When set, the list branch ignores the `start-after` query param
        /// and returns every key (simulates stores that do not honor it —
        /// the trash refresh must detect and degrade, unit 3).
        pub(crate) ignore_start_after: std::sync::atomic::AtomicBool,
        /// When set, PUT with an If-Match header answers 412 PreconditionFailed
        /// regardless of the stored etag (simulates the GET→PUT window of
        /// `set_recycle_i` being raced by a concurrent restore/permanent-delete
        /// — F8: a conditional write must not resurrect a deleted tombstone).
        pub(crate) force_precondition_failed: std::sync::atomic::AtomicBool,
    }

    impl MockS3 {
        pub(crate) fn set_object(&self, key: &str, data: Vec<u8>) {
            self.objects.lock().unwrap().insert(key.to_string(), data);
        }

        pub(crate) fn set_size(&self, key: &str, size: u64) {
            self.sizes.lock().unwrap().insert(key.to_string(), size);
        }

        fn set_head_etag(&self, v: &str) {
            *self.head_etag.lock().unwrap() = v.to_string();
        }

        /// per-key etag 覆盖(HEAD 该 key 时优先返回;缺省回退 head_etag)。
        /// 值存裸形态(不含引号),HEAD 响应按 S3/OSS 惯例包引号。
        pub(crate) fn set_etag(&self, key: &str, v: &str) {
            self.etags
                .lock()
                .unwrap()
                .insert(key.to_string(), v.to_string());
        }

        /// per-key LastModified(list 分支返回,ISO 8601 字符串;
        /// 目录 GC 的 mtime 启发式消费)。
        pub(crate) fn set_last_modified(&self, key: &str, v: &str) {
            self.last_modified
                .lock()
                .unwrap()
                .insert(key.to_string(), v.to_string());
        }

        fn set_crc64(&self, v: u64) {
            *self.crc64.lock().unwrap() = v;
        }

        pub(crate) async fn start(
            entries: Vec<(String, bool)>,
            delay: Duration,
        ) -> (Arc<Self>, u16) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mock = Arc::new(MockS3 {
                active: Arc::new(AtomicUsize::new(0)),
                max_concurrent: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(Mutex::new(Vec::new())),
                recorded: Arc::new(Mutex::new(Vec::new())),
                delay,
                objects: Arc::new(Mutex::new(HashMap::new())),
                get_count: Arc::new(AtomicUsize::new(0)),
                head_count: Arc::new(AtomicUsize::new(0)),
                fail_get: AtomicUsize::new(0),
                fail_delete: AtomicUsize::new(0),
                delete_errors: Arc::new(Mutex::new(Vec::new())),
                entries: Arc::new(Mutex::new(entries)),
                sizes: Arc::new(Mutex::new(HashMap::new())),
                crc64: Mutex::new(0),
                head_etag: Mutex::new("mock-etag".to_string()),
                etags: Arc::new(Mutex::new(HashMap::new())),
                last_modified: Arc::new(Mutex::new(HashMap::new())),
                head_status: std::sync::atomic::AtomicU16::new(0),
                complete_no_such_upload: std::sync::atomic::AtomicBool::new(false),
                list_truncated_no_token: std::sync::atomic::AtomicBool::new(false),
                fail_put: AtomicUsize::new(0),
                ignore_start_after: std::sync::atomic::AtomicBool::new(false),
                force_precondition_failed: std::sync::atomic::AtomicBool::new(false),
            });
            let server = Arc::clone(&mock);
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(ok) => ok,
                        Err(_) => break,
                    };
                    let mock = Arc::clone(&server);
                    tokio::spawn(async move {
                        handle_conn(stream, mock).await;
                    });
                }
            });
            (mock, port)
        }
    }

    async fn handle_conn(mut stream: TcpStream, mock: Arc<MockS3>) {
        // Read the full HTTP request: headers first, then the Content-Length
        // body (PUT upload-part / complete-multipart carry a payload).
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut header_end = None;
        let mut content_length = 0usize;
        while header_end.is_none() {
            let n = match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
            }
        }
        let head = String::from_utf8_lossy(&buf[..header_end.unwrap()]);
        let mut range_header: Option<String> = None;
        let mut storage_class_header: Option<String> = None;
        let mut content_md5_header: Option<String> = None;
        let mut copy_source_header: Option<String> = None;
        let mut if_match_header: Option<String> = None;
        let mut checksum_headers: Vec<(String, String)> = Vec::new();
        for line in head.lines() {
            let lower = line.to_ascii_lowercase();
            if (lower.starts_with("x-amz-checksum-")
                || lower.starts_with("x-amz-sdk-checksum-algorithm"))
                && let Some((k, v)) = line.split_once(':')
            {
                checksum_headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            if let Some(v) = lower.strip_prefix("range:") {
                range_header = Some(v.trim().to_string());
            }
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if lower.strip_prefix("x-amz-storage-class:").is_some() {
                storage_class_header = line.split_once(':').map(|(_, v)| v.trim().to_string());
            }
            if lower.strip_prefix("content-md5:").is_some() {
                content_md5_header = line.split_once(':').map(|(_, v)| v.trim().to_string());
            }
            if lower.strip_prefix("x-amz-copy-source:").is_some() {
                copy_source_header = line.split_once(':').map(|(_, v)| v.trim().to_string());
            }
            if let Some(v) = lower.strip_prefix("if-match:") {
                if_match_header = Some(v.trim().to_string());
            }
        }
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let query_raw = target.split('?').nth(1).unwrap_or("").to_string();
        // Lowercased for the method/query dispatch below; prefix filtering
        // must use the raw query (percent-decoded) so keys keep their case.
        let query = query_raw.to_lowercase();

        // Read the remaining body bytes.
        let total = header_end.unwrap() + content_length;
        while buf.len() < total {
            let n = match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
        }
        let body = if total <= buf.len() {
            buf[header_end.unwrap()..total].to_vec()
        } else {
            Vec::new()
        };

        let in_flight = mock.active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut cur = mock.max_concurrent.load(Ordering::SeqCst);
        while in_flight > cur {
            match mock.max_concurrent.compare_exchange(
                cur,
                in_flight,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        mock.requests.lock().unwrap().push(target.clone());
        mock.recorded.lock().unwrap().push(MockRequest {
            method: method.clone(),
            target: target.clone(),
            body: body.clone(),
            storage_class: storage_class_header.clone(),
            content_md5: content_md5_header.clone(),
            copy_source: copy_source_header.clone(),
            checksum_headers,
        });

        tokio::time::sleep(mock.delay).await;
        // 模拟的服务端处理（sleep）到此结束，先释放并发槽位再写响应。
        // 若等写完响应再 -1，客户端读到响应即释放限流 permit 放入新请求，
        // 新请求的 +1 会与这里滞后的 -1 重叠，把并发峰值虚记高一档（ flaky ）。
        mock.active.fetch_sub(1, Ordering::SeqCst);

        let mut get_body: Option<Vec<u8>> = None;
        let response = if query.contains("list-type=2") {
            // Honor the `prefix` query param: ObjectFs lists with a prefix
            // (and probes implicit dirs with max_keys=1); returning entries
            // outside the prefix would make list/stat see phantom children.
            let prefix = query_raw
                .split('&')
                .find_map(|kv| kv.strip_prefix("prefix="))
                .unwrap_or("")
                // 系统回收站测试键含 '$'(SDK 查询编码 %24),逐字解码
                .replace("%24", "$")
                .replace("%2F", "/")
                .replace("%20", " ")
                .replace('+', " ");
            // start-after filtering (ListObjectsV2): keys strictly greater
            // than the cursor. The ignore switch simulates stores that do
            // not honor the param (trash refresh degrades, unit 3).
            let start_after: Option<String> = if mock.ignore_start_after.load(Ordering::SeqCst) {
                None
            } else {
                query_raw
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("start-after="))
                    .map(|v| {
                        v.replace("%24", "$")
                            .replace("%2F", "/")
                            .replace("%20", " ")
                            .replace('+', " ")
                    })
            };
            let entries = mock.entries.lock().unwrap().clone();
            // ObjectFs lists without a delimiter; mock entries marked as
            // directories then surface as plain (marker) objects in
            // Contents, like real S3/OSS. Requests with a delimiter would
            // fold them into CommonPrefixes instead.
            let use_delimiter = query.contains("delimiter=");
            let filtered: Vec<(String, bool)> = entries
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .filter(|(k, _)| start_after.as_deref().is_none_or(|sa| k.as_str() > sa))
                .collect();
            let sizes = mock.sizes.lock().unwrap().clone();
            let last_modified = mock.last_modified.lock().unwrap().clone();
            let truncated = mock.list_truncated_no_token.load(Ordering::SeqCst);
            let body = list_xml(
                &filtered,
                &sizes,
                &last_modified,
                truncated,
                use_delimiter,
                &prefix,
            );
            http_response(200, "application/xml", Some(&format!("{body}")))
        } else if method == "GET" {
            mock.get_count.fetch_add(1, Ordering::SeqCst);
            if mock.fail_get.load(Ordering::SeqCst) > 0 {
                mock.fail_get.fetch_sub(1, Ordering::SeqCst);
                let body = "<Error><Code>InternalError</Code><Message>mock</Message></Error>";
                http_response(500, "application/xml", Some(&body.to_string()))
            } else {
                let path = target.split('?').next().unwrap_or(&target);
                let key = path
                    .trim_start_matches('/')
                    .split_once('/')
                    .map(|(_, k)| k.to_string())
                    // 生产对齐:SDK 路径编码 %24(SDK 对非保留字符转义;
                    // 真实 S3 先解码再寻址,同 list 分支口径)。系统回收站
                    // 键含 '$',GET/HEAD/DELETE 不经此解码会查不到对象。
                    .map(|k| k.replace("%24", "$"))
                    .unwrap_or_default();
                let objects = mock.objects.lock().unwrap();
                match objects.get(&key) {
                    Some(object) => {
                        let len = object.len();
                        let (start, end) = match &range_header {
                            Some(range) => {
                                let range = range.trim().strip_prefix("bytes=").unwrap_or(range);
                                match range.split_once('-') {
                                    Some((start, end)) => {
                                        let start = start.parse::<usize>().unwrap_or(0).min(len);
                                        let end = end
                                            .parse::<usize>()
                                            .ok()
                                            .map(|e| e + 1)
                                            .unwrap_or(len)
                                            .min(len)
                                            .max(start);
                                        (start, end)
                                    }
                                    None => (0, len),
                                }
                            }
                            None => (0, len),
                        };
                        get_body = Some(object[start..end].to_vec());
                        // per-key etag 覆盖(同 HEAD 分支口径;read_tombstone_
                        // with_etag 的条件写 F8 依赖 GET 响应带 ETag)。
                        let etag = mock
                            .etags
                            .lock()
                            .unwrap()
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| mock.head_etag.lock().unwrap().clone());
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nETag: \"{etag}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            end - start
                        )
                    }
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                }
            }
        } else if query.contains("uploads") && !query.contains("uploadid") {
            // InitiateMultipartUpload: POST /key?uploads
            let body = initiate_multipart_xml();
            http_response(200, "application/xml", Some(&body))
        } else if query.contains("uploadid") && query.contains("partnumber") {
            // UploadPart / UploadPartCopy: PUT /key?partNumber=N&uploadId=...
            // Answer a CopyPartResult when a copy-source header is present so
            // the SDK's etag extraction path is exercised (#71 review).
            if copy_source_header.is_some() {
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyPartResult><ETag>&quot;etag-part&quot;</ETag><LastModified>2026-01-01T00:00:00.000Z</LastModified></CopyPartResult>";
                http_response(200, "application/xml", Some(&body.to_string()))
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nETag: \"etag-{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    "mock"
                )
            }
        } else if query.contains("uploadid") && method == "DELETE" {
            // AbortMultipartUpload
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        } else if query.contains("uploadid") && method == "POST" {
            // CompleteMultipartUpload
            if mock.complete_no_such_upload.load(Ordering::SeqCst) {
                let body = "<Error><Code>NoSuchUpload</Code>\
                            <Message>The specified upload does not exist. \
                            The upload may have already been completed.</Message></Error>";
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                let crc = *mock.crc64.lock().unwrap();
                let body = complete_multipart_xml();
                format!(
                    "HTTP/1.1 200 OK\r\nx-oss-hash-crc64ecma: {crc}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
        } else if query.contains("delete") && method == "POST" {
            // DeleteObjects: mirror Aliyun OSS's DeleteMultipleObjects
            // contract — Content-MD5 is mandatory; without it the real OSS
            // answers 400 InvalidDigest and the batch is a no-op (#74). The
            // AWS SDK's automatic CRC32 checksum headers do not satisfy it.
            if mock.fail_delete.load(Ordering::SeqCst) > 0 {
                mock.fail_delete.fetch_sub(1, Ordering::SeqCst);
                let body = "<Error><Code>InternalError</Code><Message>mock</Message></Error>";
                http_response(500, "application/xml", Some(&body.to_string()))
            } else if content_md5_header.is_none() {
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidDigest</Code><Message>The Content-MD5 you specified was invalid.</Message></Error>".to_string();
                http_response(400, "application/xml", Some(&body))
            } else {
                // 真实删除:解析 <Key> 列表并从 objects/entries 移除
                // (mock 服务端语义必须与生产对齐 —— GC 批删测试断言删除
                // 效果;单元 2 前置扩展只断言请求形状,未暴露此缺口)。
                // 失败 keys(delete_errors 配置)不删,与真实 OSS 一致。
                let text = String::from_utf8_lossy(&body).to_string();
                let mut keys: Vec<String> = Vec::new();
                let mut rest = text.as_str();
                while let Some(start) = rest.find("<Key>") {
                    let key_start = start + "<Key>".len();
                    let Some(end) = rest[key_start..].find("</Key>") else {
                        break;
                    };
                    keys.push(rest[key_start..key_start + end].to_string());
                    rest = &rest[key_start + end + "</Key>".len()..];
                }
                let errors = mock.delete_errors.lock().unwrap();
                {
                    let mut objects = mock.objects.lock().unwrap();
                    let mut entries = mock.entries.lock().unwrap();
                    for key in &keys {
                        if errors.iter().any(|e| e == key) {
                            continue; // 配置的失败 keys 不删
                        }
                        objects.remove(key);
                        entries.retain(|(k, _)| k != key);
                    }
                }
                // Answer a result listing any configured failures.
                let mut body =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult>".to_string();
                for key in errors.iter() {
                    body.push_str(&format!(
                        "<Error><Key>{key}</Key><Code>AccessDenied</Code><Message>mock</Message></Error>"
                    ));
                }
                body.push_str("</DeleteResult>");
                http_response(200, "application/xml", Some(&body))
            }
        } else if method == "HEAD" {
            mock.head_count.fetch_add(1, Ordering::SeqCst);
            let forced = mock.head_status.load(Ordering::SeqCst);
            if forced != 0 {
                format!(
                    "HTTP/1.1 {forced} Forced\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                let path = target.split('?').next().unwrap_or(&target);
                let key = path
                    .trim_start_matches('/')
                    .split_once('/')
                    .map(|(_, k)| k.to_string())
                    // 生产对齐:SDK 路径编码 %24(SDK 对非保留字符转义;
                    // 真实 S3 先解码再寻址,同 list 分支口径)。系统回收站
                    // 键含 '$',GET/HEAD/DELETE 不经此解码会查不到对象。
                    .map(|k| k.replace("%24", "$"))
                    .unwrap_or_default();
                let objects = mock.objects.lock().unwrap();
                if let Some(obj) = objects.get(&key) {
                    // per-key etag 覆盖(单元 4 restore/GC 判定),缺省回退
                    // 全局 head_etag;Last-Modified 头同 per-key(无则省略,
                    // SDK 解析失败也仅 mtime 归零,无行为影响)。
                    let etag = mock
                        .etags
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| mock.head_etag.lock().unwrap().clone());
                    let lm = mock
                        .last_modified
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .map(|v| {
                            // last_modified 存储为 ISO 8601(list XML 用);
                            // HEAD 的 Last-Modified 头必须 HTTP-date 形态
                            // (RFC 7231),SDK 解析失败是硬错误而非 mtime
                            // 归零 —— PUT 落地记 last_modified 后 HEAD
                            // 路径必须给出可解析的头。
                            chrono::DateTime::parse_from_rfc3339(&v)
                                .map(|dt| {
                                    format!(
                                        "\r\nLast-Modified: {}",
                                        dt.format("%a, %d %b %Y %H:%M:%S GMT")
                                    )
                                })
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: \"{etag}\"{lm}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        obj.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                }
            }
        } else {
            // Plain PutObject / DeleteObject / CopyObject / ... — really
            // store/remove so multi-step flows (trash soft delete: HEAD →
            // PUT tombstone → verify original survives) observe a coherent
            // store. CopyObject materializes the copy when the source object
            // exists; tests that rename without seeding data keep the old
            // no-op 200 (their assertions only cover recorded requests).
            let path = target.split('?').next().unwrap_or(&target);
            let key = path
                .trim_start_matches('/')
                .split_once('/')
                .map(|(_, k)| k.to_string())
                // 生产对齐:SDK 路径编码 %24(见 GET/HEAD 分支注释)
                .map(|k| k.replace("%24", "$"))
                .unwrap_or_default();
            if method == "PUT" {
                if let Some(src) = &copy_source_header {
                    // x-amz-copy-source: /bucket/percent-encoded-key
                    let src_key = src
                        .trim_start_matches('/')
                        .split_once('/')
                        .map(|(_, k)| percent_decode(k))
                        .unwrap_or_default();
                    let data = mock.objects.lock().unwrap().get(&src_key).cloned();
                    if let Some(data) = data {
                        mock.objects.lock().unwrap().insert(key.clone(), data);
                        // 生产对齐(C1):COPY 落地即记当前时间 last_modified,
                        // 与真实 S3 一致(目录 GC mtime 启发式的判据)。
                        mock.last_modified
                            .lock()
                            .unwrap()
                            .insert(key.clone(), mock_now_lm());
                        let mut entries = mock.entries.lock().unwrap();
                        if !entries.iter().any(|(k, _)| *k == key) {
                            entries.push((key, false));
                        }
                        drop(entries);
                    }
                    let crc = *mock.crc64.lock().unwrap();
                    format!(
                        "HTTP/1.1 200 OK\r\nx-oss-hash-crc64ecma: {crc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else if mock.fail_put.load(Ordering::SeqCst) > 0 {
                    mock.fail_put.fetch_sub(1, Ordering::SeqCst);
                    let body = "<Error><Code>InternalError</Code><Message>mock</Message></Error>";
                    http_response(500, "application/xml", Some(&body.to_string()))
                } else if let Some(im) = &if_match_header {
                    // if-match 条件写(F8:set_recycle_i 的「无墓碑不复活」):
                    // etag 失配或对象缺失 → 412 PreconditionFailed;force 开关
                    // 模拟 GET→PUT 窗口内的并发删除/改写。真实 S3/OSS 对
                    // If-Match 条件 PUT 返回 412(对象缺失同样 412)。
                    let etag = mock
                        .etags
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| mock.head_etag.lock().unwrap().clone());
                    let matched = !mock.force_precondition_failed.load(Ordering::SeqCst)
                        && mock.objects.lock().unwrap().contains_key(&key)
                        && etag == im.trim_matches('"');
                    if matched {
                        mock.objects
                            .lock()
                            .unwrap()
                            .insert(key.clone(), body.clone());
                        mock.last_modified
                            .lock()
                            .unwrap()
                            .insert(key.clone(), mock_now_lm());
                        let mut entries = mock.entries.lock().unwrap();
                        if !entries.iter().any(|(k, _)| *k == key) {
                            entries.push((key, false));
                        }
                        drop(entries);
                        let crc = *mock.crc64.lock().unwrap();
                        format!(
                            "HTTP/1.1 200 OK\r\nx-oss-hash-crc64ecma: {crc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else {
                        let body = "<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message></Error>";
                        format!(
                            "HTTP/1.1 412 Precondition Failed\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                } else {
                    mock.objects
                        .lock()
                        .unwrap()
                        .insert(key.clone(), body.clone());
                    // 生产对齐(C1):PUT 落地即记当前时间 last_modified ——
                    // 墓碑目录下新写入的对象必须被判「新数据」,不得被目录
                    // GC 的 mtime 启发式误删;显式 set_last_modified 覆盖。
                    mock.last_modified
                        .lock()
                        .unwrap()
                        .insert(key.clone(), mock_now_lm());
                    let mut entries = mock.entries.lock().unwrap();
                    if !entries.iter().any(|(k, _)| *k == key) {
                        entries.push((key, false));
                    }
                    drop(entries);
                    let crc = *mock.crc64.lock().unwrap();
                    format!(
                        "HTTP/1.1 200 OK\r\nx-oss-hash-crc64ecma: {crc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                }
            } else if method == "DELETE" {
                mock.objects.lock().unwrap().remove(&key);
                mock.entries.lock().unwrap().retain(|(k, _)| *k != key);
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            } else {
                let crc = *mock.crc64.lock().unwrap();
                format!(
                    "HTTP/1.1 200 OK\r\nx-oss-hash-crc64ecma: {crc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        };
        let _ = stream.write_all(response.as_bytes()).await;
        if let Some(body) = get_body {
            let _ = stream.write_all(&body).await;
        }
        let _ = stream.shutdown().await;
    }

    /// Percent-decode a URL-escaped S3 key (%XX hex; '+' → space).
    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let (Some(h), Some(l)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                )
            {
                out.push((h * 16 + l) as u8);
                i += 3;
            } else {
                out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn http_response(status: u16, content_type: &str, body: Option<&String>) -> String {
        let body = body.cloned().unwrap_or_default();
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn initiate_multipart_xml() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>bucket</Bucket><Key>key</Key><UploadId>mock-upload-1</UploadId></InitiateMultipartUploadResult>"
            .to_string()
    }

    fn complete_multipart_xml() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>http://127.0.0.1/bucket/key</Location><Bucket>bucket</Bucket><Key>key</Key><ETag>&quot;mock&quot;</ETag></CompleteMultipartUploadResult>"
            .to_string()
    }

    /// 当前 UTC 时间的 last_modified 字符串(ISO 8601 毫秒,与
    /// set_last_modified 的既有形态一致)。mock 服务端语义对齐生产(C1):
    /// PUT/COPY 落地写当前时间;list 对无记录对象缺省当前时间 —— 避免
    /// 恒早于墓碑日期的假时间把新对象误判为「过期可删」(目录 GC mtime
    /// 启发式)。
    fn mock_now_lm() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    fn list_xml(
        entries: &[(String, bool)],
        sizes: &HashMap<String, u64>,
        last_modified: &HashMap<String, String>,
        truncated_no_token: bool,
        use_delimiter: bool,
        prefix: &str,
    ) -> String {
        // 无记录对象缺省当前时间(生产对齐,C1:对象总是「已存在」,
        // 绝非 2026-01-01 的远古时间)。
        let default_lm = mock_now_lm();
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        body.push_str("<Name>bucket</Name><Prefix></Prefix>");
        // delimiter 语义与真实 S3 对齐(裁决 #10 分区枚举的依赖):带
        // delimiter 时按「前缀之后第一个分隔符」折叠 CommonPrefixes
        // (去重、升序),仅直接子项进 Contents;目录标记 key 本身就是
        // 其公共前缀,折叠行为与旧实现一致。不带 delimiter(如何 ObjectFs
        // 的 max_keys 探测)时标记是普通零字节对象。
        if use_delimiter {
            let mut common: Vec<String> = Vec::new();
            let mut direct: Vec<&(String, bool)> = Vec::new();
            for e in entries {
                let rest = e.0.strip_prefix(prefix).unwrap_or(&e.0);
                match rest.find('/') {
                    Some(idx) => {
                        let cp = format!("{prefix}{}", &rest[..=idx]);
                        if !common.contains(&cp) {
                            common.push(cp);
                        }
                    }
                    None => direct.push(e),
                }
            }
            common.sort_unstable();
            body.push_str(&format!(
                "<KeyCount>{}</KeyCount>",
                common.len() + direct.len()
            ));
            body.push_str("<MaxKeys>1000</MaxKeys><IsTruncated>");
            body.push_str(if truncated_no_token { "true" } else { "false" });
            body.push_str("</IsTruncated>");
            for cp in &common {
                body.push_str(&format!(
                    "<CommonPrefixes><Prefix>{cp}</Prefix></CommonPrefixes>"
                ));
            }
            for (key, _) in direct {
                let size = sizes.get(key).copied().unwrap_or(5);
                let lm = last_modified
                    .get(key)
                    .map(String::as_str)
                    .unwrap_or(default_lm.as_str());
                body.push_str(&format!(
                    "<Contents><Key>{key}</Key><LastModified>{lm}</LastModified><ETag>&quot;mock&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>"
                ));
            }
        } else {
            body.push_str(&format!("<KeyCount>{}</KeyCount>", entries.len()));
            body.push_str("<MaxKeys>1000</MaxKeys><IsTruncated>");
            body.push_str(if truncated_no_token { "true" } else { "false" });
            body.push_str("</IsTruncated>");
            for (key, _) in entries {
                // Without a delimiter a directory marker is an ordinary
                // zero-byte object in Contents, matching real S3/OSS
                // semantics (#60 review).
                let size = sizes.get(key).copied().unwrap_or(5);
                let lm = last_modified
                    .get(key)
                    .map(String::as_str)
                    .unwrap_or(default_lm.as_str());
                body.push_str(&format!(
                    "<Contents><Key>{key}</Key><LastModified>{lm}</LastModified><ETag>&quot;mock&quot;</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>"
                ));
            }
        }
        body.push_str("</ListBucketResult>");
        body
    }

    pub(crate) fn test_fs(port: u16, limit: usize) -> ObjectFs {
        test_fs_with_budget(port, limit, None)
    }

    pub(crate) fn test_fs_with_budget(
        port: u16,
        limit: usize,
        max_dirty_bytes: Option<usize>,
    ) -> ObjectFs {
        let client = Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .endpoint_url(format!("http://127.0.0.1:{port}"))
                .force_path_style(true)
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "ak", "sk", None, None, "test",
                ))
                .behavior_version(BehaviorVersion::latest())
                .build(),
        );
        ObjectFs {
            client,
            bucket: "b".into(),
            prefix: String::new(),
            stats: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
            limiter: Arc::new(Semaphore::new(limit)),
            read_only: false,
            allow_other: false,
            list_rate: None,
            mount_attr: MountAttr::default(),
            allow_rename_dir: true,
            rename_dir_limit: None,
            upload_budget: None,
            upload_budget_units: 0,
            read_ahead_window: 0,
            read_cache: Mutex::new(ReadCache::default()),
            read_cache_max_bytes: READ_CACHE_MAX_BYTES,
            disk_cache: None,
            disk_cache_prefetch_blocks: 1,
            prefetch_inflight: Arc::new(Mutex::new(HashSet::new())),
            prefetch_sem: Arc::new(Semaphore::new(DISK_CACHE_PREFETCH_CONCURRENCY)),
            disk_cache_verify_etag: false,
            etag_checked: Mutex::new(HashMap::new()),
            etag_ttl: ETAG_CHECK_TTL,
            negative_ttl: NEGATIVE_CACHE_TTL,
            stat_ttl: STAT_TTL,
            negative_max_entries: MAX_NEGATIVE_ENTRIES,
            stat_max_entries: MAX_STAT_ENTRIES,
            read_seq: Mutex::new(HashMap::new()),
            ignore_fsync: true,
            verify_crc64: false,
            storage_class: None,
            content_md5: false,
            notsup_compat_dir: false,
            multipart_part_size: MULTIPART_PART_SIZE as usize,
            multipart_concurrency: MULTIPART_UPLOAD_CONCURRENCY,
            metrics: Arc::new(Metrics::default()),
            dirty_budget: DirtyBudget::new(max_dirty_bytes.unwrap_or(0)),
            operation_timeout: std::time::Duration::from_secs(60),
            trash: None,
            trash_refresh_started: AtomicBool::new(false),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_rejects_subtree_move() {
        // #46: rename("/a", "/a/b") would copy the tree then recursively
        // delete the freshly copied subtree — wipe both. Must fail; a no-op
        // self-rename succeeds (POSIX).
        let (mock, port) = MockS3::start(Vec::new(), Duration::ZERO).await;
        let fs = test_fs(port, 32);
        let err = fs
            .rename("/a", "/a/b", true)
            .await
            .expect_err("subtree rename must fail");
        assert!(
            err.to_string().contains("subtree"),
            "unexpected error: {err:?}"
        );
        fs.rename("/a", "/a", true)
            .await
            .expect("self-rename is a no-op");
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            0,
            "no S3 traffic for rejected/no-op renames"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_honors_replace_if_exists() {
        // #46: without replace the target must not be clobbered; with it,
        // the rename proceeds.
        let (mock, port) = MockS3::start(Vec::new(), Duration::ZERO).await;
        let fs = test_fs(port, 32);
        mock.set_object("a", b"old-a".to_vec());
        mock.set_object("b", b"old-b".to_vec());

        let err = fs
            .rename("/a", "/b", false)
            .await
            .expect_err("existing target without replace must fail");
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err:?}"
        );
        // Only the existence-check HEAD may have hit the wire; no copy.
        assert!(
            !mock
                .recorded
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.copy_source.is_some()),
            "no copy for a rejected rename"
        );

        fs.rename("/a", "/b", true)
            .await
            .expect("replace=true must succeed");
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "PUT" && r.copy_source.is_some()),
            "a copy request must have been issued"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_special_char_key_uses_encoded_copy_source() {
        // #46: keys with spaces / reserved characters must be RFC 3986
        // encoded in x-amz-copy-source, or the rename fails / targets the
        // wrong object.
        let (mock, port) = MockS3::start(Vec::new(), Duration::ZERO).await;
        let fs = test_fs(port, 32);
        mock.set_object("a b.txt", b"data".to_vec());

        fs.rename("/a b.txt", "/a c.txt", true)
            .await
            .expect("rename with space in key");

        let recorded = mock.recorded.lock().unwrap();
        let copy = recorded
            .iter()
            .find(|r| r.method == "PUT" && r.copy_source.is_some())
            .expect("a copy request must have been issued");
        assert_eq!(
            copy.copy_source.as_deref(),
            Some("/b/a%20b.txt"),
            "copy-source must be percent-encoded"
        );
    }

    #[test]
    fn s3_copy_source_encodes_reserved_chars() {
        assert_eq!(s3_copy_source("b", "plain.txt"), "/b/plain.txt");
        assert_eq!(
            s3_copy_source("b", "a b+%#中"),
            "/b/a%20b%2B%25%23%E4%B8%AD"
        );
        assert_eq!(s3_copy_source("b", "dir/file.txt"), "/b/dir/file.txt");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_dir_disabled_rejects_directory_rename() {
        let entries = vec![("dir/a.txt".to_string(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(0)).await;
        let mut fs = test_fs(port, 8);
        fs.allow_rename_dir = false;
        let err = fs.rename("/dir", "/newdir", true).await.unwrap_err();
        assert!(err.to_string().contains("directory rename is disabled"));
        drop(mock);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_dir_limit_exceeded_rejects_before_copy() {
        let entries = vec![
            ("dir/a.txt".to_string(), false),
            ("dir/b.txt".to_string(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(0)).await;
        let mut fs = test_fs(port, 8);
        fs.rename_dir_limit = Some(1);
        let err = fs.rename("/dir", "/newdir", true).await.unwrap_err();
        assert!(err.to_string().contains("rename-dir-limit"));
        drop(mock);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn list_concurrency_is_bounded_by_limiter() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(30)).await;
        let fs = Arc::new(test_fs(port, 2));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let fs = Arc::clone(&fs);
            handles.push(tokio::spawn(async move { fs.list("/").await }));
        }
        for h in handles {
            assert!(h.await.unwrap().is_ok(), "list failed");
        }
        let max = mock.max_concurrent.load(Ordering::SeqCst);
        assert!(
            max <= 2,
            "limiter not honored: observed {max} concurrent S3 requests with limit 2"
        );
        assert!(
            max >= 2,
            "test is vacuous: never saw concurrency ({max}), mock/delay broken?"
        );
    }

    #[tokio::test]
    async fn list_rate_limit_throttles_recursive_walk() {
        let (mock, port) =
            MockS3::start(vec![("docs/a.txt".into(), false)], Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.list_rate = Some(Mutex::new(TokenBucket::new(2.0)));

        // Burst capacity is 2; the 3rd list must wait and therefore count as
        // throttled. The limiter delays but never drops, so all 3 requests
        // still reach the mock.
        for _ in 0..3 {
            fs.list("/docs").await.expect("list");
        }
        let throttled = fs.metrics().list_throttled;
        assert!(
            throttled >= 1,
            "expected at least one throttled list, got {throttled}"
        );
        assert_eq!(mock.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn stat_probes_implied_dir_with_max_keys_1() {
        let (mock, port) = MockS3::start(
            vec![("implied/f.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);
        let got = fs.stat("/implied").await.expect("stat");
        let entry = got.expect("implied directory should exist via probe");
        assert!(entry.is_dir, "probe must report an implied directory");
        let reqs = mock.requests.lock().unwrap();
        let list_reqs: Vec<&String> = reqs
            .iter()
            .filter(|t| t.to_lowercase().contains("list-type=2"))
            .collect();
        assert!(!list_reqs.is_empty(), "expected a probe LIST request");
        assert!(
            list_reqs
                .iter()
                .any(|t| t.to_lowercase().contains("max-keys=1")),
            "probe must use max_keys=1, got: {list_reqs:?}"
        );
    }

    #[tokio::test]
    async fn stat_missing_path_returns_none_via_probe() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let got = fs.stat("/nope").await.expect("stat");
        assert!(got.is_none(), "missing path must be None");
        assert!(!mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stat_trailing_slash_finds_implied_dir() {
        // Regression (#60): `stat("/a")` found an implied directory while
        // `stat("/a/")` — the same directory — returned None.
        let (_mock, port) = MockS3::start(
            vec![("implied/f.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);
        let got = fs.stat("/implied/").await.expect("stat");
        let entry = got.expect("trailing-slash stat must find the implied dir");
        assert!(entry.is_dir);
        assert_eq!(entry.name, "implied");
    }

    #[tokio::test]
    async fn stat_counts_each_issued_request() {
        // Regression (#60): a miss that falls through to the marker HEAD and
        // the prefix probe used to count a single HEAD.
        let (_mock, port) = MockS3::start(
            vec![("implied/f.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);
        assert!(fs.stat("/").await.expect("stat root").is_some());
        let m = fs.metrics();
        assert_eq!(m.s3_heads, 0, "root stat is local and issues no request");

        let entry = fs
            .stat("/implied")
            .await
            .expect("stat")
            .expect("implied dir");
        assert!(entry.is_dir);
        let m = fs.metrics();
        assert_eq!(m.s3_heads, 2, "initial HEAD + marker HEAD");
        assert_eq!(m.s3_stat_heads, 2);
        assert_eq!(m.s3_lists, 1, "prefix probe counts as a list");
    }

    #[tokio::test]
    async fn list_truncated_without_continuation_token_errors() {
        // Regression (#60): a truncated listing without a continuation token
        // was returned as a successful partial result (silent missing
        // readdir entries).
        let (mock, port) =
            MockS3::start(vec![("a.txt".into(), false)], Duration::from_millis(1)).await;
        mock.list_truncated_no_token.store(true, Ordering::SeqCst);
        let fs = test_fs(port, 32);
        let err = fs.list("/").await.unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn delete_dir_recursive_truncated_without_token_errors() {
        // Regression (#60): a partial delete must not report success while
        // objects remain under the prefix.
        let (mock, port) =
            MockS3::start(vec![("dir/a.txt".into(), false)], Duration::from_millis(1)).await;
        mock.list_truncated_no_token.store(true, Ordering::SeqCst);
        let fs = test_fs(port, 32);
        let err = fs.delete_dir_recursive("/dir").await.unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
    }

    /// #59 happy path: delete_dir_recursive removes every object under the
    /// prefix plus the directory marker. The mock never mutates its object
    /// store on DELETE, so the assertions check the issued DELETE targets.
    /// Without a delimiter (how ObjectFs lists) directory markers are
    /// ordinary objects in Contents and are covered by the batch delete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_removes_tree_and_marker() {
        let (mock, port) = MockS3::start(
            vec![
                ("dir/".into(), true),
                ("dir/a.txt".into(), false),
                ("dir/sub/".into(), true),
                ("dir/sub/b.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);

        fs.delete_dir_recursive("/dir")
            .await
            .expect("recursive delete");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        // Without a delimiter, directory markers are ordinary objects in
        // the listing, so the batch delete covers them too; the trailing
        // plain DELETE is a redundant 404 no-op kept for safety.
        let batch = recorded
            .iter()
            .find(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .expect("objects must be deleted via a batch delete");
        let body = String::from_utf8_lossy(&batch.body);
        for key in ["dir/", "dir/a.txt", "dir/sub/", "dir/sub/b.txt"] {
            assert!(
                body.contains(key),
                "batch delete body must contain {key}: {body}"
            );
        }
        let plain_deletes = recorded.iter().filter(|r| r.method == "DELETE").count();
        assert_eq!(
            plain_deletes, 1,
            "trailing marker DELETE stays a plain delete"
        );
    }

    /// #74 regression: Aliyun OSS's DeleteMultipleObjects requires
    /// Content-MD5. aws-sdk-s3's automatic CRC32 checksum
    /// (behavior-version-latest) does not send it, so the real OSS rejected
    /// the batch with 400, the directory marker survived, and a freshly
    /// created folder reappeared after refresh ("新建文件夹删不掉"). The batch
    /// must carry Content-MD5 over the exact serialized body — and no
    /// `x-amz-checksum-*` headers at all. The mock enforces the OSS gate, so
    /// this test fails outright on the pre-fix request shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_sends_oss_content_md5() {
        let (mock, port) =
            MockS3::start(vec![("dir/".into(), true)], Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        fs.delete_dir_recursive("/dir")
            .await
            .expect("batch delete must pass the OSS Content-MD5 gate");

        let recorded = mock.recorded.lock().unwrap();
        let lc = |t: &str| t.to_lowercase();
        let batch = recorded
            .iter()
            .find(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .expect("objects must be deleted via a batch delete");
        let md5 = content_md5(&batch.body);
        assert_eq!(
            batch.content_md5.as_deref(),
            Some(md5.as_str()),
            "Content-MD5 must be the base64 md5 of the exact serialized body"
        );
        for (name, _) in &batch.checksum_headers {
            assert!(
                !name.starts_with("x-amz-checksum-") && !name.starts_with("x-amz-sdk-checksum-"),
                "SDK automatic checksum headers must not reach OSS: {name}"
            );
        }
    }

    /// #74: the interceptor runs per attempt in `modify_before_signing`, so
    /// a retried batch must carry the identical Content-MD5 on every attempt
    /// (the SDK rewinds the serialized body between attempts). The raw
    /// config Builder ships no retries, so they are enabled explicitly like
    /// the #43 retry tests do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_content_md5_survives_retry() {
        let (mock, port) =
            MockS3::start(vec![("dir/".into(), true)], Duration::from_millis(1)).await;
        mock.fail_delete.store(1, Ordering::SeqCst); // first batch answers 500
        let mut fs = test_fs(port, 32);
        fs.client = Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .endpoint_url(format!("http://127.0.0.1:{port}"))
                .force_path_style(true)
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "ak", "sk", None, None, "test",
                ))
                .behavior_version(BehaviorVersion::latest())
                .retry_config(aws_smithy_types::retry::RetryConfig::standard())
                .build(),
        );

        fs.delete_dir_recursive("/dir")
            .await
            .expect("recursive delete must survive a transient 500");

        let recorded = mock.recorded.lock().unwrap();
        let lc = |t: &str| t.to_lowercase();
        let batches: Vec<_> = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .collect();
        assert_eq!(
            batches.len(),
            2,
            "a 500 on the first attempt must be retried"
        );
        for (i, batch) in batches.iter().enumerate() {
            let md5 = content_md5(&batch.body);
            assert_eq!(
                batch.content_md5.as_deref(),
                Some(md5.as_str()),
                "attempt {i} must carry the correct Content-MD5"
            );
            assert!(
                batch.checksum_headers.is_empty(),
                "attempt {i} must carry no checksum headers: {:?}",
                batch.checksum_headers
            );
        }
    }

    /// #59 happy path: delete() issues exactly one DELETE for the object.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_removes_single_object() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        fs.delete("/single.txt")
            .await
            .expect("delete single object");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "single DELETE for a single object");
        assert_eq!(recorded[0].method, "DELETE");
        assert!(
            recorded[0].target.contains("/single.txt"),
            "target must be the object key: {}",
            recorded[0].target
        );
    }

    /// #60: >1000 keys are deleted in multiple DeleteObjects requests
    /// (S3's per-request cap).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_chunks_over_1000_keys() {
        let entries: Vec<(String, bool)> = (0..1001)
            .map(|i| (format!("dir/f{i:04}.bin"), false))
            .collect();
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        fs.delete_dir_recursive("/dir")
            .await
            .expect("recursive delete");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        let batches = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .count();
        assert_eq!(
            batches, 2,
            "1001 keys must be split into two DeleteObjects requests"
        );
        let batch_bodies: usize = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .map(|r| String::from_utf8_lossy(&r.body).matches("<Key>").count())
            .sum();
        assert_eq!(batch_bodies, 1001, "all keys must be in the batch bodies");
    }

    /// #60: a partially-failing DeleteObjects must surface an error instead
    /// of silently reporting success.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_reports_batch_failures() {
        let (mock, port) = MockS3::start(
            vec![
                ("dir/".into(), true),
                ("dir/a.txt".into(), false),
                ("dir/b.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        mock.delete_errors
            .lock()
            .unwrap()
            .push("dir/a.txt".to_string());
        let fs = test_fs(port, 32);

        let err = fs
            .delete_dir_recursive("/dir")
            .await
            .expect_err("a partially-failing batch delete must error");
        assert!(
            err.to_string().contains("batch delete failed"),
            "unexpected error: {err:?}"
        );
    }

    /// #60: delete_dir_recursive batches keys through DeleteObjects (one
    /// request, `?delete`) instead of one DELETE per object.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_dir_recursive_uses_batch_delete() {
        let (mock, port) = MockS3::start(
            vec![
                ("dir/".into(), true),
                ("dir/a.txt".into(), false),
                ("dir/b.txt".into(), false),
                ("dir/c.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);

        fs.delete_dir_recursive("/dir")
            .await
            .expect("recursive delete");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        let batch = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .collect::<Vec<_>>();
        assert_eq!(
            batch.len(),
            1,
            "objects must be deleted in one DeleteObjects request: {recorded:?}"
        );
        let body = String::from_utf8_lossy(&batch[0].body);
        for key in ["dir/a.txt", "dir/b.txt", "dir/c.txt"] {
            assert!(
                body.contains(key),
                "DeleteObjects body must contain {key}: {body}"
            );
        }
        // The marker itself is still a plain DELETE (one request).
        assert_eq!(
            recorded.iter().filter(|r| r.method == "DELETE").count(),
            1,
            "the directory marker is deleted with a plain DELETE"
        );
    }

    /// #43: the operation timeout caps the *whole* request including its
    /// retry chain. A failing (500) request must not burn attempts × read
    /// timeout; the SDK must give up as soon as the operation budget is
    /// exhausted, so the limiter permit / part slot it holds is freed
    /// promptly. Without the operation timeout the retry chain would retry
    /// the 500 until it succeeds (3 attempts here); with it, only the first
    /// attempt fits in the budget.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn operation_timeout_cuts_off_retry_chain() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(500)).await;
        mock.fail_get.store(3, Ordering::SeqCst); // first 3 GETs fail with 500
        let mut fs = test_fs(port, 32);
        // 1s read + operation budget: attempt 1 (~0.5s) fails with 500; the
        // retry backoff would exceed the remaining operation budget, so the
        // SDK must give up without a second attempt.
        fs.client = Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .endpoint_url(format!("http://127.0.0.1:{port}"))
                .force_path_style(true)
                .region(aws_sdk_s3::config::Region::new("cn-shanghai"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "ak", "sk", None, None, "test",
                ))
                .behavior_version(aws_config::BehaviorVersion::latest())
                .retry_config(aws_smithy_types::retry::RetryConfig::standard())
                .timeout_config(s3_timeout_config(Some(10), Some(1)))
                .build(),
        );

        let started = std::time::Instant::now();
        let err = fs
            .read_range("/stall.bin", 0, 16)
            .await
            .expect_err("a stalled request must fail within the operation budget");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(4),
            "operation must give up within the operation budget, took {:?}",
            started.elapsed()
        );
        let attempts = mock.get_count.load(Ordering::SeqCst);
        assert!(
            attempts < 3,
            "retry chain must be cut by the operation budget, got {attempts} GET attempts: {err}"
        );
    }

    /// #60: objects at or above the 5 GiB single-copy cap are copied via
    /// multipart copy (upload_part_copy chunks), smaller ones via a single
    /// copy_object.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_dir_copies_big_object_via_multipart_copy() {
        let (mock, port) = MockS3::start(
            vec![
                ("dir/".into(), true),
                ("dir/big.bin".into(), false),
                ("dir/small.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        mock.set_size("dir/big.bin", MULTIPART_COPY_THRESHOLD + 1);
        let fs = test_fs(port, 32);

        fs.rename("/dir", "/dir2", false)
            .await
            .expect("rename directory");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        // The 5 GiB object: copied through upload_part_copy chunks with a
        // copy-source range (PUT + partNumber + uploadId + copy-source).
        let parts = recorded
            .iter()
            .filter(|r| {
                r.method == "PUT" && lc(&r.target).contains("partnumber") && r.copy_source.is_some()
            })
            .collect::<Vec<_>>();
        assert!(
            parts.len() >= 2,
            "big object must be copied in multiple parts: {recorded:?}"
        );
        for p in &parts {
            assert!(
                p.copy_source
                    .as_deref()
                    .map(|s| s.contains("/dir/big.bin"))
                    .unwrap_or(false),
                "copy source must reference the source object: {p:?}"
            );
        }
        // Small objects: a single copy_object each (PUT + copy-source, no
        // part). Without a delimiter the source dir marker is an ordinary
        // object, so: small.txt + source dir/ marker + dst dir marker.
        let plain_copies = recorded
            .iter()
            .filter(|r| {
                r.method == "PUT"
                    && r.copy_source.is_some()
                    && !lc(&r.target).contains("partnumber")
            })
            .count();
        assert_eq!(
            plain_copies, 3,
            "small.txt + source + dst dir markers copied with plain copy_object: {recorded:?}"
        );
        // One multipart upload initiated + completed for the big object.
        let creates = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("uploads"))
            .count();
        assert_eq!(creates, 1, "one multipart upload for the big object");
        let completes = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploadid")
                    && !lc(&r.target).contains("partnumber")
            })
            .count();
        assert_eq!(completes, 1, "one multipart complete");
    }

    #[test]
    fn next_page_token_requires_token_when_truncated() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
        let complete = ListObjectsV2Output::builder().build();
        assert_eq!(next_page_token(&complete).unwrap(), None);
        let paged = ListObjectsV2Output::builder()
            .is_truncated(true)
            .next_continuation_token("tok")
            .build();
        assert_eq!(next_page_token(&paged).unwrap().as_deref(), Some("tok"));
        let dangling = ListObjectsV2Output::builder().is_truncated(true).build();
        assert!(next_page_token(&dangling).is_err());
    }

    #[tokio::test]
    async fn mkdir_and_delete_reject_mount_root() {
        // Regression (#60): `mkdir("/")` PUT and `delete("/")` DELETE targeted
        // an empty key (the bucket itself) instead of failing locally.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let err = fs.mkdir("/").await.unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
        let err = fs.delete("/").await.unwrap_err();
        assert!(err.to_string().contains("mount root"), "got: {err}");
        let err = fs.delete("//").await.unwrap_err();
        assert!(err.to_string().contains("mount root"), "got: {err}");
        assert!(
            mock.requests.lock().unwrap().is_empty(),
            "rejected root operations must not reach S3"
        );
    }

    #[tokio::test]
    async fn read_only_write_is_not_counted() {
        // Regression (#60): a read-only-rejected write used to increment the
        // write/put/byte counters without issuing any request.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.read_only = true;
        assert!(fs.write("/a.bin", &[1, 2, 3]).await.is_err());
        let m = fs.metrics();
        assert_eq!(m.writes, 0);
        assert_eq!(m.s3_puts, 0);
        assert_eq!(m.upload_bytes_total, 0);
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bucket_existence_check_distinguishes_missing_bucket() {
        // Regression (#60): mounting a nonexistent bucket used to look like an
        // empty drive because every 404 is treated as "missing object".
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let err = fs.ensure_bucket_exists().await.unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
        // The bucket-level HEAD target ("/<bucket>") maps to the empty key in
        // the mock; an object stored there makes HeadBucket succeed.
        mock.set_object("", Vec::new());
        fs.ensure_bucket_exists().await.expect("bucket exists");
    }

    #[tokio::test]
    async fn bucket_check_forbidden_or_5xx_continues_mount() {
        // Review B1: 403 (credentials valid but lacking s3:ListBucket) and
        // 5xx (transient) must not fail the mount — only a definitive 404
        // means the bucket is missing.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        mock.head_status.store(403, Ordering::SeqCst);
        fs.ensure_bucket_exists()
            .await
            .expect("403 must not fail mount");

        mock.head_status.store(500, Ordering::SeqCst);
        fs.ensure_bucket_exists()
            .await
            .expect("5xx must not fail mount");

        mock.head_status.store(404, Ordering::SeqCst);
        let err = fs.ensure_bucket_exists().await.unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "404 must still be definitive: {err}"
        );
    }

    #[test]
    fn effective_memory_budgets_nan_ratio_falls_back_to_default() {
        // Regression (#60): NaN.clamp(0.01, 0.99) stays NaN, `(total * NaN)
        // as usize` collapses to 0, silently zeroing the read-cache budget.
        let (upload, dirty, read) =
            effective_memory_budgets(Some(64 * 1024 * 1024), f64::NAN, None, None, None);
        assert_eq!(read, 32 * 1024 * 1024);
        assert_eq!(upload, Some(16 * 1024 * 1024));
        assert_eq!(dirty, Some(16 * 1024 * 1024));
    }

    #[test]
    fn disk_cache_overwrite_tracks_size_delta() {
        // Regression (#60): overwriting a cached block only added the new
        // size, so `used` grew monotonically and evicted live blocks early.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = DiskCache::new(
            dir.path().to_path_buf(),
            64 * 1024 * 1024,
            4 * 1024 * 1024,
            0,
            None,
        )
        .expect("cache");
        cache.write_block("k", 0, &[1, 2, 3, 4]).expect("write");
        let first = cache.used.load(Ordering::Relaxed);
        cache.write_block("k", 0, &[1, 2]).expect("overwrite");
        let second = cache.used.load(Ordering::Relaxed);
        assert_eq!(
            first - second,
            2,
            "shrinking overwrite must shrink `used` by the size delta"
        );
        cache
            .write_block("k", 0, &[1, 2, 3, 4, 5, 6])
            .expect("grow");
        assert_eq!(
            cache.used.load(Ordering::Relaxed) - second,
            4,
            "growing overwrite must grow `used` by the size delta"
        );
    }

    #[tokio::test]
    async fn streaming_upload_is_counted() {
        // Regression (#60): streaming uploads were invisible to the write /
        // put / byte counters.
        let (_mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let mut upload = fs
            .begin_streaming_upload("/large.bin")
            .await
            .expect("begin");
        assert_eq!(fs.metrics().writes, 1, "begin counts one write");
        assert_eq!(fs.metrics().s3_puts, 0, "nothing completed yet");
        upload.write(&[7u8; 100]).await.expect("feed");
        upload.finish().await.expect("finish");
        let m = fs.metrics();
        assert_eq!(m.s3_puts, 1);
        assert_eq!(m.upload_bytes_total, 100);
    }

    #[tokio::test]
    async fn list_parses_common_prefixes_and_objects() {
        let (mock, port) = MockS3::start(
            vec![("docs/sub/".into(), true), ("docs/a.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);
        let entries = fs.list("/docs").await.expect("list");
        let names: Vec<(String, bool)> =
            entries.iter().map(|e| (e.name.clone(), e.is_dir)).collect();
        assert_eq!(
            names,
            vec![("sub".to_string(), true), ("a.txt".to_string(), false)]
        );
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_skips_legacy_folder_markers_when_enabled() {
        let (mock, port) = MockS3::start(
            vec![
                ("docs/sub_$folder$".into(), false),
                ("docs/a.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        let mut fs = test_fs(port, 32);
        fs.notsup_compat_dir = true;
        let entries = fs.list("/docs").await.expect("list");
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["a.txt".to_string()]);
    }

    #[tokio::test]
    async fn list_keeps_legacy_folder_markers_when_disabled() {
        let (mock, port) = MockS3::start(
            vec![
                ("docs/sub_$folder$".into(), false),
                ("docs/a.txt".into(), false),
            ],
            Duration::from_millis(1),
        )
        .await;
        let fs = test_fs(port, 32);
        let entries = fs.list("/docs").await.expect("list");
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec!["sub_$folder$".to_string(), "a.txt".to_string()]);
    }

    #[tokio::test]
    async fn write_small_object_uses_single_put() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let data = vec![0x5Au8; 1024];
        fs.write("/small.bin", &data).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "small write must be a single request");
        assert_eq!(recorded[0].method, "PUT");
        let q = recorded[0].target.to_lowercase();
        assert!(!q.contains("uploads"), "must not initiate multipart");
        assert!(!q.contains("uploadid"), "must not touch multipart");
        assert!(!q.contains("partnumber"), "must not upload parts");
        assert_eq!(recorded[0].body, data, "whole object must be the PUT body");
    }

    #[tokio::test]
    async fn write_small_object_sets_storage_class() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.storage_class = Some(StorageClass::from("Standard"));

        fs.write("/small-sc.bin", &[1u8, 2, 3])
            .await
            .expect("write");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "PUT");
        assert_eq!(
            recorded[0].storage_class.as_deref(),
            Some("Standard"),
            "PUT must carry the requested x-amz-storage-class header"
        );
    }

    #[tokio::test]
    async fn write_small_object_sets_content_md5() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.content_md5 = true;

        let data = vec![0x5Au8; 1024];
        fs.write("/small-md5.bin", &data).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].content_md5.as_deref(),
            Some(content_md5(&data).as_str()),
            "single PUT must carry the base64 Content-MD5 header"
        );
    }

    #[tokio::test]
    async fn write_small_object_verifies_crc64() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;

        let data = vec![0x5Au8; 1024];
        let expected = crc64ecma(&data);
        mock.set_crc64(expected);

        fs.write("/small-crc.bin", &data).await.expect("write");
    }

    #[tokio::test]
    async fn write_small_object_rejects_crc64_mismatch() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;

        let data = vec![0x5Au8; 1024];
        mock.set_crc64(crc64ecma(&data).wrapping_add(1));

        let err = fs.write("/small-bad.bin", &data).await.unwrap_err();
        assert!(
            err.to_string().contains("crc64 mismatch"),
            "expected crc64 mismatch error, got: {err}"
        );
    }

    #[tokio::test]
    async fn write_large_object_uses_multipart_and_reassembles() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        // 20 MiB > MULTIPART_THRESHOLD (16 MiB), byte pattern varies so the
        // reassembled order can be verified.
        let data: Vec<u8> = (0..20 * 1024 * 1024usize)
            .map(|i| (i % 256) as u8)
            .collect();
        fs.write("/large.bin", &data).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        let lc = |t: &str| t.to_lowercase();

        let creates = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploads")
                    && !lc(&r.target).contains("uploadid")
            })
            .count();
        assert_eq!(creates, 1, "exactly one initiate-multipart");

        let aborts = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && lc(&r.target).contains("uploadid"))
            .count();
        assert_eq!(aborts, 0, "no abort on a successful upload");

        let completes = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploadid")
                    && !lc(&r.target).contains("partnumber")
            })
            .count();
        assert_eq!(completes, 1, "exactly one complete-multipart");

        let mut parts: Vec<(i32, Vec<u8>)> = recorded
            .iter()
            .filter(|r| r.method == "PUT" && lc(&r.target).contains("partnumber"))
            .map(|r| {
                let query = r.target.split('?').nth(1).unwrap_or("");
                let part_no = query
                    .split('&')
                    .find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        k.eq_ignore_ascii_case("partnumber")
                            .then(|| v.parse::<i32>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                (part_no, r.body.clone())
            })
            .collect();
        parts.sort_by_key(|(n, _)| *n);
        assert!(
            parts.len() >= 2,
            "expected multiple multipart parts, got {}",
            parts.len()
        );

        let reassembled: Vec<u8> = parts.iter().flat_map(|(_, b)| b.clone()).collect();
        assert_eq!(
            reassembled, data,
            "multipart parts must reassemble to the original bytes in order"
        );
    }

    #[tokio::test]
    async fn write_from_file_streams_multipart_without_whole_buffer() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("large.bin");
        let data: Vec<u8> = (0..20 * 1024 * 1024usize)
            .map(|i| (i % 256) as u8)
            .collect();
        std::fs::write(&src, &data).expect("write spool");

        fs.write_from_file("/large.bin", &src).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        let lc = |t: &str| t.to_lowercase();
        let creates = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploads")
                    && !lc(&r.target).contains("uploadid")
            })
            .count();
        assert_eq!(creates, 1, "exactly one initiate-multipart");

        let mut parts: Vec<(i32, Vec<u8>)> = recorded
            .iter()
            .filter(|r| r.method == "PUT" && lc(&r.target).contains("partnumber"))
            .map(|r| {
                let query = r.target.split('?').nth(1).unwrap_or("");
                let part_no = query
                    .split('&')
                    .find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        k.eq_ignore_ascii_case("partnumber")
                            .then(|| v.parse::<i32>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                (part_no, r.body.clone())
            })
            .collect();
        parts.sort_by_key(|(n, _)| *n);
        let reassembled: Vec<u8> = parts.iter().flat_map(|(_, b)| b.clone()).collect();
        assert_eq!(
            reassembled, data,
            "multipart parts must reassemble in order"
        );
    }

    #[tokio::test]
    async fn write_from_file_small_uses_single_put() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("small.bin");
        let data = vec![0x5Au8; 1024];
        std::fs::write(&src, &data).expect("write spool");

        fs.write_from_file("/small.bin", &src).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "small file must be a single PUT");
        assert_eq!(recorded[0].method, "PUT");
        assert!(!recorded[0].target.to_lowercase().contains("uploads"));
        assert_eq!(recorded[0].body, data);
    }

    #[tokio::test]
    async fn streaming_upload_reassembles() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        let mut up = fs
            .begin_streaming_upload("/large.bin")
            .await
            .expect("begin");
        let data: Vec<u8> = (0..20 * 1024 * 1024usize)
            .map(|i| (i % 256) as u8)
            .collect();
        up.write(&data).await.expect("write");
        up.finish().await.expect("finish");

        let recorded = mock.recorded.lock().unwrap();
        let lc = |t: &str| t.to_lowercase();
        let creates = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploads")
                    && !lc(&r.target).contains("uploadid")
            })
            .count();
        assert_eq!(creates, 1, "exactly one initiate-multipart");

        let mut parts: Vec<(i32, Vec<u8>)> = recorded
            .iter()
            .filter(|r| r.method == "PUT" && lc(&r.target).contains("partnumber"))
            .map(|r| {
                let query = r.target.split('?').nth(1).unwrap_or("");
                let part_no = query
                    .split('&')
                    .find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        k.eq_ignore_ascii_case("partnumber")
                            .then(|| v.parse::<i32>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                (part_no, r.body.clone())
            })
            .collect();
        parts.sort_by_key(|(n, _)| *n);
        let reassembled: Vec<u8> = parts.iter().flat_map(|(_, b)| b.clone()).collect();
        assert_eq!(
            reassembled, data,
            "streaming parts must reassemble in order"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_finish_no_such_upload_with_intact_object_succeeds_without_abort() {
        // A retried CompleteMultipartUpload can race an already-completed
        // attempt and report NoSuchUpload. When HEAD shows the object landed
        // with the exact byte count the write must succeed and NOT abort.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        mock.complete_no_such_upload.store(true, Ordering::SeqCst);
        let data: Vec<u8> = (0..(MULTIPART_PART_SIZE as usize + 123))
            .map(|i| (i % 256) as u8)
            .collect();
        // Simulate the server-side completion that the failed complete implies.
        mock.set_object("large.bin", data.clone());

        let mut up = fs
            .begin_streaming_upload("/large.bin")
            .await
            .expect("begin");
        up.write(&data).await.expect("write");
        up.finish()
            .await
            .expect("finish must treat a raced completion as success");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        let aborted = recorded
            .iter()
            .any(|r| r.method == "DELETE" && lc(&r.target).contains("uploadid"));
        assert!(!aborted, "no abort for an object that completed intact");
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "HEAD" && r.target.starts_with("/b/large.bin")),
            "NoSuchUpload must trigger a HEAD verification"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_finish_no_such_upload_without_object_fails() {
        // Same race but the object is genuinely gone: the write must fail.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        mock.complete_no_such_upload.store(true, Ordering::SeqCst);
        let data: Vec<u8> = vec![0x21u8; MULTIPART_PART_SIZE as usize + 7];

        let mut up = fs
            .begin_streaming_upload("/missing.bin")
            .await
            .expect("begin");
        up.write(&data).await.expect("write");
        let res = up.finish().await;
        assert!(
            res.is_err(),
            "genuinely-missing upload must surface an error"
        );
    }

    // -------------------------------------------------------------------
    // StreamingUpload hardening (#55): Drop abort, budget, part size,
    // limiter coverage
    // -------------------------------------------------------------------

    /// A dropped (never-finished, never-aborted) streaming handle must abort
    /// its multipart upload so uploaded parts are not orphaned on the bucket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_drop_without_finish_aborts_multipart() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        let mut up = fs
            .begin_streaming_upload("/dropped.bin")
            .await
            .expect("begin");
        up.write(&vec![0x42u8; MULTIPART_PART_SIZE as usize + 17])
            .await
            .expect("feed at least one full part");
        // Drop without finish / abort: Drop must issue the abort itself.
        drop(up);

        // The abort is spawned async; poll instead of a fixed sleep.
        let lc = |t: &str| t.to_lowercase();
        assert!(
            wait_for_recorded(&mock, |r| {
                r.method == "DELETE" && lc(&r.target).contains("uploadid")
            })
            .await,
            "dropping an unfinished streaming handle must abort the upload"
        );
        let recorded = mock.recorded.lock().unwrap();
        let completes = recorded
            .iter()
            .filter(|r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploadid")
                    && !lc(&r.target).contains("partnumber")
            })
            .count();
        assert_eq!(completes, 0, "no complete for a dropped upload");
    }

    /// A read-only mount must refuse to begin a streaming upload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_begin_rejects_read_only_mount() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.read_only = true;

        let err = match fs.begin_streaming_upload("/ro.bin").await {
            Err(e) => e,
            Ok(_) => panic!("read-only mount must reject begin_streaming_upload"),
        };
        assert!(
            err.to_string().contains("read-only"),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            0,
            "no S3 request may be issued for a rejected begin"
        );
    }

    /// The upload-budget (max-upload-bytes) must bound streaming writes:
    /// exceeding it fails the write, and a finish releases the budget for a
    /// subsequent upload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_write_enforces_upload_budget() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.upload_budget = Some(Arc::new(Semaphore::new(1)));
        fs.upload_budget_units = 1; // 1 MiB budget

        // A single write beyond the budget must fail fast (try_acquire),
        // and the failed handle must not leave an upload behind.
        let mut up = fs.begin_streaming_upload("/big.bin").await.expect("begin");
        let err = up
            .write(&vec![0x7Au8; (2 << 20) + 1])
            .await
            .expect_err("write beyond the upload budget must fail");
        assert!(
            err.to_string().contains("max-upload-bytes"),
            "unexpected error: {err:?}"
        );
        drop(up);
        let lc = |t: &str| t.to_lowercase();
        assert!(
            wait_for_recorded(&mock, |r| {
                r.method == "DELETE" && lc(&r.target).contains("uploadid")
            })
            .await,
            "failed budget write must abort its upload"
        );

        // Within budget: write 512 KiB, finish, and the budget must be free
        // for the next upload (permit released with the handle).
        let mut up = fs.begin_streaming_upload("/ok.bin").await.expect("begin");
        up.write(&vec![0x11u8; 512 * 1024])
            .await
            .expect("write within budget");
        up.finish().await.expect("finish within budget");
        let mut up2 = fs
            .begin_streaming_upload("/ok2.bin")
            .await
            .expect("second begin after finish must have budget available");
        up2.write(&vec![0x22u8; 512 * 1024])
            .await
            .expect("write after finish must succeed");
        up2.finish().await.expect("second finish");
    }

    /// #55-review B1: with the whole budget held by an in-flight streaming
    /// upload, a whole-object write (the flush path, which runs on the FUSE
    /// dispatcher) must fail fast instead of blocking on the budget — a
    /// blocking wait would park the single macOS dispatcher thread that must
    /// later release the streaming handle, deadlocking the mount.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn whole_object_write_fails_fast_when_budget_held_by_streaming() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.upload_budget = Some(Arc::new(Semaphore::new(1)));
        fs.upload_budget_units = 1; // 1 MiB budget

        // Streaming handle holds the whole budget across operations.
        let mut up = fs.begin_streaming_upload("/hold.bin").await.expect("begin");
        up.write(&vec![0x11u8; 512 * 1024])
            .await
            .expect("streaming write within budget");

        // A small whole-object write must fail fast, not block forever.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fs.write("/small.bin", &vec![0x22u8; 1024]),
        )
        .await;
        let err = result
            .expect("whole-object write must not block when the budget is held")
            .expect_err("whole-object write must fail when the budget is held");
        assert!(
            err.to_string().contains("max-upload-bytes"),
            "unexpected error: {err:?}"
        );
        // Finish the streaming upload so the budget is released cleanly.
        up.finish().await.expect("finish");
    }

    /// Every S3 request of the streaming path must hold a limiter permit:
    /// with a 1-permit pool a full upload (create → parts → complete → the
    /// recovery HEAD) must serialize without deadlock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_path_serializes_on_single_permit_limiter() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.limiter = Arc::new(Semaphore::new(1));
        mock.complete_no_such_upload.store(true, Ordering::SeqCst);
        let data: Vec<u8> = (0..(MULTIPART_PART_SIZE as usize + 31))
            .map(|i| (i % 256) as u8)
            .collect();
        mock.set_object("single.bin", data.clone());

        let mut up = fs
            .begin_streaming_upload("/single.bin")
            .await
            .expect("begin");
        up.write(&data).await.expect("write");
        // complete fails (NoSuchUpload) → the recovery HEAD must acquire the
        // single permit without deadlocking (it is released before the HEAD).
        up.finish()
            .await
            .expect("recovery HEAD under a 1-permit limiter must not deadlock");
    }

    /// Parts must be cut at the configured multipart size, not the hardcoded
    /// default (#55).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_parts_follow_configured_part_size() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.multipart_part_size = 1024 * 1024; // 1 MiB parts

        let mut up = fs
            .begin_streaming_upload("/parts.bin")
            .await
            .expect("begin");
        let data: Vec<u8> = vec![0x5Au8; 2 * 1024 * 1024 + 4096];
        up.write(&data).await.expect("write");
        up.finish().await.expect("finish");

        let lc = |t: &str| t.to_lowercase();
        let recorded = mock.recorded.lock().unwrap();
        let mut parts: Vec<(i32, Vec<u8>)> = recorded
            .iter()
            .filter(|r| r.method == "PUT" && lc(&r.target).contains("partnumber"))
            .map(|r| {
                let query = r.target.split('?').nth(1).unwrap_or("");
                let part_no = query
                    .split('&')
                    .find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        k.eq_ignore_ascii_case("partnumber")
                            .then(|| v.parse::<i32>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                (part_no, r.body.clone())
            })
            .collect();
        parts.sort_by_key(|(n, _)| *n);
        assert!(parts.len() >= 3, "expected 3 parts, got {}", parts.len());
        for (_, body) in &parts {
            assert!(
                body.len() <= 1024 * 1024,
                "part of {} bytes exceeds the configured 1 MiB size",
                body.len()
            );
        }
        let reassembled: Vec<u8> = parts.iter().flat_map(|(_, b)| b.clone()).collect();
        assert_eq!(reassembled, data, "parts must reassemble in order");
    }

    /// S3's 10000-part cap must be enforced while writing, not discovered at
    /// CompleteMultipartUpload after the whole object was uploaded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_write_rejects_more_than_10000_parts() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.multipart_part_size = 1024; // 10000 parts = 10 MiB

        let mut up = fs.begin_streaming_upload("/huge.bin").await.expect("begin");
        let over = 10_000 * 1024 + 1;
        let err = up
            .write(&vec![0x9Cu8; over])
            .await
            .expect_err("more than 10000 parts must be rejected while writing");
        assert!(
            err.to_string().contains("multipart limit"),
            "unexpected error: {err:?}"
        );
        drop(up);
        let lc = |t: &str| t.to_lowercase();
        assert!(
            wait_for_recorded(&mock, |r| {
                r.method == "DELETE" && lc(&r.target).contains("uploadid")
            })
            .await,
            "the rejected upload must still be aborted on drop"
        );
    }

    /// #55-review M3: a CRC mismatch after a completed multipart must surface
    /// the error WITHOUT a follow-up abort — the object already exists, so
    /// aborting would be a wasted (NoSuchUpload) request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn streaming_crc_mismatch_does_not_abort_completed_object() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;
        let data: Vec<u8> = (0..(MULTIPART_PART_SIZE as usize + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        mock.set_crc64(crc64ecma(&data).wrapping_add(1)); // wrong CRC

        let mut up = fs.begin_streaming_upload("/crc.bin").await.expect("begin");
        up.write(&data).await.expect("write");
        let res = up.finish().await;
        assert!(res.is_err(), "CRC mismatch must surface an error");

        // The complete must have been issued first (it carries the bad CRC).
        let lc = |t: &str| t.to_lowercase();
        assert!(
            wait_for_recorded(&mock, |r| {
                r.method == "POST"
                    && lc(&r.target).contains("uploadid")
                    && !lc(&r.target).contains("partnumber")
            })
            .await,
            "complete-multipart must be issued"
        );
        // Give a hypothetically-spawned abort time to (not) land. The
        // negative assertion cannot poll; 300ms is generous for the mock.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !mock
                .recorded
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.method == "DELETE" && lc(&r.target).contains("uploadid")),
            "a completed object must not be aborted after a CRC mismatch"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_multipart_complete_failure_with_crc64_and_intact_object_succeeds() {
        // Regression: write_multipart/_from_file's complete-failure recovery
        // used to call check_crc64_response, but the complete response never
        // arrived so the crc slot was empty → check_crc64_response bailed
        // ("header missing"), turning a recovered success into an error. This
        // only manifested with verify_crc64=true (tests default it off).
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;
        mock.complete_no_such_upload.store(true, Ordering::SeqCst);
        // > MULTIPART_THRESHOLD (16 MiB) routes through write_multipart.
        let data: Vec<u8> = vec![0x33u8; 16 * 1024 * 1024 + 1];
        mock.set_object("large.bin", data.clone());

        fs.write("/large.bin", &data)
            .await
            .expect("complete failure with an intact object must recover to success");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_from_file_complete_failure_recovers_on_intact_object() {
        // Same recovery contract as the buffered write path, through the
        // spool-file multipart implementation.
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;
        mock.complete_no_such_upload.store(true, Ordering::SeqCst);

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("large.bin");
        let data: Vec<u8> = (0..20 * 1024 * 1024usize)
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&src, &data).expect("write spool");
        mock.set_object("large.bin", data);

        fs.write_from_file("/large.bin", &src)
            .await
            .expect("complete failure with an intact object must recover to success");
    }

    #[test]
    fn read_body_budget_scales_with_expected_length() {
        // The smithy read timeout does not bound response-body streaming, so
        // read_range wraps the body collect in read_body_budget(...). The
        // budget must scale with the expected length (so a slow but healthy
        // link always fits) while staying finite for unbounded lazy loads.
        assert_eq!(read_body_budget(0), READ_BODY_MIN_TOTAL);
        assert_eq!(read_body_budget(1024), READ_BODY_MIN_TOTAL);
        // 8 MiB at 8 KiB/s = 1024 s.
        assert_eq!(read_body_budget(8 * 1024 * 1024), Duration::from_secs(1024));
        // Unbounded reads (lazy loads pass usize::MAX) are capped at 64 MiB.
        assert_eq!(read_body_budget(usize::MAX), Duration::from_secs(8192));
    }

    #[tokio::test]
    async fn write_large_object_honors_custom_part_size() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.multipart_part_size = 6 * 1024 * 1024;

        let data: Vec<u8> = vec![0xAAu8; 20 * 1024 * 1024];
        fs.write("/large-custom.bin", &data).await.expect("write");

        let recorded = mock.recorded.lock().unwrap();
        let part_count = recorded
            .iter()
            .filter(|r| r.method == "PUT" && r.target.to_lowercase().contains("partnumber"))
            .count();
        assert_eq!(
            part_count, 4,
            "20 MiB with a 6 MiB part size must upload 4 parts"
        );
    }

    #[tokio::test]
    async fn write_large_object_verifies_crc64() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.verify_crc64 = true;

        let data: Vec<u8> = (0..20 * 1024 * 1024usize)
            .map(|i| (i % 256) as u8)
            .collect();
        mock.set_crc64(crc64ecma(&data));

        fs.write("/large-crc.bin", &data).await.expect("write");
    }

    #[tokio::test]
    async fn disk_cache_serves_repeat_reads_without_s3() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                DISK_CACHE_BLOCK_SIZE as usize,
                0,
                None,
            )
            .expect("cache"),
        ));

        let data: Vec<u8> = (0..5 * 1024 * 1024usize).map(|i| (i % 251) as u8).collect();
        mock.set_object("big.bin", data.clone());

        let off = 4 * 1024 * 1024 - 8;
        let first = fs.read_range("/big.bin", off, 16).await.expect("read");
        assert_eq!(first, data[off as usize..off as usize + 16]);
        assert_eq!(mock.get_count.load(Ordering::SeqCst), 2); // crosses a block boundary

        let second = fs.read_range("/big.bin", off, 16).await.expect("read");
        assert_eq!(second, data[off as usize..off as usize + 16]);
        assert_eq!(
            mock.get_count.load(Ordering::SeqCst),
            2,
            "second read must hit disk cache"
        );
    }

    #[tokio::test]
    async fn disk_cache_prefetches_next_block_on_sequential_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.read_ahead_window = 8 * 1024 * 1024;
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                4 * 1024 * 1024,
                0,
                None,
            )
            .expect("cache"),
        ));

        let data: Vec<u8> = (0..13 * 1024 * 1024usize)
            .map(|i| (i % 256) as u8)
            .collect();
        mock.set_object("seq.bin", data);
        fs.read_range("/seq.bin", 0, 1024).await.expect("read");
        fs.read_range("/seq.bin", 1024, 1024).await.expect("read");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            fs.disk_cache
                .as_ref()
                .unwrap()
                .read_block("seq.bin", 2)
                .is_some(),
            "sequential read should prefetch the next block"
        );
    }

    #[tokio::test]
    async fn disk_cache_etag_verification_invalidates_on_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                4 * 1024 * 1024,
                0,
                None,
            )
            .expect("cache"),
        ));
        fs.disk_cache_verify_etag = true;

        let data: Vec<u8> = (0..5 * 1024 * 1024usize).map(|i| (i % 256) as u8).collect();
        mock.set_object("e.bin", data);
        fs.read_range("/e.bin", 0, 1024).await.expect("read");
        fs.read_range("/e.bin", 0, 1024).await.expect("hit");
        assert_eq!(mock.get_count.load(Ordering::SeqCst), 1);

        fs.etag_checked.lock().unwrap().clear();
        mock.set_head_etag("changed");
        fs.read_range("/e.bin", 0, 1024).await.expect("refetch");
        assert_eq!(mock.get_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn disk_cache_etag_ttl_skips_repeated_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                4 * 1024 * 1024,
                0,
                None,
            )
            .expect("cache"),
        ));
        fs.disk_cache_verify_etag = true;

        let data: Vec<u8> = (0..5 * 1024 * 1024usize).map(|i| (i % 256) as u8).collect();
        mock.set_object("t.bin", data);
        fs.read_range("/t.bin", 0, 1024).await.expect("read");
        fs.read_range("/t.bin", 0, 1024).await.expect("hit");
        assert_eq!(mock.head_count.load(Ordering::SeqCst), 1);
        // Regression (#60): the TTL-suppressed second check must not count as
        // an issued HEAD either.
        assert_eq!(fs.metrics().s3_etag_heads, 1);
        assert_eq!(fs.metrics().s3_heads, 1);
    }

    #[tokio::test]
    async fn disk_cache_invalidated_by_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                DISK_CACHE_BLOCK_SIZE as usize,
                0,
                None,
            )
            .expect("cache"),
        ));

        let data: Vec<u8> = (0..1024usize).map(|i| i as u8).collect();
        mock.set_object("small.bin", data.clone());
        fs.read_range("/small.bin", 0, 1024).await.expect("read");
        assert_eq!(mock.get_count.load(Ordering::SeqCst), 1);

        fs.write("/small.bin", &data).await.expect("write");
        fs.read_range("/small.bin", 0, 1024).await.expect("read");
        assert_eq!(
            mock.get_count.load(Ordering::SeqCst),
            2,
            "write must invalidate the cached block"
        );
    }

    #[tokio::test]
    async fn metrics_count_reads_writes_and_caches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.disk_cache = Some(Arc::new(
            DiskCache::new(
                dir.path().to_path_buf(),
                64 * 1024 * 1024,
                DISK_CACHE_BLOCK_SIZE as usize,
                0,
                None,
            )
            .expect("cache"),
        ));

        let data = vec![0xAAu8; 1024];
        mock.set_object("a.bin", data);
        fs.read_range("/a.bin", 0, 1024).await.expect("read");
        fs.read_range("/a.bin", 0, 1024).await.expect("read");
        fs.write("/a.bin", &[1, 2, 3]).await.expect("write");

        let m = fs.metrics();
        assert_eq!(m.reads, 2);
        assert_eq!(m.disk_cache_hits, 1);
        assert_eq!(m.writes, 1);
        assert_eq!(m.s3_gets, 1);
        assert_eq!(m.s3_puts, 1);
        assert_eq!(m.upload_bytes_total, 3);
        assert_eq!(m.download_bytes_total, 1024);
    }

    #[tokio::test]
    async fn s3_errors_increment_on_get_failure() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);
        let err = fs.read_range("/missing.bin", 0, 16).await.unwrap_err();
        assert!(err.to_string().contains("s3 get"));
        assert_eq!(fs.metrics().s3_get_errors, 1);
    }

    #[tokio::test]
    async fn stat_missing_path_is_negatively_cached() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let fs = test_fs(port, 32);

        assert!(fs.stat("/nope").await.expect("stat").is_none());
        let before = mock.requests.lock().unwrap().len();

        // Within NEGATIVE_CACHE_TTL, a second stat of the same missing path
        // must not issue any remote HEAD/probe requests.
        assert!(fs.stat("/nope").await.expect("stat").is_none());
        let after = mock.requests.lock().unwrap().len();
        assert_eq!(before, after, "second stat must hit the negative cache");
    }

    #[test]
    fn crc64ecma_matches_known_vectors() {
        assert_eq!(crc64ecma(b"123456789"), 0x995DC9BBDF1939FA);
        assert_eq!(crc64ecma(b"a"), 0x330284772E652B05);
    }

    /// 裁决 #9:trash_insert 必须同步 index_entries gauge(修复前:测试
    /// 用 trash_insert 建索引后断言 gauge 会得 0 —— 既有集成测试未断言
    /// 故未暴露;trash_remove 无生产调用点,已删除,trash_insert 为仅存
    /// 测试驱动接缝)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_insert_updates_gauge() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/a.txt", false);
        assert_eq!(fs.metrics().trash_index_entries, 1, "文件墓碑 gauge=1");
        fs.trash_insert("/docs", true);
        assert_eq!(fs.metrics().trash_index_entries, 2, "目录墓碑 gauge=2");
        fs.trash_insert("/a.txt", false); // 幂等
        assert_eq!(fs.metrics().trash_index_entries, 2, "重复插入不涨 gauge");
    }

    /// 回收站集成测试统一手法:直接构造 ObjectFs 不走 connect,手置
    /// `fs.trash`(避免 connect 的 spawn/head-bucket 干扰 metrics 增量)。
    /// 默认 lazy 档 + 常量周期;测试可改 pub(crate) 字段定制
    /// (mode=Eager、强制重建周期)。
    fn trash_state(prefix: &str) -> Arc<trash::TrashState> {
        trash::TrashState::new(
            prefix.to_string(),
            TrashRefreshMode::Lazy,
            Duration::from_secs(TRASH_REFRESH_INTERVAL_SECS),
            Duration::from_secs(TRASH_REBUILD_INTERVAL_SECS),
            Duration::from_secs(TRASH_GC_INTERVAL_SECS),
            TRASH_RETENTION_DAYS,
        )
    }

    /// 单元 1:系统回收站测试统一构造 —— TrashState + 注入 system 视图
    /// (不走 build_trash_state,平台/目录名由测试显式定制)。
    fn system_trash_state(prefix: &str, sys: trash::SystemTrash) -> Arc<trash::TrashState> {
        let mut state = trash_state(prefix);
        Arc::get_mut(&mut state)
            .expect("freshly created arc is uniquely owned")
            .system = Some(sys);
        state
    }

    fn win_sys() -> trash::SystemTrash {
        trash::SystemTrash {
            dir_name: "$Recycle.Bin".into(),
            platform: trash::SystemTrashPlatform::WindowsRecycleBin,
            macos_uid_dirs: vec![],
        }
    }

    fn mac_sys() -> trash::SystemTrash {
        trash::SystemTrash {
            dir_name: ".Trashes".into(),
            platform: trash::SystemTrashPlatform::MacOsTrashes,
            macos_uid_dirs: vec![501],
        }
    }

    /// 单元 1 测试日期(墓碑 key 分区)。
    fn sys_date() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 8, 16).unwrap()
    }

    /// 文件墓碑 body JSON(mock 对象内容)。
    fn tombstone_json(
        recycle_name: Option<&str>,
        size: Option<u64>,
        recycle_i: Option<&[u8]>,
    ) -> Vec<u8> {
        serde_json::to_vec(&trash::TombstoneBody {
            etag: Some("\"mock-etag\"".into()),
            size,
            is_dir: false,
            recycle_name: recycle_name.map(str::to_string),
            recycle_i: recycle_i.map(|b| b.to_vec()),
        })
        .unwrap()
    }

    /// 系统回收站测试的本地软删落盘(单元 2 形态):索引 insert +
    /// by_name/by_key 填充(mock 墓碑对象另由 set_object 提供)。
    fn seed_system_tombstone(
        fs: &ObjectFs,
        trash: &Arc<trash::TrashState>,
        original_key: &str,
        recycle_name: &str,
    ) {
        trash
            .index
            .write()
            .unwrap()
            .insert(original_key, false, sys_date());
        let tomb_key = trash::encode_tombstone_key(&trash.prefix, sys_date(), original_key, false);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert(recycle_name.to_string(), tomb_key);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert(original_key.to_string(), recycle_name.to_string());
    }

    /// 统计 mock 上真实的 getObject 请求数(ListObjectsV2 也是 HTTP GET,
    /// 以 query 区分;墓碑 body GET 必须走 getObject)。
    fn count_object_gets(mock: &MockS3) -> usize {
        mock.recorded
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == "GET" && !r.target.contains("list-type"))
            .count()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_list_warm_zero_body_gets() {
        // P1 守卫(Windows 暖路径):list("/$Recycle.Bin/<SID>") = 1 次 list
        // 循环 + 合成零额外请求;条目 = $R + $I 成对($I size = 合成长度)。
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        trash.seen_sids.write().unwrap().insert("S-1-5-21-1".into());
        // 暖路径:by_key 全覆盖 → 零 body GET(P1)
        let before = fs.metrics();
        let before_gets = count_object_gets(&mock);
        let list = fs.list("/$Recycle.Bin/S-1-5-21-1").await.unwrap();
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "P1:系统目录 list 请求数 = 普通目录(1 次 list 循环)"
        );
        assert_eq!(
            count_object_gets(&mock) - before_gets,
            0,
            "P1:暖路径零 body GET"
        );
        assert_eq!(list.len(), 2, "Windows 成对 $R/$I");
        let r = list
            .iter()
            .find(|e| e.name == "$R4de00001a.txt")
            .expect("$R 条目");
        assert!(!r.is_dir);
        let i = list
            .iter()
            .find(|e| e.name == "$I4de00001a.txt")
            .expect("$I 成对条目");
        assert!(!i.is_dir);
        assert_eq!(
            i.size,
            (8 + 8 + 8 + 4 + 2 * "C:\\docs\\a.txt".chars().count()) as u64,
            "$I size = 合成长度"
        );
        // 目录层 level 0:seen_sids 渲染(裁决 R14)
        let root = fs.list("/$Recycle.Bin").await.unwrap();
        assert!(root.iter().any(|e| e.name == "S-1-5-21-1" && e.is_dir));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_list_macos_zero_extra_and_dedup() {
        // P1 守卫(macOS):list("/.Trashes/501") 恒零额外请求;真实条目
        // (.DS_Store)与合成条目合并、同名去重(真实优先)。
        let entries = vec![
            (".trash/2026-08-16/docs/a.txt".into(), false),
            (".Trashes/501/.DS_Store".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(None, Some(5), None), // macOS:recycle_name None → basename 渲染
        );
        mock.set_object(".Trashes/501/.DS_Store", b"ds".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());
        fs.trash
            .as_ref()
            .unwrap()
            .index
            .write()
            .unwrap()
            .insert("docs/a.txt", false, sys_date());
        let before_gets = count_object_gets(&mock);
        let list = fs.list("/.Trashes/501").await.unwrap();
        assert_eq!(
            count_object_gets(&mock) - before_gets,
            0,
            "P1:macOS 恒零额外请求"
        );
        assert!(list.iter().any(|e| e.name == ".DS_Store" && !e.is_dir));
        assert!(list.iter().any(|e| e.name == "a.txt" && !e.is_dir));
        // macOS level 0:渲染 macos_uid_dirs
        let root = fs.list("/.Trashes").await.unwrap();
        assert!(root.iter().any(|e| e.name == "501" && e.is_dir));
        // 真实条目与合成条目同名去重(真实优先):桶中真实 real.txt +
        // 墓碑 basename 同名 → 只显一条且 size 为真实对象 size
        let entries = vec![
            (".trash/2026-08-16/docs/real.txt".into(), false),
            ("$Recycle.Bin/S-1-5-21-1/real.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/real.txt",
            tombstone_json(None, None, None),
        );
        mock.set_object("$Recycle.Bin/S-1-5-21-1/real.txt", b"real".to_vec());
        mock.set_size("$Recycle.Bin/S-1-5-21-1/real.txt", 4);
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        fs.trash.as_ref().unwrap().index.write().unwrap().insert(
            "docs/real.txt",
            false,
            sys_date(),
        );
        let list = fs.list("/$Recycle.Bin/S-1-5-21-1").await.unwrap();
        let _ = &mock;
        let real: Vec<&DirEntry> = list.iter().filter(|e| e.name == "real.txt").collect();
        assert_eq!(real.len(), 1, "同名去重,真实条目优先");
        assert_eq!(real[0].size, 4, "保留真实对象 size");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_list_cold_gets_bounded() {
        // P1 守卫(Windows 冷路径):by_key 未覆盖条目按需 GET body 填充,
        // GET 数 ≤ 未命中条目数;recycle_name 命中者改名并填充索引。
        let entries = vec![
            (".trash/2026-08-16/docs/a.txt".into(), false),
            (".trash/2026-08-16/x/b.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        mock.set_object(
            ".trash/2026-08-16/x/b.txt",
            tombstone_json(None, Some(5), None), // 非系统视图墓碑
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        trash
            .index
            .write()
            .unwrap()
            .insert("docs/a.txt", false, sys_date());
        trash
            .index
            .write()
            .unwrap()
            .insert("x/b.txt", false, sys_date());
        let before_gets = count_object_gets(&mock);
        let list = fs.list("/$Recycle.Bin/S-1-5-21-1").await.unwrap();
        let gets = count_object_gets(&mock) - before_gets;
        assert!(gets <= 2, "P1:冷路径 GET 数 ≤ 未命中条目数(2),实际 {gets}");
        assert!(list.iter().any(|e| e.name == "$R4de00001a.txt"));
        assert!(list.iter().any(|e| e.name == "$I4de00001a.txt"));
        assert!(
            list.iter().any(|e| e.name == "b.txt"),
            "无 recycle_name 保持 basename"
        );
        // 填充已生效:by_key 覆盖 docs/a.txt(下一次该条目零 GET)
        assert!(
            trash
                .recycle_names
                .read()
                .unwrap()
                .by_key
                .contains_key("docs/a.txt")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_root_list_zero_extra_requests() {
        // P2 守卫:list("/") 追加系统虚拟目录,请求数 = 普通根列表(1 次)。
        let entries = vec![("a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));
        let before = fs.metrics();
        let root = fs.list("/").await.unwrap();
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "P2:追加系统虚拟目录零额外请求"
        );
        assert!(root.iter().any(|e| e.name == "$Recycle.Bin" && e.is_dir));
        // 桶中已有同名真实 common_prefix:去重后仍只一条(真实优先)
        let entries = vec![("a.txt".into(), false), ("$Recycle.Bin/".into(), true)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));
        let root = fs.list("/").await.unwrap();
        assert_eq!(
            root.iter().filter(|e| e.name == "$Recycle.Bin").count(),
            1,
            "真实 common_prefix 与合成目录去重"
        );
        // macOS 平台目录名
        let entries = vec![("a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", mac_sys()));
        let root = fs.list("/").await.unwrap();
        assert!(root.iter().any(|e| e.name == ".Trashes" && e.is_dir));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_stat_guards() {
        // P3 守卫:Dir 层零远程;Entry 层 ≤1 次 body GET;stat 缓存命中后零。
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        trash.seen_sids.write().unwrap().insert("S-1-5-21-1".into());
        // Dir 层:零远程
        let before = count_object_gets(&mock);
        let root = fs.stat("/$Recycle.Bin").await.unwrap().expect("Dir stat");
        let sid = fs
            .stat("/$Recycle.Bin/S-1-5-21-1")
            .await
            .unwrap()
            .expect("SID Dir stat");
        assert_eq!(count_object_gets(&mock) - before, 0, "P3:Dir 层零远程");
        assert!(root.is_dir && sid.is_dir);
        // Entry 层:≤1 次 body GET;缓存命中后零
        let before = count_object_gets(&mock);
        let entry = fs
            .stat("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .unwrap()
            .expect("Entry stat");
        assert_eq!(
            count_object_gets(&mock) - before,
            1,
            "P3:Entry 层 ≤1 次 body GET"
        );
        assert!(!entry.is_dir);
        assert_eq!(entry.size, 5, "size 来自墓碑 body(删除时 HEAD)");
        let before = count_object_gets(&mock);
        let again = fs
            .stat("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .unwrap();
        assert_eq!(count_object_gets(&mock) - before, 0, "P3:stat 缓存命中后零");
        assert!(again.is_some());
        // 未知条目(by_name 未覆盖):stat 零远程返回 None(P3 的 ≤1 只
        // 覆盖已解析条目,未知条目不得触发冷扫描)
        let before = count_object_gets(&mock);
        let unknown = fs
            .stat("/$Recycle.Bin/S-1-5-21-1/NotSeen.txt")
            .await
            .unwrap();
        assert_eq!(count_object_gets(&mock) - before, 0);
        assert!(unknown.is_none());
        // $I stat:size = 捕获字节长度或合成长度
        let before = count_object_gets(&mock);
        let i_stat = fs
            .stat("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt")
            .await
            .unwrap()
            .expect("$I stat");
        assert_eq!(count_object_gets(&mock) - before, 1);
        assert_eq!(
            i_stat.size,
            (8 + 8 + 8 + 4 + 2 * "C:\\docs\\a.txt".chars().count()) as u64
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_read_forwards_to_original() {
        // $R / macOS 条目读 = 原 key 内容(请求键断言;缓存键沿用视图 path)
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        mock.set_object("docs/a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        let data = fs
            .read_range("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt", 0, 5)
            .await
            .unwrap();
        assert_eq!(data, b"hello");
        // 请求键断言:GET 目标是原 key(去 SDK 附加的 query,如 ?x-id=GetObject)
        let forwarded = mock.recorded.lock().unwrap().iter().any(|r| {
            r.method == "GET"
                && r.target
                    .split('?')
                    .next()
                    .is_some_and(|t| t.ends_with("/docs/a.txt"))
        });
        assert!(forwarded, "读必须转发到原 key");
        // macOS 条目读 = 原 key(索引内 basename 解析)
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"macdata".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());
        fs.trash
            .as_ref()
            .unwrap()
            .index
            .write()
            .unwrap()
            .insert("docs/a.txt", false, sys_date());
        let data = fs.read_range("/.Trashes/501/a.txt", 0, 7).await.unwrap();
        assert_eq!(data, b"macdata");
        // 未解析条目(无墓碑也无真实对象)→ 仍 Err(不静默):macOS 回退
        // 真实 key 后由 S3 404 自然报错(单元 5 起,见
        // system_trash_macos_ds_store_roundtrip)
        let err = fs
            .read_range("/.Trashes/501/ghost.txt", 0, 1)
            .await
            .expect_err("未知条目读必须报错");
        assert!(
            err.chain()
                .any(|c| c.to_string().contains("not found") || c.to_string().contains("NotFound")),
            "got: {err:?}"
        );
    }

    /// 单元 5(§5.3 测试 3):macOS `.DS_Store` 往返 —— Finder 写入的
    /// **真实对象**(非墓碑条目)write 直落真实 PUT(不经墓碑编解码)、
    /// stat 命中真实对象、read 读回真实字节;list 可见且与合成条目
    /// 同名去重(真实优先)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_macos_ds_store_roundtrip() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());

        // 1) Finder 写 .DS_Store → 真实 PUT(无墓碑对应,清墓碑挂点 no-op)
        fs.write("/.Trashes/501/.DS_Store", b"ds-meta")
            .await
            .expect(".DS_Store 写必须直落真实对象");
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|r| { r.method == "PUT" && r.target.contains(".Trashes/501/.DS_Store") }),
            ".DS_Store 必须真实落桶: {recorded:?}"
        );
        drop(recorded);

        // 2) stat:合成路径 resolve 失败不得吞掉真实条目
        let stat = fs
            .stat("/.Trashes/501/.DS_Store")
            .await
            .unwrap()
            .expect(".DS_Store stat 必须命中真实对象");
        assert!(!stat.is_dir);
        assert_eq!(stat.size, 7, "size = 真实对象大小");

        // 3) read:读回真实字节(不因「回收站条目未解析」而 bail)
        let data = fs
            .read_range("/.Trashes/501/.DS_Store", 0, 7)
            .await
            .expect(".DS_Store read 必须命中真实对象");
        assert_eq!(data, b"ds-meta");

        // 4) list:真实条目可见(合并合成条目;同名去重见
        // system_trash_list_macos_zero_extra_and_dedup)
        let list = fs.list("/.Trashes/501").await.unwrap();
        assert!(
            list.iter().any(|e| e.name == ".DS_Store" && !e.is_dir),
            ".DS_Store 必须可见: {list:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_read_i_synthesizes_bytes() {
        // $I 读 = 合成字节(裁决 R8 回退):8B 头 0x01 + 8B size + 8B
        // FILETIME + 4B 字符数 + UTF-16LE 路径,字节级断言。
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        let data = fs
            .read_range("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt", 0, 100)
            .await
            .unwrap();
        // 8B 头(版本 0x01 + 填充)
        assert_eq!(&data[..8], &[0x01, 0, 0, 0, 0, 0, 0, 0]);
        // 8B size = 删除时 HEAD 的 content_length
        assert_eq!(&data[8..16], &5u64.to_le_bytes());
        // 8B FILETIME = 删除日期 UTC 午夜(100ns 步进,1601 纪元)
        let unix = sys_date()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let filetime = ((unix as u128 + 11_644_473_600u128) * 10_000_000u128) as u64;
        assert_eq!(&data[16..24], &filetime.to_le_bytes());
        // 4B 路径字符数 + UTF-16LE 路径("C:\docs\a.txt")
        let path = "C:\\docs\\a.txt";
        assert_eq!(&data[24..28], &(path.chars().count() as u32).to_le_bytes());
        let utf16: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(&data[28..], &utf16[..]);
        // 捕获字节优先(裁决 R8):body.recycle_i 原样返回
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(
                Some("$R4de00001a.txt"),
                Some(5),
                Some(&[0xDE, 0xAD, 0xBE, 0xEF]),
            ),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        let data = fs
            .read_range("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt", 0, 100)
            .await
            .unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF], "捕获字节优先");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_trash_mkdir_noop_zero_puts() {
        // mkdir 虚拟目录 no-op:零 PUT;Windows 记录 SID 段(裁决 R14);
        // 普通目录 mkdir 不受影响(回归)。
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        fs.mkdir("/$Recycle.Bin").await.expect("level 0 no-op");
        fs.mkdir("/$Recycle.Bin/S-1-5-21-1")
            .await
            .expect("level 1 no-op");
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            0,
            "mkdir no-op 必须零 PUT"
        );
        assert!(
            trash.seen_sids.read().unwrap().contains("S-1-5-21-1"),
            "Windows mkdir 记录 SID 段"
        );
        // 只读挂载:ensure_writable 在拦截之前,写拒绝语义不变
        let mut ro = test_fs(port, 32);
        ro.read_only = true;
        ro.trash = Some(trash.clone());
        assert!(
            ro.mkdir("/$Recycle.Bin/S-1-5-21-1").await.is_err(),
            "只读挂载 mkdir 系统目录也必须拒绝"
        );
        // 普通目录 mkdir 照常(回归)
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash.clone());
        fs.mkdir("/docs").await.expect("普通 mkdir");
        assert!(
            mock.recorded
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.method == "PUT"),
            "普通目录 mkdir 仍写 marker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolve_entry_original_warm_and_cold() {
        // 裁决 R3 ③:by_name 命中零远程;未命中按需 GET 填充后命中。
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        // 冷:索引有、by_name 空 → 按需 GET 填充后命中
        fs.trash
            .as_ref()
            .unwrap()
            .index
            .write()
            .unwrap()
            .insert("docs/a.txt", false, sys_date());
        let before_gets = count_object_gets(&mock);
        let orig = trash
            .resolve_entry_original(&fs, "$R4de00001a.txt")
            .await
            .unwrap();
        assert_eq!(orig.as_deref(), Some("docs/a.txt"));
        assert_eq!(
            count_object_gets(&mock) - before_gets,
            1,
            "冷路径 GET 数 = 未覆盖条目数(1)"
        );
        // 填充后:by_name 命中零远程
        let before_gets = count_object_gets(&mock);
        let orig = trash
            .resolve_entry_original(&fs, "$R4de00001a.txt")
            .await
            .unwrap();
        assert_eq!(orig.as_deref(), Some("docs/a.txt"));
        assert_eq!(count_object_gets(&mock) - before_gets, 0, "暖路径零远程");
        // 未知条目 → None(扫描未命中,不误报)
        let orig = trash
            .resolve_entry_original(&fs, "$Rdeadbeef.txt")
            .await
            .unwrap();
        assert!(orig.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolve_entry_macos_basename_scan_latest() {
        // 裁决 R7:macOS basename 扫描,同名多日期/重名取最新(零远程)。
        let entries = vec![
            (".trash/2026-08-15/docs/a.txt".into(), false),
            (".trash/2026-08-16/x/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());
        fs.trash.as_ref().unwrap().index.write().unwrap().insert(
            "docs/a.txt",
            false,
            chrono::NaiveDate::from_ymd_opt(2026, 8, 15).unwrap(),
        );
        fs.trash
            .as_ref()
            .unwrap()
            .index
            .write()
            .unwrap()
            .insert("x/a.txt", false, sys_date());
        let before_gets = count_object_gets(&mock);
        let orig = trash.resolve_entry_original(&fs, "a.txt").await.unwrap();
        assert_eq!(count_object_gets(&mock) - before_gets, 0, "macOS 零远程");
        assert_eq!(
            orig.as_deref(),
            Some("x/a.txt"),
            "同名多日期取最新(裁决 R7)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clear_tombstones_cleans_recycle_maps() {
        // remove_tombstone_maps 挂点:clear_tombstones_both_forms 后
        // by_name/by_key 与索引同生命周期(单元 3 的 GC 联动同语义)。
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        trash
            .clear_tombstones_if_covered(&fs, "/docs/a.txt")
            .await
            .expect("清墓碑");
        assert!(
            trash.recycle_names.read().unwrap().by_key.is_empty(),
            "by_key 随墓碑清理"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "by_name 随墓碑清理"
        );
    }

    // ===== 单元 2:rename 拦截(目标=软删除 / 源=还原)=====

    /// 目录墓碑 body(mock 对象内容;tombstone_json 仅文件形态)。
    fn tombstone_dir_json(recycle_name: Option<&str>) -> Vec<u8> {
        serde_json::to_vec(&trash::TombstoneBody {
            etag: None,
            size: None,
            is_dir: true,
            recycle_name: recycle_name.map(str::to_string),
            recycle_i: None,
        })
        .unwrap()
    }

    /// 测试 1(P4):rename 目标在回收站条目层、源不在 → 软删,零 copy_object;
    /// 墓碑 body.recycle_name = $R 名(裁决 R2);索引/反向索引(裁决 R3 ①)/
    /// seen_sids(裁决 R14)覆盖;stat 消失。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_into_recycle_soft_deletes_zero_copy() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());

        fs.rename(
            "/docs/a.txt",
            "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
            false,
        )
        .await
        .expect("rename 目标在回收站 = 软删");

        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "P4:软删必须零 copy_object: {recorded:?}"
        );
        let tomb: Vec<_> = recorded
            .iter()
            .filter(|r| r.method == "PUT" && r.target.contains(".trash/"))
            .collect();
        assert_eq!(tomb.len(), 1, "恰好一个墓碑 PUT: {recorded:?}");
        assert!(
            tomb[0]
                .target
                .split('?')
                .next()
                .unwrap()
                .ends_with("/docs/a.txt"),
            "墓碑 key = .trash/<date>/docs/a.txt: {}",
            tomb[0].target
        );
        let body: trash::TombstoneBody = serde_json::from_slice(&tomb[0].body).unwrap();
        assert_eq!(
            body.recycle_name.as_deref(),
            Some("$R4de00001a.txt"),
            "Windows 恒写 $R 名(裁决 R2)"
        );
        assert!(!body.is_dir);
        assert_eq!(body.size, Some(4));
        drop(recorded);

        // 索引与反向索引覆盖(裁决 R3 ①:本地软删写入)
        assert!(
            trash.index.read().unwrap().is_covered("docs/a.txt"),
            "索引覆盖"
        );
        let names = trash.recycle_names.read().unwrap();
        assert!(
            names.by_name["$R4de00001a.txt"].ends_with("/docs/a.txt"),
            "by_name → 墓碑 key"
        );
        assert_eq!(names.by_key["docs/a.txt"], "$R4de00001a.txt");
        drop(names);
        assert!(
            trash.seen_sids.read().unwrap().contains("S-1-5-21-1"),
            "Windows 记录 SID 段(裁决 R14)"
        );
        // stat 消失
        assert!(fs.stat("/docs/a.txt").await.unwrap().is_none());
    }

    /// 测试 1(macOS 变体):rename 目标在 .Trashes → 软删,条目名 = 原名,
    /// recycle_name None(与 basename 一致时 None,渲染回退 basename);零 copy。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_into_recycle_macos_keeps_basename() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());

        fs.rename("/docs/a.txt", "/.Trashes/501/a.txt", false)
            .await
            .expect("macOS rename 目标在 .Trashes = 软删");

        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "P4:软删零 copy_object: {recorded:?}"
        );
        let tomb: Vec<_> = recorded.iter().filter(|r| r.method == "PUT").collect();
        assert_eq!(tomb.len(), 1, "恰好一个墓碑 PUT: {recorded:?}");
        let body: trash::TombstoneBody = serde_json::from_slice(&tomb[0].body).unwrap();
        assert_eq!(
            body.recycle_name, None,
            "与 basename 一致 → None(裁决 R2),渲染回退 basename"
        );
        drop(recorded);
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "macOS 不写反向索引名"
        );
        // 系统视图渲染 = basename(原名)
        let list = fs.list("/.Trashes/501").await.unwrap();
        assert!(
            list.iter().any(|e| e.name == "a.txt" && !e.is_dir),
            "视图条目 = 原名: {list:?}"
        );
    }

    /// 测试 5:目录入回收站 —— allow_rename_dir=false 且 rename_dir_limit=0
    /// 下 rename("/dir", 回收站条目) 仍成功(拦截先于目录 rename 检查,
    /// 限数计数不触发);还原回原路径零 copy(P4)后墓碑清、子树可见。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_dir_into_recycle_ignores_rename_dir_guard() {
        let entries = vec![("dir/".into(), true), ("dir/x.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("dir/x.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        fs.allow_rename_dir = false;
        fs.rename_dir_limit = Some(0); // 若走普通 rename 路径必被拒
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());

        fs.rename("/dir", "/$Recycle.Bin/S-1-5-21-1/$Rdir", false)
            .await
            .expect("目录进回收站 = 软删,拦截先于 allow_rename_dir 检查");

        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "软删零 copy: {recorded:?}"
        );
        let tomb: Vec<_> = recorded.iter().filter(|r| r.method == "PUT").collect();
        assert_eq!(tomb.len(), 1);
        assert!(
            tomb[0].target.split('?').next().unwrap().ends_with("/dir/"),
            "目录墓碑 key 带尾斜杠: {}",
            tomb[0].target
        );
        let body: trash::TombstoneBody = serde_json::from_slice(&tomb[0].body).unwrap();
        assert!(body.is_dir, "目录墓碑");
        drop(recorded);

        // 还原到原路径:零 copy(P4),墓碑清,子树可见
        fs.rename("/$Recycle.Bin/S-1-5-21-1/$Rdir", "/dir", false)
            .await
            .expect("还原目录到原路径");
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "还原到原路径零 copy(P4): {recorded:?}"
        );
        assert!(
            recorded.iter().any(|r| r.method == "DELETE"
                && r.target.contains(".trash/")
                && r.target.split('?').next().unwrap().ends_with("/dir/")),
            "目录墓碑已清: {recorded:?}"
        );
        drop(recorded);
        assert!(fs.stat("/dir").await.unwrap().is_some(), "目录复活");
        let list = fs.list("/dir").await.unwrap();
        assert!(
            list.iter().any(|e| e.name == "x.txt"),
            "还原后子树可见: {list:?}"
        );
    }

    /// 测试 2(P4):rename 源在回收站 → 还原到原路径:零 copy_object、墓碑删、
    /// stat 复活;原对象 404 → OriginalGone 仅清墓碑;同名多日期 → 全部版本
    /// 清除(裁决 R7,clear_target_tombstones 语义)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_restores_in_place_zero_copy() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        mock.set_object("docs/a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.rename(
            "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
            "/docs/a.txt",
            false,
        )
        .await
        .expect("还原到原路径");

        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "P4:还原到原路径零 copy_object: {recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash/2026-08-16/docs/a.txt")),
            "墓碑已删: {recorded:?}"
        );
        drop(recorded);
        assert!(
            !trash.index.read().unwrap().is_covered("docs/a.txt"),
            "索引不再覆盖"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "反向索引随墓碑清理"
        );
        assert!(fs.stat("/docs/a.txt").await.unwrap().is_some(), "stat 复活");
    }

    /// 测试 2(原对象 404):还原时原对象已被 GC/其他端删 → OriginalGone,
    /// 仅清墓碑,stat 仍 None(不留空引用)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_original_gone_clears_tombstone() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        // 无 "docs/a.txt" 对象:模拟 GC 已删原对象
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.rename(
            "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
            "/docs/a.txt",
            false,
        )
        .await
        .expect("原对象 404 → 清墓碑(OriginalGone 语义),不报错");

        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.copy_source.is_some()),
            "OriginalGone 零 copy: {recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash/2026-08-16/docs/a.txt")),
            "墓碑已清(不留空引用): {recorded:?}"
        );
        drop(recorded);
        assert!(
            !trash.index.read().unwrap().is_covered("docs/a.txt"),
            "索引不再覆盖"
        );
        assert!(
            fs.stat("/docs/a.txt").await.unwrap().is_none(),
            "原对象已不存在"
        );
    }

    /// 测试 2(裁决 R7):同名多日期墓碑(先删两次再还原)→ 全部版本清除。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_multiple_versions_clears_all() {
        let entries = vec![
            (".trash/2026-08-15/docs/a.txt".into(), false),
            (".trash/2026-08-16/docs/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        for d in ["2026-08-15", "2026-08-16"] {
            mock.set_object(
                &format!(".trash/{d}/docs/a.txt"),
                tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
            );
        }
        mock.set_object("docs/a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.rename(
            "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
            "/docs/a.txt",
            false,
        )
        .await
        .expect("还原");

        let recorded = mock.recorded.lock().unwrap();
        let tombstone_deletes = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && r.target.contains(".trash/"))
            .count();
        assert_eq!(
            tombstone_deletes, 2,
            "全部日期版本的墓碑都清(裁决 R7): {recorded:?}"
        );
        drop(recorded);
        assert!(
            !trash.index.read().unwrap().is_covered("docs/a.txt"),
            "索引不再覆盖"
        );
        assert!(fs.stat("/docs/a.txt").await.unwrap().is_some());
    }

    /// 测试 3:还原到任意目标 → 1 次 copy_object + 墓碑清;原路径按 copy
    /// 语义复活(规格 §2.2 步骤 4:clear_target_tombstones(original_key))。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_to_arbitrary_path_copies_once() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        mock.set_object("docs/a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.rename(
            "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
            "/elsewhere/b.txt",
            false,
        )
        .await
        .expect("还原到任意目标");

        let recorded = mock.recorded.lock().unwrap();
        let copies = recorded
            .iter()
            .filter(|r| {
                r.method == "PUT"
                    && r.copy_source.is_some()
                    && !r.target.to_lowercase().contains("partnumber")
            })
            .count();
        assert_eq!(copies, 1, "还原到任意目标 = 1 次 copy_object: {recorded:?}");
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash/2026-08-16/docs/a.txt")),
            "墓碑已清: {recorded:?}"
        );
        drop(recorded);
        assert!(
            fs.stat("/elsewhere/b.txt").await.unwrap().is_some(),
            "目标复活"
        );
        let list = fs.list("/elsewhere").await.unwrap();
        assert!(list.iter().any(|e| e.name == "b.txt"), "目标可见: {list:?}");
    }

    /// 测试 3(目录):还原目录到任意目标 → copy_tree + 墓碑清;守卫
    /// allow_rename_dir=false 时拒绝(镜像 rename_impl,规格 §2.2 步骤 4)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_dir_to_arbitrary_copies_tree() {
        let entries = vec![
            (".trash/2026-08-16/dir/".into(), true),
            ("dir/".into(), true),
            ("dir/x.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".trash/2026-08-16/dir/", tombstone_dir_json(Some("$Rdir")));
        mock.set_object("dir/", Vec::new()); // marker 对象存在,拷贝不触发 SDK 重试
        mock.set_object("dir/x.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        let tomb_key = trash::encode_tombstone_key(".trash/", sys_date(), "dir/", true);
        trash
            .index
            .write()
            .unwrap()
            .insert("dir/", true, sys_date());
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rdir".into(), tomb_key);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("dir/".into(), "$Rdir".into());

        fs.rename("/$Recycle.Bin/S-1-5-21-1/$Rdir", "/elsewhere", false)
            .await
            .expect("还原目录到任意目标");

        let recorded = mock.recorded.lock().unwrap();
        let copies = recorded
            .iter()
            .filter(|r| {
                r.method == "PUT"
                    && r.copy_source.is_some()
                    && !r.target.to_lowercase().contains("partnumber")
            })
            .count();
        // mock+SDK 交互:目标键以 '/' 结尾(marker)的 copy 会被重试一次 ——
        // 既有 rename_dir_copies_big_object_via_multipart_copy 断言同形态
        // ("source + dst dir markers" 两拷贝);x.txt 只拷一次。
        assert_eq!(
            copies, 3,
            "marker 两次(mock 重试形态,既有 #60 同)+ x.txt 一次: {recorded:?}"
        );
        let dst_keys: Vec<&str> = recorded
            .iter()
            .filter(|r| r.copy_source.is_some())
            .filter_map(|r| r.target.split('?').next())
            .collect();
        assert!(
            dst_keys.contains(&"/b/elsewhere/") && dst_keys.contains(&"/b/elsewhere/x.txt"),
            "copy 目标覆盖 marker 与 x.txt: {dst_keys:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash/2026-08-16/dir")),
            "目录墓碑已清: {recorded:?}"
        );
        drop(recorded);
        assert!(
            fs.stat("/elsewhere").await.unwrap().is_some(),
            "目标目录复活"
        );
        let list = fs.list("/elsewhere").await.unwrap();
        assert!(
            list.iter().any(|e| e.name == "x.txt"),
            "还原树可见: {list:?}"
        );
        // 源墓碑清后原目录也复活(copy 语义,与文件还原一致)
        assert!(fs.stat("/dir").await.unwrap().is_some());
    }

    /// 测试 3(守卫):目录还原到任意目标受 allow_rename_dir 约束。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_dir_to_arbitrary_honors_rename_dir_guard() {
        let entries = vec![
            (".trash/2026-08-16/dir/".into(), true),
            ("dir/".into(), true),
            ("dir/x.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".trash/2026-08-16/dir/", tombstone_dir_json(Some("$Rdir")));
        mock.set_object("dir/", Vec::new());
        mock.set_object("dir/x.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        fs.allow_rename_dir = false;
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        let tomb_key = trash::encode_tombstone_key(".trash/", sys_date(), "dir/", true);
        trash
            .index
            .write()
            .unwrap()
            .insert("dir/", true, sys_date());
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rdir".into(), tomb_key);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("dir/".into(), "$Rdir".into());

        let err = fs
            .rename("/$Recycle.Bin/S-1-5-21-1/$Rdir", "/elsewhere", false)
            .await
            .expect_err("目录还原到任意目标受 allow_rename_dir 约束");
        assert!(
            err.to_string().contains("directory rename is disabled"),
            "unexpected error: {err:?}"
        );
        // 被拒后墓碑不动、索引覆盖仍在
        assert!(trash.index.read().unwrap().is_covered("dir/"));
    }

    /// 测试 4(裁决 R5):回收站内互相 rename = no-op 成功,零 S3 请求,
    /// 墓碑不动。F14:no-op 前校验源存在 —— 此处种子真实条目;
    /// 幽灵源场景由 system_within_recycle_rename_ghost_source_enoent
    /// 覆盖(ENOENT)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_within_recycle_rename_noop_zero_requests() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$Ra"), Some(1), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$Ra");

        fs.rename(
            "/$Recycle.Bin/S-1-5-21-1/$Ra",
            "/$Recycle.Bin/S-1-5-21-1/$Rb",
            false,
        )
        .await
        .expect("回收站内 rename = no-op 成功(裁决 R5)");
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "WithinRecycle 必须零 S3 请求"
        );
        assert!(
            trash.index.read().unwrap().is_covered("docs/a.txt"),
            "墓碑不动"
        );
    }

    /// 测试 6:涉及回收站目录层本身的 rename(源或目标为 $Recycle.Bin /
    /// SID 目录)→ Err。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_recycle_dir_level_rejected() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));
        for (old, new) in [
            ("/$Recycle.Bin", "/x"),
            ("/$Recycle.Bin/S-1-5-21-1", "/docs"),
            ("/docs", "/$Recycle.Bin/S-1-5-21-1"),
        ] {
            let err = fs
                .rename(old, new, false)
                .await
                .expect_err("回收站目录层 rename 必须拒绝");
            assert!(
                err.to_string().contains("recycle bin directory"),
                "({old} → {new}) unexpected error: {err:?}"
            );
        }
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "被拒路径零 S3 请求"
        );
    }

    /// 测试 8:$I 形态为源 → Err(元数据条目不可还原)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_i_entry_rejected() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));
        let err = fs
            .rename(
                "/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt",
                "/docs/a.txt",
                false,
            )
            .await
            .expect_err("$I 形态为源必须拒绝");
        assert!(err.to_string().contains("$I"), "unexpected error: {err:?}");
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "$I 拒绝路径零 S3 请求"
        );
    }

    /// 测试 8($R 名重复):第二条软删同 recycle_name → by_name 覆盖为最新
    /// (裁决 R7),不静默错删 —— 还原 "$R1.txt" 只动最新墓碑,旧文件仍隐藏。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_duplicate_recycle_name_overwrites_latest() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_object("b.txt", b"b".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());

        fs.rename("/a.txt", "/$Recycle.Bin/S-1-5-21-1/$R1.txt", false)
            .await
            .expect("第一次软删");
        fs.rename("/b.txt", "/$Recycle.Bin/S-1-5-21-1/$R1.txt", false)
            .await
            .expect("第二次软删(同名 $R)");
        let names = trash.recycle_names.read().unwrap();
        assert!(
            names.by_name["$R1.txt"].ends_with("/b.txt"),
            "by_name 覆盖为最新墓碑(裁决 R7)"
        );
        assert_eq!(names.by_key["a.txt"], "$R1.txt", "a 的映射保留");
        assert_eq!(names.by_key["b.txt"], "$R1.txt");
        drop(names);

        // 还原同名条目 → 只还原最新(b),不静默错删 a
        fs.rename("/$Recycle.Bin/S-1-5-21-1/$R1.txt", "/b.txt", false)
            .await
            .expect("还原最新");
        assert!(fs.stat("/b.txt").await.unwrap().is_some(), "b 复活");
        assert!(
            fs.stat("/a.txt").await.unwrap().is_none(),
            "a 仍隐藏 —— 不静默错删"
        );
        let names = trash.recycle_names.read().unwrap();
        assert!(names.by_name.get("$R1.txt").is_none(), "by_name 随墓碑清理");
        assert_eq!(names.by_key["a.txt"], "$R1.txt", "a 的映射保留");
        drop(names);
    }

    // ---------- 单元 3:回收站内删除 = 永久删 ----------

    /// 测试 1(主路径):delete("$Recycle.Bin/S-1/$R..") → 原对象删 + 墓碑删,
    /// 请求序断言(裁决 R6:先 DELETE 原对象,后 DELETE 墓碑);索引/反向索引
    /// 同步清理;$R/$I 条目随之不可见。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_entry_permanent_removes_original_then_tombstone() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("回收站内删除 = 永久删");

        // 请求序(裁决 R6):先 DELETE 原对象,后 DELETE 墓碑
        // (mock target 含 bucket 路径段与 x-id 查询,如
        // "/b/docs/a.txt?x-id=DeleteObject")
        let recorded = mock.recorded.lock().unwrap();
        let deletes: Vec<&MockRequest> = recorded.iter().filter(|r| r.method == "DELETE").collect();
        let orig = deletes
            .iter()
            .position(|r| {
                let t = r.target.split('?').next().unwrap_or(&r.target);
                t.ends_with("/docs/a.txt") && !t.contains(".trash/")
            })
            .expect("原对象 DELETE");
        let tomb = deletes
            .iter()
            .position(|r| r.target.contains(".trash/"))
            .expect("墓碑 DELETE");
        assert!(orig < tomb, "裁决 R6:先原对象后墓碑: {deletes:?}");
        drop(recorded);

        // 效果:原对象与墓碑都被删除;索引与反向索引清空
        assert!(
            !mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "原对象已删"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑已删"
        );
        assert!(
            !trash.index.read().unwrap().is_covered("docs/a.txt"),
            "索引清空"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "by_name 同步清理"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_key.is_empty(),
            "by_key 同步清理"
        );
        // $R 与成对 $I 条目随之不可见($I 由 $R 的墓碑合成,测试 2 语义)
        assert!(
            fs.stat("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
                .await
                .unwrap()
                .is_none(),
            "$R stat None"
        );
        assert!(
            fs.stat("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt")
                .await
                .unwrap()
                .is_none(),
            "$I stat None"
        );
        let err = fs
            .read_range("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt", 0, 10)
            .await
            .expect_err("$I 读 404 语义");
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err:?}"
        );
    }

    /// 测试 1(etag 不一致):其他端改写原对象 → HEAD etag ≠ 墓碑记录 →
    /// warn + 仅删墓碑(原对象孤儿化,不销毁可能存活的数据,裁决 R6)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_entry_etag_mismatch_keeps_original() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        // 其他端改写原对象:HEAD etag(默认 "mock-etag")→ 不一致
        mock.set_etag("docs/a.txt", "other-etag");
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("不一致 → 仅删墓碑");

        assert!(
            mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "etag 不一致:原对象必须保留(孤儿化)"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑仍删"
        );
        // 请求序:原对象无 DELETE(跳过),墓碑 DELETE 照常
        let recorded = mock.recorded.lock().unwrap();
        let deletes: Vec<&MockRequest> = recorded.iter().filter(|r| r.method == "DELETE").collect();
        assert!(
            deletes.iter().all(|r| r.target.contains(".trash/")),
            "仅墓碑 DELETE(原对象跳过): {deletes:?}"
        );
        drop(recorded);
        assert!(!trash.index.read().unwrap().is_covered("docs/a.txt"));
    }

    /// 测试 1(原对象 404):已 GC/其他端删 → HEAD 404 → DELETE 幂等 +
    /// 清墓碑,不留空引用。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_entry_original_404_clears_tombstone() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("404 → 仅清墓碑");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑已清"
        );
        assert!(!trash.index.read().unwrap().is_covered("docs/a.txt"));
    }

    /// 测试 2:$I 形态删除 = no-op(捕获字节随对应 $R 的永久删一并清除)
    /// 且零 S3 请求;unlink($R) 后 $I 读 404/stat None(见测试 1 收尾断言)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_i_entry_noop_zero_requests() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt")
            .await
            .expect("$I 形态删除 no-op");
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "$I no-op 零 S3 请求"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "原对象未动"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑未动"
        );
        assert!(trash.index.read().unwrap().is_covered("docs/a.txt"));
    }

    /// 测试 1(目录形态):unlink 回收站内目录条目 → 无条件递归删原目录
    /// (镜像 rmdir 语义,裁决 R6)+ 清墓碑。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_dir_entry_recurses_original() {
        let entries = vec![
            (".trash/2026-08-16/dir/".into(), true),
            ("dir/".into(), true),
            ("dir/x.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("dir/x.txt", b"x".to_vec());
        mock.set_object(".trash/2026-08-16/dir/", tombstone_dir_json(Some("$Rdir")));
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("dir/", true, sys_date());
            trash.store_index_entries(idx.len());
        }
        trash.recycle_names.write().unwrap().by_name.insert(
            "$Rdir".into(),
            trash::encode_tombstone_key(&trash.prefix, sys_date(), "dir/", true),
        );
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("dir/".into(), "$Rdir".into());

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$Rdir")
            .await
            .expect("目录条目永久删:无条件递归删原子树(镜像 rmdir)");

        assert!(
            !mock.objects.lock().unwrap().contains_key("dir/x.txt"),
            "子树对象已删"
        );
        assert!(
            !mock
                .entries
                .lock()
                .unwrap()
                .iter()
                .any(|(k, _)| k == "dir/"),
            "目录 marker 已删"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/dir/"),
            "目录墓碑已删"
        );
        assert!(!trash.index.read().unwrap().is_covered("dir/"));
    }

    /// 测试 3(清空):delete_dir_recursive("$Recycle.Bin") → 快照索引逐条
    /// 永久删;桶中真实 `$Recycle.Bin/` 杂项对象不被触碰(风险 6 口径);
    /// 幂等重入(索引已空 → 零远程)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_purge_all_clears_tombstones_not_real_objects() {
        let entries = vec![
            (".trash/2026-08-16/docs/a.txt".into(), false),
            (".trash/2026-08-16/dir/".into(), true),
            ("docs/a.txt".into(), false),
            ("dir/".into(), true),
            ("dir/x.txt".into(), false),
            ("$Recycle.Bin/S-1-5-21-1/real.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object("dir/x.txt", b"x".to_vec());
        mock.set_object("$Recycle.Bin/S-1-5-21-1/real.txt", b"real".to_vec());
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        mock.set_object(".trash/2026-08-16/dir/", tombstone_dir_json(Some("$Rdir")));
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("dir/", true, sys_date());
            trash.store_index_entries(idx.len());
        }
        trash.recycle_names.write().unwrap().by_name.insert(
            "$Rdir".into(),
            trash::encode_tombstone_key(&trash.prefix, sys_date(), "dir/", true),
        );
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("dir/".into(), "$Rdir".into());

        fs.delete_dir_recursive("/$Recycle.Bin")
            .await
            .expect("清空整个系统回收站");

        assert!(
            !mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "原文件已删"
        );
        assert!(
            !mock.objects.lock().unwrap().contains_key("dir/x.txt"),
            "目录子树已删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-1/real.txt"),
            "桶中真实 $Recycle.Bin 杂项对象不被触碰(风险 6 口径)"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt")
                && !mock
                    .objects
                    .lock()
                    .unwrap()
                    .contains_key(".trash/2026-08-16/dir/"),
            "全部墓碑清空"
        );
        assert!(trash.index.read().unwrap().is_empty(), "索引清空");
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "by_name 清空"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_key.is_empty(),
            "by_key 清空"
        );
        // 幂等:索引空 → 重入零远程
        let before = mock.recorded.lock().unwrap().len();
        fs.delete_dir_recursive("/$Recycle.Bin")
            .await
            .expect("空回收站再次清空幂等");
        assert_eq!(mock.recorded.lock().unwrap().len(), before, "重入零请求");
    }

    /// F1(high):purge_all 目录分支删除前重查墓碑 body —— 多端交错下
    /// 索引可能陈旧(他端已 restore/GC/永久删),修复前无条件递归删会
    /// 连带删除墓碑消失后他端写入的新数据(数据丢失)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_purge_all_skips_dir_tree_when_tombstone_gone() {
        // 远端墓碑已消失(他端已处理),本端索引陈旧仍覆盖 dir/;
        // 桶中原对象(他端新写入的 x.txt)必须存活 —— 仅清墓碑。
        let entries = vec![("dir/".into(), true), ("dir/x.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("dir/x.txt", b"new-data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("dir/", true, sys_date());
            trash.store_index_entries(idx.len());
        }

        fs.delete_dir_recursive("/$Recycle.Bin")
            .await
            .expect("清空系统回收站");

        assert!(
            mock.objects.lock().unwrap().contains_key("dir/x.txt"),
            "墓碑已消失:原树不得被删(多端交错数据保全)"
        );
        assert!(
            trash.index.read().unwrap().is_empty(),
            "仅清墓碑:索引条目移除"
        );
    }

    /// F1(high):permanent_delete_entry 目录分支同款重查 —— 单端
    /// purge_all 与 restore 交错 / 多端交错均触发。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_permanent_delete_dir_skips_tree_when_tombstone_gone() {
        let entries = vec![("dir/".into(), true), ("dir/x.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("dir/x.txt", b"new-data".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        let tomb_key = trash::encode_tombstone_key(".trash/", sys_date(), "dir/", true);
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("dir/", true, sys_date());
            trash.store_index_entries(idx.len());
        }
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rdir".into(), tomb_key);

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$Rdir")
            .await
            .expect("目录永久删");

        assert!(
            mock.objects.lock().unwrap().contains_key("dir/x.txt"),
            "墓碑已消失:原树不得被删"
        );
        assert!(trash.index.read().unwrap().is_empty(), "索引条目移除");
    }

    /// F2(high):restore_via_system 还原到原 key 子树内/祖先 → 拒绝
    /// (镜像 rename_impl 的子树检查;修复前 new 落子树内 → copy_tree
    /// 自拷贝无限膨胀,还原到祖先 → 拷贝落入源前缀)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_into_own_subtree_or_ancestor_rejected() {
        let entries = vec![
            (".trash/2026-08-16/dir/".into(), true),
            (".trash/2026-08-16/docs/dir/a.txt".into(), false),
            ("dir/".into(), true),
            ("dir/x.txt".into(), false),
            ("docs/dir/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".trash/2026-08-16/dir/", tombstone_dir_json(Some("$Rdir")));
        mock.set_object(
            ".trash/2026-08-16/docs/dir/a.txt",
            tombstone_json(Some("$Rf"), Some(1), None),
        );
        mock.set_object("dir/x.txt", b"x".to_vec());
        mock.set_object("docs/dir/a.txt", b"a".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        // 目录条目:原 key "dir/"(还原进自身子树)
        let tomb_key = trash::encode_tombstone_key(".trash/", sys_date(), "dir/", true);
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("dir/", true, sys_date());
            trash.store_index_entries(idx.len());
        }
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rdir".into(), tomb_key);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("dir/".into(), "$Rdir".into());
        // 文件条目:原 key "docs/dir/a.txt"(还原到自身祖先)
        let tomb_key_f =
            trash::encode_tombstone_key(".trash/", sys_date(), "docs/dir/a.txt", false);
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("docs/dir/a.txt", false, sys_date());
            trash.store_index_entries(idx.len());
        }
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rf".into(), tomb_key_f);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("docs/dir/a.txt".into(), "$Rf".into());

        // 还原进原 key 子树:new = /dir/sub → 拒绝
        let err = fs
            .rename("/$Recycle.Bin/S-1-5-21-1/$Rdir", "/dir/sub", false)
            .await
            .expect_err("还原进自身子树必须拒绝");
        assert!(
            err.to_string().contains("subtree"),
            "unexpected error: {err:?}"
        );
        // 还原到自身祖先:new = /docs/dir → 拒绝
        let err = fs
            .rename("/$Recycle.Bin/S-1-5-21-1/$Rf", "/docs/dir", false)
            .await
            .expect_err("还原到自身祖先必须拒绝");
        assert!(
            err.to_string().contains("subtree"),
            "unexpected error: {err:?}"
        );
        // 拒绝后:墓碑不动、原树完好(零 copy)
        assert!(trash.index.read().unwrap().is_covered("dir/"));
        assert!(trash.index.read().unwrap().is_covered("docs/dir/a.txt"));
        assert!(mock.objects.lock().unwrap().contains_key("dir/x.txt"));
        assert!(
            mock.objects.lock().unwrap().contains_key("docs/dir/a.txt"),
            "还原到祖先被拒:文件不得拷贝到 /docs/dir 覆盖原 key"
        );
    }

    /// F3(medium):rename 拦截分派顺序 —— (Some(Entry), Some(Dir)) 必须被
    /// 「回收站目录层拒绝」分支拦下(修复前被 (Some(Entry), _) 还原分支
    /// 吞掉,restore_via_system 把原对象 copy 到 "$Recycle.Bin" 真实键,
    /// 根列表以真实文件形态覆盖合成目录,Explorer 回收站探测失效)。
    /// 注:entry → 同前缀 SID 目录($R 名所在 SID)会被 rename_impl 更早
    /// 的子树检查拦下,此处用跨 SID 目录(子树检查不命中)触发分派缺陷。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rename_entry_into_recycle_dir_level_rejected() {
        let entries = vec![
            (".trash/2026-08-16/docs/a.txt".into(), false),
            ("docs/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(1), None),
        );
        mock.set_object("docs/a.txt", b"a".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");
        let err = fs
            .rename(
                "/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt",
                "/$Recycle.Bin/S-1-5-21-2",
                false,
            )
            .await
            .expect_err("条目 → 回收站目录层必须拒绝");
        assert!(
            err.to_string().contains("recycle bin directory"),
            "unexpected error: {err:?}"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "拒绝后零 copy:原对象仍在"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-2"),
            "不得把原对象 copy 到回收站目录真实键"
        );
    }

    /// F4(medium):macOS .Trashes 视图内真实对象(.DS_Store,无墓碑)删除
    /// 回退普通 delete —— 修复前 resolve 失败 bail → Finder 清空废纸篓
    /// EIO(stat/read 已有真实对象回退,删除侧补齐对称)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_macos_real_object_in_trash_deletable() {
        let (mock, port) = MockS3::start(
            vec![(".Trashes/501/.DS_Store".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        mock.set_object(".Trashes/501/.DS_Store", b"ds".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", mac_sys()));

        fs.delete("/.Trashes/501/.DS_Store")
            .await
            .expect("macOS 视图内真实对象可删");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".Trashes/501/.DS_Store"),
            "真实对象已删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(".trash/")),
            "真实对象删除不产生墓碑"
        );
    }

    /// F4(medium):Windows 同构 —— 桶中真实 $Recycle.Bin 条目可删除。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_win_real_object_in_recycle_bin_deletable() {
        let (mock, port) = MockS3::start(
            vec![("$Recycle.Bin/S-1-5-21-1/real.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        mock.set_object("$Recycle.Bin/S-1-5-21-1/real.txt", b"real".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));

        fs.delete("/$Recycle.Bin/S-1-5-21-1/real.txt")
            .await
            .expect("Windows 真实条目可删");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-1/real.txt"),
            "真实对象已删"
        );
    }

    /// F5(medium):$I 捕获未解析(历史遗留/捕获丢失的真实 $I 幽灵对象)
    /// delete 回退删除同键真实对象 —— 修复前恒 no-op,幽灵条目不可删。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_ghost_i_entry_removes_real_object() {
        let (mock, port) = MockS3::start(
            vec![("$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        mock.set_object("$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt", b"ghost".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));

        fs.delete("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt")
            .await
            .expect("幽灵 $I 可删");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt"),
            "幽灵真实对象已删"
        );
    }

    /// F5 守卫:对应 $R 墓碑已解析 → $I delete 保持 no-op(捕获字节随
    /// $R 永久删一并清除,零远程)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_i_entry_noop_when_r_tombstone_resolved() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        let before = mock.recorded.lock().unwrap().len();
        fs.delete("/$Recycle.Bin/S-1-5-21-1/$I4de00001a.txt")
            .await
            .expect("$I delete no-op");
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            before,
            "已解析 $I 删除零 S3 请求"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑不动"
        );
    }

    /// F6(medium):还原目标各级祖先被墓碑覆盖 → bail(规格 §2.4:还原进
    /// 已删目录会失败;修复前清墓碑/拷贝静默成功但结果被祖先墓碑隐藏
    /// —— 条目从视图与回收站双消失)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_restore_into_deleted_ancestor_rejected() {
        // 多端:A 删 /docs(目录墓碑仍在)、B 删 /docs/a.txt 并还原 same_place
        let entries = vec![
            (".trash/2026-08-16/docs/".into(), true),
            (".trash/2026-08-16/docs/a.txt".into(), false),
            ("docs/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".trash/2026-08-16/docs/", tombstone_dir_json(None));
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$Rf"), Some(1), None),
        );
        mock.set_object("docs/a.txt", b"a".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("docs/", true, sys_date());
            idx.insert("docs/a.txt", false, sys_date());
            trash.store_index_entries(idx.len());
        }
        let tomb_key = trash::encode_tombstone_key(".trash/", sys_date(), "docs/a.txt", false);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$Rf".into(), tomb_key);
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("docs/a.txt".into(), "$Rf".into());

        let err = fs
            .rename("/$Recycle.Bin/S-1-5-21-1/$Rf", "/docs/a.txt", false)
            .await
            .expect_err("还原进被删祖先必须拒绝");
        assert!(
            err.to_string().contains("trash"),
            "unexpected error: {err:?}"
        );
        assert!(
            trash.index.read().unwrap().is_covered("docs/a.txt"),
            "拒绝后墓碑不动"
        );
    }

    /// F7(medium):full_rebuild diff 新增墓碑读 body 填充 recycle_names
    /// (裁决 R3②)—— 远端软删后本端首次 list 回收站暖路径零逐个 GET。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_full_rebuild_fills_recycle_names_then_list_warm() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(5), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        // 远端软删:本端索引空、反向索引空(未刷新)
        trash.full_rebuild(&fs).await.expect("full_rebuild");
        assert_eq!(
            trash
                .recycle_names
                .read()
                .unwrap()
                .by_name
                .get("$R4de00001a.txt")
                .map(String::as_str),
            Some(".trash/2026-08-16/docs/a.txt"),
            "F7:diff 新增墓碑读 body 填充 by_name"
        );
        let before_gets = count_object_gets(&mock);
        let list = fs.list("/$Recycle.Bin/S-1-5-21-1").await.unwrap();
        assert_eq!(
            count_object_gets(&mock) - before_gets,
            0,
            "F7:暖路径零 body GET(P1)"
        );
        assert!(
            list.iter().any(|e| e.name == "$R4de00001a.txt"),
            "条目可见: {list:?}"
        );
    }

    /// F9(medium):full_rebuild 的 removed 列表走 remove_tombstone_maps
    /// —— 远端 restore/GC 移除的墓碑在 by_name/by_key 不得残留(修复前
    /// 整体换入索引时映射残留:同名 $R 再软删前 resolve 命中陈旧映射)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_full_rebuild_clears_stale_recycle_name_maps() {
        let (_mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        // 本地索引与反向索引有、远端墓碑已无(他端 restore/GC)
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        trash.full_rebuild(&fs).await.expect("full_rebuild");
        assert!(
            trash.recycle_names.read().unwrap().by_name.is_empty(),
            "F9:by_name 无残留"
        );
        assert!(
            trash.recycle_names.read().unwrap().by_key.is_empty(),
            "F9:by_key 无残留"
        );
        assert!(trash.index.read().unwrap().is_empty(), "索引同步移除");
    }

    /// F10(low):桶中真实 $Recycle.Bin 条目列出后 stat/read 可访问
    /// (合成失败落到普通链;修复前 stat None / read bail = 幽灵条目,
    /// 与 macOS 回退不对称)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_win_real_object_in_recycle_bin_openable() {
        let entries = vec![("$Recycle.Bin/S-1-5-21-1/real.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("$Recycle.Bin/S-1-5-21-1/real.txt", b"real-data".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));

        let e = fs
            .stat("/$Recycle.Bin/S-1-5-21-1/real.txt")
            .await
            .unwrap()
            .expect("真实条目可 stat");
        assert_eq!(e.size, 9, "size = 真实对象长度");
        let data = fs
            .read_range("/$Recycle.Bin/S-1-5-21-1/real.txt", 0, 9)
            .await
            .expect("真实条目可读");
        assert_eq!(data, b"real-data");
    }

    /// F13(low):仅剩真实对象(.DS_Store)时 rmdir → ENOTEMPTY(修复前
    /// Ok 但对象残留,下次列表重现)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rmdir_sid_dir_enotempty_when_real_object_remains() {
        let entries = vec![(".Trashes/501/.DS_Store".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".Trashes/501/.DS_Store", b"ds".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", mac_sys()));

        let err = fs
            .delete_dir_recursive("/.Trashes/501")
            .await
            .expect_err("真实对象残留 → ENOTEMPTY");
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err:?}"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(".Trashes/501/.DS_Store"),
            "真实对象不被删除(rmdir 失败语义)"
        );
    }

    /// F14(low):WithinRecycle rename 的幽灵源(无墓碑)→ Err(NotFound);
    /// 存在源场景由 system_within_recycle_rename_noop_zero_requests 保持
    /// Ok 零远程。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_within_recycle_rename_ghost_source_enoent() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(system_trash_state(".trash/", win_sys()));

        let err = fs
            .rename(
                "/$Recycle.Bin/S-1-5-21-1/$Rghost",
                "/$Recycle.Bin/S-1-5-21-1/$Rnew",
                false,
            )
            .await
            .expect_err("幽灵源必须 ENOENT");
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err:?}"
        );
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "F14 拒绝路径零远程"
        );
    }

    /// F16(裁决 R17):范围外 uid 路径 delete 按硬删除 —— 修复前走普通
    /// 软删产生墓碑,经 level-1 全索引遍历渲染进范围内 uid 视图(跨 uid
    /// 数据可见,与 R17「不产生无视图对应的墓碑」冲突)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_out_of_scope_uid_delete_is_hard() {
        let entries = vec![(".Trashes/999/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(".Trashes/999/a.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys()); // macos_uid_dirs=[501]
        fs.trash = Some(trash.clone());

        fs.delete("/.Trashes/999/a.txt")
            .await
            .expect("范围外 uid delete = 硬删除");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".Trashes/999/a.txt"),
            "真实对象已删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(".trash/")),
            "不产生墓碑(无视图对应的墓碑)"
        );
        assert!(trash.index.read().unwrap().is_empty(), "索引无条目");
    }

    /// F16 兜底:macOS level-1 合成渲染按条目所属 uid 段过滤 —— 泄漏
    /// 墓碑(原 key 落在 .Trashes/ 前缀下且 uid 段 ≠ 渲染层)不显示;
    /// 正常数据路径(原 key 在 .Trashes/ 外)不受影响。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_macos_view_filters_foreign_uid_entries() {
        let entries = vec![
            (".trash/2026-08-16/.Trashes/999/a.txt".into(), false),
            (".trash/2026-08-16/docs/b.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/.Trashes/999/a.txt",
            tombstone_json(None, Some(1), None),
        );
        mock.set_object(
            ".trash/2026-08-16/docs/b.txt",
            tombstone_json(None, Some(1), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert(".Trashes/999/a.txt", false, sys_date());
            idx.insert("docs/b.txt", false, sys_date());
            trash.store_index_entries(idx.len());
        }

        let list = fs.list("/.Trashes/501").await.unwrap();
        assert!(
            list.iter().any(|e| e.name == "b.txt"),
            "正常数据路径条目照常渲染: {list:?}"
        );
        assert!(
            !list.iter().any(|e| e.name == "a.txt"),
            "跨 uid 泄漏墓碑不渲染(F16 兜底): {list:?}"
        );
    }

    /// 测试 3(rmdir SID 目录):有残余墓碑 → Err(directory not empty);
    /// 空 → Ok(F13 起含 1 次 max_keys=1 真实对象探测)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_rmdir_sid_dir_enotempty_or_ok() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        seed_system_tombstone(&fs, &trash, "docs/a.txt", "$R4de00001a.txt");

        let err = fs
            .delete_dir_recursive("/$Recycle.Bin/S-1-5-21-1")
            .await
            .expect_err("有残余墓碑 → ENOTEMPTY");
        assert!(
            err.to_string().contains("not empty"),
            "unexpected error: {err:?}"
        );
        // 永久删条目后 rmdir → Ok(含 1 次 max_keys=1 真实对象探测,F13)
        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("先清空条目");
        let before = mock.recorded.lock().unwrap().len();
        fs.delete_dir_recursive("/$Recycle.Bin/S-1-5-21-1")
            .await
            .expect("空 → Ok");
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            before + 1,
            "rmdir 空 SID 目录 = 1 次 max_keys=1 真实对象探测(F13)"
        );
    }

    /// 测试 4(macOS):unlink(".Trashes/501/a.txt") → 永久删;
    /// rmdir(".Trashes/501") 同语义(空 → Ok、有残余 → ENOTEMPTY)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_macos_unlink_rmdir_permanent() {
        let entries = vec![(".trash/2026-08-16/docs/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object(
            ".trash/2026-08-16/docs/a.txt",
            tombstone_json(None, Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", mac_sys());
        fs.trash = Some(trash.clone());
        fs.trash
            .as_ref()
            .unwrap()
            .index
            .write()
            .unwrap()
            .insert("docs/a.txt", false, sys_date());

        fs.delete("/.Trashes/501/a.txt")
            .await
            .expect("macOS unlink = 永久删");
        assert!(
            !mock.objects.lock().unwrap().contains_key("docs/a.txt"),
            "原对象已删"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(".trash/2026-08-16/docs/a.txt"),
            "墓碑已删"
        );
        assert!(trash.index.read().unwrap().is_empty());
        // rmdir(.Trashes/501):索引空 → Ok(含 1 次 max_keys=1 探测,F13)
        let before = mock.recorded.lock().unwrap().len();
        fs.delete_dir_recursive("/.Trashes/501")
            .await
            .expect("空 uid 目录 rmdir Ok");
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            before + 1,
            "rmdir 空 uid 目录 = 1 次 max_keys=1 真实对象探测(F13)"
        );
    }

    /// 测试 5(退化回归):trash 关闭(整体 None)→ 系统前缀退化为普通路径,
    /// delete 直删;trash 开启但 system=None(如 macOS 默认关)→ 软删(现状)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_trash_off_degrades() {
        // 变体 1:trash 整体关闭 → 直删(无墓碑)
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt", b"data".to_vec());
        let fs = test_fs(port, 32); // fs.trash = None
        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("trash 关闭 → 普通 DELETE");
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt"),
            "直删"
        );
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded.iter().all(|r| r.method == "DELETE"),
            "直删无墓碑: {recorded:?}"
        );
        drop(recorded);

        // 变体 2:trash 开启但 system=None → 软删(现状回归)
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt", b"data".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect("trash 开 + system 关 → 软删");
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "PUT" && r.target.contains(".trash/")),
            "软删写墓碑: {recorded:?}"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key("$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt"),
            "原对象保留"
        );
    }

    /// 测试 7(只读回归):只读挂载下回收站内删除被拒(ensure_writable 在
    /// 拦截之前),零 S3 请求。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn system_delete_read_only_rejected_zero_requests() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.read_only = true;
        fs.trash = Some(system_trash_state(".trash/", win_sys()));
        let err = fs
            .delete("/$Recycle.Bin/S-1-5-21-1/$R4de00001a.txt")
            .await
            .expect_err("只读拒绝");
        assert!(
            err.to_string().contains("read-only"),
            "unexpected error: {err:?}"
        );
        assert!(mock.recorded.lock().unwrap().is_empty(), "零 S3 请求");
    }

    /// 测试 6(GC 联动):trash_gc 删过期墓碑后 recycle_names 同步移除
    /// (remove_tombstone_maps 挂点,RecycleNameIndex 与墓碑同生命周期)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_gc_cleans_recycle_name_maps() {
        let old = chrono::NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        let tomb_key = trash::encode_tombstone_key(".trash/", old, "docs/a.txt", false);
        let entries = vec![(tomb_key.clone().into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/a.txt", b"data".to_vec());
        mock.set_object(
            &tomb_key,
            tombstone_json(Some("$R4de00001a.txt"), Some(4), None),
        );
        let mut fs = test_fs(port, 32);
        let trash = system_trash_state(".trash/", win_sys());
        fs.trash = Some(trash.clone());
        {
            let mut idx = trash.index.write().unwrap();
            idx.insert("docs/a.txt", false, old);
            trash.store_index_entries(idx.len());
        }
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_name
            .insert("$R4de00001a.txt".into(), tomb_key.clone());
        trash
            .recycle_names
            .write()
            .unwrap()
            .by_key
            .insert("docs/a.txt".into(), "$R4de00001a.txt".into());

        let report = fs
            .trash_gc(trash::GcOptions {
                before: None,
                dry_run: false,
            })
            .await
            .expect("GC 跑通");
        assert!(
            report.tombstones_deleted > 0,
            "过期墓碑被 GC 删: {report:?}"
        );
        let names = trash.recycle_names.read().unwrap();
        assert!(names.by_name.is_empty(), "by_name 随 GC 清理");
        assert!(names.by_key.is_empty(), "by_key 随 GC 清理");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn list_filter_keeps_remote_cost() {
        // 性能守卫:trash 开启后普通 list 的远程请求数与关闭时一致。
        let entries = vec![
            ("a.txt".into(), false),
            ("docs/".into(), true),
            ("docs/b.txt".into(), false),
            (".trash/2026-08-16/a.txt".into(), false), // 墓碑对象
        ];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        // trash 关闭基线
        let fs = test_fs(port, 32);
        let before = fs.metrics();
        let root = fs.list("/").await.unwrap();
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "基线 list = 1 次 s3 list"
        );
        assert!(root.iter().any(|e| e.name == "a.txt"));
        assert!(root.iter().any(|e| e.name == "docs"));
        // trash 开启 + rebuild
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let count = fs.rebuild_trash_index().await.unwrap();
        assert_eq!(count, 1, "只有文件墓碑被索引");
        let before = fs.metrics();
        let root = fs.list("/").await.unwrap();
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "trash 开启 list 的 s3_lists 增量与关闭时一致(过滤零额外远程成本)"
        );
        assert_eq!(after.s3_heads - before.s3_heads, 0, "list 无 HEAD");
        assert!(!root.iter().any(|e| e.name == "a.txt"), "被删文件隐藏");
        assert!(!root.iter().any(|e| e.name == ".trash"), ".trash 自隐藏");
        assert!(root.iter().any(|e| e.name == "docs"), "docs 可见");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn list_hides_tombstoned_dir() {
        let entries = vec![("docs/".into(), true), ("docs/b.txt".into(), false)];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/docs", true);
        let root = fs.list("/").await.unwrap();
        assert!(
            root.is_empty(),
            "docs common_prefix 与 marker 均隐藏: {:?}",
            root.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        let before = fs.metrics();
        let docs = fs.list("/docs").await.unwrap();
        let after = fs.metrics();
        assert!(docs.is_empty(), "被删目录内容为空: {:?}", docs);
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "过滤在分页循环内,零重分页"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stat_hidden_is_local() {
        // 性能守卫:被删路径 stat 零远程请求(head 都不发),negative cache 续零。
        let entries = vec![("a.txt".into(), false), ("b.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_object("b.txt", b"b".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/a.txt", false);
        let before = fs.metrics();
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "被删路径 stat 零 HEAD");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // negative cache:再次 stat 仍零请求
        let before = fs.metrics();
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // 正向对照:活文件仍走一次 HEAD
        let before = fs.metrics();
        assert!(fs.stat("/b.txt").await.unwrap().is_some());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stat_dir_tombstone_covers_both_forms() {
        // 回归 stat 复活 bug:目录墓碑存 "docs/",stat("/docs") 得 key "docs"。
        let (_mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/docs", true);
        let before = fs.metrics();
        assert!(fs.stat("/docs").await.unwrap().is_none());
        assert!(fs.stat("/docs/").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "双形态均零请求");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_self_hiding() {
        let entries = vec![
            (".trash/2026-08-16/a.txt".into(), false),
            ("a.txt".into(), false),
            ("ossfs/.trash/2026-08-16/a.txt".into(), false),
            ("ossfs/a.txt".into(), false),
        ];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        // 无命名空间变体
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let root = fs.list("/").await.unwrap();
        assert!(
            root.iter().all(|e| e.name != ".trash"),
            "根 list 隐藏 .trash: {:?}",
            root.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert!(root.iter().any(|e| e.name == "a.txt"));
        let before = fs.metrics();
        assert!(
            fs.stat("/.trash").await.unwrap().is_none(),
            "stat 裸 key 形态"
        );
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // 命名空间 prefix 变体
        let mut fs = test_fs(port, 32);
        fs.prefix = "ossfs/".into();
        fs.trash = Some(trash_state("ossfs/.trash/"));
        let root = fs.list("/").await.unwrap();
        assert!(
            root.iter().all(|e| e.name != ".trash"),
            "prefix 变体同样隐藏: {:?}",
            root.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        let before = fs.metrics();
        assert!(fs.stat("/.trash").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rebuild_from_mock() {
        // 特殊字符 key、目录墓碑、垃圾对象(坏日期/裸日期分区/非 trash 前缀)
        let entries = vec![
            (".trash/2026-08-16/a b+c%23.txt".into(), false), // 文件墓碑(特殊字符)
            (".trash/2026-08-16/docs/".into(), true),         // 目录墓碑
            (".trash/bad-date/x.txt".into(), false),          // 垃圾:坏日期
            (".trash/2026-08-16/".into(), false),             // 垃圾:裸日期分区
            ("other/2026-08-16/x.txt".into(), false),         // 非 trash 前缀(列表前缀之外)
            ("a b+c%23.txt".into(), false),                   // 原对象
            ("docs/b.txt".into(), false),                     // 原对象
        ];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let before = fs.metrics();
        let count = fs.rebuild_trash_index().await.unwrap();
        let after = fs.metrics();
        assert_eq!(count, 2, "文件+目录墓碑各一条,垃圾跳过");
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "s3_lists 增量 = 分页数"
        );
        // 过滤生效
        let root = fs.list("/").await.unwrap();
        assert!(
            !root.iter().any(|e| e.name == "a b+c%23.txt"),
            "特殊字符 key 被隐藏"
        );
        assert!(!root.iter().any(|e| e.name == "docs"), "docs 目录被隐藏");
        // 索引内容精确(垃圾未入索引)
        let idx = fs.trash.as_ref().unwrap().index.read().unwrap();
        assert_eq!(idx.files.len(), 1);
        assert!(idx.files.contains_key("a b+c%23.txt"));
        assert_eq!(idx.dirs.len(), 1);
        assert_eq!(idx.dirs[0].0, "docs/");
        drop(idx);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_trash_zero_change() {
        // --no-trash 语义:同一 bucket 含 .trash 内容,trash None → list 返回
        // 全部(回收站关闭则软删除语义不存在),远程成本不变。
        let entries = vec![
            ("a.txt".into(), false),
            (".trash/2026-08-16/a.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        let fs = test_fs(port, 32); // trash = None
        let before = fs.metrics();
        let root = fs.list("/").await.unwrap();
        let after = fs.metrics();
        assert_eq!(after.s3_lists - before.s3_lists, 1);
        assert!(root.iter().any(|e| e.name == "a.txt"));
        assert!(
            root.iter().any(|e| e.name.contains(".trash")),
            "关闭时 .trash 内容可见: {:?}",
            root.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        // stat 不隐藏
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stat_cache_invalidation() {
        let entries = vec![("a.txt".into(), false), ("docs/b.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_object("docs/b.txt", b"b".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        // 正值缓存命中
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        assert!(
            fs.stat("/a.txt").await.unwrap().is_some(),
            "第二次走正值缓存"
        );
        // trash_insert 后立即 None 且零请求
        fs.trash_insert("/a.txt", false);
        let before = fs.metrics();
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "失效后不复活");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // 目录墓碑 insert 后,先前缓存的 "/docs/b.txt" 正值条目被前缀扫描失效
        assert!(fs.stat("/docs/b.txt").await.unwrap().is_some());
        fs.trash_insert("/docs", true);
        let before = fs.metrics();
        assert!(fs.stat("/docs/b.txt").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "目录后代缓存被扫掉");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
    }

    // ===== 单元 2:软删除写墓碑(unlink/rmdir 门控 + 即时索引)=====

    /// 索引含 key 时 soft_delete_file → 幂等 Ok 且零远程请求(性能守卫)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn soft_delete_covered_is_idempotent_zero_remote() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/a.txt", false);
        let before = fs.metrics();
        fs.delete("/a.txt").await.expect("covered → 幂等 Ok");
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
        assert_eq!(after.s3_puts - before.s3_puts, 0);
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        assert!(
            mock.recorded.lock().unwrap().is_empty(),
            "stale handle 二次删除必须零远程"
        );
        // 目录被覆盖同理
        fs.trash_insert("/docs", true);
        let before = fs.metrics();
        fs.delete_dir_recursive("/docs").await.expect("幂等 Ok");
        let after = fs.metrics();
        assert_eq!(after.s3_puts - before.s3_puts, 0);
        assert_eq!(after.s3_lists - before.s3_lists, 0);
    }

    /// 未覆盖路径 write → 请求数与 trash 关闭时一致(清墓碑门控零额外成本)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clear_tombstone_gate_zero_remote() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let before = fs.metrics();
        fs.write("/fresh.txt", b"x").await.expect("write");
        let after = fs.metrics();
        assert_eq!(after.s3_puts - before.s3_puts, 1, "仅一次 PUT");
        assert_eq!(after.s3_lists - before.s3_lists, 0, "未覆盖不扫描墓碑");
        assert_eq!(after.s3_heads - before.s3_heads, 0);
        assert_eq!(
            mock.recorded.lock().unwrap().len(),
            1,
            "与 --no-trash 完全一致的单请求"
        );
    }

    /// unlink → HEAD 原对象(etag/size)→ PUT 墓碑;无 DELETE;原对象仍在;
    /// 挂载视图立即隐藏且 stat 零请求;gauge 与计数器联动。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unlink_writes_tombstone() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));

        fs.delete("/a.txt").await.expect("soft delete");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 2, "HEAD + PUT 墓碑: {recorded:?}");
        assert_eq!(recorded[0].method, "HEAD");
        assert!(recorded[0].target.ends_with("/a.txt"));
        assert_eq!(recorded[1].method, "PUT");
        // SDK 为 PutObject 追加 ?x-id=PutObject 查询串,key 部分按 '?' 剥离
        let put_target = recorded[1]
            .target
            .split('?')
            .next()
            .unwrap_or(&recorded[1].target);
        assert!(
            put_target.contains("/.trash/"),
            "墓碑 key 必须带 .trash 前缀: {}",
            recorded[1].target
        );
        assert!(
            put_target.ends_with("/a.txt"),
            "墓碑 key 以原 key 结尾: {}",
            recorded[1].target
        );
        let body: trash::TombstoneBody = serde_json::from_slice(&recorded[1].body).unwrap();
        assert_eq!(
            body.etag.as_deref(),
            Some("\"mock-etag\""),
            "HEAD 原样 etag"
        );
        assert_eq!(body.size, Some(5), "HEAD content_length");
        assert!(!body.is_dir);
        assert!(
            !recorded.iter().any(|r| r.method == "DELETE"),
            "软删除不得 DELETE 原对象"
        );
        drop(recorded);
        // 原对象仍在桶里
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象必须保留"
        );
        assert_eq!(fs.metrics().trash_tombstones_written, 1, "写墓碑计数");
        assert_eq!(fs.metrics().trash_index_entries, 1, "gauge=1");
        // 视图立即隐藏;再次 stat 走 negative cache,零请求
        let before = fs.metrics();
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "被删路径 stat 零 HEAD");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // list 不含
        let root = fs.list("/").await.unwrap();
        assert!(!root.iter().any(|e| e.name == "a.txt"));
    }

    /// rmdir → 仅一个 PUT 目录墓碑(尾斜杠,{"is_dir":true});无 list、
    /// 无 DeleteObjects(对比原逻辑 list+批删);子树 stat 隐藏零请求。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rmdir_writes_dir_tombstone() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("d/x", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));

        fs.delete_dir_recursive("/d")
            .await
            .expect("soft delete dir");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "仅一个 PUT,无 list、无 DeleteObjects");
        assert_eq!(recorded[0].method, "PUT");
        assert!(recorded[0].target.contains("/.trash/"));
        let put_target = recorded[0]
            .target
            .split('?')
            .next()
            .unwrap_or(&recorded[0].target);
        assert!(
            put_target.ends_with("/d/"),
            "目录墓碑 key 尾斜杠: {}",
            recorded[0].target
        );
        let body: trash::TombstoneBody = serde_json::from_slice(&recorded[0].body).unwrap();
        assert!(body.is_dir);
        assert!(body.etag.is_none() && body.size.is_none());
        drop(recorded);
        assert_eq!(fs.metrics().trash_tombstones_written, 1);
        assert_eq!(fs.metrics().trash_index_entries, 1);
        // 子树隐藏:子文件 stat 零请求
        let before = fs.metrics();
        assert!(fs.stat("/d/x").await.unwrap().is_none());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
        assert_eq!(after.s3_lists - before.s3_lists, 0);
    }

    /// 失败语义:PUT 墓碑失败 → delete Err、索引未 insert(stat 仍可见)、
    /// 无墓碑残留;HEAD 404 → delete Ok 且零墓碑(幂等删除)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn soft_delete_failure_semantics() {
        // ① PUT 全败(10 > SDK 默认 3 次尝试)→ Err
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"x".to_vec());
        mock.fail_put.store(10, Ordering::SeqCst);
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let err = fs.delete("/a.txt").await.unwrap_err();
        assert!(err.to_string().contains("s3 put tombstone"), "{err:?}");
        // 提交点前零副作用:索引未 insert → stat 仍可见(正向 HEAD)
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        // 无墓碑残留
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .keys()
                .any(|k| k.contains(".trash"))
        );
        assert!(
            mock.entries
                .lock()
                .unwrap()
                .iter()
                .all(|(k, _)| !k.contains(".trash"))
        );
        assert_eq!(fs.metrics().trash_tombstones_written, 0);
        // ② HEAD 404 → delete Ok 且零墓碑(幂等删除,不写墓碑隐藏不存在之物)
        mock.recorded.lock().unwrap().clear(); // 清掉 ① 的 HEAD + 失败 PUT 记录
        mock.objects.lock().unwrap().remove("a.txt");
        let mut fs = test_fs(port, 32); // 新实例避免 negative cache 干扰
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("404 → 幂等 Ok");
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded
                .iter()
                .all(|r| r.method != "PUT" || !r.target.contains(".trash")),
            "404 分支不得写墓碑: {recorded:?}"
        );
        assert_eq!(fs.metrics().trash_tombstones_written, 0);
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 同名重建(覆盖语义):write 前清墓碑 → 立即可见;旧内容随覆盖丢失。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recreate_same_name_clears_tombstone() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("soft delete");
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        mock.recorded.lock().unwrap().clear();

        fs.write("/a.txt", b"new").await.expect("recreate");

        let recorded = mock.recorded.lock().unwrap();
        let trash_deletes = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && r.target.contains(".trash"))
            .count();
        assert_eq!(trash_deletes, 1, "清墓碑 DELETE: {recorded:?}");
        let puts = recorded
            .iter()
            .filter(|r| r.method == "PUT" && !r.target.contains(".trash"))
            .count();
        assert_eq!(puts, 1, "新对象 PUT: {recorded:?}");
        drop(recorded);
        assert_eq!(fs.metrics().trash_index_entries, 0, "墓碑已清除");
        // stat/list 立即可见
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        let root = fs.list("/").await.unwrap();
        assert!(root.iter().any(|e| e.name == "a.txt"));
        // 索引 remove 后再次 stat 走正值缓存,零 HEAD
        let before = fs.metrics();
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0);
    }

    /// 裁决 #4 回归:外部客户端直接删远端墓碑后(其他挂载端恢复/管理命令),
    /// 本地索引条目成「幽灵」;同名 write 必须立即可见 —— 清墓碑扫描无命中
    /// 也要无条件移除索引条目(修复前:扫描为空跳过 index.remove,同名重建
    /// 文件最长 600s 全量重建周期后才解除隐藏)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recreate_after_external_tombstone_deleted_is_visible() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("soft delete");
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        assert_eq!(fs.metrics().trash_index_entries, 1);

        // 外部客户端直接删除远端墓碑(mock 移除墓碑对象;索引仍覆盖)
        mock.entries
            .lock()
            .unwrap()
            .retain(|(k, _)| !k.starts_with(".trash/"));
        mock.objects
            .lock()
            .unwrap()
            .retain(|k, _| !k.starts_with(".trash/"));

        fs.write("/a.txt", b"new").await.expect("同名重建");

        assert!(
            fs.stat("/a.txt").await.unwrap().is_some(),
            "外部删墓碑后同名 write 必须立即可见(幽灵索引不得持续隐藏)"
        );
        assert_eq!(
            fs.metrics().trash_index_entries,
            0,
            "幽灵索引条目必须移除并同步 gauge"
        );
    }

    // ===== F1/F2:跨形态同名重建(rmdir 后写文件 / unlink 后建目录)+ mkdir 失败窗口 =====

    /// F1 回归:rmdir /e(目录墓碑 e/)后再写文件 /e —— 目录墓碑前缀覆盖
    /// 新文件 key,修复前 write 只清文件形态(门控 is_file_covered 不含
    /// 目录前缀),新文件写入成功但 list/stat 全部隐藏且无自愈(600s 全量
    /// 重建也救不了,墓碑还在桶里)。修复后清双形态:新文件立即可见,
    /// 索引无幽灵。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cross_form_recreate_file_after_rmdir_visible() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        // rmdir /e → 目录墓碑 e/(空目录也可软删:不 HEAD、不枚举)
        fs.delete_dir_recursive("/e")
            .await
            .expect("soft delete dir");
        assert!(fs.stat("/e").await.unwrap().is_none(), "rmdir 后隐藏");
        assert_eq!(fs.metrics().trash_index_entries, 1);
        mock.recorded.lock().unwrap().clear();

        // 跨形态重建:在目录墓碑上写同名文件
        fs.write("/e", b"new").await.expect("写文件到原目录路径");

        // 目录形态墓碑必须被清除(否则新文件被前缀覆盖隐藏)
        let recorded = mock.recorded.lock().unwrap();
        let dir_tomb_delete = recorded.iter().any(|r| {
            r.method == "DELETE"
                && r.target
                    .split('?')
                    .next()
                    .is_some_and(|t| t.contains(".trash") && t.ends_with("/e/"))
        });
        assert!(dir_tomb_delete, "目录墓碑 e/ 必须被 DELETE: {recorded:?}");
        drop(recorded);
        assert_eq!(fs.metrics().trash_index_entries, 0, "索引无幽灵");
        assert!(fs.stat("/e").await.unwrap().is_some(), "新文件立即可见");
        let root = fs.list("/").await.unwrap();
        assert!(
            root.iter().any(|e| e.name == "e"),
            "list 立即可见: {root:?}"
        );
    }

    /// F1 回归:unlink /e(文件墓碑 e)后再 mkdir /e —— 修复前 mkdir 门控
    /// is_covered(dir_key "e/") 不命中文件墓碑,目录 marker 写入但
    /// stat("/e") 返回 None,目录打不开、rename 被「source path is in
    /// the trash」拦截。修复后清双形态:目录 stat Some、可进入、可写。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cross_form_recreate_dir_after_unlink_usable() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        // unlink 前原对象必须存在(mock 的 HEAD 只对 set_object 过的 key
        // 返回 200,否则软删走 404 幂等分支不写墓碑)
        mock.set_object("e", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/e").await.expect("soft delete file");
        assert!(fs.stat("/e").await.unwrap().is_none(), "unlink 后隐藏");
        assert_eq!(fs.metrics().trash_index_entries, 1);
        mock.recorded.lock().unwrap().clear();

        // 跨形态重建:在文件墓碑上建同名目录
        fs.mkdir("/e").await.expect("mkdir 同名重建");

        // 文件形态墓碑必须被清除(否则 stat("/e") 仍被文件墓碑隐藏)
        let recorded = mock.recorded.lock().unwrap();
        let file_tomb_delete = recorded.iter().any(|r| {
            r.method == "DELETE"
                && r.target
                    .split('?')
                    .next()
                    .is_some_and(|t| t.contains(".trash") && t.ends_with("/e"))
        });
        assert!(file_tomb_delete, "文件墓碑 e 必须被 DELETE: {recorded:?}");
        drop(recorded);
        assert_eq!(fs.metrics().trash_index_entries, 0, "索引无幽灵");
        // 目录可用:stat Some、可进入、可写
        assert!(fs.stat("/e").await.unwrap().is_some(), "目录立即可用");
        assert!(fs.list("/e").await.unwrap().is_empty(), "可进入");
        fs.write("/e/f.txt", b"x").await.expect("目录内可写");
        assert!(fs.stat("/e/f.txt").await.unwrap().is_some());
    }

    /// F2 回归(mkdir 失败窗口):mkdir 的 marker 写失败 → 目录墓碑必须
    /// 保留(软删除不被静默撤销,已删目录不得复活)。修复前:先清墓碑
    /// 再写 marker,写失败后墓碑已被删、已删目录复活且 trash 追踪丢失。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mkdir_failure_keeps_tombstone() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("e/x", b"x".to_vec()); // rmdir 前子树对象
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete_dir_recursive("/e")
            .await
            .expect("soft delete dir");
        assert!(fs.stat("/e").await.unwrap().is_none());
        assert_eq!(fs.metrics().trash_index_entries, 1);
        mock.recorded.lock().unwrap().clear();

        // marker 写失败(10 > 重试上限)
        mock.fail_put.store(10, Ordering::SeqCst);
        let err = fs.mkdir("/e").await.unwrap_err();
        assert!(err.to_string().contains("s3 put"), "{err:?}");

        // 墓碑仍在 → 索引仍覆盖 → 已删目录不得复活
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .any(|k| k.starts_with(".trash/")),
            "mkdir 失败后目录墓碑必须保留(软删除不得被静默撤销)"
        );
        assert_eq!(fs.metrics().trash_index_entries, 1, "索引仍覆盖");
        assert!(
            fs.stat("/e").await.unwrap().is_none(),
            "mkdir 失败后已删目录不得复活"
        );

        // 故障恢复后重试 mkdir 收敛(清墓碑 + marker 写都成功)
        mock.fail_put.store(0, Ordering::SeqCst);
        fs.mkdir("/e").await.expect("重试 mkdir");
        assert!(fs.stat("/e").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 裁决 #8:stat("/d/") 尾斜杠形态先入正值缓存 → soft_delete_dir 后
    /// 双形态都必须立即失效(修复前:soft_delete_dir 只失效裸形态
    /// invalidate_stat("/d") + clear_read_cache,stat("/d/") 缓存条目
    /// 存活至 TTL ≤3s,期间 stat("/d/") 短暂返回存在)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn soft_delete_dir_invalidates_both_stat_forms() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("d/", Vec::new()); // 隐式目录 marker
        let mut fs = test_fs(port, 32);
        fs.stat_ttl = Duration::from_secs(3600); // 冻结 TTL:缓存不自然过期,确定性
        fs.trash = Some(trash_state(".trash/"));
        // 尾斜杠形态正值缓存(远程 marker 存在)
        assert!(fs.stat("/d/").await.unwrap().is_some());
        fs.delete_dir_recursive("/d")
            .await
            .expect("soft delete dir");
        let before = fs.metrics();
        assert!(
            fs.stat("/d/").await.unwrap().is_none(),
            "soft_delete_dir 后 stat(\"/d/\") 尾斜杠形态必须立即失效"
        );
        let after = fs.metrics();
        assert_eq!(after.s3_heads - before.s3_heads, 0, "失效后零请求");
        assert_eq!(after.s3_lists - before.s3_lists, 0);
        // 裸形态同样失效
        assert!(fs.stat("/d").await.unwrap().is_none());
    }

    /// 裁决 #3 回归:同名重建 write 的 PUT 失败 → 墓碑必须保留(软删除
    /// 不被静默撤销)。修复前:先清墓碑再 PUT,PUT 失败后已删文件带旧内容
    /// 永久可见、trash 索引/GC 追踪丢失。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_put_failure_keeps_tombstone() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("soft delete");
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        mock.recorded.lock().unwrap().clear();

        // 之后所有 PUT 失败(10 > SDK 默认 3 次重试)
        mock.fail_put.store(10, Ordering::SeqCst);
        let err = fs.write("/a.txt", b"new").await.unwrap_err();
        assert!(err.to_string().contains("s3 put"), "{err:?}");

        // 墓碑仍在(mock 远端墓碑对象仍在)→ 索引仍覆盖 → 文件仍隐藏
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .any(|k| k.starts_with(".trash/")),
            "write PUT 失败后墓碑必须保留(软删除不得被静默撤销)"
        );
        assert_eq!(fs.metrics().trash_index_entries, 1, "索引仍覆盖(墓碑未清)");
        assert!(
            fs.stat("/a.txt").await.unwrap().is_none(),
            "PUT 失败后已删文件不得复活"
        );

        // 故障恢复后重试 write 收敛(清墓碑 + PUT 都成功)
        mock.fail_put.store(0, Ordering::SeqCst);
        fs.write("/a.txt", b"new").await.expect("重试 write");
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 裁决 #3 回归:目录 rename 目标被墓碑覆盖 + 源超 rename-dir-limit →
    /// 失败检查(count)必须发生在清墓碑之前;超限 bail 后墓碑仍在(修复前:
    /// 先清墓碑再 count,超限 bail 后已删目录子树永久复活、trash 追踪丢失)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_over_limit_keeps_tombstone() {
        let entries = vec![
            ("d/a.txt".to_string(), false),
            ("d/b.txt".to_string(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("d/a.txt", b"x".to_vec());
        mock.set_object("d/b.txt", b"y".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rename_dir_limit = Some(1);
        fs.delete_dir_recursive("/e")
            .await
            .expect("soft delete dir e");
        mock.recorded.lock().unwrap().clear();

        let err = fs.rename("/d", "/e", false).await.unwrap_err();
        assert!(err.to_string().contains("rename-dir-limit"), "{err:?}");
        // 失败检查在清墓碑之前:超限 bail 前不得发生任何 .trash DELETE
        // (锁在作用域块内释放,不跨后续 await 持有)
        {
            let recorded = mock.recorded.lock().unwrap();
            assert!(
                !recorded
                    .iter()
                    .any(|r| r.method == "DELETE" && r.target.contains(".trash")),
                "超限 bail 前不得清墓碑: {recorded:?}"
            );
        }
        // 墓碑仍在 → 索引仍覆盖 → 视图仍隐藏(已删目录不得复活)
        assert_eq!(fs.metrics().trash_index_entries, 1, "目录墓碑索引必须保留");
        assert!(
            fs.stat("/e").await.unwrap().is_none(),
            "rename 超限失败后已删目录不得复活"
        );
    }

    /// rename 源被墓碑覆盖 → Err 且零 copy 请求(隐藏对象不得被搬出)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_source_covered_bails() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_insert("/a.txt", false);

        let err = fs.rename("/a.txt", "/b.txt", false).await.unwrap_err();
        assert!(err.to_string().contains("in the trash"), "{err:?}");
        // guard 不得跨后续锁(同线程重入 std Mutex 自死锁)
        assert!(mock.recorded.lock().unwrap().is_empty(), "bail 前零远程");
        // 目录源被目录墓碑覆盖同样拒绝
        fs.trash_insert("/docs", true);
        mock.recorded.lock().unwrap().clear();
        let err = fs.rename("/docs", "/docs2", false).await.unwrap_err();
        assert!(err.to_string().contains("in the trash"), "{err:?}");
        assert!(mock.recorded.lock().unwrap().is_empty());
    }

    /// rename 目标被墓碑覆盖 → 先清墓碑再 copy,stat(new) 立即可见。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_target_covered_clears_first() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"x".to_vec());
        mock.set_object("b.txt", b"y".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/b.txt").await.expect("soft delete b");
        mock.recorded.lock().unwrap().clear();

        fs.rename("/a.txt", "/b.txt", false)
            .await
            .expect("rename onto covered target");

        let recorded = mock.recorded.lock().unwrap();
        let trash_deletes = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && r.target.contains(".trash"))
            .count();
        assert_eq!(trash_deletes, 1, "提交点前清墓碑: {recorded:?}");
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "PUT" && r.copy_source.is_some()),
            "copy 发生: {recorded:?}"
        );
        drop(recorded);
        // 目标立即可见(旧墓碑已清)
        assert!(fs.stat("/b.txt").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 目录 rename:源树真实 DeleteObjects(尾部删除保持,移动语义不留墓碑);
    /// 目标被目录墓碑覆盖 → 清目录墓碑后成功。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_dir_source_real_delete() {
        let entries = vec![("d/".into(), true), ("d/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("d/", Vec::new());
        mock.set_object("d/a.txt", b"x".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        // 目标 e 已被软删除(目录墓碑)
        fs.delete_dir_recursive("/e").await.expect("soft delete e");
        mock.recorded.lock().unwrap().clear();

        fs.rename("/d", "/e", false)
            .await
            .expect("rename dir onto covered target");

        let recorded = mock.recorded.lock().unwrap();
        // 提交点前清目录墓碑
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash")),
            "清目录墓碑: {recorded:?}"
        );
        // 源树真实批删(移动语义:尾部真实删除,不留目录墓碑)
        let lc = |t: &str| t.to_lowercase();
        let batches = recorded
            .iter()
            .filter(|r| r.method == "POST" && lc(&r.target).contains("delete"))
            .count();
        assert_eq!(batches, 1, "源目录 DeleteObjects 批删: {recorded:?}");
        // 未产生新目录墓碑
        assert_eq!(
            recorded
                .iter()
                .filter(|r| r.method == "PUT" && r.target.contains(".trash"))
                .count(),
            0
        );
        drop(recorded);
        // 目标可见
        assert!(fs.stat("/e").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// C9 裁决回归:WinFsp overwrite 回调经 write_from_file()(独立方法
    /// 不走 write())—— 同名重建同样必须清墓碑。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overwrite_callback_clears_tombstone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"new").expect("spool");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.bin", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.bin").await.expect("soft delete");
        mock.recorded.lock().unwrap().clear();

        fs.write_from_file("/a.bin", &src).await.expect("overwrite");

        let recorded = mock.recorded.lock().unwrap();
        assert_eq!(
            recorded
                .iter()
                .filter(|r| r.method == "DELETE" && r.target.contains(".trash"))
                .count(),
            1,
            "write_from_file 路径必须清墓碑: {recorded:?}"
        );
        drop(recorded);
        assert!(fs.stat("/a.bin").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    // ===== 单元 3:多端同步刷新调度 =====

    /// bootstrap 预置墓碑(文件×2 + 目录×1)→ 过滤生效,s3_lists = 分页数;
    /// gauge 联动。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bootstrap_builds_index() {
        let entries = vec![
            ("a.txt".into(), false),
            ("b.txt".into(), false),
            ("docs/c.txt".into(), false),
            (".trash/2026-08-16/a.txt".into(), false),
            (".trash/2026-08-16/b.txt".into(), false),
            (".trash/2026-08-16/docs/".into(), true),
        ];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let before = fs.metrics();
        fs.trash_bootstrap().await.expect("bootstrap");
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            1,
            "bootstrap = 单页 1 次 list"
        );
        assert_eq!(after.trash_index_entries, 3, "gauge = 3 条墓碑");
        // 过滤生效:文件/目录墓碑与 .trash 自隐藏,活文件可见
        let root = fs.list("/").await.unwrap();
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"a.txt"), "被删文件隐藏: {names:?}");
        assert!(!names.contains(&"b.txt"));
        assert!(!names.contains(&"docs"), "目录墓碑隐藏 common_prefix");
        assert!(!names.contains(&".trash"), ".trash 自隐藏");
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        assert!(fs.stat("/b.txt").await.unwrap().is_none());
        assert!(fs.stat("/docs").await.unwrap().is_none());
    }

    /// 两个挂载实例共享同一 mock(各自独立 index/cursor):A 删除 → A 即时
    /// 隐藏;B 未刷新仍可见;第一次增量后 B 隐藏;**第二次刷新的 start-after
    /// 列表 == 第一轮游标(游标推进正确)**;**同分区先删 z 再删 a 的字典序
    /// 逆序新墓碑不得被游标漏掉(裁决 #2:增量轮次对当前 UTC 日期分区
    /// 始终完整扫描)**。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_instance_incremental_sync() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("z.txt", b"zz".to_vec());
        mock.set_object("a.txt", b"aa".to_vec());
        let mut a = test_fs(port, 32);
        let mut b = test_fs(port, 32);
        a.trash = Some(trash_state(".trash/"));
        b.trash = Some(trash_state(".trash/"));
        a.trash_bootstrap().await.expect("A bootstrap");
        b.trash_bootstrap().await.expect("B bootstrap");

        // 同分区先删 z 再删 a:游标推进到 z 墓碑后,字典序更小的 a 墓碑
        // 不得被 start-after 游标永远跳过(修复前 a.txt 最长 600s 不可见)
        a.delete("/z.txt").await.expect("A soft delete z");
        assert!(a.stat("/z.txt").await.unwrap().is_none(), "A 立即隐藏");
        assert!(
            b.stat("/z.txt").await.unwrap().is_some(),
            "B 未刷新前仍可见(多端窗口)"
        );
        // B 第一次增量刷新(bootstrap 时桶空,游标 None)
        b.trash_refresh_once().await.expect("B 第一次增量");
        assert!(b.stat("/z.txt").await.unwrap().is_none(), "B 增量后 z 隐藏");
        assert_eq!(b.metrics().trash_refresh_incrementals, 1);

        // 墓碑 key = A 的 PUT target(剥离查询串与桶前缀)
        let z_tomb_key: String = {
            let recorded = mock.recorded.lock().unwrap();
            let put = recorded
                .iter()
                .find(|r| r.method == "PUT" && r.target.contains(".trash"))
                .expect("A 写墓碑");
            let target = put.target.split('?').next().unwrap();
            target
                .split(".trash/")
                .nth(1)
                .map(|k| format!(".trash/{k}"))
                .expect("target 含 .trash 前缀")
        };
        // 游标推进断言:第二轮刷新的 start-after 列表 == 第一轮游标(z 墓碑
        // key);今天分区完整扫描的列表不带 start-after,不计入。锁在块内
        // 释放,不得跨后续 await 持有(mock 请求记录锁由连接任务使用)。
        let second_lists: Vec<String>;
        {
            let lists_before = mock.requests.lock().unwrap().len();
            b.trash_refresh_once().await.expect("B 第二次刷新");
            let requests = mock.requests.lock().unwrap();
            second_lists = requests[lists_before..]
                .iter()
                .filter(|t| t.contains("list-type=2") && t.contains("start-after="))
                .cloned()
                .collect();
        }
        assert_eq!(
            second_lists.len(),
            1,
            "第二轮刷新恰好 1 次 start-after 增量列表"
        );
        let sa = second_lists[0]
            .split("start-after=")
            .nth(1)
            .map(|v| v.split('&').next().unwrap())
            .unwrap_or("");
        let sa_decoded = sa.replace("%2F", "/").replace("%20", " ");
        assert_eq!(
            sa_decoded, z_tomb_key,
            "第二轮刷新的 start-after == 第一轮游标(z 墓碑 key)"
        );
        assert_eq!(b.metrics().trash_refresh_incrementals, 2);

        // 同分区新墓碑(字典序 ≤ 游标):A 再删 a.txt,B 必须感知 ——
        // 增量轮次对当前 UTC 日期分区始终完整扫描(裁决 #2)
        a.delete("/a.txt").await.expect("A soft delete a");
        assert!(
            b.stat("/a.txt").await.unwrap().is_some(),
            "B 未刷新前仍可见(多端窗口)"
        );
        b.trash_refresh_once().await.expect("B 第三轮刷新");
        assert!(
            b.stat("/a.txt").await.unwrap().is_none(),
            "同日新墓碑必须被 B 感知:游标不得漏掉字典序更小的新墓碑"
        );
        assert!(b.stat("/z.txt").await.unwrap().is_none());
    }

    /// 其他端恢复:远端墓碑被外部 DELETE → 全量重建 diff 移除 → 本端复活
    /// (缓存失效纪律:不复活则 stats 正向缓存旧文件仍可见);未刷新的 A
    /// 仍隐藏。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn external_delete_surfaces_on_full_rebuild() {
        let entries = vec![(".trash/2026-08-16/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut a = test_fs(port, 32);
        let mut b = test_fs(port, 32);
        a.trash = Some(trash_state(".trash/"));
        b.trash = Some(trash_state(".trash/"));
        a.trash_bootstrap().await.expect("A bootstrap");
        b.trash_bootstrap().await.expect("B bootstrap");
        assert!(a.stat("/a.txt").await.unwrap().is_none());
        assert!(b.stat("/a.txt").await.unwrap().is_none());

        // 外部恢复:远端墓碑被删(mock entries 移除墓碑对象)
        mock.entries
            .lock()
            .unwrap()
            .retain(|(k, _)| !k.starts_with(".trash/"));

        // B 强制到全量重建周期 → refresh_once 走 full_rebuild → diff 移除
        {
            let t = b.trash.as_ref().unwrap();
            *t.last_full_rebuild.lock().unwrap() = Instant::now()
                .checked_sub(Duration::from_secs(601))
                .unwrap();
        }
        b.trash_refresh_once().await.expect("full rebuild");
        assert_eq!(b.metrics().trash_refresh_rebuilds, 1);
        assert_eq!(b.metrics().trash_index_entries, 0, "diff 移除墓碑");
        assert!(
            b.stat("/a.txt").await.unwrap().is_some(),
            "B 全量重建后复活(缓存已失效)"
        );
        // A 未刷新仍隐藏
        assert!(a.stat("/a.txt").await.unwrap().is_none());
    }

    /// eager 档:远端写墓碑后本端一次 list 即隐藏(先拉后滤);节流 ≥1s:
    /// 连续 100 次 list 的增量拉取 ≤ 上界;lazy 下 list 请求数与关闭时
    /// 一致(性能守卫:lazy 零额外远程成本)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eager_throttles() {
        let (mock, port) = MockS3::start(
            vec![("a.txt".into(), false), ("b.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_object("b.txt", b"b".to_vec());
        let mut eager = test_fs(port, 32);
        let mut state = trash_state(".trash/");
        Arc::get_mut(&mut state).expect("独占引用").mode = TrashRefreshMode::Eager;
        eager.trash = Some(state);
        eager.trash_bootstrap().await.expect("bootstrap");

        // 其他端删除 b.txt:只写墓碑对象(远端状态),本端索引未感知
        mock.entries
            .lock()
            .unwrap()
            .push((".trash/2026-08-16/b.txt".into(), false));
        // 一次 list 即隐藏(先拉后滤)
        let root = eager.list("/").await.unwrap();
        assert!(
            !root.iter().any(|e| e.name == "b.txt"),
            "eager 一次 list 即感知远端墓碑"
        );
        assert!(root.iter().any(|e| e.name == "a.txt"), "活文件仍可见");
        let incr_after_one = eager.metrics().trash_refresh_incrementals;

        // 连续 100 次 list:节流不变量为「每 1s 至多一次增量拉取」—— 断言
        // 随真实墙钟缩放(满载 CI 下 100 次 list 可能超过 1s,固定上界会
        // 误报 flake;按 elapsed 秒 + 1 的上界仍精确验证节流)。
        let tick_start = Instant::now();
        for _ in 0..100 {
            let _ = eager.list("/").await.unwrap();
        }
        let bound = tick_start.elapsed().as_secs() + 1;
        let incr_delta = eager.metrics().trash_refresh_incrementals - incr_after_one;
        assert!(
            incr_delta <= bound,
            "节流必须 ≤ 每秒一次:100 次 list 增量 {incr_delta} 次,墙钟上界 {bound}"
        );

        // lazy 性能守卫:mode=lazy 时 list 的 s3_lists 增量 == 关闭时
        let mut lazy = test_fs(port, 32);
        lazy.trash = Some(trash_state(".trash/"));
        let base = lazy.metrics().s3_lists;
        for _ in 0..10 {
            let _ = lazy.list("/").await.unwrap();
        }
        assert_eq!(
            lazy.metrics().s3_lists - base,
            10,
            "lazy 下 list 无额外远程成本"
        );

        // 阳性对照(裁决 #1):eager + ignore_start_after(降级)下,全量重建
        // 次数受 last_full_rebuild 周期节流 —— 连续多轮 eager poll 至多
        // 一次全量(修复前:降级分支每轮都 full_rebuild,5 轮 poll = 5 次
        // 全量,每分钟 ~60 次全量 ≈ 3000 次 list/分)。
        mock.ignore_start_after.store(true, Ordering::SeqCst);
        let rebuilds_before = eager.metrics().trash_refresh_rebuilds;
        {
            let t = eager.trash.as_ref().unwrap();
            *t.last_full_rebuild.lock().unwrap() = Instant::now()
                .checked_sub(Duration::from_secs(601))
                .unwrap();
        }
        let tick_start = Instant::now();
        for _ in 0..5 {
            // 手动拨快 eager 节流戳:绕过 1s 节流,保证 5 轮都真正执行 poll
            {
                let t = eager.trash.as_ref().unwrap();
                *t.last_eager_poll.lock().unwrap() =
                    Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
            }
            let _ = eager.list("/").await.unwrap();
        }
        let rebuild_delta = eager.metrics().trash_refresh_rebuilds - rebuilds_before;
        // 节流断言随真实墙钟缩放(LESSON):全量重建 ≤ 每 rebuild_interval 一次
        let bound = tick_start.elapsed().as_secs() / TRASH_REBUILD_INTERVAL_SECS + 1;
        assert!(
            rebuild_delta <= bound,
            "降级 eager 全量重建必须受周期节流:5 轮 poll 全量 {rebuild_delta} 次,上界 {bound}(修复前为 5)"
        );
    }

    /// 裁决 #10:清墓碑按日期分区反向扫描(先查今天分区)—— 请求数从
    /// O(墓碑总数/页) 收紧为 O(分区数);全量覆盖(不做「首个命中即停」:
    /// 旧分区残留墓碑会让已提交写入在下次刷新后重新隐藏);今天分区最先
    /// 探测。修复前:全量分页枚举 .trash(1 次 list),本测试断言
    /// 1+2×分区数次列表(文件+目录双形态,常量因子)与探测顺序,旧实现
    /// 必红。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clear_tombstones_partition_scan_bounded_and_full_coverage() {
        let today = trash::date_partition_utc(std::time::SystemTime::now());
        let yesterday = today.pred_opt().expect("today 非纪元首日");
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"old".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        // 今天分区墓碑(软删除真实写入)+ 昨天分区墓碑 + 无关墓碑
        fs.delete("/a.txt").await.expect("soft delete");
        mock.recorded.lock().unwrap().clear();
        let old_tomb = format!(".trash/{yesterday}/a.txt");
        mock.set_object(&old_tomb, br#"{"is_dir":false}"#.to_vec());
        mock.entries.lock().unwrap().push((old_tomb, false));
        let unrelated = format!(".trash/{today}/b.txt");
        mock.set_object(&unrelated, br#"{"is_dir":false}"#.to_vec());
        mock.entries
            .lock()
            .unwrap()
            .push((unrelated.clone(), false));
        let today_tomb = format!(".trash/{today}/a.txt");

        fs.write("/a.txt", b"new").await.expect("同名重建");

        let recorded = mock.recorded.lock().unwrap();
        // 全量覆盖:两个分区的同名墓碑都必须删除;无关墓碑保留
        let trash_deletes: Vec<&str> = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && r.target.contains(".trash"))
            .map(|r| {
                r.target
                    .split('?')
                    .next()
                    .unwrap_or(&r.target)
                    .split(".trash/")
                    .nth(1)
                    .unwrap_or("")
            })
            .collect();
        assert_eq!(
            trash_deletes.len(),
            2,
            "跨分区同名墓碑全清: {trash_deletes:?}"
        );
        assert!(
            trash_deletes.iter().any(|k| *k == format!("{today}/a.txt")),
            "今天分区墓碑被删: {trash_deletes:?}"
        );
        assert!(
            trash_deletes
                .iter()
                .any(|k| *k == format!("{yesterday}/a.txt")),
            "旧分区墓碑被删: {trash_deletes:?}"
        );
        drop(recorded);
        assert!(
            mock.objects.lock().unwrap().contains_key(&unrelated),
            "无关墓碑不得误删"
        );
        // 请求数有界:1 次分区枚举(delimiter)+ 分区数 × 2 形态(文件 +
        // 目录)探测 —— 与墓碑总数无关,仅双形态常量因子(修复前单形态
        // 为 1 次全量分页枚举,本断言约束 O(分区数) 上界不回归)
        let lists: Vec<String> = mock
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.contains("list-type=2"))
            .cloned()
            .collect();
        assert_eq!(
            lists.len(),
            5,
            "1 delimiter 枚举 + 2 分区 × 2 形态探测: {lists:?}"
        );
        assert!(
            lists[0].contains("delimiter="),
            "第一笔必须是分区枚举(delimiter): {lists:?}"
        );
        // 反向顺序:今天分区最先探测
        let today_idx = lists
            .iter()
            .position(|t| t.contains(&format!("prefix=")) && t.contains(&today.to_string()))
            .expect("今天分区探测存在");
        let yesterday_idx = lists
            .iter()
            .position(|t| t.contains(&yesterday.to_string()))
            .expect("旧分区探测存在");
        assert!(today_idx < yesterday_idx, "今天分区必须最先探测: {lists:?}");
        // 重建后立即可见,gauge 归零
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 裁决 #7:refresh_once 入口统一 poll_inflight 互斥 —— 周期循环与
    /// eager 挂点共用一把锁(失败即跳过,天然限 1)。占住互斥位时周期
    /// 刷新必须零远程请求(修复前:eager 挂点与周期 refresh_loop 可并发
    /// refresh_once,两轮全量 list + 双倍 S3 成本)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refresh_once_skips_when_inflight_held() {
        let (mock, port) = MockS3::start(
            vec![(".trash/2026-08-16/a.txt".into(), false)],
            Duration::from_millis(1),
        )
        .await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_bootstrap().await.expect("bootstrap");
        // 模拟并发中的增量/重建:占住互斥位
        fs.trash
            .as_ref()
            .unwrap()
            .poll_inflight
            .store(true, Ordering::SeqCst);
        let before = fs.metrics();
        fs.trash_refresh_once()
            .await
            .expect("占锁时刷新必须静默跳过(Ok)");
        let after = fs.metrics();
        assert_eq!(
            after.s3_lists - before.s3_lists,
            0,
            "占锁时周期刷新必须零远程列表(与 eager 共用 poll_inflight)"
        );
        assert_eq!(
            after.trash_refresh_incrementals - before.trash_refresh_incrementals,
            0,
            "占锁时不得计数增量"
        );
        assert_eq!(
            after.trash_refresh_rebuilds - before.trash_refresh_rebuilds,
            0,
            "占锁时不得计数全量重建"
        );
        // 释放后恢复正常刷新
        fs.trash
            .as_ref()
            .unwrap()
            .poll_inflight
            .store(false, Ordering::SeqCst);
        fs.trash_refresh_once().await.expect("释放后刷新正常");
    }

    /// 刷新失败不拖垮挂载:强制 trash list 报错(分页无 token 护栏)→
    /// refresh_once Err + trash_refresh_errors 计数;故障恢复后上层
    /// list/stat 正常、索引未被破坏;下一轮刷新自愈。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refresh_failure_does_not_fail_mount() {
        let entries = vec![(".trash/2026-08-16/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.trash_bootstrap().await.expect("bootstrap");

        // 截断无 continuation token → next_page_token 护栏 bail(等价 list 故障)
        mock.list_truncated_no_token.store(true, Ordering::SeqCst);
        let err = fs
            .trash_refresh_once()
            .await
            .expect_err("截断无 token 必须报错");
        assert!(
            err.to_string().contains("continuation token"),
            "next_page_token 护栏: {err:?}"
        );
        assert_eq!(fs.metrics().trash_refresh_errors, 1);

        // 故障恢复:上层操作正常,索引未被故障破坏(墓碑仍隐藏)
        mock.list_truncated_no_token.store(false, Ordering::SeqCst);
        let root = fs.list("/").await.unwrap();
        assert!(!root.iter().any(|e| e.name == "a.txt"));
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        // 下一轮刷新自愈
        fs.trash_refresh_once().await.expect("刷新自愈");
    }

    /// start-after 自动探测降级:mock 忽略 start-after(返回全部 key)→
    /// 当轮 start_after_supported=false、转全量重建、计数联动;后续每轮
    /// 退化为全量(正确性不损)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn start_after_detection_degrades() {
        let entries = vec![(".trash/2026-08-16/a.txt".into(), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        // 先 bootstrap(游标 = 最后 key);再让 store 忽略 start-after
        fs.trash_bootstrap().await.expect("bootstrap");
        mock.ignore_start_after.store(true, Ordering::SeqCst);
        fs.trash_refresh_once().await.expect("降级全量必须成功");
        let m = fs.metrics();
        assert_eq!(m.trash_start_after_ignored, 1, "探测计数");
        assert_eq!(m.trash_refresh_rebuilds, 1, "降级当轮计入全量重建");
        assert!(
            !fs.trash
                .as_ref()
                .unwrap()
                .start_after_supported
                .load(Ordering::SeqCst),
            "探测后 start_after_supported=false"
        );
        // 后续刷新退化为「今天分区扫描 + 周期节流全量」(裁决 #1):
        // 探测当轮的全量重建已重置 last_full_rebuild,非到期轮不再重复
        // 全量(修复前:每轮都 full_rebuild,降级 eager 每分钟数百次全量)
        fs.trash_refresh_once().await.expect("降级后的刷新");
        assert_eq!(
            fs.metrics().trash_refresh_rebuilds,
            1,
            "降级全量受 last_full_rebuild 周期节流(600s 内至多一次)"
        );
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
    }

    // ---------- 单元 4:管理命令与 GC ----------

    fn days_before(n: u32) -> chrono::NaiveDate {
        trash::date_partition_utc(std::time::SystemTime::now())
            .checked_sub_days(chrono::Days::new(n as u64))
            .unwrap()
    }

    fn days_after(n: u32) -> chrono::NaiveDate {
        trash::date_partition_utc(std::time::SystemTime::now())
            .checked_add_days(chrono::Days::new(n as u64))
            .unwrap()
    }

    /// 文件墓碑 body 写入 mock(etag 来自删除时 HEAD 的形态,含引号)。
    fn seed_tombstone(mock: &MockS3, tomb_key: &str, body: &trash::TombstoneBody) {
        mock.set_object(
            tomb_key,
            serde_json::to_vec(body).expect("tombstone body json"),
        );
    }

    /// 恢复三分支 ①:正常恢复 —— 墓碑删、原对象保留、索引 remove 后
    /// is_covered=false、invalidate 后立即可见;无 date 全量扫描与
    /// --date 快速路径均恢复。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restore_normal_branch() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("软删");
        assert!(fs.stat("/a.txt").await.unwrap().is_none(), "软删后隐藏");
        let today = trash::date_partition_utc(std::time::SystemTime::now());

        // 无 date → find_tombstone 全量扫描
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: false,
            }
        );
        let recorded = mock.recorded.lock().unwrap();
        let tomb_deletes: Vec<_> = recorded
            .iter()
            .filter(|r| r.method == "DELETE" && r.target.contains(".trash/"))
            .collect();
        assert_eq!(tomb_deletes.len(), 1, "墓碑被删: {recorded:?}");
        drop(recorded);
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象保留"
        );
        assert!(fs.stat("/a.txt").await.unwrap().is_some(), "恢复后立即可见");
        assert_eq!(fs.metrics().trash_index_entries, 0, "索引 remove");

        // --date 快速路径
        fs.delete("/a.txt").await.expect("再软删");
        let out = fs.trash_restore("/a.txt", Some(today)).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: false,
            }
        );
        assert!(fs.stat("/a.txt").await.unwrap().is_some());
        // 目录墓碑恢复:无需 HEAD,删墓碑即恢复
        fs.delete_dir_recursive("/docs").await.expect("软删目录");
        assert!(fs.stat("/docs").await.unwrap().is_none());
        let out = fs.trash_restore("/docs", None).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: false,
            }
        );
        assert_eq!(fs.metrics().trash_index_entries, 0, "目录索引 remove");
    }

    /// 恢复三分支 ②:etag 不一致(其他端覆盖同名 key)→ 警告后默认仍
    /// 恢复(恢复的是当前内容),outcome.etag_mismatch=true。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restore_etag_mismatch_branch() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("软删"); // 墓碑 etag = "mock-etag"
        mock.set_etag("a.txt", "changed-by-other-end"); // 其他端覆盖
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: true,
                multiple_versions: false,
            },
            "etag 不一致仍恢复,但必须标记"
        );
        assert!(
            fs.stat("/a.txt").await.unwrap().is_some(),
            "恢复的是当前内容"
        );
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            recorded
                .iter()
                .any(|r| r.method == "DELETE" && r.target.contains(".trash/")),
            "墓碑仍被删: {recorded:?}"
        );
        drop(recorded);
        assert_eq!(fs.metrics().trash_index_entries, 0);
    }

    /// 恢复三分支 ③:原对象 HEAD 404(已被 GC/其他端删除)→ OriginalGone,
    /// 墓碑被清、桶内不留空引用;④:无墓碑 → NoTombstone 且零删除请求。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restore_original_gone_and_no_tombstone() {
        // ③ 原对象 404
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("软删");
        mock.objects.lock().unwrap().remove("a.txt"); // 其他端/GC 已删原对象
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(out, trash::RestoreOutcome::OriginalGone);
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(".trash/")),
            "404 分支必须清墓碑,不留空引用"
        );
        assert_eq!(fs.metrics().trash_index_entries, 0);
        assert!(fs.stat("/a.txt").await.unwrap().is_none());

        // ④ 无墓碑
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let out = fs.trash_restore("/nope.txt", None).await.unwrap();
        assert_eq!(out, trash::RestoreOutcome::NoTombstone);
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| r.method == "DELETE"
                || (r.method == "POST" && r.target.to_lowercase().contains("delete"))),
            "无墓碑零删除请求: {recorded:?}"
        );
    }

    /// find_tombstone:文件/目录两形匹配;外部杂项 key(坏日期)跳过;
    /// date Some 快速路径直查两形;date None 全量扫描。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn find_tombstone_matches_both_forms() {
        let d = days_before(31);
        let entries = vec![
            (format!(".trash/{d}/a.txt"), false),
            (format!(".trash/{d}/docs/"), true),
            (".trash/garbage/x.txt".into(), false), // 外部杂项 key → decode 跳过
        ];
        let (_mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let trash_state = fs.trash.clone().unwrap();
        // 文件形
        let hit = trash_state
            .find_tombstone(&fs, "a.txt", None)
            .await
            .unwrap();
        assert_eq!(hit, vec![(d, false)], "文件墓碑命中");
        // 目录形(输入无尾斜杠 → 匹配 key+"/")
        let hit = trash_state.find_tombstone(&fs, "docs", None).await.unwrap();
        assert_eq!(hit, vec![(d, true)], "目录墓碑命中");
        // 未命中
        assert!(
            trash_state
                .find_tombstone(&fs, "nope.txt", None)
                .await
                .unwrap()
                .is_empty()
        );
        // date 快速路径
        let hit = trash_state
            .find_tombstone(&fs, "a.txt", Some(d))
            .await
            .unwrap();
        assert_eq!(hit, vec![(d, false)], "date 快速路径");
        assert!(
            trash_state
                .find_tombstone(&fs, "a.txt", Some(days_before(29)))
                .await
                .unwrap()
                .is_empty(),
            "错误日期不命中"
        );
    }

    /// L6 回归:同名多日期墓碑下 trash-restore 无 --date —— 恢复最旧一条
    /// 并标记 multiple_versions(CLI 据此提示用 --date 指定版本),较新
    /// 墓碑保留 —— 否则 CLI 报「已恢复」而 key 仍被较新墓碑隐藏。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restore_without_date_reports_multiple_versions() {
        let d_old = days_before(20);
        let d_new = days_before(3);
        let entries = vec![
            (format!(".trash/{d_old}/a.txt"), false),
            (format!(".trash/{d_new}/a.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_etag("a.txt", "mock-etag");
        for key in [
            format!(".trash/{d_old}/a.txt"),
            format!(".trash/{d_new}/a.txt"),
        ] {
            seed_tombstone(
                &mock,
                &key,
                &trash::TombstoneBody {
                    etag: Some("\"mock-etag\"".into()),
                    size: Some(1),
                    is_dir: false,
                    recycle_name: None,
                    recycle_i: None,
                },
            );
        }
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        // 无 --date:恢复最旧一条 + multiple_versions 标记
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: true,
            },
            "多版本必须标记(L6)"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/a.txt")),
            "最旧墓碑被清"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_new}/a.txt")),
            "较新墓碑保留(key 仍被隐藏,提示用户用 --date)"
        );
        // --date 精确指定:恢复较新版本,单命中无标记
        let out = fs.trash_restore("/a.txt", Some(d_new)).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: false,
            }
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_new}/a.txt")),
            "--date 指定的版本墓碑被清"
        );
        // 全部墓碑已清后 NoTombstone
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(out, trash::RestoreOutcome::NoTombstone);
    }

    /// L7 语义钉:--before 晚于默认保留期 → 无效(cutoff 仍为 today-
    /// retention,只收紧不放松)—— 31 天前墓碑仍被清(30 天保留),29 天
    /// 前保留;用户以为「清 8/1 前」实际只清保留期之前。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_before_later_than_retention_is_ignored() {
        let d_31 = days_before(31);
        let d_29 = days_before(29);
        let entries = vec![
            (format!(".trash/{d_31}/a.txt"), false),
            (format!(".trash/{d_29}/b.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        for (obj, tomb_key) in [
            ("a.txt", format!(".trash/{d_31}/a.txt")),
            ("b.txt", format!(".trash/{d_29}/b.txt")),
        ] {
            mock.set_object(obj, vec![1]);
            mock.set_etag(obj, "mock-etag");
            seed_tombstone(
                &mock,
                &tomb_key,
                &trash::TombstoneBody {
                    etag: Some("\"mock-etag\"".into()),
                    size: Some(1),
                    is_dir: false,
                    recycle_name: None,
                    recycle_i: None,
                },
            );
        }
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        // before = 5 天前,晚于 30 天保留期 → 无效
        let report = fs
            .trash_gc(trash::GcOptions {
                before: Some(days_before(5)),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!(
            report.files_removed, 1,
            "--before 晚于保留期无效:仍按 30 天保留期清理"
        );
        assert!(
            !mock.objects.lock().unwrap().contains_key("a.txt"),
            "31 天前(超保留期)被清"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("b.txt"),
            "29 天前(保留期内)保留"
        );
    }

    /// GC 文件墓碑:etag 一致 → DELETE 原对象严格先于删墓碑;etag 不一致
    /// → 原对象/墓碑均保留 + trash_gc_etag_skips 计数;原对象 404 → 仅删
    /// 墓碑;§7 竞态(先删原对象再 restore)→ 404 分支清墓碑不留空引用。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_files_order_and_races() {
        // ① etag 一致删除 + ② etag 不一致跳过
        let d_old = days_before(31);
        let entries = vec![
            (format!(".trash/{d_old}/a.txt"), false),
            (format!(".trash/{d_old}/b.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"aa".to_vec());
        mock.set_object("b.txt", b"bb".to_vec());
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"same-etag\"".into()),
                size: Some(2),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/b.txt"),
            &trash::TombstoneBody {
                etag: Some("\"old-etag\"".into()),
                size: Some(2),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        mock.set_etag("a.txt", "same-etag"); // 一致 → 删
        mock.set_etag("b.txt", "new-etag"); // 不一致 → 活数据跳过
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(report.files_removed, 1, "etag 一致的原对象被删");
        assert_eq!(report.files_skipped_etag, 1, "etag 不一致跳过");
        assert_eq!(report.files_tombstone_only, 0);
        assert_eq!(report.tombstones_deleted, 1, "a.txt 墓碑被删");
        assert_eq!(fs.metrics().trash_gc_etag_skips, 1, "跳过计数");
        assert!(
            !mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象已删"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("b.txt"),
            "活数据保留"
        );
        assert!(
            !mock
                .objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/a.txt")),
            "墓碑已删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/b.txt")),
            "不一致墓碑保留"
        );
        // 顺序:DELETE 原对象(a.txt 单对象)严格先于墓碑批删
        let recorded = mock.recorded.lock().unwrap();
        let plain_del = recorded
            .iter()
            .position(|r| {
                r.method == "DELETE" && r.target.split('?').next().unwrap_or("").ends_with("/a.txt")
            })
            .expect("原对象单 DELETE");
        let batch = recorded
            .iter()
            .position(|r| r.method == "POST" && r.target.to_lowercase().contains("delete"))
            .expect("墓碑批删");
        assert!(plain_del < batch, "先删原对象后删墓碑: {recorded:?}");
        drop(recorded);
        assert_eq!(fs.metrics().trash_index_entries, 1, "b.txt 墓碑仍在索引");

        // ③ 原对象 404 → 仅删墓碑(files_tombstone_only)
        let d_old2 = days_before(32);
        let entries2 = vec![(format!(".trash/{d_old2}/c.txt"), false)];
        let (mock2, port2) = MockS3::start(entries2, Duration::from_millis(1)).await;
        seed_tombstone(
            &mock2,
            &format!(".trash/{d_old2}/c.txt"),
            &trash::TombstoneBody {
                etag: None,
                size: None,
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        // 原对象不存在(外部已删)
        let mut fs2 = test_fs(port2, 32);
        fs2.trash = Some(trash_state(".trash/"));
        fs2.rebuild_trash_index().await.expect("rebuild");
        let report = fs2.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(report.files_tombstone_only, 1);
        assert_eq!(report.files_removed, 0);
        assert!(
            !mock2
                .objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old2}/c.txt")),
            "空引用墓碑被清"
        );
        assert_eq!(fs2.metrics().trash_index_entries, 0);

        // ④ §7 竞态:先手动删原对象再 restore → 404 分支清墓碑,不留空引用
        let d_old3 = days_before(33);
        let entries3 = vec![(format!(".trash/{d_old3}/d.txt"), false)];
        let (mock3, port3) = MockS3::start(entries3, Duration::from_millis(1)).await;
        mock3.set_object("d.txt", b"dd".to_vec());
        seed_tombstone(
            &mock3,
            &format!(".trash/{d_old3}/d.txt"),
            &trash::TombstoneBody {
                etag: Some("\"e\"".into()),
                size: Some(2),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs3 = test_fs(port3, 32);
        fs3.trash = Some(trash_state(".trash/"));
        fs3.rebuild_trash_index().await.expect("rebuild");
        mock3.objects.lock().unwrap().remove("d.txt"); // 模拟 GC 已删原对象
        let out = fs3.trash_restore("/d.txt", None).await.unwrap();
        assert_eq!(out, trash::RestoreOutcome::OriginalGone, "竞态走 404 分支");
        assert!(
            mock3
                .objects
                .lock()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(".trash/")),
            "竞态后不留空引用墓碑"
        );
    }

    /// GC 目录墓碑 mtime 启发式:last_modified < 墓碑日期 00:00 UTC 的
    /// 对象被 DeleteObjects 批删、>= 的保留(新数据);report.objects_deleted
    /// 精确计数;墓碑最后删(原对象批删先于墓碑批删)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_dirs_mtime_heuristic() {
        let d_old = days_before(31);
        let lm_before = format!("{}T10:00:00.000Z", days_before(32));
        let lm_after = format!("{}T10:00:00.000Z", days_before(30));
        let entries = vec![
            (format!(".trash/{d_old}/docs/"), true),
            ("docs/x.txt".into(), false),
            ("docs/y.txt".into(), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("docs/x.txt", b"x".to_vec());
        mock.set_object("docs/y.txt", b"y".to_vec());
        mock.set_last_modified("docs/x.txt", &lm_before); // < D 00:00 UTC → 删
        mock.set_last_modified("docs/y.txt", &lm_after); // >= D → 保留
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(report.dirs_removed, 1, "目录墓碑已处理");
        assert_eq!(report.objects_deleted, 1, "仅早于墓碑日期的对象被删");
        assert_eq!(report.tombstones_deleted, 1, "目录墓碑最后删");
        assert!(!mock.objects.lock().unwrap().contains_key("docs/x.txt"));
        assert!(
            mock.objects.lock().unwrap().contains_key("docs/y.txt"),
            "新数据保留"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with(".trash/")),
            "目录墓碑已删"
        );
        // 墓碑最后删:原对象批删先于墓碑批删
        let recorded = mock.recorded.lock().unwrap();
        let batches: Vec<usize> = recorded
            .iter()
            .enumerate()
            .filter(|(_, r)| r.method == "POST" && r.target.to_lowercase().contains("delete"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(batches.len(), 2, "原对象批删 + 墓碑批删: {recorded:?}");
        let body0 = String::from_utf8_lossy(&recorded[batches[0]].body);
        assert!(body0.contains("docs/x.txt"), "第一批删原对象: {body0}");
        let body1 = String::from_utf8_lossy(&recorded[batches[1]].body);
        assert!(body1.contains(".trash/"), "第二批删墓碑: {body1}");
    }

    /// GC 分区过滤:--before 只清严格早于该日期的分区;未来日期墓碑
    /// 天然跳过(时钟偏快保护)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_partition_filtering() {
        let d_old = days_before(41); // < cutoff(40 天前)→ 清
        let d_recent = days_before(39); // >= cutoff → 不清
        let d_future = days_after(1); // 未来日期 → 跳过
        let entries = vec![
            (format!(".trash/{d_old}/a.txt"), false),
            (format!(".trash/{d_recent}/b.txt"), false),
            (format!(".trash/{d_future}/c.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_object("b.txt", b"b".to_vec());
        mock.set_object("c.txt", b"c".to_vec());
        for key in [
            format!(".trash/{d_old}/a.txt"),
            format!(".trash/{d_recent}/b.txt"),
            format!(".trash/{d_future}/c.txt"),
        ] {
            seed_tombstone(
                &mock,
                &key,
                &trash::TombstoneBody {
                    etag: Some("\"mock-etag\"".into()),
                    size: Some(1),
                    is_dir: false,
                    recycle_name: None,
                    recycle_i: None,
                },
            );
        }
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let before = days_before(40); // cutoff = min(before, today-30) = before
        let report = fs
            .trash_gc(trash::GcOptions {
                before: Some(before),
                dry_run: false,
            })
            .await
            .unwrap();
        assert_eq!(report.files_removed, 1, "仅早于 --before 的分区被清");
        assert!(!mock.objects.lock().unwrap().contains_key("a.txt"));
        assert!(
            mock.objects.lock().unwrap().contains_key("b.txt"),
            "晚于 --before 不清"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("c.txt"),
            "未来日期墓碑不清"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_recent}/b.txt"))
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_future}/c.txt"))
        );
    }

    /// H1 回归:--trash-retention-days 必须被 GC 消费 —— 设 7 天保留期时
    /// 8 天前墓碑被清(旧实现恒用常量 30 天,8 天前不会清 → 红;设 90 则
    /// 第 30 天数据即被删,合规场景=数据丢失)、2 天前保留(保留期内边界)、
    /// 29 天前被清(7 < 默认 30,证明选项确实缩短了保留期)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_uses_configured_retention_days() {
        let d_8 = days_before(8);
        let d_2 = days_before(2);
        let d_29 = days_before(29);
        let entries = vec![
            (format!(".trash/{d_8}/a.txt"), false),
            (format!(".trash/{d_2}/b.txt"), false),
            (format!(".trash/{d_29}/c.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        for (obj, tomb_key) in [
            ("a.txt", format!(".trash/{d_8}/a.txt")),
            ("b.txt", format!(".trash/{d_2}/b.txt")),
            ("c.txt", format!(".trash/{d_29}/c.txt")),
        ] {
            mock.set_object(obj, vec![1]);
            mock.set_etag(obj, "mock-etag");
            seed_tombstone(
                &mock,
                &tomb_key,
                &trash::TombstoneBody {
                    etag: Some("\"mock-etag\"".into()),
                    size: Some(1),
                    is_dir: false,
                    recycle_name: None,
                    recycle_i: None,
                },
            );
        }
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash::TrashState::new(
            ".trash/".to_string(),
            TrashRefreshMode::Lazy,
            Duration::from_secs(TRASH_REFRESH_INTERVAL_SECS),
            Duration::from_secs(TRASH_REBUILD_INTERVAL_SECS),
            Duration::from_secs(TRASH_GC_INTERVAL_SECS),
            7, // 保留期 7 天
        ));
        fs.rebuild_trash_index().await.expect("rebuild");
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(
            report.files_removed, 2,
            "7 天保留期下 8 天前与 29 天前墓碑被清(2 天前保留)"
        );
        assert!(
            !mock.objects.lock().unwrap().contains_key("a.txt"),
            "8 天前原对象已删"
        );
        assert!(
            !mock.objects.lock().unwrap().contains_key("c.txt"),
            "29 天前原对象已删(7 天保留期短于默认 30)"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("b.txt"),
            "2 天前原对象保留(保留期内)"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_2}/b.txt")),
            "2 天前墓碑保留"
        );
    }

    /// M2 回归:--read-only 挂载不得触发破坏性 GC —— trash_gc 在只读挂载
    /// 上必须早退零动作(后台周期 GC 与任何直接调用都不删桶内对象)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn read_only_mount_never_gc_deletes() {
        let d_old = days_before(31);
        let entries = vec![(format!(".trash/{d_old}/a.txt"), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_etag("a.txt", "mock-etag");
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"mock-etag\"".into()),
                size: Some(1),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs = test_fs(port, 32);
        fs.read_only = true;
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(report, trash::GcReport::default(), "只读挂载 GC 必须零动作");
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象未删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/a.txt")),
            "墓碑未删"
        );
    }

    /// C1 回归:mock PUT 必须按当前时间写 per-key last_modified —— 墓碑
    /// 目录下 PUT 新对象后直接跑目录 GC 时,新对象不得被判「早于墓碑
    /// 日期」而误删(旧 mock 对无记录对象缺省 2026-01-01,恒早于一切
    /// 墓碑日期 → 假红/假绿源)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_dirs_preserves_freshly_written_object() {
        let d_old = days_before(31);
        let entries = vec![(format!(".trash/{d_old}/docs/"), true)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        // 墓碑目录下 PUT 新对象(走 fs 写路径 → mock PUT;不显式设
        // last_modified —— 生产语义:PUT 后 last_modified=now)
        fs.write("/docs/new.txt", b"fresh").await.unwrap();
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(
            report.objects_deleted, 0,
            "新写入对象不得被目录 GC 的 mtime 启发式误删"
        );
        assert!(
            mock.objects.lock().unwrap().contains_key("docs/new.txt"),
            "新对象必须存活"
        );
    }

    /// L1 回归:dry-run 只跳过 S3 DELETE,不改变任何状态 —— 索引 remove
    /// 与 invalidate_key 必须门控 !dry_run(dry-run 契约:判定照做、删除
    /// 不落、状态不变;否则未来挂载进程内复用 dry-run 会错误解除墓碑
    /// 隐藏并清缓存)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_gc_dry_run_keeps_index_untouched() {
        let d_old = days_before(31);
        let entries = vec![(format!(".trash/{d_old}/a.txt"), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_etag("a.txt", "mock-etag");
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"mock-etag\"".into()),
                size: Some(1),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let state = fs.trash.clone().unwrap();
        assert!(
            state.index.read().unwrap().is_covered("a.txt"),
            "前置:索引含墓碑"
        );
        let report = fs
            .trash_gc(trash::GcOptions {
                before: None,
                dry_run: true,
            })
            .await
            .unwrap();
        assert_eq!(report.files_removed, 1, "dry-run 仍完成 etag 判定");
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象未删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/a.txt")),
            "墓碑未删"
        );
        assert!(
            state.index.read().unwrap().is_covered("a.txt"),
            "dry-run 不得改变索引状态(L1)"
        );
        assert_eq!(
            fs.metrics().trash_index_entries,
            1,
            "dry-run 后索引条目必须保留"
        );
    }

    /// L5 回归:GC 读到并发 restore 已删的墓碑(404)必须跳过该墓碑,绝不
    /// 动原对象 —— 旧实现把 404 的空 body 当「无 etag」按 matched 处理,
    /// 恢复成功瞬间原对象又被 GC 永久删除(规格 4.4 风险 2 的窗口被
    /// 放大为 GET 之后任意时点)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gc_skips_tombstone_deleted_by_concurrent_restore() {
        let d_old = days_before(31);
        let entries = vec![(format!(".trash/{d_old}/a.txt"), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        mock.set_etag("a.txt", "mock-etag");
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"mock-etag\"".into()),
                size: Some(1),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        // 模拟并发 restore 已删墓碑(索引未动 —— 同进程双任务竞态)
        mock.objects
            .lock()
            .unwrap()
            .remove(&format!(".trash/{d_old}/a.txt"));
        let report = fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(report.files_removed, 0, "404 墓碑不得删除原对象(L5)");
        assert_eq!(report.files_skipped_etag, 0);
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象必须存活"
        );
    }

    /// L2 回归:trash_restore 入口持一个 permit 覆盖 find_tombstone 之后
    /// 的 HEAD/GET/DELETE —— 并发上限=1 下必须仍能完成(delete_tombstone
    /// 改「调用方已持 permit」后,二次 acquire 会造成饱和池死锁,本测试
    /// 钉死该不变量)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_restore_works_with_single_permit() {
        let (mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"hello".to_vec());
        let mut fs = test_fs(port, 1); // max_concurrent_requests = 1
        fs.trash = Some(trash_state(".trash/"));
        fs.delete("/a.txt").await.expect("软删");
        assert!(fs.stat("/a.txt").await.unwrap().is_none());
        let out = fs.trash_restore("/a.txt", None).await.unwrap();
        assert_eq!(
            out,
            trash::RestoreOutcome::Restored {
                etag_mismatch: false,
                multiple_versions: false,
            },
            "单 permit 下 restore 必须完成且不二次 acquire 死锁(L2)"
        );
        assert!(fs.stat("/a.txt").await.unwrap().is_some(), "恢复后可见");
    }

    /// L4:trash_gc(非 dry-run)完成后代际必须推进,dry-run 不推进 ——
    /// refresh/rebuild 凭代际丢弃陈旧快照(apply_added_discards 测试
    /// 在 trash.rs 钉机制,这里是 GC 侧的代际推进钉)。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_gc_bumps_generation_but_dry_run_does_not() {
        let (_mock, port) = MockS3::start(Vec::new(), Duration::from_millis(1)).await;
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let state = fs.trash.clone().unwrap();
        fs.rebuild_trash_index().await.expect("rebuild");
        let gen0 = state.generation.load(Ordering::SeqCst);
        fs.trash_gc(trash::GcOptions {
            before: None,
            dry_run: true,
        })
        .await
        .unwrap();
        assert_eq!(
            state.generation.load(Ordering::SeqCst),
            gen0,
            "dry-run 零状态变更,不推进代际"
        );
        fs.trash_gc(trash::GcOptions::default()).await.unwrap();
        assert_eq!(
            state.generation.load(Ordering::SeqCst),
            gen0 + 1,
            "GC 完成后代际推进(L4)"
        );
    }

    /// trash-clean --dry-run:判定照做(HEAD/GET/list),删除动作全部跳过
    /// —— 原对象与墓碑都在,report 计数反映「将删除」。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_gc_dry_run_reports_without_deleting() {
        let d_old = days_before(31);
        let entries = vec![(format!(".trash/{d_old}/a.txt"), false)];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        mock.set_object("a.txt", b"a".to_vec());
        seed_tombstone(
            &mock,
            &format!(".trash/{d_old}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"mock-etag\"".into()),
                size: Some(1),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        fs.rebuild_trash_index().await.expect("rebuild");
        let report = fs
            .trash_gc(trash::GcOptions {
                before: None,
                dry_run: true,
            })
            .await
            .unwrap();
        assert_eq!(report.files_removed, 1, "dry-run 仍完成 etag 判定");
        assert!(
            mock.objects.lock().unwrap().contains_key("a.txt"),
            "原对象未删"
        );
        assert!(
            mock.objects
                .lock()
                .unwrap()
                .contains_key(&format!(".trash/{d_old}/a.txt")),
            "墓碑未删"
        );
        let recorded = mock.recorded.lock().unwrap();
        assert!(
            !recorded.iter().any(|r| {
                r.method == "DELETE"
                    || (r.method == "POST" && r.target.to_lowercase().contains("delete"))
            }),
            "dry-run 不发任何删除请求"
        );
    }

    /// trash-list 输出:多分区、目录尾 '/'、etag/size 列(文件墓碑 GET
    /// body 解析);--json 形态逐条 NDJSON 可解析回 TrashEntry。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trash_list_output() {
        let d1 = days_before(31);
        let d2 = days_before(29);
        let entries = vec![
            (format!(".trash/{d1}/a.txt"), false),
            (format!(".trash/{d1}/docs/"), true),
            (format!(".trash/{d2}/b.txt"), false),
        ];
        let (mock, port) = MockS3::start(entries, Duration::from_millis(1)).await;
        seed_tombstone(
            &mock,
            &format!(".trash/{d1}/a.txt"),
            &trash::TombstoneBody {
                etag: Some("\"e1\"".into()),
                size: Some(5),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        seed_tombstone(
            &mock,
            &format!(".trash/{d2}/b.txt"),
            &trash::TombstoneBody {
                etag: Some("\"e2\"".into()),
                size: Some(7),
                is_dir: false,
                recycle_name: None,
                recycle_i: None,
            },
        );
        let mut fs = test_fs(port, 32);
        fs.trash = Some(trash_state(".trash/"));
        let mut got: Vec<trash::TrashEntry> = Vec::new();
        fs.trash_list(|page| {
            got.extend(page);
            Ok(())
        })
        .await
        .expect("trash-list");
        assert_eq!(got.len(), 3, "三条墓碑: {got:?}");
        got.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(got[0].path, "a.txt");
        assert_eq!(got[0].deleted_date, d1);
        assert_eq!(got[0].etag.as_deref(), Some("\"e1\""), "文件墓碑 etag 列");
        assert_eq!(got[0].size, Some(5));
        assert!(!got[0].is_dir);
        assert_eq!(got[1].path, "b.txt");
        assert_eq!(got[1].deleted_date, d2);
        assert_eq!(got[1].etag.as_deref(), Some("\"e2\""));
        assert_eq!(got[1].size, Some(7));
        assert_eq!(got[2].path, "docs/", "目录 path 带尾斜杠");
        assert!(got[2].is_dir);
        assert!(
            got[2].etag.is_none() && got[2].size.is_none(),
            "目录墓碑无 etag/size"
        );
        // --json 形态:逐条 NDJSON 可解析
        let json = serde_json::to_string(&got[0]).unwrap();
        let back: trash::TrashEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, got[0]);
    }
}

/// Test-only S3 mock shared by the platform adapter test modules
/// (`ossfs::winfsp` on Windows, `ossfs::fuse` on macOS/Linux).
#[cfg(test)]
pub(crate) use s3_mock_tests::{MockS3, test_fs, test_fs_with_budget};
