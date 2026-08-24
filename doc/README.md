# OSSFS Documentation

OSSFS mounts an S3-compatible bucket as a local filesystem with no local
metadata database (s3fs-style layout).

## Components

- `src/ossfs/` — the object-store filesystem: `ObjectFs` (list / stat / read /
  write / rename / delete against S3), plus the mount adapters:
  - `src/ossfs/winfsp.rs` — Windows WinFsp adapter (`ossmount` on Windows)
  - `src/ossfs/fuse.rs` — macOS / Linux FUSE adapter (FUSE-T / macFUSE / libfuse)
- `src/bin/ossmount.rs` — the `ossmount` CLI
- `desktop/` — `ossfs-tray` system-tray manager

## Design notes

- **Metadata-less**: every directory enumeration / stat is a remote S3 request.
  Layout is s3fs-style: `/docs/report.txt` → object key `docs/report.txt`;
  directories are implicit via prefix, with a zero-byte marker object so empty
  directories survive listing.
- **Concurrency & memory bounds**: `ObjectFs` caps in-flight S3 requests
  (`MAX_CONCURRENT_S3_REQUESTS`, default 32, configurable via
  `OssConfig::max_concurrent_requests`), probes implied directories with
  `max_keys=1`, and bounds the notify snapshot cache. This prevents an I/O
  storm (e.g. `find /` recursing into the drive) from exhausting memory and
  aborting the process (0xc0000409).
- **WinFsp thread stacks**: the PE image reserves a 16 MiB thread stack so the
  deep AWS-SDK async stack cannot overflow WinFsp callback threads.
- **Writes**: whole-file buffered; pushed to the object store on close/flush.

## Operational notes

- Avoid full-disk scans over the mounted drive — every operation is a remote
  round trip.
- Runtime records: `ossmount` writes per-instance JSON under
  `%TEMP%\ossfs-oss` (used by the tray to list/stop mounts).

## Trash (soft delete, opt-in)

**Deletion is immediate and permanent by default** (0.4.0): `unlink`/`rmdir`
remove the object from the bucket right away, and the deletion is **not
recoverable** (the mount logs a warning on every permanent delete). The
soft-delete trash is **opt-in**: mount with `--trash-dir NAME` to enable it.
With trash enabled, `unlink`/`rmdir` no longer remove the object — they write
a small JSON tombstone under the hidden `.trash/` prefix
(`.trash/<YYYY-MM-DD>/<original-key>`, partitioned by the UTC deletion date)
while the original object stays in the bucket. The mount filters tombstoned
keys out of `list`/`stat`, so deleted paths disappear from the drive view
without any extra remote requests. Restore = delete the tombstone; real space
reclamation = GC purging expired tombstones and their original objects
(default retention: 30 days, `--trash-retention-days N` to override). GC runs
at mount time, then every `--trash-gc-interval-secs` (default 86400 = 24 h),
and on demand via `ossmount trash-clean`. `--no-trash` forces immediate
permanent delete even when a trash dir is configured; `--trash-dir NAME`
(default `.trash`) selects the tombstone prefix.

Management commands (they share the mount connection arguments
`--bucket`/`--endpoint`/`--region`/...):

- `ossmount trash-list [--json]` — list tombstones: UTC deletion date,
  original path, etag, size (`--json` for machine-readable output).
- `ossmount trash-restore <path>` — restore by deleting the tombstone. The
  original object is HEAD-checked first: if it no longer exists (already
  GC'd) restore fails with exit 1; if its etag differs from the tombstone,
  restore proceeds with a warning that the content was modified elsewhere.
- `ossmount trash-clean [--before YYYY-MM-DD] [--dry-run]` — run GC on
  demand: purge expired tombstones and their original objects (only when the
  etag still matches; mismatches are skipped and counted as
  `trash_gc_etag_skips`). `--before` sets an earlier cutoff than the default
  retention period; `--dry-run` reports without deleting.

The default soft-delete semantics deliberately deviate from POSIX and are
documented here:

1. **Deleting no longer frees space.** `unlink`/`rmdir` keep the original
   objects until GC purges them (default 30 days). `--no-trash` restores
   immediate permanent deletion.
2. **"Deleted" is a client-side illusion of this mount.** The OSS console,
   other S3 clients, and other mounts that have not synced the tombstones
   still see the "deleted" original objects.
3. **Restore does not guarantee the content as of deletion time.** A tombstone
   records only the key and an etag. If the same key was overwritten after
   deletion, restoring yields the new content; restore checks the etag and
   warns in that case.
4. **Deletion takes effect with a delay window.** A remote deletion becomes
   visible on this mount within the refresh interval (default 30 s) plus OSS
   eventual consistency (seconds); restore propagates the same way, with the
   longest delay being the full-rebuild period (10 min).
5. **Directory GC uses an mtime heuristic** to decide whether objects under a
   tombstoned directory predate the tombstone date — it is not guaranteed to
   be perfect.

- **Bucket versioning**: versioning preserves content — every version and
  delete marker stays in the bucket and is recoverable from the console/SDK —
  while tombstones manage interaction: what the mount view hides and how
  restore/GC behave. The two are complementary and can be enabled together.
- **Operations**: the `.trash/` prefix stays in the bucket and is hidden from
  the mount view (creating it succeeds but it is immediately hidden from the
  view, so a real `.trash` directory at the namespace root is unavailable).
  Recreating a path with the same name first clears its tombstone, so the new
  content is immediately visible (overwrite semantics).

## System recycle bin (issue #80, opt-in / experimental)

**Status (0.4.0): opt-in and experimental.** Real Explorer/Finder recycle-bin
integration is **not available**: on macOS 26 the macFUSE kext is blocked by
the OS and FUSE-T mounts as an NFS volume (Finder trash unavailable); on
Windows the Explorer delete protocol does not move files into the bin on
WinFsp mounts (verified by live testing). The virtual view itself still works
— browse tombstones, restore via `trash-restore`, empty via delete — but the
**system recycle bin entry point is not observable to users**, so this is
disabled by default and kept only for users who opt in explicitly.

A **virtual** recycle-bin view at the mount root, synthesized from the trash
tombstone index — no local metadata database, zero data copies. The OS delete
protocol is intercepted in the `ObjectFs` layer: the shell's "move into the
bin" becomes a soft delete (one tombstone object; the original never moves),
the bin's contents render from tombstones, restore = rename out of the bin
(delete the tombstone), empty = permanent delete (tombstone + original).

- Windows: `$Recycle.Bin` (OFF — `--system-trash-dir` to enable) — the `$R`
  name is recorded in the tombstone, the `$I` metadata file is captured
  byte-faithfully (≤ 4 KiB, stored in the tombstone body, never a real object).
- macOS: `.Trashes` (OFF — `--system-trash-dir` to enable) — needs **macFUSE**
  and the `local` mount option (appended automatically); **FUSE-T mounts as an
  NFS network volume: Finder trash unavailable, deletes take effect
  immediately** (mount-time warning). `.Trashes/<uid>` mode `0700`.
- Linux: `$Recycle.Bin` (ON with trash) — browsable view, no shell delete
  integration.

CLI: `--system-trash-dir NAME` / `--system-trash-uids N[,N...]` (macOS) /
`--no-system-trash`. Full details and known limitations in the root README.

## Known POSIX / FUSE limitations

- (Trash soft-delete further deviates from POSIX — see
  [Trash (soft delete)](#trash-soft-delete) above.)
- (System recycle bin: Windows is code-level verified only — unit tests and
  the WinFsp build gate cover interception semantics; the real Explorer
  protocol needs a live Windows mount + ProcMon capture before first release.
  macOS Finder behavior needs a live macFUSE mount check.)
- `generic/075` (xfstests) and LTP `iogen01` remain excluded from default test
  profiles: buffered FUSE mmap after truncate/extend can expose stale
  page-cache data, and the tiny-overlap direct-I/O profile has a
  split-write/page-cache coherency race. Full direct I/O is not a substitute
  (mmap returns `ENODEV`).
- Special file types are **not supported**. The FUSE adapter only produces
  `Directory` / `RegularFile` attributes (`rdev` is always 0) and `mknod`
  rejects non-regular modes with `EPERM`; `DirEntry` carries no type or
  `rdev` field. FIFOs, sockets, and char/block devices cannot be created or
  represented. (Whether to persist them as object markers like the WinFsp
  side is an open decision — see the tracking issue.)
- Symlinks (`symlink`/`readlink`), hard links (`link`), extended attributes
  (`setxattr`/`getxattr`/`listxattr`/`removexattr`), `lseek` (`SEEK_DATA` /
  `SEEK_HOLE`) and `fallocate` are not implemented; the vendored fuser
  defaults answer `ENOSYS` for all of them (e.g. `ln -s` fails with `ENOSYS`,
  not `EPERM`/`ENOTSUP`).
- POSIX file locks (`setlk`/`getlk`) are not implemented and answer `ENOSYS`;
  `flush` ignores `lock_owner`. Local `flock`/`fcntl` locking still works
  inside one machine via the kernel's page-cache-level locking; there is no
  cross-machine lock coordination.
- `rmdir` on a non-empty directory fails with `ENOTEMPTY` (POSIX); `rm -rf`
  and Finder/Explorer recursive deletes still work because the shell deletes
  children first and the final `rmdir` lands on an empty directory.
  **Windows note**: the WinFsp `cleanup` callback has no error return
  channel, so a refused non-empty delete is a warn-only silent no-op — the
  caller sees success while the directory remains.
