//! OSSFS desktop tray manager (Slint 1.17), Windows + macOS.
//!
//! A system-tray app that keeps a list of saved OSSFS mount
//! profiles (config records), shows their live mount state, and lets the user
//! open / mount|unmount / delete each record from one list, edit the selected
//! profile in the form, and add new configs.
//!
//! Requires a ossfs build with the `fuse-winfsp` feature on Windows
//! (`ossmount` for the metadata-less OSS direct-mount mode; macOS uses
//! the FUSE-based `ossmount` with FUSE-T/macFUSE). Binaries are located next
//! to this executable, via `OSSMOUNT_EXE`, or on PATH.

#![cfg_attr(windows, windows_subsystem = "windows")]
#![cfg_attr(not(windows), allow(dead_code))]

mod model;
mod secrets;
mod winutil;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::{ModelRc, SharedString, Timer, TimerMode, VecModel};

// 版本更新检查(issue #87):GET GitHub Releases 最新版,与当前版本对比,
// 发现新版提示下载。网络失败/解析失败静默(不打扰用户)。

/// 解析 "v0.4.2" 或 "0.4.2" → (0,4,2)。非数字段返回 None。
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let v = s.trim().trim_start_matches('v');
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// 拉取 GitHub 最新 release 信息(tag_name + 安装包下载 URL);网络/解析
/// 失败返回 None(静默降级)。Windows 找 `OSSFS-Setup-*.exe`,macOS 找
/// `OSSFS-*-macos-arm64.dmg`。
struct ReleaseInfo {
    version: String,
    url: String,
}

/// HTTP 超时策略(issue #87 修复):
/// - 必须用 per-read 超时而非整体超时。旧实现 `AgentBuilder::timeout(30s)`
///   是 ureq 的"整体请求超时"(DNS+连接+读完整 body),国内到 GitHub CDN
///   实测 ~0.6MB/s,43MB DMG 需 ~70s,30s 就被掐断 → 误判下载失败 → fallback
///   打开浏览器页面(用户看到的"打开页面"现象)。
/// - per-read 30s:只要数据持续到达就不会被打断;真正卡死(30s 无数据)才失败。
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn fetch_latest_release() -> Option<ReleaseInfo> {
    let resp = build_http_agent()
        .get("https://api.github.com/repos/gqf2008/ossfs/releases/latest")
        .set("User-Agent", "ossfs-tray")
        .call()
        .ok()?;
    let json: serde_json::Value = resp.into_json().ok()?;
    let version = json.get("tag_name")?.as_str()?.to_string();
    let url = parse_release_asset(&json)?;
    Some(ReleaseInfo { version, url })
}

/// 构建 HTTP agent(读 HTTPS_PROXY/https_proxy 环境变量;ureq 2 的便捷
/// 函数不自动读 env 代理,需显式 Proxy——中国网络到 GitHub 需走代理)。
/// 只设 per-read/connect 超时,不设整体超时(见 HTTP_*_TIMEOUT 注释)。
fn build_http_agent() -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(HTTP_CONNECT_TIMEOUT)
        .timeout_read(HTTP_READ_TIMEOUT);
    for var in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(p) = std::env::var(var)
            && let Ok(proxy) = ureq::Proxy::new(&p)
        {
            builder = builder.proxy(proxy);
            break;
        }
    }
    builder.build()
}

/// 从 release JSON 里挑出当前平台的安装包下载 URL。
fn parse_release_asset(json: &serde_json::Value) -> Option<String> {
    let suffix = if cfg!(target_os = "macos") {
        "-macos-arm64.dmg"
    } else {
        "-Setup-"
    };
    json.get("assets")?.as_array()?.iter().find_map(|a| {
        let name = a.get("name")?.as_str()?;
        let url = a.get("browser_download_url")?.as_str()?;
        (name.contains(suffix) && name.ends_with(".exe") == cfg!(target_os = "windows"))
            .then_some(url.to_string())
    })
}

/// 检查是否有新版本:最新 > 当前 → Some((版本号, 下载 URL))。
fn check_for_update(current: &str) -> Option<ReleaseInfo> {
    let release = fetch_latest_release()?;
    let (c, l) = (parse_version(current)?, parse_version(&release.version)?);
    (l > c).then_some(release)
}

/// 打开 GitHub release 下载页(手动 fallback)。
fn open_release_page() {
    let _ = webbrowser::open("https://github.com/gqf2008/ossfs/releases/latest");
}

/// 下载安装包到临时目录。返回本地路径,失败返回 None。
fn download_installer(url: &str, version: &str) -> Option<std::path::PathBuf> {
    let ext = if cfg!(target_os = "macos") {
        "dmg"
    } else {
        "exe"
    };
    let filename = format!("OSSFS-{version}.{ext}");
    let dir = std::env::temp_dir();
    let path = dir.join(&filename);
    let resp = build_http_agent()
        .get(url)
        .set("User-Agent", "ossfs-tray")
        .call()
        .map_err(|e| eprintln!("download connect failed: {e}"))
        .ok()?;
    use std::io::Write;
    let mut file = std::fs::File::create(&path)
        .map_err(|e| eprintln!("create file failed: {e}"))
        .ok()?;
    let mut reader = resp.into_reader();
    std::io::copy(&mut reader, &mut file)
        .map_err(|e| eprintln!("copy bytes failed: {e}"))
        .ok()?;
    eprintln!("downloaded to {}", path.display());
    Some(path)
}

/// 运行安装包(程序内自安装,不引导用户):
/// - macOS:`hdiutil attach` → `cp -R OSSFS.app /Applications/` → `detach` →
///   spawn 新 tray + 退出当前(覆盖式更新,挂载进程不受影响)。
/// - Windows:`ShellExecute runas /passive`(WiX 静默安装)+ 退出 tray 让
///   安装器写文件;安装后由 WiX 重启应用或用户手动启动(后续增强)。
#[cfg(target_os = "macos")]
fn run_installer(path: &std::path::Path) {
    use std::process::{Command, exit};
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return,
    };
    // 挂载 dmg(-nobrowse:不在 Finder 弹窗)。
    let out = match Command::new("hdiutil")
        .args(["attach", "-nobrowse", path_str])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("hdiutil attach failed: {e}");
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    // hdiutil 输出最后字段为挂载点(如 /Volumes/OSSFS)。
    let mount = match stdout
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().last())
    {
        Some(m) => m.to_string(),
        None => return,
    };
    eprintln!("mounted at {mount}");
    // 拷贝 .app 到 /Applications(覆盖式更新;运行中的旧 tray 仍可用旧二进制
    // 直到 exit,新 spawn 的是新版)。
    let cp = Command::new("cp")
        .args(["-R", &format!("{mount}/OSSFS.app"), "/Applications/"])
        .status();
    eprintln!("cp -R status: {:?}", cp);
    // 卸载 dmg。
    let _ = Command::new("hdiutil").args(["detach", &mount]).status();
    // 重启:spawn 新 tray(/Applications/OSSFS.app)+ 退出当前。
    let _ = Command::new("/Applications/OSSFS.app/Contents/MacOS/ossfs-tray")
        .env(
            "OSSMOUNT_EXE",
            "/Applications/OSSFS.app/Contents/MacOS/ossmount",
        )
        .spawn();
    exit(0);
}

/// 非 macOS(Windows):ShellExecute runas /passive + 退出。
#[cfg(windows)]
fn run_installer(path: &std::path::Path) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let op: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let params: Vec<u16> = "/passive\0".encode_utf16().collect();
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
    // 退出 tray 让 WiX 安装器写文件(替换 ossfs-tray/ossmount)。
    std::process::exit(0);
}

/// Linux:tray 可编译但无安装包(release 仅 dmg/exe),不自动更新。
#[cfg(target_os = "linux")]
fn run_installer(_path: &std::path::Path) {
    eprintln!("auto-update not supported on Linux (no installer asset)");
}

/// 发现新版弹提示:确认后打开下载页。
#[cfg(windows)]
fn show_update_dialog(current: &str, latest: &str) {
    let msg = format!("发现新版本 {latest}(当前 {current})。\n\n是否打开下载页面?",);
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONINFORMATION, MB_YESNO, MessageBoxW,
    };
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "OSSFS 更新"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let choice = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONINFORMATION,
        )
    };
    if choice == IDYES {
        open_release_page();
    }
}

/// 非 Windows 平台:直接打开下载页(无原生消息框)。
#[cfg(not(windows))]
fn show_update_dialog(_current: &str, latest: &str) {
    eprintln!("OSSFS update available: {latest}");
    open_release_page();
}

/// 下载完成提示安装:Windows MessageBox「下载完成,是否立即安装?」。
#[cfg(windows)]
fn show_install_prompt(version: &str, path: &std::path::Path) -> bool {
    let msg = format!("新版本 {version} 已下载完成。\n\n是否立即安装?(安装会关闭托盘)",);
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONINFORMATION, MB_YESNO, MessageBoxW,
    };
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = "OSSFS 更新"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let choice = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONINFORMATION,
        )
    };
    let _ = path; // path 用于后续安装(此函数仅询问)
    choice == IDYES
}

#[cfg(not(windows))]
fn show_install_prompt(_version: &str, _path: &std::path::Path) -> bool {
    // 非 Windows:无原生消息框,下载完成直接自安装(run_installer 程序内
    // 完成 hdiutil+cp+重启,不引导用户操作)。
    true
}

/// 后台线程检查更新:发现新版 → 菜单显示「下载新版本」→ 自动下载 →
/// 完成提示安装(Windows MessageBox;非 Windows 打开 dmg)。
/// `quiet_on_none` 控制"无新版/失败"时是否静默(自动检查静默;手动检查
/// 要告知结果)。UI 更新经 `upgrade_in_event_loop`(Slint 跨线程纪律)。
fn run_update_check(current: String, quiet_on_none: bool, tray_weak: slint::Weak<Tray>) {
    std::thread::spawn(move || {
        match check_for_update(&current) {
            Some(release) => {
                let version_dl = release.version.clone();
                let _ = tray_weak.upgrade_in_event_loop(move |tray| {
                    tray.set_update_status(format!("下载新版本 {version_dl}…").into());
                });
                let url = release.url.clone();
                let version = release.version.clone();
                if let Some(path) = download_installer(&url, &version) {
                    let status = format!("有新版本({version})");
                    let _ = tray_weak.upgrade_in_event_loop(move |tray| {
                        tray.set_update_status(status.into());
                    });
                    if show_install_prompt(&version, &path) {
                        run_installer(&path);
                    }
                } else {
                    // 下载失败:fallback 打开下载页。
                    let status = format!("有新版本({version})");
                    let _ = tray_weak.upgrade_in_event_loop(move |tray| {
                        tray.set_update_status(status.into());
                    });
                    show_update_dialog(&current, &version);
                }
            }
            None if !quiet_on_none => {
                // 手动检查:区分"已是最新"与"检查失败"(网络/解析)。
                #[cfg(windows)]
                {
                    use windows_sys::Win32::UI::WindowsAndMessaging::{
                        MB_ICONINFORMATION, MB_OK, MessageBoxW,
                    };
                    let msg = if parse_version(&current).is_some() {
                        "检查失败(网络不可达或解析失败)。".to_string()
                    } else {
                        "已是最新版本。".to_string()
                    };
                    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
                    let title: Vec<u16> = "OSSFS 更新"
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    unsafe {
                        MessageBoxW(
                            std::ptr::null_mut(),
                            wide.as_ptr(),
                            title.as_ptr(),
                            MB_OK | MB_ICONINFORMATION,
                        );
                    }
                }
                #[cfg(not(windows))]
                {
                    eprintln!("OSSFS update check: no update or check failed");
                }
            }
            None => {}
        }
    });
}

slint::include_modules!();

/// A `ossfs mount` process we started that has not yet produced a runtime
/// registry record (control plane still initializing) or failed to do so.
struct RecentSpawn {
    drive: String,
    pid: u32,
    log: PathBuf,
    at: Instant,
}

/// Holds a transient/error status message for a short window so the 2s
/// refresh summary cannot overwrite it on the same tick (e.g. a mount
/// failure message replaced by "当前没有活动挂载。" before the user sees it).
struct StatusHold {
    until: Cell<Option<Instant>>,
    msg: RefCell<String>,
}

impl Default for StatusHold {
    fn default() -> Self {
        Self {
            until: Cell::new(None),
            msg: RefCell::new(String::new()),
        }
    }
}

/// Set a status message and keep it visible for `secs` even across refresh().
fn hold_status(ui: &MainWindow, hold: &StatusHold, msg: String, secs: u64) {
    *hold.msg.borrow_mut() = msg.clone();
    hold.until
        .set(Some(Instant::now() + Duration::from_secs(secs)));
    ui.set_status_text(msg.into());
}

/// Configure the Slint backend before any window is created.
///
/// On macOS the window is created with a transparent, hidden titlebar while
/// keeping the native traffic-light buttons (close/minimize/zoom). This uses
/// winit's window-attributes hook (slint feature `unstable-winit-030`): a plain
/// `titlebar_hidden` would drop the `Closable` style mask and remove the buttons,
/// so we combine `titlebar_transparent` + `fullsize_content_view` + `title_hidden`
/// instead, which is the standard "hidden titlebar, buttons still visible" recipe.
fn configure_backend() -> Result<(), Box<dyn std::error::Error>> {
    let selector = slint::BackendSelector::new();
    #[cfg(target_os = "macos")]
    let selector = selector.with_winit_window_attributes_hook(|attributes| {
        use slint::winit_030::winit::platform::macos::WindowAttributesExtMacOS;
        attributes
            .with_titlebar_transparent(true)
            .with_fullsize_content_view(true)
            .with_title_hidden(true)
    });
    selector.select()?;
    Ok(())
}

/// Desired mounts + auto-restart bookkeeping for the mount-process guard.
#[derive(Default)]
struct GuardState {
    /// Drive letters the user explicitly mounted; auto-restarted if the
    /// process dies unexpectedly.
    desired: std::collections::HashSet<String>,
    /// When we last spawned each drive (backoff against restart loops).
    last_spawn: std::collections::HashMap<String, Instant>,
    /// Drives that fast-failed (e.g. bad config) and must be retried only by
    /// the user manually.
    failed: std::collections::HashSet<String>,
    /// Auto-restarts already spent per drive since the mount was last seen
    /// healthy; bounded by [`MAX_AUTO_RESTARTS`] (#61).
    restarts: std::collections::HashMap<String, u32>,
    /// When each desired drive was first observed alive at a refresh tick.
    /// A drive continuously alive for [`STABLE_ALIVE_RESET`] is presumed
    /// healthy and its restart budget is replenished (review B2).
    alive_since: std::collections::HashMap<String, Instant>,
}

/// Maximum auto-restart attempts before the guard gives up on a drive and
/// leaves it for the user to remount manually. A mount that crashes ~every
/// 30s would otherwise be respawned forever (#61).
const MAX_AUTO_RESTARTS: u32 = 5;

/// How long a drive must stay alive before its restart budget is
/// replenished. Without this, a mount that crashes just slower than the 2s
/// refresh tick (e.g. every 30s) would have its budget cleared on every
/// alive tick and the [`MAX_AUTO_RESTARTS`] cap would be dead code
/// (review B2).
const STABLE_ALIVE_RESET: Duration = Duration::from_secs(60);

/// Whether a drive that has been continuously alive for `alive` may have
/// its restart budget replenished (see [`STABLE_ALIVE_RESET`]). Extracted
/// for unit testing.
fn budget_resets(alive: Duration) -> bool {
    alive >= STABLE_ALIVE_RESET
}

/// Decision extracted from [`auto_restart`] so the backoff / give-up policy
/// is unit-testable without a UI (#61).
#[derive(Debug, PartialEq, Eq)]
enum RestartDecision {
    /// Backoff window since the last spawn has not elapsed yet.
    WaitForBackoff,
    /// Restart budget exhausted: stop auto-restarting this drive.
    GiveUp,
    /// Safe to spawn a replacement now.
    Proceed,
}

fn restart_decision(elapsed_since_spawn: Duration, restarts_spent: u32) -> RestartDecision {
    if elapsed_since_spawn < Duration::from_secs(30) {
        return RestartDecision::WaitForBackoff;
    }
    if restarts_spent >= MAX_AUTO_RESTARTS {
        return RestartDecision::GiveUp;
    }
    RestartDecision::Proceed
}

static MOUNT_GUARD: std::sync::OnceLock<std::sync::Mutex<GuardState>> = std::sync::OnceLock::new();

/// Snapshot of the drive names shown in the tray menu, in menu order. The
/// menu callback only receives an index; re-reading the mount list at click
/// time could resolve the index against a differently-ordered list (menu
/// open → 2s refresh reorders → click opens the wrong drive, #61).
static TRAY_MENU_DRIVES: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
    std::sync::OnceLock::new();

fn tray_menu_drives() -> std::sync::MutexGuard<'static, Vec<String>> {
    TRAY_MENU_DRIVES
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Persist the desired set after a mutation so a tray restart or crash
/// re-arms the auto-restart supervision (#61). Best-effort: a failed state
/// write only loses supervision across a restart, never blocks I/O.
/// Callers must drop the guard before calling (the 2s refresh timer shares
/// the lock; file I/O must not run under it).
fn persist_desired(desired: &std::collections::HashSet<String>) {
    let _ = model::save_desired(&model::desired_path(), desired);
}

fn guard() -> std::sync::MutexGuard<'static, GuardState> {
    MOUNT_GUARD
        .get_or_init(|| std::sync::Mutex::new(GuardState::default()))
        // A panic while holding the guard (e.g. inside the 2s timer) must
        // not cascade into a panic on every later callback, killing the
        // Slint event loop: the GuardState invariants are simple enough that
        // recovering the (possibly mid-update) state is strictly better than
        // dying (#61).
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Monitor desired mounts and auto-restart any whose process died without a
/// user-initiated unmount. Backs off 30s between attempts, stops retrying
/// after a fast failure (config error) until the user mounts manually, and
/// gives up after [`MAX_AUTO_RESTARTS`] consecutive restarts so a
/// crash-looping mount cannot be respawned forever (#61).
fn auto_restart(
    ui: &MainWindow,
    hold: &StatusHold,
    state: &Rc<RefCell<model::ProfilesFile>>,
    recent: &Rc<RefCell<Vec<RecentSpawn>>>,
    ossmount: &Rc<Option<PathBuf>>,
) {
    let profiles = state.borrow().profiles.clone();
    let mounts = model::read_mounts(&profiles);
    let mut g = guard();
    for drive in g.desired.clone() {
        if mounts.iter().any(|m| m.alive && m.drive == drive) {
            g.failed.remove(&drive);
            // Replenish the restart budget only after the mount has stayed
            // alive for a while — a mount that dies every ~30s must not get
            // its budget cleared on every 2s alive tick (review B2).
            let stable_elapsed = g.alive_since.get(&drive).map(|t| t.elapsed());
            match stable_elapsed {
                None => {
                    g.alive_since.insert(drive.clone(), Instant::now());
                }
                Some(elapsed) if budget_resets(elapsed) => {
                    g.restarts.remove(&drive);
                    g.alive_since.insert(drive.clone(), Instant::now());
                }
                Some(_) => {}
            }
            continue;
        }
        // Not alive: the stable-alive clock resets with the mount.
        g.alive_since.remove(&drive);
        if g.failed.contains(&drive) {
            continue;
        }
        let since = g
            .last_spawn
            .get(&drive)
            .map(|t| t.elapsed())
            .unwrap_or(Duration::from_secs(60));
        let spent = *g.restarts.get(&drive).unwrap_or(&0);
        match restart_decision(since, spent) {
            RestartDecision::WaitForBackoff => continue,
            RestartDecision::GiveUp => {
                g.failed.insert(drive.clone());
                hold_status(
                    ui,
                    hold,
                    format!(
                        "{drive} 多次自动重启后仍退出（已达 {MAX_AUTO_RESTARTS} 次上限），已停止自动重启，请手动重挂或查看日志"
                    ),
                    30,
                );
                continue;
            }
            RestartDecision::Proceed => {}
        }
        let Some(p) = profiles
            .iter()
            .find(|p| model::normalize_mount_point(&p.drive) == drive)
            .cloned()
        else {
            g.failed.insert(drive);
            continue;
        };
        if p.validate().is_err() {
            g.failed.insert(drive);
            continue;
        }
        let spawned: Option<std::io::Result<(u32, PathBuf)>> = ossmount
            .as_ref()
            .as_deref()
            .map(|o| model::spawn_oss_mount(o, &p));
        match spawned {
            Some(Ok((pid, log))) => {
                g.last_spawn.insert(drive.clone(), Instant::now());
                g.restarts
                    .entry(drive.clone())
                    .and_modify(|n| *n += 1)
                    .or_insert(1);
                recent.borrow_mut().push(RecentSpawn {
                    drive: drive.clone(),
                    pid,
                    log,
                    at: Instant::now(),
                });
                hold_status(
                    ui,
                    hold,
                    format!("检测到 {drive} 挂载进程退出，正在自动重启…"),
                    4,
                );
            }
            Some(Err(e)) => {
                g.failed.insert(drive.clone());
                hold_status(ui, hold, format!("{drive} 自动重启失败：{e}"), 8);
            }
            None => {
                g.failed.insert(drive);
            }
        }
    }
    // Fast-fail guard: a desired mount whose spawned process died within 15s
    // is most likely a config/credential error; stop auto-retrying.
    for s in recent.borrow().iter() {
        if g.desired.contains(&s.drive)
            && g.last_spawn.get(&s.drive).is_some()
            && s.at.elapsed() < Duration::from_secs(15)
            && !winutil::pid_alive(s.pid)
            && !mounts.iter().any(|m| m.alive && m.drive == s.drive)
        {
            g.failed.insert(s.drive.clone());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the winit backend (macOS: hidden titlebar, keep traffic lights)
    // before creating any Slint component.
    configure_backend()?;

    // Single-instance protection via a Windows named mutex (kernel object):
    // a second launch is shown a message box and exits immediately.
    let _single_instance = match winutil::single_instance_guard("OSSFS-Tray") {
        Some(guard) => guard,
        None => {
            winutil::alert_single_instance();
            return Ok(());
        }
    };

    let ui = MainWindow::new()?;
    let edit = EditDialog::new()?;
    let tray = Tray::new()?;

    let loaded = model::load_profiles();
    let state = Rc::new(RefCell::new(loaded.file));
    let recent = Rc::new(RefCell::new(Vec::<RecentSpawn>::new()));
    let hold = Rc::new(StatusHold::default());
    let ossmount = Rc::new(model::find_ossmount());

    // Re-arm the auto-restart guard from the persisted desired set: a tray
    // restart/crash must not silently abandon supervision of mounts that are
    // still running (#61). Drives that are NOT running are deliberately NOT
    // re-armed — a machine reboot must not turn a past session's mounts into
    // auto-mounts on tray startup; the user remounts explicitly.
    {
        let running: std::collections::HashSet<String> =
            model::read_mounts(&state.borrow().profiles)
                .into_iter()
                .filter(|m| m.alive)
                .map(|m| m.drive)
                .collect();
        let mut g = guard();
        let persisted = model::load_desired(&model::desired_path());
        g.desired
            .extend(persisted.into_iter().filter(|d| running.contains(d)));
    }

    // Surface profile-storage problems (corrupt file recovered, secure
    // store unavailable, ...) to the user instead of failing silently.
    if !loaded.warnings.is_empty() {
        hold_status(&ui, &hold, format!("⚠️ {}", loaded.warnings.join("；")), 30);
    }

    // Drive letters are a Windows concept; macOS/Linux use mount directories.
    edit.set_show_free_drives(cfg!(windows));

    // On macOS the titlebar is hidden and content extends under it; leave room
    // for the native traffic-light buttons at the top of both windows.
    ui.set_traffic_light_padding(cfg!(target_os = "macos"));
    edit.set_traffic_light_padding(cfg!(target_os = "macos"));

    // Clicking the Dock icon should re-show the tray window (macOS).
    #[cfg(target_os = "macos")]
    {
        let ui_weak = ui.as_weak();
        mac_dock_reopen::install(move || {
            if let Some(ui) = ui_weak.upgrade() {
                winutil::set_dock_visible(true);
                let _ = ui.show();
                raise_window_to_front();
            }
        });
    }

    // Drop stale runtime records from earlier crashed/force-killed mounts so
    // both the tray status and `ossfs info` stay accurate.
    model::prune_stale_records();

    refresh(&ui, &tray, &state, &recent, &hold);

    // Preload the first saved profile into the form.
    if !state.borrow().profiles.is_empty() {
        profile_to_form(&edit, &state.borrow().profiles[0]);
    }

    // 模态确认：主窗口内的覆盖层（无第二个窗口、无第二个任务栏图标）。
    let pending: Rc<RefCell<Option<Box<dyn FnOnce()>>>> = Rc::new(RefCell::new(None));
    {
        let ui_weak = ui.as_weak();
        let pending_confirm = Rc::clone(&pending);
        ui.on_confirm_dialog(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_dlg_visible(false);
            }
            if let Some(f) = pending_confirm.borrow_mut().take() {
                f();
            }
        });
        let ui_weak = ui.as_weak();
        let pending_cancel = Rc::clone(&pending);
        ui.on_cancel_dialog(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_dlg_visible(false);
            }
            pending_cancel.borrow_mut().take();
        });
    }
    tray.set_autostart(winutil::autostart_enabled());

    wire_callbacks(
        &ui, &edit, &tray, &hold, &state, &recent, &ossmount, &pending,
    );

    // Periodic status refresh (2s) driven from the UI thread.
    let timer = Timer::default();
    {
        let ui_weak = ui.as_weak();
        let tray_weak = tray.as_weak();
        let hold = hold.clone();
        let state = state.clone();
        let recent = recent.clone();
        let ossmount = ossmount.clone();
        timer.start(TimerMode::Repeated, Duration::from_secs(2), move || {
            if let (Some(ui), Some(tray)) = (ui_weak.upgrade(), tray_weak.upgrade()) {
                auto_restart(&ui, &hold, &state, &recent, &ossmount);
                refresh(&ui, &tray, &state, &recent, &hold);
            }
        });
    }

    tray.show()?;
    ui.show()?;
    // macOS: 主窗口可见 → 显示 Dock 图标（纯托盘态才隐藏）。
    winutil::set_dock_visible(true);
    // macOS: 预热编辑窗的 Metal layer（同 feishu-bridge-rs 的做法）。Slint 首次 show
    // 的预渲染帧是空的（surface 在窗口 map 前没就绪），内容要等下一帧 redraw 才补上；
    // Metal layer 会保留上一帧，所以启动时挪到屏外 show + redraw 一次（不可见、无闪烁），
    // 下一帧再 hide 并复位位置。此后用户首次点「编辑」走「非首次 show」路径，秒开不透明。
    #[cfg(target_os = "macos")]
    {
        let saved = edit.window().position();
        edit.window()
            .set_position(slint::PhysicalPosition::new(-16_000, -16_000));
        let _ = edit.show();
        edit.window().request_redraw();
        let ew = edit.as_weak();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = ew.upgrade() {
                let _ = w.hide();
                w.window().set_position(saved);
            }
        });
    }
    ui.set_status_text(SharedString::from("OSSFS 托盘已就绪"));
    refresh(&ui, &tray, &state, &recent, &hold);

    slint::run_event_loop()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn wire_callbacks(
    ui: &MainWindow,
    edit: &EditDialog,
    tray: &Tray,
    hold: &Rc<StatusHold>,
    state: &Rc<RefCell<model::ProfilesFile>>,
    recent: &Rc<RefCell<Vec<RecentSpawn>>>,
    ossmount: &Rc<Option<PathBuf>>,
    pending: &Rc<RefCell<Option<Box<dyn FnOnce()>>>>,
) {
    let ui_weak = ui.as_weak();
    let edit_weak = edit.as_weak();
    let tray_weak = tray.as_weak();
    let hold = Rc::clone(hold);
    let state = Rc::clone(state);
    let recent = Rc::clone(recent);
    let ossmount = Rc::clone(ossmount);
    let pending = Rc::clone(pending);

    // --- save the form back into a profile ---
    edit.on_save_form({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        let tray_weak = tray_weak.clone();
        let state = state.clone();
        let recent = recent.clone();
        let hold = Rc::clone(&hold);
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(edit) = edit_weak.upgrade() else {
                return;
            };
            let p = form_to_profile(&edit);
            if let Err(e) = p.validate() {
                let msg = format!("保存失败：{e}");
                edit.set_form_error(msg.clone().into());
                ui.set_status_text(msg.into());
                return;
            }
            let occupied = drive_occupied(&p.drive);
            let mut save_warning: Option<String> = None;
            {
                let mut file = state.borrow_mut();
                upsert_profile(&mut file, &p);
                match model::save_profiles(&file) {
                    Ok(res) => {
                        save_warning = res.warnings.into_iter().next();
                    }
                    Err(e) => {
                        let msg = format!("保存失败：{e}");
                        edit.set_form_error(msg.clone().into());
                        ui.set_status_text(msg.into());
                        return;
                    }
                }
            }
            if let Some(w) = &save_warning {
                // Non-fatal: the profile IS saved — refresh so it shows up in
                // the main window and tray right away, but keep the dialog
                // open with the warning in the form so it is not missed.
                if let Some(tray) = tray_weak.upgrade() {
                    refresh(&ui, &tray, &state, &recent, &hold);
                }
                let msg = format!("已保存，但 ⚠️ {w}");
                edit.set_form_error(msg.clone().into());
                ui.set_status_text(msg.into());
                return;
            }
            edit.set_form_error(String::new().into());
            if let Some(tray) = tray_weak.upgrade() {
                refresh(&ui, &tray, &state, &recent, &hold);
            }
            close_edit_dialog(&ui, &edit);
            if occupied {
                ui.set_status_text(
                    format!("⚠️ 已保存，但盘符 {} 已被占用，挂载前请更换", p.drive).into(),
                );
            } else {
                ui.set_status_text(format!("配置「{}」已保存", p.name).into());
            }
        }
    });

    // --- add a new blank config -> open the edit window ---
    ui.on_add_config({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(edit) = edit_weak.upgrade() else {
                return;
            };
            let mut p = model::Profile::default();
            p.name = {
                let file = state.borrow();
                // 取第一个不冲突的默认名（避免「新建配置 2」这种依赖已有数量的叫法）。
                let mut n = 1;
                while file
                    .profiles
                    .iter()
                    .any(|q| q.name == format!("新建配置 {n}"))
                {
                    n += 1;
                }
                if n == 1 {
                    "新建配置".to_string()
                } else {
                    format!("新建配置 {n}")
                }
            };
            // 新配置默认 OSS 直挂 + 第一个空闲盘符。
            #[cfg(windows)]
            if let Some(d) = winutil::free_drives().first() {
                p.drive = d.clone();
            }
            profile_to_form(&edit, &p);
            open_edit_dialog(&ui, &edit, format!("添加配置「{}」", p.name));
            ui.set_status_text(format!("添加配置「{}」，填写后点保存", p.name).into());
        }
    });

    // --- edit a record -> load into the edit window ---
    ui.on_edit_record({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        let state = state.clone();
        move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(edit) = edit_weak.upgrade() else {
                return;
            };
            let profiles = state.borrow();
            let Some(p) = profiles.profiles.get(index as usize) else {
                return;
            };
            let p = p.clone();
            drop(profiles);
            profile_to_form(&edit, &p);
            open_edit_dialog(&ui, &edit, format!("编辑配置「{}」", p.name));
        }
    });

    // --- cancel editing ---
    edit.on_cancel_edit({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        move || {
            if let (Some(ui), Some(edit)) = (ui_weak.upgrade(), edit_weak.upgrade()) {
                close_edit_dialog(&ui, &edit);
            }
        }
    });

    // --- open a record's drive in Explorer ---
    ui.on_open_record({
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let profiles = state.borrow().profiles.clone();
            let Some(p) = profiles.get(index as usize) else {
                ui.set_status_text("记录不存在".into());
                return;
            };
            open_in_explorer(&model::normalize_mount_point(&p.drive));
        }
    });

    // --- per-record mount / unmount toggle ---
    ui.on_toggle_record({
        let ui_weak = ui_weak.clone();
        let tray_weak = tray_weak.clone();
        let state = state.clone();
        let recent = recent.clone();
        let ossmount = ossmount.clone();
        let pending = Rc::clone(&pending);
        let hold = Rc::clone(&hold);
        move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let profiles = state.borrow().profiles.clone();
            let Some(p) = profiles.get(index as usize).cloned() else {
                ui.set_status_text("记录不存在".into());
                return;
            };
            let drive = model::normalize_mount_point(&p.drive);
            let mounts = model::read_mounts(&profiles);
            if let Some(m) = mounts.iter().find(|m| m.drive == drive && m.alive) {
                // mounted -> confirm then unmount (Slint modal dialog)
                let m = m.clone();
                let ui_weak2 = ui_weak.clone();
                let tray_weak2 = tray_weak.clone();
                let state2 = state.clone();
                let recent2 = recent.clone();
                let hold2 = Rc::clone(&hold);
                ask_confirm(
                    &ui,
                    &pending,
                    &format!("确定要卸载 {drive} 吗？"),
                    move || {
                        // graceful_or_kill takes the drive out of the
                        // auto-restart desired set itself.
                        // 卸载已发起：立刻从“挂载中”跟踪里摘掉这条，避免进程还在
                        // 优雅退出期间被误判为“挂载中”而把挂载按钮一直置灰。
                        recent2.borrow_mut().retain(|r| r.pid != m.pid);
                        if let Some(ui) = ui_weak2.upgrade() {
                            graceful_or_kill(&ui, &m);
                        }
                        if let (Some(ui), Some(tray)) = (ui_weak2.upgrade(), tray_weak2.upgrade()) {
                            refresh(&ui, &tray, &state2, &recent2, &hold2);
                        }
                    },
                );
            } else {
                // not mounted -> mount
                if let Err(e) = p.validate() {
                    ui.set_status_text(format!("挂载失败：{e}").into());
                } else {
                    let started = mount_profile(
                        &ui, &pending, &tray_weak, &hold, &state, &recent, &ossmount, &p,
                    );
                    // Ask the guard to auto-restart this mount if it dies.
                    if started {
                        let desired = {
                            let mut g = guard();
                            g.desired.insert(drive.clone());
                            // A manual mount starts a new lifetime: clear any
                            // accumulated restart budget and fast-fail marks
                            // so the fresh mount gets a full budget (B2).
                            g.failed.remove(&drive);
                            g.restarts.remove(&drive);
                            g.alive_since.remove(&drive);
                            g.desired.clone()
                        };
                        persist_desired(&desired);
                    }
                }
            }
            if let Some(tray) = tray_weak.upgrade() {
                refresh(&ui, &tray, &state, &recent, &hold);
            }
        }
    });

    // --- delete a config record ---
    ui.on_delete_record({
        let ui_weak = ui_weak.clone();
        let tray_weak = tray_weak.clone();
        let state = state.clone();
        let recent = recent.clone();
        let pending = Rc::clone(&pending);
        let hold = Rc::clone(&hold);
        move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let (name, mounted) = {
                let profiles = state.borrow();
                let Some(p) = profiles.profiles.get(index as usize) else {
                    ui.set_status_text("记录不存在".into());
                    return;
                };
                let drive = model::normalize_mount_point(&p.drive);
                let mounted = model::read_mounts(&profiles.profiles)
                    .iter()
                    .any(|m| m.alive && m.drive == drive);
                (p.name.clone(), mounted)
            };
            // Regression (#61): deleting a config never checked whether its
            // drive is currently mounted.
            let mount_note = if mounted {
                "\n⚠️ 该配置的挂载点当前已挂载：删除配置不会卸载它。".to_string()
            } else {
                String::new()
            };
            let state2 = state.clone();
            let recent2 = recent.clone();
            let tray_weak2 = tray_weak.clone();
            let ui_weak2 = ui_weak.clone();
            let hold2 = Rc::clone(&hold);
            ask_confirm(
                &ui,
                &pending,
                &format!("确定要删除配置「{name}」吗？{mount_note}"),
                move || {
                    {
                        let mut file = state2.borrow_mut();
                        if index >= 0 && (index as usize) < file.profiles.len() {
                            let removed = file.profiles.remove(index as usize);
                            // A deleted profile's drive must leave the
                            // desired set too, or desired.json keeps a stale
                            // entry that the watchdog retries forever (#61).
                            // Match the normalized key the mount path uses.
                            let desired = {
                                let mut g = guard();
                                let key = model::normalize_mount_point(&removed.drive);
                                let changed = g.desired.remove(&key);
                                (changed, g.desired.clone())
                            };
                            if desired.0 {
                                persist_desired(&desired.1);
                            }
                        }
                        match model::save_profiles(&file) {
                            Ok(res) => {
                                if let Some(w) = res.warnings.first() {
                                    if let Some(ui) = ui_weak2.upgrade() {
                                        ui.set_status_text(format!("⚠️ {w}").into());
                                    }
                                }
                            }
                            Err(e) => {
                                if let Some(ui) = ui_weak2.upgrade() {
                                    ui.set_status_text(format!("删除失败：{e}").into());
                                }
                                return;
                            }
                        }
                    }
                    if let (Some(ui), Some(tray)) = (ui_weak2.upgrade(), tray_weak2.upgrade()) {
                        refresh(&ui, &tray, &state2, &recent2, &hold2);
                        ui.set_status_text(format!("已删除配置「{name}」").into());
                    }
                },
            );
        }
    });

    // --- import a config from an `ossmount --config` JSON file ---
    ui.on_import_config({
        let ui_weak = ui_weak.clone();
        let tray_weak = tray_weak.clone();
        let state = state.clone();
        let recent = recent.clone();
        let hold = Rc::clone(&hold);
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(path) = rfd::FileDialog::new()
                .add_filter("OSSFS 配置", &["json"])
                .pick_file()
            else {
                return;
            };
            let Ok(raw) = std::fs::read_to_string(&path) else {
                ui.set_status_text("导入失败：无法读取所选文件".into());
                return;
            };
            let p = match model::Profile::from_ossmount_config(&raw) {
                Ok(p) => p,
                Err(e) => {
                    ui.set_status_text(format!("导入失败：{e}").into());
                    return;
                }
            };
            if let Err(e) = p.validate() {
                ui.set_status_text(format!("导入失败：{e}").into());
                return;
            }
            let mut save_warning: Option<String> = None;
            {
                let mut file = state.borrow_mut();
                let mut p = p;
                p.name = unique_import_name(&file.profiles, &p.name);
                file.profiles.push(p);
                match model::save_profiles(&file) {
                    Ok(res) => save_warning = res.warnings.into_iter().next(),
                    Err(e) => {
                        ui.set_status_text(format!("导入失败：{e}").into());
                        return;
                    }
                }
            }
            if let Some(tray) = tray_weak.upgrade() {
                refresh(&ui, &tray, &state, &recent, &hold);
            }
            // The import itself succeeded (the list above was refreshed);
            // store-fallback warnings are reported, not fatal.
            let msg = match &save_warning {
                Some(w) => format!("已导入配置，但 ⚠️ {w}"),
                None => "已导入配置".to_string(),
            };
            ui.set_status_text(msg.into());
        }
    });

    // --- export a record's config to an `ossmount --config` JSON file ---
    ui.on_export_config({
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let p = {
                let profiles = state.borrow();
                let Some(p) = profiles.profiles.get(index as usize) else {
                    ui.set_status_text("记录不存在".into());
                    return;
                };
                p.clone()
            };
            let safe = sanitize_filename(&p.name);
            let Some(path) = rfd::FileDialog::new()
                .set_file_name(format!("{safe}.json"))
                .add_filter("OSSFS 配置", &["json"])
                .save_file()
            else {
                return;
            };
            if let Err(e) = std::fs::write(&path, p.to_ossmount_config()) {
                ui.set_status_text(format!("导出失败：{e}").into());
                return;
            }
            ui.set_status_text(
                format!(
                    "已导出配置到 {}（⚠️ 文件内含明文 AccessKey/SecretKey，请妥善保管）",
                    path.display()
                )
                .into(),
            );
        }
    });

    // --- select a record -> load into the form ---
    // --- tray: open a mounted drive ---
    // The index identifies a row of the menu as it was rendered; resolve it
    // against the snapshot taken when the menu was last populated instead of
    // re-reading the (possibly reordered) mount list (#61).
    tray.on_open_mount(move |index| {
        let drive = tray_menu_drives().get(index as usize).cloned();
        if let Some(drive) = drive {
            open_in_explorer(&drive);
        }
    });

    // --- window close -> hide to tray (进程保留，双击托盘图标重新打开) ---
    ui.window().on_close_requested({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        move || {
            if let (Some(ui), Some(edit)) = (ui_weak.upgrade(), edit_weak.upgrade()) {
                close_edit_dialog(&ui, &edit);
                let _ = ui.hide();
                #[cfg(target_os = "macos")]
                sync_dock_visibility(&ui, &edit);
            }
            slint::CloseRequestResponse::HideWindow
        }
    });
    // Edit dialog X button == cancel: close modally and re-enable the owner.
    edit.window().on_close_requested({
        let ui_weak = ui_weak.clone();
        let edit_weak = edit_weak.clone();
        move || {
            if let (Some(ui), Some(edit)) = (ui_weak.upgrade(), edit_weak.upgrade()) {
                close_edit_dialog(&ui, &edit);
                #[cfg(target_os = "macos")]
                sync_dock_visibility(&ui, &edit);
            }
            slint::CloseRequestResponse::HideWindow
        }
    });
    tray.on_show_window({
        let ui_weak = ui_weak.clone();
        move || {
            if let Some(ui) = ui_weak.upgrade() {
                winutil::set_dock_visible(true);
                let _ = ui.show();
                // Slint has no public bring-to-front API; raise + focus the
                // window natively so it always lands on top (Windows needs
                // Win32 activation; macOS uses Cocoa activation).
                raise_window_to_front();
            }
        }
    });
    // --- 开机自启 ---
    tray.on_autostart_changed({
        let ui_weak = ui_weak.clone();
        move |enabled| {
            if let Err(e) = winutil::set_autostart(enabled) {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_status_text(format!("设置开机自启失败：{e}").into());
                }
            }
        }
    });

    // 退出：先显式移除托盘图标（避免任何情况下残留），再退出事件循环。
    // Slint 的 SystemTrayIcon 在组件 drop 时也会 NIM_DELETE，这里 double-check。
    // Regression (#61): quitting used to ignore live mounts entirely — no
    // hint and no choice. Now quitting with live mounts asks for
    // confirmation first (they stay mounted but lose auto-restart
    // supervision once the tray is gone).
    let tray_for_quit = tray_weak.clone();
    let ui_for_quit = ui.as_weak();
    let state_for_quit = state.clone();
    let pending_for_quit = Rc::clone(&pending);
    let do_quit = move || {
        let mounts = model::read_mounts(&state_for_quit.borrow().profiles);
        let live: Vec<String> = mounts
            .iter()
            .filter(|m| m.alive)
            .map(|m| m.drive.clone())
            .collect();
        let tray_weak_now = tray_for_quit.clone();
        let quit_now = move || {
            if let Some(tray) = tray_weak_now.upgrade() {
                // 先移除托盘图标（Slint 组件 drop 时也会 NIM_DELETE，双保险）。
                let _ = tray.hide();
            }
            quit_app();
        };
        if live.is_empty() {
            quit_now();
            return;
        }
        if let Some(ui) = ui_for_quit.upgrade() {
            // The confirm dialog lives in the main window; make sure it is
            // visible even when quitting from the tray menu.
            let _ = ui.show();
            ask_confirm(
                &ui,
                &pending_for_quit,
                &format!(
                    "仍有 {} 个挂载在运行（{}）。\n退出托盘不会卸载它们，但退出后它们不再被自动重启看护。确定退出吗？",
                    live.len(),
                    live.join("、")
                ),
                quit_now,
            );
        } else {
            quit_now();
        }
    };
    ui.on_quit_app(do_quit.clone());
    tray.on_quit_app(do_quit);

    // --- 检查更新(issue #87) ---
    // 菜单状态默认「检查更新」;发现新版时回写「有新版本(x.x.x)」。
    // 菜单状态:默认「检查更新 v0.4.2」(版本号常显);发现新版 →「有新版本(x.x.x)」。
    tray.set_update_status(format!("检查更新 v{}", env!("CARGO_PKG_VERSION")).into());
    // 手动:菜单点击 → 新版弹提示,无新版/失败也告知结果。
    tray.on_check_update({
        let current = env!("CARGO_PKG_VERSION").to_string();
        let tray_weak = tray.as_weak();
        move || run_update_check(current.clone(), false, tray_weak.clone())
    });
    // 自动:启动后异步检查,仅发现新版时提示(网络失败静默)。
    run_update_check(env!("CARGO_PKG_VERSION").to_string(), true, tray.as_weak());
}

/// Spawn `ossmount` for `p`, remember the profile, and report progress.
/// Used by the per-record mount action.
fn mount_profile(
    ui: &MainWindow,
    pending: &Rc<RefCell<Option<Box<dyn FnOnce()>>>>,
    tray_weak: &slint::Weak<Tray>,
    hold: &Rc<StatusHold>,
    state: &Rc<RefCell<model::ProfilesFile>>,
    recent: &Rc<RefCell<Vec<RecentSpawn>>>,
    ossmount: &Rc<Option<PathBuf>>,
    p: &model::Profile,
) -> bool {
    let drive = model::normalize_mount_point(&p.drive);
    if drive_occupied(&drive) {
        ui.set_status_text(format!("盘符 {drive} 已被占用，请更换后挂载").into());
        return false;
    }
    // Another saved config already mounts this drive -> conflict.
    if model::read_mounts(&state.borrow().profiles)
        .iter()
        .any(|m| m.alive && m.drive == drive)
    {
        ui.set_status_text(format!("盘符 {drive} 已被其他配置挂载，请更换").into());
        return false;
    }
    // Double-click / auto-restart race guard: if we recently spawned a mount
    // process for this drive and it is still alive but has not yet produced a
    // mount, don't launch a second one.
    if recent.borrow().iter().any(|r| {
        r.drive == drive && r.at.elapsed() < Duration::from_secs(20) && winutil::pid_alive(r.pid)
    }) {
        ui.set_status_text(format!("{drive} 正在挂载中，请稍候…").into());
        return false;
    }
    // Kernel-level guard: never stack a second mount on a directory that is
    // already a mount point (e.g. a previous ossmount that left its NFS mount
    // behind, or the same dir mounted elsewhere).
    #[cfg(not(windows))]
    if winutil::path_is_mount_point(std::path::Path::new(&drive)) {
        ui.set_status_text(format!("{drive} 已是一个挂载点，请先卸载再挂载").into());
        return false;
    }
    #[cfg(target_os = "macos")]
    if !macos_fuse_backend_ready() {
        let ui_weak = ui.as_weak();
        let hold = Rc::clone(hold);
        ask_confirm(
            ui,
            pending,
            "未检测到 FUSE 后端。\nOSS 直挂需要 FUSE-T（免内核扩展，无需修改系统安全策略）或 macFUSE。\n是否自动下载并安装 FUSE-T？会弹出系统管理员密码框。",
            move || {
                if let Some(ui) = ui_weak.upgrade() {
                    hold_status(
                        &ui,
                        &hold,
                        "正在安装 FUSE-T（请在弹出的系统框输入密码，约 1-2 分钟）…".into(),
                        120,
                    );
                }
                std::thread::spawn(move || {
                    let msg = match macos_install_fuse_t() {
                        Ok(s) => format!("{s}，请再次点击挂载"),
                        Err(e) => format!("FUSE-T 安装失败：{e}"),
                    };
                    let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                        ui.set_status_text(msg.into());
                    });
                });
            },
        );
        return false;
    }

    // Make sure the mountpoint directory exists (on macOS /Volumes needs
    // admin to create); without it the FUSE backend cannot mount.
    #[cfg(target_os = "macos")]
    if let Err(e) = macos_ensure_mountpoint_dir(&drive) {
        ui.set_status_text(e.into());
        return false;
    }

    let Some(ossmount) = ossmount.as_ref() else {
        #[cfg(windows)]
        ui.set_status_text("未找到 ossmount.exe（OSS 直挂需要 Windows + WinFsp）".into());
        #[cfg(not(windows))]
        ui.set_status_text(
            "未找到 ossmount（OSS 直挂需要 macOS + FUSE-T 或 macFUSE，请先安装 FUSE-T：brew install --cask fuse-t）".into(),
        );
        return false;
    };
    let spawned = model::spawn_oss_mount(ossmount, p);
    // Persist-failure note appended to the final status line ("" when the
    // save was clean); saving problems must not abort the mount, but they
    // must stay visible instead of being swallowed.
    let mut save_note = String::new();
    match spawned {
        Ok((pid, log)) => {
            {
                let mut file = state.borrow_mut();
                upsert_profile(&mut file, p);
                match model::save_profiles(&file) {
                    Ok(res) => {
                        if let Some(w) = res.warnings.first() {
                            save_note = format!("（⚠️ {w}）");
                        }
                    }
                    Err(e) => save_note = format!("（⚠️ 保存配置失败：{e}）"),
                }
            }
            recent.borrow_mut().push(RecentSpawn {
                drive: drive.clone(),
                pid,
                log,
                at: Instant::now(),
            });
        }
        Err(e) => {
            hold_status(ui, hold, format!("挂载启动失败：{e}"), 8);
            return false;
        }
    }
    if let Some(tray) = tray_weak.upgrade() {
        refresh(ui, &tray, state, recent, hold);
    }
    // Set after refresh() so the summary cannot clobber it on the same tick.
    let pid = recent.borrow().last().map(|s| s.pid).unwrap_or(0);
    ui.set_status_text(format!("正在挂载 {drive}（PID {pid}），等待就绪…{save_note}").into());
    true
}

/// Insert or update `p` in the profile list (keyed by name).
fn upsert_profile(file: &mut model::ProfilesFile, p: &model::Profile) {
    let pos = file.profiles.iter().position(|x| x.name == p.name);
    match pos {
        Some(i) => {
            let mut p = p.clone();
            // The edit form has no field for it: keep the secure-store key of
            // the profile being replaced so the credentials are updated in
            // place instead of orphaning the old entry.
            if p.secret_ref.is_none() {
                p.secret_ref = file.profiles[i].secret_ref.clone();
            }
            file.profiles[i] = p;
        }
        None => file.profiles.push(p.clone()),
    }
}

/// Sanitize a profile name into a filesystem-safe file stem.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Return a profile name that does not collide with existing profiles, by
/// appending a numeric suffix (`导入配置 2`, ...) when needed.
fn unique_import_name(existing: &[model::Profile], base: &str) -> String {
    let mut name = base.to_string();
    let mut n = 1;
    while existing.iter().any(|q| q.name == name) {
        n += 1;
        name = format!("{base} {n}");
    }
    name
}

fn refresh(
    ui: &MainWindow,
    tray: &Tray,
    state: &Rc<RefCell<model::ProfilesFile>>,
    recent: &Rc<RefCell<Vec<RecentSpawn>>>,
    hold: &Rc<StatusHold>,
) {
    let profiles = state.borrow().profiles.clone();
    let mounts = model::read_mounts(&profiles);

    // Surface mounts we spawned that died before the runtime registry record
    // appeared (e.g. WinFsp missing, bad S3 credentials, invalid data dir).
    {
        let mut recent = recent.borrow_mut();
        recent.retain(|s| {
            // Give up tracking very slow mounts (long S3/meta init) silently.
            if s.at.elapsed() > Duration::from_secs(120) {
                return false;
            }
            let mounted = mounts
                .iter()
                .any(|m| m.drive == s.drive && m.alive && m.pid == s.pid);
            if mounted {
                return false;
            }
            if !winutil::pid_alive(s.pid) {
                // Reap the zombie so the process table entry disappears.
                winutil::reap_child(s.pid);
                let tail = model::read_log_tail(&s.log, 2048);
                let detail = tail.trim();
                let msg = if detail.is_empty() {
                    format!("挂载 {} 失败（PID {} 已退出）", s.drive, s.pid)
                } else {
                    format!("挂载 {} 失败：{}", s.drive, detail)
                };
                hold_status(ui, hold, msg, 8);
                return false;
            }
            true
        });
    }

    // Main list: every saved profile, tagged with its mount state.
    let records: Vec<ProfileRecord> = profiles
        .iter()
        .map(|p| {
            let drive = model::normalize_mount_point(&p.drive);
            let m = mounts.iter().find(|m| m.drive == drive);
            // 行内只展示“盘名”（对象存储即 bucket），其余参数在编辑表单里看。
            let detail = p.s3_bucket.clone();
            ProfileRecord {
                name: p.name.clone().into(),
                drive: drive.clone().into(),
                detail: detail.into(),
                mounted: m.map(|m| m.alive).unwrap_or(false),
                // “挂载中”：有我们刚拉起的、还活着且尚未挂上的进程（recent 里
                // 只剩这类进程，见上面的 retain）。此时禁用挂载按钮防重复点击。
                mounting: recent.borrow().iter().any(|s| s.drive == drive),
            }
        })
        .collect();
    ui.set_records(ModelRc::new(Rc::new(VecModel::from(records))));

    // Tray menu: only live mounts. Keep a same-order snapshot of the drives
    // so the menu callback's index resolves against what the user saw (#61).
    let tray_rows: Vec<MountInfo> = mounts
        .iter()
        .filter(|m| m.alive)
        .map(|m| MountInfo {
            drive: m.drive.clone().into(),
            backend: m.backend.clone().into(),
            detail: m.detail.clone().into(),
            pid: m.pid as i32,
            alive: m.alive,
        })
        .collect();
    *tray_menu_drives() = tray_rows.iter().map(|m| m.drive.to_string()).collect();
    tray.set_mounts(ModelRc::new(Rc::new(VecModel::from(tray_rows))));

    let live: Vec<&model::MountStatus> = mounts.iter().filter(|m| m.alive).collect();
    let status = if live.is_empty() {
        "当前没有活动挂载。".to_string()
    } else {
        let drives: Vec<&str> = live.iter().map(|m| m.drive.as_str()).collect();
        format!("已挂载 {} 个盘符：{}", live.len(), drives.join(", "))
    };
    // Keep a held error/transient message visible instead of overwriting it
    // with the summary on the next 2s refresh tick.
    if let Some(until) = hold.until.get() {
        if Instant::now() < until {
            ui.set_status_text(hold.msg.borrow().clone().into());
            let tooltip = if live.is_empty() {
                "OSSFS（无挂载）".to_string()
            } else {
                let drives: Vec<&str> = live.iter().map(|m| m.drive.as_str()).collect();
                format!("OSSFS：已挂载 {}", drives.join(", "))
            };
            tray.set_tray_tooltip(tooltip.into());
            return;
        }
    }
    ui.set_status_text(status.into());

    let tooltip = if live.is_empty() {
        "OSSFS（无挂载）".to_string()
    } else {
        let drives: Vec<&str> = live.iter().map(|m| m.drive.as_str()).collect();
        format!("OSSFS：已挂载 {}", drives.join(", "))
    };
    tray.set_tray_tooltip(tooltip.into());
}

/// Whether a Windows drive letter is currently in use (system drive or
/// already-mounted). macOS/Linux mount points are directories, no check.
#[cfg(windows)]
fn drive_occupied(drive: &str) -> bool {
    let d = model::normalize_mount_point(drive);
    winutil::used_drives()
        .iter()
        .any(|u| u.eq_ignore_ascii_case(&d))
}

#[cfg(not(windows))]
fn drive_occupied(_drive: &str) -> bool {
    false
}

/// The mount point currently selected in the form: the chosen drive letter
/// on Windows (from the dropdown), the typed directory on macOS/Linux.
fn drive_from_form(edit: &EditDialog) -> String {
    #[cfg(windows)]
    {
        // Prefer the typed/selected value (the dropdown's selected() keeps
        // cfg-drive in sync, and profile_to_form sets it from a saved record,
        // so a saved drive is never silently replaced by the dropdown).
        let typed = edit.get_cfg_drive().to_string();
        if !typed.is_empty() {
            return typed;
        }
        // Fresh form: default to the first free drive.
        winutil::free_drives().first().cloned().unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        edit.get_cfg_drive().to_string()
    }
}

fn profile_to_form(edit: &EditDialog, p: &model::Profile) {
    edit.set_cfg_name(p.name.clone().into());
    edit.set_cfg_drive(p.drive.clone().into());
    #[cfg(windows)]
    {
        let free = winutil::free_drives();
        let idx = free
            .iter()
            .position(|d| d.eq_ignore_ascii_case(&p.drive))
            .unwrap_or(0);
        edit.set_cfg_drive_index(idx as i32);
    }
    edit.set_cfg_s3_bucket(p.s3_bucket.clone().into());
    edit.set_cfg_s3_endpoint(p.s3_endpoint.clone().into());
    edit.set_cfg_s3_region(p.s3_region.clone().into());
    edit.set_cfg_s3_access_key(p.access_key.clone().into());
    edit.set_cfg_s3_secret_key(p.secret_key.clone().into());
    edit.set_cfg_s3_force_path_style(p.s3_force_path_style);
    edit.set_cfg_prefix(p.prefix.clone().into());
}

fn form_to_profile(edit: &EditDialog) -> model::Profile {
    model::Profile {
        name: edit.get_cfg_name().to_string(),
        mode: "oss".to_string(),
        drive: drive_from_form(edit),
        s3_bucket: edit.get_cfg_s3_bucket().to_string(),
        s3_endpoint: edit.get_cfg_s3_endpoint().to_string(),
        s3_region: edit.get_cfg_s3_region().to_string(),
        s3_force_path_style: edit.get_cfg_s3_force_path_style(),
        s3_disable_payload_checksum: true,
        prefix: edit.get_cfg_prefix().to_string(),
        access_key: edit.get_cfg_s3_access_key().to_string(),
        secret_key: edit.get_cfg_s3_secret_key().to_string(),
        // Preserved from the replaced profile by `upsert_profile`.
        secret_ref: None,
    }
}

/// Show the Slint modal confirm dialog and run `on_yes` when the user
/// confirms. The dialog is a separate always-shown-on-top window, so it is
/// never hidden behind other windows (unlike the old Win32 MessageBox).
///
/// The dialog is a single shared slot: if another confirmation is already
/// pending (e.g. the tray "quit" fires while an unmount/delete dialog is
/// open), the new request is refused instead of silently replacing the
/// pending action — confirming the visible dialog must never execute a
/// different action than the one shown (review B3).
fn ask_confirm(
    ui: &MainWindow,
    pending: &Rc<RefCell<Option<Box<dyn FnOnce()>>>>,
    message: &str,
    on_yes: impl FnOnce() + 'static,
) {
    if pending.borrow().is_some() {
        ui.set_status_text("请先完成当前确认操作".into());
        return;
    }
    ui.set_dlg_message(message.into());
    ui.set_dlg_visible(true);
    *pending.borrow_mut() = Some(Box::new(on_yes));
}

/// How long a mount gets to flush its whole-file write buffers and unmount
/// after SIGTERM before it is force-killed (#61). In-flight buffered writes
/// are lost on a force kill, so the graceful window matters.
const GRACEFUL_UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Unmount an OSS mount.
///
/// Writes are whole-file buffered and pushed on close, so force-killing the
/// process can lose the entire in-flight buffer of a large file. The
/// sequence is therefore: ask for a graceful shutdown (SIGTERM on Unix —
/// `ossmount` unmounts cleanly on it; on Windows the tray signals the
/// mount's `Local\ossfs-unmount-<pid>` control event, added in #61), wait up
/// to [`GRACEFUL_UNMOUNT_TIMEOUT`] for the process to exit, and only then
/// force-terminate. A mount running an ossmount build without the control
/// event reports no graceful channel and is force-terminated as before.
fn graceful_or_kill(ui: &MainWindow, m: &model::MountStatus) {
    let desired = {
        let mut g = guard();
        g.desired.remove(&m.drive);
        g.desired.clone()
    };
    persist_desired(&desired);
    guard().alive_since.remove(&m.drive);
    let ui_weak = ui.as_weak();
    let m = m.clone();
    std::thread::spawn(move || {
        let graceful = winutil::request_graceful_shutdown(m.pid);
        if !(graceful && winutil::wait_for_exit(m.pid, GRACEFUL_UNMOUNT_TIMEOUT)) {
            if let Err(e) = winutil::terminate_process(m.pid) {
                // The unmount failed and the drive is no longer supervised:
                // re-arm the auto-restart guard so the (possibly still
                // running) mount stays watched, instead of silently losing
                // supervision with a stale runtime record (review B4). Only
                // re-arm when the process is genuinely still alive — a stale
                // pid would make the watchdog resurrect a dead mount on the
                // next tick, and the re-arm would survive a tray restart via
                // desired.json (#61).
                if winutil::pid_alive(m.pid) {
                    let desired = {
                        let mut g = guard();
                        g.desired.insert(m.drive.clone());
                        g.desired.clone()
                    };
                    persist_desired(&desired);
                }
                let msg = format!("卸载 {} 失败：{e}", m.drive);
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    ui.set_status_text(msg.into());
                });
                return;
            }
        }
        // Drop the stale drive icon from "This PC" right away.
        winutil::notify_drive_removed(&m.drive);
        // Remove the runtime record so the row can't linger as a stale
        // "not mounted" entry (idempotent: missing file is fine).
        let _ = std::fs::remove_file(model::oss_records_dir().join(format!("{}.json", m.pid)));
        let msg = format!("已卸载 {}", m.drive);
        let _ = ui_weak.upgrade_in_event_loop(move |ui| {
            ui.set_status_text(msg.into());
        });
    });
}

fn open_in_explorer(target: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("explorer.exe")
            .arg(target)
            .creation_flags(0x08000000 /* CREATE_NO_WINDOW */)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(target).spawn();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = target;
    }
}

/// macOS: is a usable FUSE backend (FUSE-T or macFUSE) already installed?
///
/// `ossmount` needs one of them to mount. FUSE-T is preferred because it is
/// kext-less (no Recovery Mode / security-policy change on Apple Silicon).
#[cfg(target_os = "macos")]
fn macos_fuse_backend_ready() -> bool {
    std::path::Path::new("/Library/Filesystems/macfuse.fs").exists()
        || std::path::Path::new("/Library/Application Support/fuse-t").exists()
        || std::path::Path::new("/usr/local/lib/libfuse-t.dylib").exists()
        || std::path::Path::new("/opt/homebrew/lib/libfuse-t.dylib").exists()
}

/// macOS: resolve the download URL of the latest FUSE-T installer pkg.
#[cfg(target_os = "macos")]
fn macos_latest_fuse_t_pkg_url() -> Option<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "https://api.github.com/repos/macos-fuse-t/fuse-t/releases/latest",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let marker = "\"browser_download_url\": \"";
    let mut rest = text.as_ref();
    while let Some(pos) = rest.find(marker) {
        let start = pos + marker.len();
        let end = rest[start..].find('"')? + start;
        let url = &rest[start..end];
        if url.contains("fuse-t-macos-installer") && url.ends_with(".pkg") {
            return Some(url.to_string());
        }
        rest = &rest[end..];
    }
    None
}

/// macOS: download and install FUSE-T (prompts for the administrator
/// password via AppleScript). FUSE-T is kext-less, so no security-policy
/// change or reboot is required.
#[cfg(target_os = "macos")]
fn macos_install_fuse_t() -> Result<String, String> {
    let url = macos_latest_fuse_t_pkg_url().ok_or_else(|| {
        "无法获取 FUSE-T 下载地址，请检查网络，或打开 https://www.fuse-t.org/ 手动安装".to_string()
    })?;
    let pkg = std::env::temp_dir().join("fuse-t-macos-installer.pkg");
    let out = std::process::Command::new("curl")
        .args(["-fL", "-o"])
        .arg(&pkg)
        .arg(&url)
        .output()
        .map_err(|e| format!("下载 FUSE-T 安装包失败：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "下载 FUSE-T 安装包失败：{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let script = format!(
        "do shell script \"installer -pkg {} -target /\" with administrator privileges",
        pkg.display()
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("启动系统安装器失败：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "安装 FUSE-T 失败（可能取消了密码）：{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if macos_fuse_backend_ready() {
        Ok("FUSE-T 安装完成".to_string())
    } else {
        Err(
            "FUSE-T 安装程序已执行，但未检测到安装结果；请打开 https://www.fuse-t.org/ 手动安装"
                .to_string(),
        )
    }
}

/// macOS: make sure the mountpoint directory exists. `/Volumes` is
/// root-owned, so when a plain `mkdir -p` fails (Permission denied), ask the
/// user for the administrator password once (same pattern as the FUSE-T
/// installer) and create it.
#[cfg(target_os = "macos")]
fn macos_ensure_mountpoint_dir(path: &str) -> Result<(), String> {
    use std::process::Command;

    let p = std::path::Path::new(path);
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let gid = Command::new("id")
        .arg("-g")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    // Fast path: the directory exists and is owned by us. Non-root NFS/FUSE
    // mounts require the mountpoint to belong to the mounting user; a
    // root-owned mountpoint fails with EPERM ("Operation not permitted").
    if p.exists() {
        let owned = Command::new("stat")
            .args(["-f", "%u", path])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|owner| owner == uid)
            .unwrap_or(false);
        if owned {
            return Ok(());
        }
    } else if std::fs::create_dir_all(p).is_ok() {
        return Ok(());
    }

    // Missing or not owned by us: ask for the administrator password once to
    // create it under /Volumes and chown it to the current user.
    let escaped = path.replace('\'', "'\\''");
    let script = format!(
        "do shell script \"mkdir -p '{}' && chown {}:{} '{}'\" with administrator privileges",
        escaped, uid, gid, escaped
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("创建挂载点失败：{e}"))?;
    if out.status.success() && p.exists() {
        Ok(())
    } else {
        Err(format!("无法创建挂载点 {path}（需要管理员权限，已取消）"))
    }
}

/// Brings the app to the foreground on macOS (used by "显示窗口").
///
/// Slint 1.17 does not expose a window-activation API, so we activate the
/// Cocoa application natively; this raises all of its windows above other
/// apps and gives the window keyboard focus.
#[cfg(target_os = "macos")]
fn raise_window_to_front() {
    use objc::{class, msg_send, sel, sel_impl};
    #[allow(unexpected_cfgs)] // objc 0.2 macros emit cargo-clippy cfg noise
    unsafe {
        let app: *mut objc::runtime::Object = msg_send![class!(NSApplication), sharedApplication];
        let _: () = msg_send![app, activateIgnoringOtherApps: true];
    }
}

/// macOS: the Dock icon should exist only while at least one window is
/// visible (pure tray state otherwise), mirroring feishu-bridge.
#[cfg(target_os = "macos")]
fn sync_dock_visibility(ui: &MainWindow, edit: &EditDialog) {
    let any_visible = ui.window().is_visible() || edit.window().is_visible();
    winutil::set_dock_visible(any_visible);
}

/// Windows: bring the tray's main window to the foreground.
///
/// `ui.show()` alone does not raise a hidden winit window, and Slint has no
/// public bring-to-front API, so we do it natively: find the largest top-level
/// window owned by this process, restore it if minimized, then use the
/// standard tray-app sequence (topmost-toggle + SetForegroundWindow, with an
/// AttachThreadInput fallback) so the window always lands on top and focused.
#[cfg(target_os = "windows")]
fn raise_window_to_front() {
    use std::cell::Cell;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, EnumWindows, GetForegroundWindow, GetWindowTextW,
        GetWindowThreadProcessId, HWND_NOTOPMOST, HWND_TOPMOST, IsIconic, SW_RESTORE, SW_SHOW,
        SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, SetForegroundWindow, SetWindowPos, ShowWindow,
    };

    // The tray's "show window" action targets the main window only. The edit
    // dialog is a separate hidden window and must never be raised by it, so we
    // match the main window by its title ("OSSFS") instead of picking the
    // largest top-level window (the edit dialog is larger than the main one).
    thread_local! {
        static MAIN_HWND: Cell<HWND> = const { Cell::new(null_mut()) };
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, _: LPARAM) -> BOOL {
        unsafe {
            let mut pid: u32 = 0;
            let _ = GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == std::process::id() {
                let mut title = [0u16; 128];
                let len = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
                if len > 0 {
                    let t = String::from_utf16_lossy(&title[..len as usize]);
                    if t == "OSSFS" {
                        MAIN_HWND.with(|c| c.set(hwnd));
                    }
                }
            }
        }
        1
    }

    unsafe {
        MAIN_HWND.with(|c| c.set(null_mut()));
        EnumWindows(Some(enum_proc), 0);

        let hwnd = MAIN_HWND.with(|c| c.get());
        if hwnd.is_null() {
            return;
        }
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        ShowWindow(hwnd, SW_SHOW);

        // Tray-app foreground trick: temporarily mark topmost to force
        // activation, then restore normal z-order so the flag does not stick.
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        if SetForegroundWindow(hwnd) == 0 {
            let foreground = GetForegroundWindow();
            if !foreground.is_null() {
                let fg_thread = GetWindowThreadProcessId(foreground, null_mut());
                let cur_thread = GetCurrentThreadId();
                if AttachThreadInput(cur_thread, fg_thread, 1) != 0 {
                    SetForegroundWindow(hwnd);
                    AttachThreadInput(cur_thread, fg_thread, 0);
                }
            }
        }
        BringWindowToTop(hwnd);
    }
}

/// Non-Windows/non-macOS platforms: `show()` is enough.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn raise_window_to_front() {}

/// Native HWND of a Slint window (Windows). Slint exposes the underlying
/// winit window via `WinitWindowAccessor`; from there the raw window handle
/// yields the Win32 `HWND`.
#[cfg(windows)]
fn get_hwnd(window: &slint::Window) -> Option<isize> {
    use slint::winit_030::{WinitWindowAccessor, winit::raw_window_handle::HasWindowHandle};
    window.with_winit_window(|winit_window| {
        let raw = winit_window.window_handle().ok()?;
        match raw.as_raw() {
            slint::winit_030::winit::raw_window_handle::RawWindowHandle::Win32(h) => {
                Some(h.hwnd.get())
            }
            _ => None,
        }
    })?
}

/// Refresh the drive-letter dropdown of the edit dialog before showing it.
#[cfg(windows)]
fn update_drive_options(edit: &EditDialog) {
    use slint::{ModelRc, SharedString, VecModel};
    let free = winutil::free_drives();
    let options: Vec<SharedString> = free.iter().map(|d| SharedString::from(d.clone())).collect();
    edit.set_drive_options(ModelRc::new(Rc::new(VecModel::from(options))));
    let current = edit.get_cfg_drive().to_string();
    if let Some(idx) = free.iter().position(|d| d.eq_ignore_ascii_case(&current)) {
        edit.set_cfg_drive_index(idx as i32);
    }
}

/// Open the add/edit dialog as a real Win32 **owned window** of the main
/// window: no taskbar button, always above its owner, and the owner is
/// disabled so the dialog is genuinely modal (mouse/keyboard can only reach
/// the dialog).
// `ui` is only dereferenced on Windows (modal Win32 ownership); the macOS
// build would otherwise warn on the new macOS CI job.
#[cfg_attr(not(windows), allow(unused_variables))]
fn open_edit_dialog(ui: &MainWindow, edit: &EditDialog, title: String) {
    edit.set_form_error(String::new().into());
    edit.set_edit_title(title.into());
    #[cfg(windows)]
    update_drive_options(edit);
    // Secondary Slint windows can keep a stale default OS size; force the
    // dialog through Slint's own size API so the form renders at 620x560.
    edit.window()
        .set_size(slint::WindowSize::Logical(slint::LogicalSize::new(
            620.0, 700.0,
        )));
    // macOS: 顺序很关键（同 feishu-bridge-rs 的实测结论）——Slint winit 后端在
    // set_visible 里对「首次 show」的预渲染发生在窗口 map 之前、Metal surface 未就绪，
    // 首帧画空且 macOS 不会自动补 redraw，导致内容区透明只剩控制按钮。
    // 因此：先激活（窗口还藏着，重排不闪）→ show → 显式 request_redraw 补画一帧。
    #[cfg(target_os = "macos")]
    {
        winutil::set_dock_visible(true);
        raise_window_to_front();
        let _ = edit.show();
        edit.window().request_redraw();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = edit.show();
    }
    #[cfg(windows)]
    make_modal_child(edit.window(), ui.window());
}

/// Close the edit dialog: re-enable the owner window and hide the dialog.
fn close_edit_dialog(ui: &MainWindow, edit: &EditDialog) {
    #[cfg(windows)]
    restore_modal(ui.window());
    let _ = edit.hide();
    #[cfg(target_os = "macos")]
    sync_dock_visibility(ui, edit);
}

/// Make `dialog` an owned window of `owner` (no taskbar entry, above owner),
/// center it over the owner, and disable the owner for modality.
#[cfg(windows)]
fn make_modal_child(dialog: &slint::Window, owner: &slint::Window) {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GWLP_HWNDPARENT, GetSystemMetrics, GetWindowRect, HWND_TOP, SPI_GETWORKAREA, SWP_NOSIZE,
        SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, SystemParametersInfoW,
    };
    unsafe {
        let Some(owner_hwnd) = get_hwnd(owner) else {
            return;
        };
        let Some(dlg_hwnd) = get_hwnd(dialog) else {
            return;
        };
        let owner_hwnd = owner_hwnd as HWND;
        let dlg_hwnd = dlg_hwnd as HWND;

        // Owned window: disappears from the taskbar, stays above the owner,
        // minimizes/hides together with it.
        SetWindowLongPtrW(dlg_hwnd, GWLP_HWNDPARENT, owner_hwnd as isize);
        // Modal: the owner cannot receive input while the dialog is open.
        EnableWindow(owner_hwnd, 0);

        // Center the dialog in the screen work area (excludes the taskbar),
        // not over the owner: it is an owned child but should read as a
        // centered modal dialog on the desktop.
        let mut dr = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let mut wa = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let work_area_ok = SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            &mut wa as *mut RECT as *mut std::ffi::c_void,
            0,
        ) != 0;
        if GetWindowRect(dlg_hwnd, &mut dr) != 0 {
            let (w, h) = if work_area_ok && wa.right > wa.left && wa.bottom > wa.top {
                ((wa.right - wa.left), (wa.bottom - wa.top))
            } else {
                (
                    GetSystemMetrics(0), // SM_CXSCREEN
                    GetSystemMetrics(1), // SM_CYSCREEN
                )
            };
            let x = (w - (dr.right - dr.left)) / 2;
            let y = (h - (dr.bottom - dr.top)) / 2;
            SetWindowPos(dlg_hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE);
        }
        // Bring the dialog to the foreground so it is immediately visible and
        // focused (an owned window only stays above its owner, not other apps).
        SetForegroundWindow(dlg_hwnd);
    }
}

/// Re-enable the owner window after the edit dialog closes.
#[cfg(windows)]
fn restore_modal(owner: &slint::Window) {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
    unsafe {
        if let Some(h) = get_hwnd(owner) {
            EnableWindow(h as HWND, 1);
        }
    }
}

fn quit_app() {
    let _ = slint::quit_event_loop();
}

/// macOS: clicking the Dock icon must re-show the tray window.
///
/// winit installs its own `NSApplicationDelegate` and does not implement
/// `applicationShouldHandleReopen:hasVisibleWindows:`, so the default Cocoa
/// behaviour (activate, but leave a hidden window hidden) wins. Instead of
/// replacing winit's delegate (which would break its event handling), we add
/// that single method to the *existing* delegate class at runtime via
/// `class_addMethod`. The IMP calls a leaked callback that shows and raises
/// the Slint window, and returns YES so macOS proceeds with reactivation.
#[cfg(target_os = "macos")]
mod mac_dock_reopen {
    use std::ffi::CString;
    use std::sync::OnceLock;

    use objc2::ffi;
    use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, Sel};
    use objc2::{MainThreadMarker, sel};
    use objc2_app_kit::NSApplication;

    type Callback = Box<dyn Fn()>;
    /// Raw pointer holder: the callback is only ever dereferenced on the main
    /// thread (from the Cocoa delegate method), so Send/Sync are safe.
    struct CallbackPtr(*mut Callback);
    unsafe impl Send for CallbackPtr {}
    unsafe impl Sync for CallbackPtr {}
    static CALLBACK: OnceLock<CallbackPtr> = OnceLock::new();

    unsafe extern "C-unwind" fn reopen_imp(
        _this: &AnyObject,
        _cmd: Sel,
        _sender: *mut AnyObject,
        _has_visible_windows: Bool,
    ) -> Bool {
        if let Some(CallbackPtr(ptr)) = CALLBACK.get() {
            // The callback is leaked for the app lifetime, so this is valid.
            let callback = unsafe { &**ptr };
            callback();
        }
        Bool::new(true)
    }

    pub fn install(callback: impl Fn() + 'static) {
        // Keep the callback alive for the whole app lifetime.
        let _ = CALLBACK.set(CallbackPtr(Box::into_raw(Box::new(
            Box::new(callback) as Callback
        ))));

        let mtm = MainThreadMarker::new().expect("Dock reopen hook must run on the main thread");
        let app = NSApplication::sharedApplication(mtm);
        let Some(delegate) = app.delegate() else {
            eprintln!("OSSFS: no NSApplication delegate yet; Dock reopen hook not installed");
            return;
        };
        let class_ptr = unsafe {
            ffi::object_getClass(
                objc2::rc::Retained::as_ptr(&delegate) as *const _ as *mut AnyObject
            )
        };
        let class = unsafe { &*class_ptr };

        // - (BOOL)applicationShouldHandleReopen:(NSApplication *)sender
        //                              hasVisibleWindows:(BOOL)flag
        let sel = sel!(applicationShouldHandleReopen:hasVisibleWindows:);
        let types = CString::new("c32@0:8@16c24").expect("valid type encoding");
        let imp: Imp = unsafe {
            std::mem::transmute::<
                unsafe extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject, Bool) -> Bool,
                Imp,
            >(
                reopen_imp
                    as unsafe extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject, Bool) -> Bool,
            )
        };

        let added = unsafe {
            ffi::class_addMethod(
                class as *const AnyClass as *mut AnyClass,
                sel,
                imp,
                types.as_ptr(),
            )
        };
        if !added.as_bool() {
            eprintln!("OSSFS: class_addMethod failed; Dock reopen may not show the window");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn parse_release_asset_picks_windows_installer() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "tag_name": "v0.4.3",
            "assets": [
                {"name": "OSSFS-0.4.3-macos-arm64.dmg", "browser_download_url": "https://x/dmg"},
                {"name": "OSSFS-Setup-0.4.3.exe", "browser_download_url": "https://x/exe"}
            ]
        }"#,
        )
        .unwrap();
        let url = parse_release_asset(&json);
        let expected = if cfg!(target_os = "macos") {
            "https://x/dmg"
        } else {
            "https://x/exe"
        };
        assert_eq!(url.as_deref(), Some(expected));
    }

    #[test]
    fn http_timeouts_avoid_overall_download_cap() {
        // 回归(issue #87):旧实现用 ureq 整体超时 timeout(30s),慢速网络
        // (国内→GitHub CDN ~0.6MB/s)下载 43MB DMG 约需 70s,30s 即被掐断,
        // 误判下载失败并 fallback 打开浏览器页面。修复后必须为 per-read
        // 超时(数据持续到达即不中断)且不设整体超时。
        // 注:这是弱守卫(常量断言,防不住实现退回整体超时);真正的回归守卫是
        // 其余 replace_app/parse_mount_point 等测试 + 本机/CI 实测下载。
        assert!(
            HTTP_READ_TIMEOUT <= Duration::from_secs(60),
            "per-read 超时不宜过长"
        );
        assert!(HTTP_CONNECT_TIMEOUT < HTTP_READ_TIMEOUT);
    }

    #[test]
    fn parse_version_handles_v_prefix_and_parts() {
        assert_eq!(parse_version("v0.4.2"), Some((0, 4, 2)));
        assert_eq!(parse_version("0.4.2"), Some((0, 4, 2)));
        assert_eq!(parse_version("v1.10.0"), Some((1, 10, 0)));
        assert_eq!(parse_version("0.4"), None);
        assert_eq!(parse_version("v0.4.x"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("v0.4.2-beta"), None);
    }

    #[test]
    fn version_compare_semantics() {
        // check_for_update 的纯比较逻辑:最新 > 当前 → Some(最新)。
        let cmp = |current: &str, latest: &str| -> bool {
            let (c, l) = (
                parse_version(current).unwrap(),
                parse_version(latest).unwrap(),
            );
            l > c
        };
        assert!(cmp("0.4.1", "0.4.2"));
        assert!(cmp("0.4.9", "0.4.10"), "10 > 9,非字典序");
        assert!(cmp("0.3.0", "0.4.0"));
        assert!(!cmp("0.4.2", "0.4.2"));
        assert!(!cmp("0.4.3", "0.4.2"));
        assert!(!cmp("0.5.0", "0.4.2"));
    }

    #[test]
    fn sanitize_filename_keeps_safe_chars() {
        assert_eq!(sanitize_filename("OSS"), "OSS");
        assert_eq!(sanitize_filename("a-b_c"), "a-b_c");
        assert_eq!(sanitize_filename("a/b?"), "a_b_");
    }

    #[test]
    fn unique_import_name_appends_suffix_on_collision() {
        let profile = |name: &str| model::Profile {
            name: name.to_string(),
            ..model::Profile::default()
        };
        assert_eq!(unique_import_name(&[], "导入配置"), "导入配置");
        assert_eq!(
            unique_import_name(&[profile("导入配置")], "导入配置"),
            "导入配置 2"
        );
        assert_eq!(
            unique_import_name(&[profile("导入配置"), profile("导入配置 2")], "导入配置"),
            "导入配置 3"
        );
    }

    #[test]
    fn restart_decision_backs_off_then_gives_up() {
        // Regression (#61): the auto-restart guard had only a 30s backoff and
        // would respawn a crash-looping mount forever.
        assert_eq!(
            restart_decision(Duration::from_secs(5), 0),
            RestartDecision::WaitForBackoff
        );
        assert_eq!(
            restart_decision(Duration::from_secs(31), 0),
            RestartDecision::Proceed
        );
        assert_eq!(
            restart_decision(Duration::from_secs(31), MAX_AUTO_RESTARTS),
            RestartDecision::GiveUp
        );
        assert_eq!(
            restart_decision(Duration::from_secs(31), MAX_AUTO_RESTARTS + 10),
            RestartDecision::GiveUp
        );
        // The backoff still applies even with budget left.
        assert_eq!(
            restart_decision(Duration::from_secs(1), MAX_AUTO_RESTARTS - 1),
            RestartDecision::WaitForBackoff
        );
    }

    #[test]
    fn restart_budget_resets_only_after_stable_alive() {
        // Review B2: without a stable-alive window the budget would be
        // cleared on every 2s alive tick and the MAX_AUTO_RESTARTS cap would
        // be dead code for mounts that crash slower than the tick (the exact
        // "crash every ~30s, respawned forever" case #61 fixes).
        assert!(!budget_resets(Duration::from_secs(29)));
        assert!(!budget_resets(Duration::from_secs(59)));
        assert!(budget_resets(Duration::from_secs(60)));
        assert!(budget_resets(Duration::from_secs(61)));
    }

    #[test]
    fn guard_recovers_from_poisoned_mutex() {
        // Regression (#61): any panic while holding the guard made every
        // later timer callback panic too, killing the Slint event loop.
        let drive = format!("poison-test-{}", std::process::id());
        std::thread::scope(|s| {
            let d = drive.clone();
            s.spawn(move || {
                let mut g = guard();
                // Mutate state, then panic while still holding the lock.
                g.desired.insert(d);
                panic!("poison the guard mutex");
            })
            .join()
            .unwrap_err();
        });
        // Must not panic; the recovered state is still usable.
        let mut g = guard();
        g.desired.remove(&drive);
        drop(g);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_exit_observes_short_lived_process() {
        // A SIGTERM'd `sleep` exits promptly: the graceful window must
        // observe it (and not report a timeout that would force-kill).
        use std::process::{Command, Stdio};
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as u32;
        assert!(winutil::request_graceful_shutdown(pid));
        assert!(
            winutil::wait_for_exit(pid, Duration::from_secs(10)),
            "graceful shutdown must be observed within the window"
        );
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_exit_times_out_on_still_running_process() {
        // A long-running process that outlives the window must make
        // wait_for_exit report a timeout (the caller then falls back to
        // terminate_process). No signal semantics involved — the process is
        // simply still alive after the window.
        use std::process::{Command, Stdio};
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as u32;
        assert!(
            !winutil::wait_for_exit(pid, Duration::from_secs(2)),
            "a still-running process must exhaust the graceful window"
        );
        winutil::terminate_process(pid).expect("force kill");
        let _ = child.wait();
    }
}
