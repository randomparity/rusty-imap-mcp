//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! when no container runtime is available.
//! See `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

/// Failure modes for `DovecotHarness::try_start`. `DockerUnavailable`
/// is the silent-skip signal: it means the host genuinely cannot run
/// the fixture (no runtime, wrong arch). All other variants represent
/// real infrastructure failures that should fail tests when
/// `RIMAP_REQUIRE_DOCKER=1` is set.
#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    ComposeFailed(String),
    ReadinessTimeout,
    PortReservationFailed(String),
    /// Last `read_fingerprint` error captured during the wait-for-ready
    /// loop. Surfaced when the wait-for-ready timeout fires and the
    /// last attempt to read the container's TLS fingerprint failed.
    FingerprintReadFailed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DockerUnavailable => {
                f.write_str("no container runtime (docker or podman) is available")
            }
            Self::ComposeFailed(s) => write!(f, "compose up failed: {s}"),
            Self::ReadinessTimeout => f.write_str("dovecot did not become ready within timeout"),
            Self::PortReservationFailed(s) => write!(f, "host port reservation failed: {s}"),
            Self::FingerprintReadFailed(s) => write!(f, "fingerprint read failed: {s}"),
        }
    }
}

impl std::error::Error for HarnessError {}

fn check_prerequisites() -> Result<(), HarnessError> {
    let require_runtime = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();

    if !runtime_available() {
        return if require_runtime {
            Err(HarnessError::ComposeFailed(
                "neither docker nor podman found but RIMAP_REQUIRE_DOCKER=1".into(),
            ))
        } else {
            Err(HarnessError::DockerUnavailable)
        };
    }

    Ok(())
}

fn runtime() -> &'static str {
    static TOOL: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    TOOL.get_or_init(|| {
        match std::env::var("RIMAP_CONTAINER_TOOL").as_deref() {
            Ok("docker") => return "docker",
            Ok("podman") => return "podman",
            _ => {}
        }
        if binary_present("docker") {
            "docker"
        } else if binary_present("podman") {
            "podman"
        } else {
            "docker"
        }
    })
}

fn binary_present(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn runtime_available() -> bool {
    binary_present("docker") || binary_present("podman")
}

fn container_name(project: &str) -> String {
    format!("{project}-dovecot")
}

/// Mint a unique-on-host identifier for compose project naming.
/// Combines `SystemTime` nanos with `process::id()` and a process-
/// local `AtomicU64` counter so no two calls on the same host can
/// produce the same string — even when two parallel threads call
/// within the same coarse `SystemTime` tick (macOS resolution is
/// not nanosecond), or when consecutive nextest binaries land on
/// the same nanos value. Mirrors `rimap-imap::uuid_like` (PR #273).
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{pid:x}-{n:x}")
}

pub struct DovecotHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    port: u16,
}

impl DovecotHarness {
    pub fn try_start() -> Result<Self, HarnessError> {
        const BACKOFF_MS: [u64; 2] = [50, 250];
        const MAX_ATTEMPTS: usize = BACKOFF_MS.len() + 1;

        check_prerequisites()?;

        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| HarnessError::ComposeFailed("manifest dir has no parent".into()))?
            .join("rimap-imap")
            .join("tests")
            .join("integration")
            .join("dovecot");

        // Compose project name must be unique across (a) parallel
        // threads within one cargo-test process and (b) consecutive
        // nextest binary invocations on the same host. SystemTime
        // nanos alone is insufficient — macOS resolution is not
        // nanosecond and we have observed collisions in the wild
        // (e.g. wire_e2e_readonly_posture_denial on parallel run).
        // Same pattern as rimap-imap::uuid_like (PR #273, 422f564).
        let project = format!("rimap-e2e-{}", uuid_like());

        let mut host_port = ReservedPort::acquire()
            .ok_or_else(|| HarnessError::PortReservationFailed("acquire returned None".into()))?;

        let mut last_stderr = String::new();

        // Attempt 0 is the initial try (no prior sleep). Attempts 1 and 2
        // are retries preceded by teardown + backoff sleep + fresh port.
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                compose_down(&project, &compose_dir);
                std::thread::sleep(std::time::Duration::from_millis(BACKOFF_MS[attempt - 1]));
                host_port = ReservedPort::acquire().ok_or_else(|| {
                    HarnessError::PortReservationFailed("retry acquire returned None".into())
                })?;
            }
            host_port.release();

            let output = Command::new(runtime())
                .arg("compose")
                .arg("-p")
                .arg(&project)
                .arg("up")
                .arg("-d")
                .env("RIMAP_DOVECOT_HOST_PORT", host_port.port().to_string())
                .current_dir(&compose_dir)
                .output()
                .map_err(|e| HarnessError::ComposeFailed(format!("spawn failed: {e}")))?;

            if output.status.success() {
                return wait_for_ready(&project, host_port.port(), &compose_dir);
            }

            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !is_port_collision(&stderr) {
                return Err(HarnessError::ComposeFailed(stderr));
            }
            last_stderr = stderr;
        }

        // All attempts hit port collisions.
        Err(HarnessError::ComposeFailed(format!(
            "exhausted {MAX_ATTEMPTS} port-collision retries; last stderr: {last_stderr}",
        )))
    }

    /// Create a mailbox via `doveadm` inside the container.
    pub fn create_mailbox(&self, name: &str) {
        let status = Command::new(runtime())
            .arg("exec")
            .arg(container_name(&self.project))
            .arg("doveadm")
            .arg("mailbox")
            .arg("create")
            .arg("-u")
            .arg("rimap-test")
            .arg(name)
            .status()
            .expect("doveadm exec failed");
        assert!(status.success(), "doveadm mailbox create {name} failed",);
    }

    pub fn fingerprint(&self) -> &TlsFingerprint {
        &self.fingerprint
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

fn wait_for_ready(
    project: &str,
    host_port: u16,
    compose_dir: &std::path::Path,
) -> Result<DovecotHarness, HarnessError> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], host_port));
    let mut last_fp_err: Option<String> = None;
    loop {
        if started.elapsed() > timeout {
            compose_down(project, compose_dir);
            return Err(match last_fp_err {
                Some(e) => HarnessError::FingerprintReadFailed(e),
                None => HarnessError::ReadinessTimeout,
            });
        }
        let fp = match read_fingerprint(project) {
            Ok(fp) => fp,
            Err(e) => {
                last_fp_err = Some(e);
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return Ok(DovecotHarness {
                project: project.to_string(),
                compose_dir: compose_dir.to_path_buf(),
                fingerprint: fp,
                port: host_port,
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

impl Drop for DovecotHarness {
    fn drop(&mut self) {
        compose_down(&self.project, &self.compose_dir);
    }
}

fn compose_down(project: &str, compose_dir: &std::path::Path) {
    let _ = Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("down")
        .arg("-v")
        .arg("--remove-orphans")
        .current_dir(compose_dir)
        .status();
}

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, String> {
    let out = Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
        .arg("cat")
        .arg("/shared/fingerprint.hex")
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("not ready".into());
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    TlsFingerprint::from_hex(&s).map_err(|e| e.to_string())
}

/// Host port reserved by binding `127.0.0.1:0` and reading the
/// kernel-assigned number. The `TcpListener` is kept open until
/// `release()` is called, holding the kernel-level lease so docker
/// (or any other process) cannot bind the same port in the meantime.
struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    fn acquire() -> Option<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        Some(Self {
            port,
            listener: Some(listener),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Drop the underlying `TcpListener`, releasing the kernel-level
    /// port lease. Idempotent.
    fn release(&mut self) {
        self.listener.take();
    }
}

/// Classify a stderr blob from a failed `compose up`: `true` when the
/// failure looks like a host-port bind collision.
fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for 127.0.0.1")
}
