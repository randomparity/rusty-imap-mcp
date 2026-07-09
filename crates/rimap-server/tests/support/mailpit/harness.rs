//! Mailpit container harness for the real-socket SMTP e2e. Mirrors
//! `DovecotHarness`: same `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER`
//! gating, same `ReservedPort` + compose-project pattern, silent-skip when no
//! runtime is available. Waits on Mailpit's HTTP `/api/v1/info` and exposes a
//! delivered-message retrieval helper over the HTTP API.
//! See `AGENTS.md` "Container runtime for integration tests".

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Failure modes for `MailpitHarness::try_start`. `DockerUnavailable` is the
/// silent-skip signal. `HealthCheckFailed` replaces Dovecot's
/// `FingerprintReadFailed` — Mailpit has no TLS fingerprint; readiness is the
/// HTTP `/api/v1/info` endpoint.
#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    ComposeFailed(String),
    ReadinessTimeout,
    PortReservationFailed(String),
    HealthCheckFailed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DockerUnavailable => {
                f.write_str("no container runtime (docker or podman) is available")
            }
            Self::ComposeFailed(s) => write!(f, "compose up failed: {s}"),
            Self::ReadinessTimeout => f.write_str("mailpit did not become ready within timeout"),
            Self::PortReservationFailed(s) => write!(f, "host port reservation failed: {s}"),
            Self::HealthCheckFailed(s) => write!(f, "mailpit health check failed: {s}"),
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

/// Mint a unique-on-host identifier for compose project naming. Same rationale
/// as `DovecotHarness::uuid_like` (PR #273): `SystemTime` nanos alone collide.
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

pub struct MailpitHarness {
    project: String,
    compose_dir: PathBuf,
    smtp_port: u16,
    api_port: u16,
}

impl MailpitHarness {
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
            .join("smtp");

        let project = format!("rimap-smtp-{}", uuid_like());

        let mut last_stderr = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                compose_down(&project, &compose_dir);
                std::thread::sleep(Duration::from_millis(BACKOFF_MS[attempt - 1]));
            }
            let mut smtp_port = ReservedPort::acquire()
                .ok_or_else(|| HarnessError::PortReservationFailed("smtp acquire None".into()))?;
            let mut api_port = ReservedPort::acquire()
                .ok_or_else(|| HarnessError::PortReservationFailed("api acquire None".into()))?;
            let (smtp, api) = (smtp_port.port(), api_port.port());
            smtp_port.release();
            api_port.release();

            let output = Command::new(runtime())
                .arg("compose")
                .arg("-p")
                .arg(&project)
                .arg("up")
                .arg("-d")
                .env("RIMAP_SMTP_HOST_PORT", smtp.to_string())
                .env("RIMAP_SMTP_API_PORT", api.to_string())
                .current_dir(&compose_dir)
                .output()
                .map_err(|e| HarnessError::ComposeFailed(format!("spawn failed: {e}")))?;

            if output.status.success() {
                return wait_for_ready(&project, &compose_dir, smtp, api);
            }

            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !is_port_collision(&stderr) {
                return Err(HarnessError::ComposeFailed(stderr));
            }
            last_stderr = stderr;
        }

        Err(HarnessError::ComposeFailed(format!(
            "exhausted {MAX_ATTEMPTS} port-collision retries; last stderr: {last_stderr}",
        )))
    }

    pub fn smtp_port(&self) -> u16 {
        self.smtp_port
    }

    pub fn api_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.api_port)
    }

    /// Fetch the raw RFC 5322 bytes of the newest delivered message whose
    /// `Subject` equals `subject`, or `None` if none match. Reads Mailpit's
    /// HTTP API: list messages, then fetch the matching message's raw source.
    pub fn fetch_raw_by_subject(&self, subject: &str) -> Option<Vec<u8>> {
        let base = self.api_base();
        let list = ureq::get(format!("{base}/api/v1/messages"))
            .call()
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()?;
        let json: serde_json::Value = serde_json::from_str(&list).ok()?;
        let id = json["messages"]
            .as_array()?
            .iter()
            .find(|m| m["Subject"].as_str() == Some(subject))
            .and_then(|m| m["ID"].as_str())?
            .to_string();
        let raw = ureq::get(format!("{base}/api/v1/message/{id}/raw"))
            .call()
            .ok()?
            .body_mut()
            .read_to_string()
            .ok()?;
        Some(raw.into_bytes())
    }
}

impl Drop for MailpitHarness {
    fn drop(&mut self) {
        compose_down(&self.project, &self.compose_dir);
    }
}

fn wait_for_ready(
    project: &str,
    compose_dir: &std::path::Path,
    smtp_port: u16,
    api_port: u16,
) -> Result<MailpitHarness, HarnessError> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    let info_url = format!("http://127.0.0.1:{api_port}/api/v1/info");
    let mut last_err = String::new();
    loop {
        if started.elapsed() > timeout {
            compose_down(project, compose_dir);
            return Err(if last_err.is_empty() {
                HarnessError::ReadinessTimeout
            } else {
                HarnessError::HealthCheckFailed(last_err)
            });
        }
        match ureq::get(&info_url).call() {
            Ok(resp) if resp.status().is_success() => {
                return Ok(MailpitHarness {
                    project: project.to_string(),
                    compose_dir: compose_dir.to_path_buf(),
                    smtp_port,
                    api_port,
                });
            }
            Ok(resp) => last_err = format!("info returned {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(500));
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

/// Host port reserved by binding `127.0.0.1:0`; the listener is held until
/// `release()` so nothing else can claim the port meanwhile. Same pattern as
/// `DovecotHarness`.
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

    fn release(&mut self) {
        self.listener.take();
    }
}

fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for 127.0.0.1")
}

/// Suppress per-binary dead-code for harness methods only some test binaries
/// call, mirroring `DovecotHarness::force_use_for_dead_code_link`.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code for harness accessors"
)]
fn force_use_for_dead_code_link(h: &MailpitHarness) {
    let _ = h.smtp_port();
    let _ = h.api_base();
    let _ = MailpitHarness::fetch_raw_by_subject;
}
