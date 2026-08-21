//! Mailpit container harness for the real-socket SMTP e2e. Mirrors
//! `DovecotHarness`: same `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER`
//! gating, same `ReservedPort` + compose-project pattern, silent-skip when no
//! runtime is usable (no binary, or an unreachable daemon). Waits on
//! Mailpit's HTTP `/api/v1/info` and exposes a
//! delivered-message retrieval helper over the HTTP API. The runtime gate
//! itself is `rimap-container-gate` (#675); only the mapping onto
//! [`HarnessError`] is local — which is why `e2e_smtp_real`, linking this
//! harness and the Dovecot one, selects and probes once rather than twice.
//! See `AGENTS.md` "Container runtime for integration tests".

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_container_gate::{
    RuntimeProbe, probe_runtime, require_runtime, runtime, unusable_reason,
};

/// Failure modes for `MailpitHarness::try_start`. `DockerUnavailable` is the
/// silent-skip signal. `HealthCheckFailed` replaces Dovecot's
/// `FingerprintReadFailed` — Mailpit has no TLS fingerprint; readiness is the
/// HTTP `/api/v1/info` endpoint. `ArchMismatch` fails loudly at every
/// posture (ADR-0023).
#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    ComposeFailed(String),
    ReadinessTimeout,
    PortReservationFailed(String),
    HealthCheckFailed(String),
    /// The pinned fixture image's architecture does not match this host,
    /// or the pinned reference could not be parsed. Always a hard failure
    /// at every posture: an arch-mismatched pin is a fixture defect, not
    /// an absent host capability (ADR-0023).
    ArchMismatch(String),
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
            Self::ArchMismatch(s) => f.write_str(s),
            Self::HealthCheckFailed(s) => write!(f, "mailpit health check failed: {s}"),
        }
    }
}

impl std::error::Error for HarnessError {}

fn check_prerequisites() -> Result<(), HarnessError> {
    gate(runtime(), probe_runtime(), require_runtime())
}

/// Map `rimap_container_gate`'s verdict onto this harness's error type. Pure,
/// so every combination is unit-testable without a container runtime. Covers
/// only *prerequisites*: a failure once the container is being brought up — an
/// unpullable image, exhausted address pools — stays a `ComposeFailed` that no
/// caller silent-skips on.
fn gate(tool: &str, probe: RuntimeProbe, require_runtime: bool) -> Result<(), HarnessError> {
    let Some(reason) = unusable_reason(tool, probe) else {
        return Ok(());
    };
    if require_runtime {
        Err(HarnessError::ComposeFailed(format!(
            "{reason} but RIMAP_REQUIRE_DOCKER=1"
        )))
    } else {
        Err(HarnessError::DockerUnavailable)
    }
}

/// Compose file for the Mailpit fixture, relative to `compose_dir`.
const COMPOSE_FILE: &str = "docker-compose.yml";

/// Verify the pinned fixture image's architecture matches this host.
/// Runs after `compose up -d` succeeded, so the image is local and one
/// inspect answers without a network path. Tears the project down before
/// returning the loud error. An unparseable reference is loud — compose
/// accepted the file, so `None` means parser drift, and a silent
/// stand-down would disarm the guard on its own target class (ADR-0023).
/// A failed inspect after a parsed reference stands down: genuinely
/// indeterminate, compose keeps owning it.
fn check_image_arch(
    project: &str,
    compose_dir: &std::path::Path,
    service: &str,
) -> Result<(), HarnessError> {
    let Some(image) = rimap_container_gate::pinned_image(&compose_dir.join(COMPOSE_FILE), service)
    else {
        compose_down(project, compose_dir);
        return Err(HarnessError::ArchMismatch(format!(
            "could not determine the pinned image for service '{service}' from \
             {COMPOSE_FILE}; the compose parser in rimap-container-gate needs \
             updating",
        )));
    };
    let (Some(arch), Some(host)) = (
        rimap_container_gate::image_arch(runtime(), &image),
        rimap_container_gate::host_arch(),
    ) else {
        return Ok(());
    };
    if let Some(reason) = rimap_container_gate::arch_mismatch_reason(&image, &arch, host) {
        compose_down(project, compose_dir);
        return Err(HarnessError::ArchMismatch(reason));
    }
    Ok(())
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
                check_image_arch(&project, &compose_dir, "smtp")?;
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

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]

    use super::{HarnessError, RuntimeProbe, gate};

    /// A reachable binary with a dead daemon must skip, not hard-fail (#636).
    #[test]
    fn gate_skips_when_daemon_is_unreachable() {
        let err =
            gate("docker", RuntimeProbe::DaemonDown, false).expect_err("must not pass the gate");
        assert!(
            matches!(err, HarnessError::DockerUnavailable),
            "daemon-down must be a silent skip, got {err:?}"
        );
    }

    /// ...but CI, which sets `RIMAP_REQUIRE_DOCKER=1`, must still see it, and
    /// must name the runtime it actually probed.
    #[test]
    fn gate_is_loud_when_daemon_is_unreachable_and_docker_required() {
        let err = gate("podman", RuntimeProbe::DaemonDown, true).expect_err("must not pass");
        let msg = err.to_string();
        assert!(
            matches!(err, HarnessError::ComposeFailed(_)),
            "RIMAP_REQUIRE_DOCKER=1 must turn a dead daemon into a hard error, got {err:?}"
        );
        assert!(msg.contains("podman"), "must name the runtime: {msg:?}");
        assert!(msg.contains("daemon"), "must name the cause: {msg:?}");
        assert!(msg.contains("RIMAP_REQUIRE_DOCKER"), "got {msg:?}");
    }

    #[test]
    fn gate_admits_a_ready_runtime_and_skips_a_missing_binary() {
        assert!(gate("docker", RuntimeProbe::Ready, true).is_ok());
        assert!(matches!(
            gate("docker", RuntimeProbe::NoBinary, false),
            Err(HarnessError::DockerUnavailable)
        ));
    }
}
