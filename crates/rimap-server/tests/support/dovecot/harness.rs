//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! when no container runtime is usable — no binary, or a binary whose
//! daemon does not answer. That decision comes from `rimap-container-gate`,
//! shared with the Mailpit and chaos harnesses here and with `rimap-imap`'s
//! Dovecot harness (#675); only the mapping onto [`HarnessError`] is local.
//! See `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_container_gate::{
    RuntimeProbe, probe_runtime, require_runtime, runtime, unusable_reason,
};
use rimap_core::TlsFingerprint;

/// Failure modes for `DovecotHarness::try_start`. `DockerUnavailable`
/// is the silent-skip signal: it means the host genuinely cannot run
/// the fixture (no runtime binary, an unreachable runtime daemon). All
/// other variants represent real infrastructure failures that should
/// fail tests when `RIMAP_REQUIRE_DOCKER=1` is set — and `ArchMismatch`
/// fails loudly at every posture (ADR-0023).
#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    ComposeFailed(String),
    ReadinessTimeout,
    PortReservationFailed(String),
    /// The pinned fixture image's architecture does not match this host,
    /// or the pinned reference could not be parsed. Always a hard failure
    /// at every posture: an arch-mismatched pin is a fixture defect, not
    /// an absent host capability (ADR-0023).
    ArchMismatch(String),
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
            Self::ArchMismatch(s) => f.write_str(s),
            Self::FingerprintReadFailed(s) => write!(f, "fingerprint read failed: {s}"),
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

/// Compose file for the Dovecot fixture, relative to `compose_dir`.
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
    if let Some(reason) = rimap_container_gate::arch_mismatch_reason(&image, &arch, &host) {
        compose_down(project, compose_dir);
        return Err(HarnessError::ArchMismatch(reason));
    }
    Ok(())
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
                check_image_arch(&project, &compose_dir, "dovecot")?;
                return wait_for_ready(&project, host_port.port(), &compose_dir);
            }

            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !is_port_collision(&stderr) && !is_address_pool_exhausted(&stderr) {
                return Err(HarnessError::ComposeFailed(stderr));
            }
            last_stderr = stderr;
        }

        // All attempts hit port collisions or network pool exhaustion.
        Err(HarnessError::ComposeFailed(format!(
            "exhausted {MAX_ATTEMPTS} retryable failures (port collision or address pool exhaustion); last stderr: {last_stderr}",
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

    pub fn delete_mailbox(&self, name: &str) {
        let status = Command::new(runtime())
            .arg("exec")
            .arg(container_name(&self.project))
            .arg("doveadm")
            .arg("mailbox")
            .arg("delete")
            .arg("-u")
            .arg("rimap-test")
            .arg(name)
            .status()
            .expect("doveadm exec failed");
        assert!(status.success(), "doveadm mailbox delete {name} failed",);
    }

    /// Stop the container so the published host port stops accepting
    /// connections. Used by fault-injection tests that need the server's
    /// next IMAP connect to be refused (`ERR_CONNECTION_LOST`). `Drop`
    /// still runs `compose down -v`, which cleans up a stopped project.
    ///
    /// `compose stop` returns once the container process exits, but the
    /// published host-port proxy can keep accepting TCP for a brief window
    /// afterward. A connect landing in that window completes at TCP level and
    /// then fails mid-TLS-handshake, surfacing as `ERR_TLS` instead of the
    /// `ERR_CONNECTION_LOST` a refused connect yields — the intermittent
    /// mismatch the fault-injection test hit. Block until the port actually
    /// refuses connections so the caller's next connect is deterministic.
    pub fn stop(&self) {
        let status = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("stop")
            .current_dir(&self.compose_dir)
            .status()
            .expect("compose stop spawn failed");
        assert!(status.success(), "compose stop failed");

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        assert!(
            wait_until_port_refused(addr, Duration::from_secs(15)),
            "host port {} still accepting connections 15s after `compose stop`; \
             the next connect would race a mid-handshake ERR_TLS",
            self.port,
        );
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

/// Poll `addr` until a TCP connect is refused (the listener is fully torn
/// down) or `deadline` elapses. Returns `true` once connections are refused,
/// `false` if the deadline passed while the port was still accepting. Used by
/// [`DovecotHarness::stop`] to wait out the host-port proxy's post-stop
/// acceptance window so the caller's next connect deterministically refuses
/// rather than failing mid-TLS-handshake.
fn wait_until_port_refused(addr: std::net::SocketAddr, deadline: Duration) -> bool {
    let start = Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
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

/// Classify a stderr blob from a failed `compose up`: `true` when the
/// failure indicates Docker address pool exhaustion.
fn is_address_pool_exhausted(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("address pools have been fully subnetted") || s.contains("failed to create network")
}

/// Per-binary dead-code suppression for `DovecotHarness` methods that
/// only some e2e binaries call — `delete_mailbox` (e2e.rs),
/// `create_mailbox` (the mailbox-seeding wire suites), and `stop`
/// (`e2e_wire_fault_injection.rs`). That suite seeds
/// straight into the always-present INBOX, so it calls neither
/// `create_mailbox` nor `delete_mailbox`. Referencing each in a
/// never-called function marks it used in every compilation unit (the
/// same pattern as `fixtures.rs`'s `force_use_for_dead_code_link`).
/// `clippy::allow_attributes = "deny"` forbids a bare `#[allow]`, and a
/// `#![expect(dead_code)]` would be unfulfilled in the binaries that do
/// call it.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code for delete_mailbox"
)]
fn force_use_for_dead_code_link(h: &DovecotHarness) {
    h.delete_mailbox("");
    let _ = DovecotHarness::create_mailbox;
    let _ = DovecotHarness::stop;
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    use super::{HarnessError, RuntimeProbe, gate, wait_until_port_refused};

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

    /// Once the listener is dropped the port refuses connects, so the poll
    /// returns `true` well within the deadline — the case `stop` relies on.
    #[test]
    fn wait_until_port_refused_returns_true_after_listener_drops() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr: SocketAddr = listener.local_addr().expect("read local addr");
        drop(listener);
        assert!(
            wait_until_port_refused(addr, Duration::from_secs(2)),
            "a closed port must be detected as refused",
        );
    }

    /// While a listener is still bound the port keeps accepting, so the poll
    /// exhausts the deadline and returns `false` rather than looping forever —
    /// the bound that keeps `stop`'s assertion from hanging.
    #[test]
    fn wait_until_port_refused_returns_false_while_listener_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr: SocketAddr = listener.local_addr().expect("read local addr");
        assert!(
            !wait_until_port_refused(addr, Duration::from_millis(300)),
            "a still-listening port must time out as not-refused",
        );
        // Drain the connections the poll left in the accept backlog before
        // dropping the listener, so each one is closed from this side rather
        // than reset. Defensive hygiene: the sockets are process-local and the
        // kernel reclaims them at exit either way, but leaving accepted-but-
        // unread connections around is the kind of state that confuses the next
        // person who adds a case here.
        listener.set_nonblocking(true).expect("set nonblocking");
        while listener.accept().is_ok() {}
        drop(listener);
    }
}
