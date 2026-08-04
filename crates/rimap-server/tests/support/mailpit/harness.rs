//! Mailpit container harness for the real-socket SMTP e2e. Mirrors
//! `DovecotHarness`: same `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER`
//! gating, same `ReservedPort` + compose-project pattern, silent-skip when no
//! runtime is usable (no binary, or an unreachable daemon). Waits on
//! Mailpit's HTTP `/api/v1/info` and exposes a
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
    gate(
        runtime(),
        probe_runtime(),
        std::env::var("RIMAP_REQUIRE_DOCKER").is_ok(),
    )
}

/// Map a probe outcome onto the skip-or-fail contract. Pure, so every
/// combination is unit-testable without a container runtime. Covers only
/// *prerequisites*: a failure once the container is being brought up — an
/// unpullable image, exhausted address pools — stays a `ComposeFailed` that no
/// caller silent-skips on.
fn gate(tool: &str, probe: RuntimeProbe, require_runtime: bool) -> Result<(), HarnessError> {
    let reason = match probe {
        RuntimeProbe::Ready => return Ok(()),
        RuntimeProbe::NoBinary => format!("{tool} is not installed"),
        RuntimeProbe::DaemonDown => format!("{tool} is installed but its daemon is unreachable"),
    };
    if require_runtime {
        Err(HarnessError::ComposeFailed(format!(
            "{reason} but RIMAP_REQUIRE_DOCKER=1"
        )))
    } else {
        Err(HarnessError::DockerUnavailable)
    }
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

/// Why the container runtime can or cannot be used. `NoBinary` and
/// `DaemonDown` are both silent-skip reasons — the host genuinely cannot run
/// the fixture — and differ only in the message they produce under
/// `RIMAP_REQUIRE_DOCKER=1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProbe {
    Ready,
    NoBinary,
    DaemonDown,
}

/// Budget for the daemon probe. A stopped daemon refuses its socket
/// immediately, but one that is mid-restart can accept the connection and then
/// never answer, so the probe needs a deadline of its own.
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// State of the runtime `runtime()` selected — probing both binaries would
/// ignore a `RIMAP_CONTAINER_TOOL` override pointing at the unusable one.
/// Cached because the verdict cannot usefully change within one test process:
/// a daemon that dies after the probe surfaces at `compose up`, which is a hard
/// error at every posture.
fn probe_runtime() -> RuntimeProbe {
    static PROBE: std::sync::OnceLock<RuntimeProbe> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        let tool = runtime();
        if binary_present(tool) {
            classify_probe(run_daemon_probe(tool, DAEMON_PROBE_TIMEOUT))
        } else {
            RuntimeProbe::NoBinary
        }
    })
}

/// Decide what a finished probe means. Only a stderr naming an unreachable
/// engine is `DaemonDown`; everything else is `Ready`, which sends the harness
/// on to `compose up`, where failures are loud. That asymmetry is the point: a
/// daemon that is merely contended, out of address pools, or misconfigured is
/// refusing work rather than absent, and skipping those would hide real
/// breakage. A probe that outlives its budget (`None`) is read the same way —
/// too busy to answer in ten seconds is busy, not missing.
fn classify_probe(outcome: Option<(bool, String)>) -> RuntimeProbe {
    match outcome {
        Some((false, stderr)) if names_unreachable_engine(&stderr) => RuntimeProbe::DaemonDown,
        _ => RuntimeProbe::Ready,
    }
}

/// Recognize the stderr of a client that could not reach its engine at all.
/// Covers docker's current `failed to connect to the docker API ...`, the older
/// `Cannot connect to the Docker daemon ...` that compose still emits, podman's
/// remote/machine equivalent, and the bare socket errors underneath all three.
fn names_unreachable_engine(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("failed to connect to the docker api")
        || s.contains("cannot connect to the docker daemon")
        || s.contains("is the docker daemon running")
        || s.contains("cannot connect to podman")
        || s.contains("connect: no such file or directory")
        || s.contains("connection refused")
}

/// Run `<tool> info` — the cheapest call that actually contacts the engine,
/// where `binary_present` only proves the CLI is on `PATH` — and return
/// `Some((succeeded, stderr))`, or `None` when it outlives `budget`.
/// `Command::output()` cannot be used here: it waits forever, which is exactly
/// what a restarting daemon provokes.
fn run_daemon_probe(tool: &str, budget: Duration) -> Option<(bool, String)> {
    let mut child = Command::new(tool)
        .arg("info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let status = wait_bounded(&mut child, budget)?;
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        // The child has already exited, so the pipe is at EOF and this read
        // cannot block. (A child wedged on a full stderr pipe never reaches
        // here — it trips the budget above and is killed.)
        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
    }
    Some((status.success(), stderr))
}

/// Wait for `child`, returning its status if it exits within `budget`. On
/// expiry the child is killed and reaped. A `try_wait` error abandons it
/// instead: that is an OS-level failure, and the `wait()` used to reap could
/// block just as long as the case being escaped.
fn wait_bounded(
    child: &mut std::process::Child,
    budget: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    }
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

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]

    use super::{HarnessError, RuntimeProbe, classify_probe, gate};

    /// Verbatim stderr from `docker info` against a socket with nothing behind
    /// it — the shape of the outage in #636.
    const DEAD_SOCKET_STDERR: &str = "failed to connect to the docker API at \
        unix:///Users/dev/.docker/run/docker.sock; check if the path is correct \
        and if the daemon is running: dial unix \
        /Users/dev/.docker/run/docker.sock: connect: no such file or directory";

    /// The classification that was broken: a live binary whose engine cannot be
    /// reached is `DaemonDown`, not usable. Flipping this to `Ready`
    /// reintroduces #636.
    #[test]
    fn classify_probe_reads_an_unreachable_engine_as_daemon_down() {
        assert_eq!(
            classify_probe(Some((false, DEAD_SOCKET_STDERR.into()))),
            RuntimeProbe::DaemonDown
        );
    }

    /// The other half of the contract: a live daemon refusing work — the
    /// address-pool exhaustion that concurrent test runs actually hit — is
    /// `Ready`, so it reaches `compose up` and fails there, loudly.
    #[test]
    fn classify_probe_reads_a_daemon_refusing_work_as_ready() {
        assert_eq!(
            classify_probe(Some((
                false,
                "Error response from daemon: all predefined address pools have been \
                 fully subnetted"
                    .into()
            ))),
            RuntimeProbe::Ready
        );
        assert_eq!(
            classify_probe(Some((true, String::new()))),
            RuntimeProbe::Ready
        );
        // Probe outlived its budget: too busy to answer is busy, not absent.
        assert_eq!(classify_probe(None), RuntimeProbe::Ready);
    }

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
