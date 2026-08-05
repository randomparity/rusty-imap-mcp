//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! when no container runtime is usable — no binary, or a binary whose
//! daemon does not answer.
//! See `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

/// Failure modes for `DovecotHarness::try_start`. `DockerUnavailable`
/// is the silent-skip signal: it means the host genuinely cannot run
/// the fixture (no runtime binary, an unreachable runtime daemon, wrong
/// arch). All other variants represent real infrastructure failures that
/// should fail tests when `RIMAP_REQUIRE_DOCKER=1` is set.
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

/// Runtimes tried, in order, when `RIMAP_CONTAINER_TOOL` is unset.
const AUTODETECT_ORDER: [&str; 2] = ["docker", "podman"];

/// The runtime this process uses and what probing it found. A single cache for
/// both: `runtime()` and `probe_runtime()` must agree on the selected tool, and
/// the probes are process-wide — the eleven container test binaries must not
/// each re-run them.
fn selection() -> (&'static str, RuntimeProbe) {
    static SELECTION: std::sync::OnceLock<(&'static str, RuntimeProbe)> =
        std::sync::OnceLock::new();
    *SELECTION.get_or_init(|| {
        select_runtime(
            std::env::var("RIMAP_CONTAINER_TOOL").ok().as_deref(),
            &probe_tool,
        )
    })
}

/// Name of the container runtime binary to invoke (`docker` or `podman`).
/// Falls back to `"docker"` even when nothing is usable — callers gate on
/// [`probe_runtime`] before using it.
fn runtime() -> &'static str {
    selection().0
}

/// Pick the runtime to use and report what probing it found.
///
/// An explicit `RIMAP_CONTAINER_TOOL` is honoured verbatim: only that runtime
/// is probed and no alternative is tried, so a typo'd or deliberately-unusable
/// override fails on its own terms instead of silently running elsewhere.
/// Otherwise each runtime in [`AUTODETECT_ORDER`] is probed in turn and the
/// first usable one wins — selecting on binary presence alone let a stopped
/// Docker Desktop mask a working podman (#674). Probing stops at the first
/// `Ready`, so the common docker-is-up case costs exactly what it did before.
///
/// `probe` is a parameter so the whole decision is unit-testable without a
/// container runtime on the host.
fn select_runtime(
    override_tool: Option<&str>,
    probe: &dyn Fn(&str) -> RuntimeProbe,
) -> (&'static str, RuntimeProbe) {
    if let Some(tool) = explicit_tool(override_tool) {
        return (tool, probe(tool));
    }
    let mut verdict: Option<(&'static str, RuntimeProbe)> = None;
    for tool in AUTODETECT_ORDER {
        let probed = probe(tool);
        if probed == RuntimeProbe::Ready {
            return (tool, probed);
        }
        if verdict.is_none_or(|(_, seen)| failure_rank(probed) > failure_rank(seen)) {
            verdict = Some((tool, probed));
        }
    }
    verdict.unwrap_or((AUTODETECT_ORDER[0], RuntimeProbe::NoBinary))
}

/// Normalize an explicit `RIMAP_CONTAINER_TOOL` value. Unrecognized values are
/// not overrides and fall through to autodetect silently — the harness has no
/// logger available and `print_stderr` is denied by the workspace lint policy.
fn explicit_tool(value: Option<&str>) -> Option<&'static str> {
    match value {
        Some("docker") => Some("docker"),
        Some("podman") => Some("podman"),
        _ => None,
    }
}

/// How useful a failed probe is as a report. `DaemonDown` outranks `NoBinary`:
/// "podman is installed but its daemon is unreachable" tells an operator what
/// to start, where "docker is not installed" does not.
fn failure_rank(probe: RuntimeProbe) -> u8 {
    match probe {
        RuntimeProbe::DaemonDown => 1,
        RuntimeProbe::Ready | RuntimeProbe::NoBinary => 0,
    }
}

/// Probe one runtime: an absent CLI is `NoBinary`, otherwise `<tool> info`
/// decides. Two spawns, and only for runtimes selection actually reaches.
fn probe_tool(tool: &str) -> RuntimeProbe {
    if binary_present(tool) {
        classify_probe(run_daemon_probe(tool, DAEMON_PROBE_TIMEOUT))
    } else {
        RuntimeProbe::NoBinary
    }
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

/// State of the runtime `runtime()` selected. Cached alongside that choice in
/// [`selection`], because the verdict cannot usefully change within one test
/// process: a daemon that dies after the probe surfaces at `compose up`, which
/// is a hard error at every posture.
fn probe_runtime() -> RuntimeProbe {
    selection().1
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

    use std::cell::RefCell;

    use super::{
        HarnessError, RuntimeProbe, classify_probe, gate, select_runtime, wait_until_port_refused,
    };

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

    /// #674: selection must not stop at the first runtime *installed*. A
    /// stopped Docker Desktop masked a working podman, and after #636 that
    /// turned the whole container suite into a silent skip.
    #[test]
    fn autodetect_falls_through_a_down_runtime_to_a_working_one() {
        let asked = RefCell::new(Vec::new());
        let selected = select_runtime(None, &|tool| {
            asked.borrow_mut().push(tool.to_owned());
            if tool == "docker" {
                RuntimeProbe::DaemonDown
            } else {
                RuntimeProbe::Ready
            }
        });
        assert_eq!(selected, ("podman", RuntimeProbe::Ready));
        assert_eq!(asked.into_inner(), ["docker", "podman"]);
    }

    /// A working docker is still used first, and podman is never probed — the
    /// fall-through must not double the probe cost in the common case.
    #[test]
    fn autodetect_stops_at_the_first_working_runtime() {
        let asked = RefCell::new(Vec::new());
        let selected = select_runtime(None, &|tool| {
            asked.borrow_mut().push(tool.to_owned());
            RuntimeProbe::Ready
        });
        assert_eq!(selected, ("docker", RuntimeProbe::Ready));
        assert_eq!(asked.into_inner(), ["docker"]);
    }

    /// With nothing usable the harness still has to name a runtime in its skip
    /// or hard-failure message.
    #[test]
    fn autodetect_reports_the_most_actionable_failure() {
        assert_eq!(
            select_runtime(None, &|_| RuntimeProbe::DaemonDown),
            ("docker", RuntimeProbe::DaemonDown),
            "both daemons down reports the first runtime tried"
        );
        assert_eq!(
            select_runtime(None, &|tool| if tool == "docker" {
                RuntimeProbe::NoBinary
            } else {
                RuntimeProbe::DaemonDown
            }),
            ("podman", RuntimeProbe::DaemonDown),
            "an installed-but-down runtime outranks an absent one"
        );
        assert_eq!(
            select_runtime(None, &|_| RuntimeProbe::NoBinary),
            ("docker", RuntimeProbe::NoBinary),
            "nothing installed still names a runtime"
        );
    }

    /// An override is honoured without probing alternatives, so a typo'd or
    /// unusable choice fails on its own terms rather than silently running
    /// somewhere else.
    #[test]
    fn an_explicit_override_probes_only_the_named_runtime() {
        let asked = RefCell::new(Vec::new());
        let selected = select_runtime(Some("podman"), &|tool| {
            asked.borrow_mut().push(tool.to_owned());
            RuntimeProbe::DaemonDown
        });
        assert_eq!(selected, ("podman", RuntimeProbe::DaemonDown));
        assert_eq!(
            asked.into_inner(),
            ["podman"],
            "an override must not fall through to another runtime"
        );
    }

    /// A value naming no known runtime is not an override at all.
    #[test]
    fn an_unrecognized_override_falls_back_to_autodetect() {
        assert_eq!(
            select_runtime(Some("containerd"), &|_| RuntimeProbe::Ready),
            ("docker", RuntimeProbe::Ready)
        );
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
