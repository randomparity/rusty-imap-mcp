//! Network-chaos container harness (#522): Dovecot + Toxiproxy on one compose
//! network, with the MCP server pointed at Toxiproxy's published proxy ports so
//! toxics (latency, resets, byte-trickle) can be injected between the server and
//! Dovecot. Reuses the `DovecotHarness` scaffolding (runtime autodetect,
//! `ReservedPort`, `uuid_like` project names, fingerprint hand-off, Drop
//! teardown). See `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md`
//! and `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "control-plane failures abort the test loudly")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;

/// Compose file for the chaos stack (relative to the shared dovecot fixture dir).
const COMPOSE_FILE: &str = "docker-compose.chaos.yml";

/// Skip reasons for `ChaosHarness::try_start`. Both are silent-skip signals; the
/// suite returns early on either. `Disabled` (no `RIMAP_CHAOS`) is checked FIRST
/// so the suite stays off PR CI even under `RIMAP_REQUIRE_DOCKER=1`.
#[derive(Debug)]
pub enum ChaosSkip {
    /// `RIMAP_CHAOS` is unset — the suite is nightly-only and opted out here.
    Disabled,
    /// `RIMAP_CHAOS=1` but no usable container runtime — no binary, or one
    /// whose daemon did not respond — and `RIMAP_REQUIRE_DOCKER` unset.
    DockerUnavailable,
}

/// Three-tier gate. `RIMAP_CHAOS` is checked before the runtime probe so the
/// suite skips even under `RIMAP_REQUIRE_DOCKER=1` — that is what keeps it off
/// PR CI, whose `binary(/e2e/)` filter otherwise selects this binary.
fn check_gate() -> Result<(), ChaosSkip> {
    if std::env::var("RIMAP_CHAOS").is_err() {
        return Err(ChaosSkip::Disabled);
    }
    match gate_reason(runtime(), probe_runtime()) {
        None => Ok(()),
        Some(reason) => Err(loud_or_skip(&reason)),
    }
}

/// The unusable-runtime message for a probe outcome, or `None` when the
/// runtime is usable. Split out from `check_gate` so the classification is
/// unit-testable without touching `RIMAP_CHAOS`/`RIMAP_REQUIRE_DOCKER` (env
/// mutation is process-global and races other tests in the same binary).
fn gate_reason(tool: &str, probe: RuntimeProbe) -> Option<String> {
    match probe {
        RuntimeProbe::Ready => None,
        RuntimeProbe::NoBinary => Some(format!("RIMAP_CHAOS=1 but {tool} is not installed")),
        RuntimeProbe::DaemonDown => Some(format!(
            "RIMAP_CHAOS=1 but {tool} is installed and its daemon is unreachable"
        )),
    }
}

/// Under `RIMAP_REQUIRE_DOCKER=1` a real infrastructure failure must fail loudly;
/// otherwise it silent-skips. Kept a non-`Result` helper so callers stay clear of
/// `panic_in_result_fn` — the panic lives here, not in the `try_start`/
/// `wait_for_ready` bodies.
fn loud_or_skip(context: &str) -> ChaosSkip {
    assert!(
        std::env::var("RIMAP_REQUIRE_DOCKER").is_err(),
        "chaos: {context}"
    );
    ChaosSkip::DockerUnavailable
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

fn dovecot_container_name(project: &str) -> String {
    format!("{project}-dovecot")
}

/// Mint a unique-on-host identifier for compose project naming. Mirrors
/// `DovecotHarness::uuid_like` (nanos + pid + process-local counter).
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

/// Toxiproxy HTTP control-API client. Every call checks the status and panics on
/// failure with a control-plane-attributed message, so a control-plane flake
/// aborts the test *before* a recovery assertion and never masquerades as a
/// product recovery-wedge.
pub struct ToxiproxyControl {
    base: String,
}

impl ToxiproxyControl {
    fn new(ctrl_port: u16) -> Self {
        Self {
            base: format!("http://127.0.0.1:{ctrl_port}"),
        }
    }

    /// POST a toxic spec (e.g. `{"type":"timeout","attributes":{"timeout":0}}`)
    /// to a proxy. Toxiproxy auto-names the toxic when `name` is omitted.
    pub fn add_toxic(&self, proxy: &str, spec: &serde_json::Value) {
        let url = format!("{}/proxies/{proxy}/toxics", self.base);
        let body = serde_json::to_string(spec).expect("serialize toxic spec");
        match ureq::post(&url)
            .content_type("application/json")
            .send(&body)
        {
            Ok(_) => {}
            Err(e) => panic!("toxiproxy control: add_toxic on '{proxy}' failed: {e}; body={body}"),
        }
    }

    /// Clear all toxics on all proxies (`POST /reset`).
    pub fn reset(&self) {
        let url = format!("{}/reset", self.base);
        match ureq::post(&url).send_empty() {
            Ok(_) => {}
            Err(e) => panic!("toxiproxy control: reset failed: {e}"),
        }
    }

    /// `GET /version` reachable — control plane is up.
    fn version_ok(&self) -> bool {
        ureq::get(format!("{}/version", self.base)).call().is_ok()
    }

    /// Both seed proxies exist, are enabled, and point at the expected Dovecot
    /// upstreams. Closes a vacuous-pass hole where a mis-upstreamed proxy would
    /// let `add_toxic` succeed while the server connection failed for the wrong
    /// reason.
    fn proxies_ok(&self) -> bool {
        let Ok(resp) = ureq::get(format!("{}/proxies", self.base)).call() else {
            return false;
        };
        let Ok(body) = resp.into_body().read_to_string() else {
            return false;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) else {
            return false;
        };
        let ok = |name: &str, upstream: &str| {
            json[name]["upstream"].as_str() == Some(upstream)
                && json[name]["enabled"].as_bool() == Some(true)
        };
        ok("imaps", "dovecot:993") && ok("starttls", "dovecot:143")
    }
}

/// A running Dovecot+Toxiproxy chaos stack. `Drop` tears it down.
pub struct ChaosHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    imaps_port: u16,
    starttls_port: u16,
    toxics: ToxiproxyControl,
}

impl ChaosHarness {
    pub fn try_start() -> Result<Self, ChaosSkip> {
        const BACKOFF_MS: [u64; 2] = [50, 250];
        const MAX_ATTEMPTS: usize = BACKOFF_MS.len() + 1;

        check_gate()?;

        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("manifest dir has no parent")
            .join("rimap-imap")
            .join("tests")
            .join("integration")
            .join("dovecot");

        let project = format!("rimap-chaos-{}", uuid_like());
        let mut last_stderr = String::new();

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                compose_down(&project, &compose_dir);
                std::thread::sleep(Duration::from_millis(BACKOFF_MS[attempt - 1]));
            }

            // Reserve three host ports, release the kernel leases just before
            // `up` so compose can bind them.
            let mut imaps = ReservedPort::acquire().expect("reserve imaps port");
            let mut starttls = ReservedPort::acquire().expect("reserve starttls port");
            let mut ctrl = ReservedPort::acquire().expect("reserve ctrl port");
            let (imaps_port, starttls_port, ctrl_port) =
                (imaps.port(), starttls.port(), ctrl.port());
            imaps.release();
            starttls.release();
            ctrl.release();

            let output = Command::new(runtime())
                .arg("compose")
                .arg("-p")
                .arg(&project)
                .arg("-f")
                .arg(COMPOSE_FILE)
                .arg("up")
                .arg("-d")
                .env("RIMAP_TOXI_IMAPS_PORT", imaps_port.to_string())
                .env("RIMAP_TOXI_STARTTLS_PORT", starttls_port.to_string())
                .env("RIMAP_TOXI_CTRL_PORT", ctrl_port.to_string())
                .current_dir(&compose_dir)
                .output()
                .expect("compose up spawn failed");

            if output.status.success() {
                return wait_for_ready(&WaitParams {
                    project: &project,
                    compose_dir: &compose_dir,
                    imaps_port,
                    starttls_port,
                    ctrl_port,
                });
            }

            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            // A failed `up` frequently leaves the network and the first
            // container created before the failing port publish. `Drop` does not
            // run (the struct is never constructed), so reap here before every
            // early return/panic — otherwise a partial stack leaks (loud_or_skip
            // panics under RIMAP_REQUIRE_DOCKER=1, skipping any later cleanup).
            compose_down(&project, &compose_dir);
            if !is_port_collision(&stderr) {
                return Err(loud_or_skip(&format!("chaos compose up failed: {stderr}")));
            }
            last_stderr = stderr;
        }

        Err(loud_or_skip(&format!(
            "chaos compose up: exhausted port-collision retries; last: {last_stderr}"
        )))
    }

    pub fn fingerprint(&self) -> &TlsFingerprint {
        &self.fingerprint
    }

    pub fn imaps_port(&self) -> u16 {
        self.imaps_port
    }

    pub fn starttls_port(&self) -> u16 {
        self.starttls_port
    }

    pub fn toxics(&self) -> &ToxiproxyControl {
        &self.toxics
    }
}

impl Drop for ChaosHarness {
    fn drop(&mut self) {
        compose_down(&self.project, &self.compose_dir);
    }
}

struct WaitParams<'a> {
    project: &'a str,
    compose_dir: &'a Path,
    imaps_port: u16,
    starttls_port: u16,
    ctrl_port: u16,
}

fn wait_for_ready(p: &WaitParams<'_>) -> Result<ChaosHarness, ChaosSkip> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    let toxics = ToxiproxyControl::new(p.ctrl_port);
    let imaps_addr = std::net::SocketAddr::from(([127, 0, 0, 1], p.imaps_port));
    loop {
        if started.elapsed() > timeout {
            let logs = compose_logs(p.project, p.compose_dir);
            compose_down(p.project, p.compose_dir);
            return Err(loud_or_skip(&format!(
                "chaos stack not ready within {timeout:?}\n{logs}"
            )));
        }
        // Cheap localhost probes first; the `docker exec` fingerprint read (a
        // full process spawn) runs only once these pass, so early startup
        // iterations don't pay it. The imaps proxy accepting a TCP connection
        // implies Dovecot is up, so by then the fingerprint file exists.
        let cheap_ok = toxics.version_ok()
            && toxics.proxies_ok()
            && std::net::TcpStream::connect_timeout(&imaps_addr, Duration::from_millis(500))
                .is_ok();
        if cheap_ok && let Ok(fp) = read_fingerprint(p.project) {
            return Ok(ChaosHarness {
                project: p.project.to_string(),
                compose_dir: p.compose_dir.to_path_buf(),
                fingerprint: fp,
                imaps_port: p.imaps_port,
                starttls_port: p.starttls_port,
                toxics,
            });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Placeholder port env for compose subcommands (`down`, `logs`) that still
/// interpolate the `ports:` mapping vars but do not bind them — silences
/// "variable is not set" warnings without affecting behavior.
fn compose_placeholder_env(cmd: &mut Command) {
    cmd.env("RIMAP_TOXI_IMAPS_PORT", "0")
        .env("RIMAP_TOXI_STARTTLS_PORT", "0")
        .env("RIMAP_TOXI_CTRL_PORT", "0");
}

fn compose_down(project: &str, compose_dir: &Path) {
    let mut cmd = Command::new(runtime());
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(COMPOSE_FILE)
        .arg("down")
        .arg("-v")
        .arg("--remove-orphans")
        .current_dir(compose_dir);
    compose_placeholder_env(&mut cmd);
    let _ = cmd.status();
}

fn compose_logs(project: &str, compose_dir: &Path) -> String {
    let mut cmd = Command::new(runtime());
    cmd.arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(COMPOSE_FILE)
        .arg("logs")
        .arg("--no-color")
        .current_dir(compose_dir);
    compose_placeholder_env(&mut cmd);
    let out = cmd.output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => format!("<compose logs failed: {e}>"),
    }
}

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, String> {
    let out = Command::new(runtime())
        .arg("exec")
        .arg(dovecot_container_name(project))
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

/// Host port reserved by binding `127.0.0.1:0` and reading the kernel-assigned
/// number; the listener is held until `release()`. Mirrors `DovecotHarness`.
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::{RuntimeProbe, classify_probe, gate_reason, is_port_collision, select_runtime};

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

    /// A reachable binary with a dead daemon is an unusable runtime, so the
    /// chaos gate must reach `loud_or_skip` rather than proceed to compose
    /// (#636). `loud_or_skip` then skips, or panics under
    /// `RIMAP_REQUIRE_DOCKER=1`.
    #[test]
    fn gate_reason_rejects_an_unreachable_daemon() {
        let reason = gate_reason("podman", RuntimeProbe::DaemonDown);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("daemon") && r.contains("podman")),
            "daemon-down must name its cause and runtime, got {reason:?}"
        );
    }

    #[test]
    fn gate_reason_rejects_a_missing_binary_and_admits_a_ready_runtime() {
        assert!(gate_reason("docker", RuntimeProbe::NoBinary).is_some());
        assert!(gate_reason("docker", RuntimeProbe::Ready).is_none());
    }

    /// Address-pool exhaustion is a live daemon refusing work, not an absent
    /// one: it happens after the gate, and must neither be retried as a port
    /// collision nor skipped.
    #[test]
    fn address_pool_exhaustion_is_not_a_port_collision() {
        assert!(!is_port_collision(
            "Error response from daemon: all predefined address pools have been fully subnetted"
        ));
    }
}
