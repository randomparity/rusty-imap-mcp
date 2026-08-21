//! Network-chaos container harness (#522): Dovecot + Toxiproxy on one compose
//! network, with the MCP server pointed at Toxiproxy's published proxy ports so
//! toxics (latency, resets, byte-trickle) can be injected between the server and
//! Dovecot. Reuses the `DovecotHarness` scaffolding (runtime autodetect,
//! `ReservedPort`, `uuid_like` project names, fingerprint hand-off, Drop
//! teardown), and takes its runtime gate from `rimap-container-gate` (#675) —
//! only the three-tier `RIMAP_CHAOS`/skip/loud policy below is local.
//! See `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md`
//! and `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "control-plane failures abort the test loudly")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_container_gate::{RuntimeProbe, probe_runtime, runtime, unusable_reason};
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
/// The `RIMAP_CHAOS=1` prefix is this suite's own: reaching here at all means
/// chaos was asked for, so the runtime being unusable is worth naming loudly.
fn gate_reason(tool: &str, probe: RuntimeProbe) -> Option<String> {
    unusable_reason(tool, probe).map(|reason| format!("RIMAP_CHAOS=1 but {reason}"))
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

/// Verify both pinned fixture images' architectures match this host.
/// Runs after `compose up -d` succeeded, so the images are local and one
/// inspect each answers without a network path. Tears the project down
/// and panics — the file's established loud-infrastructure-failure path —
/// because an arch-mismatched pin is a fixture defect, loud at every
/// posture (ADR-0023); `ChaosSkip` stays a silent-skip enum. An
/// unparseable reference is loud for the same reason; a failed inspect
/// after a parsed reference stands down (genuinely indeterminate, compose
/// keeps owning it).
fn check_image_arch(project: &str, compose_dir: &Path) {
    for service in ["dovecot", "toxiproxy"] {
        let Some(image) =
            rimap_container_gate::pinned_image(&compose_dir.join(COMPOSE_FILE), service)
        else {
            compose_down(project, compose_dir);
            panic!(
                "chaos: could not determine the pinned image for service \
                 '{service}' from {COMPOSE_FILE}; the compose parser in \
                 rimap-container-gate needs updating"
            );
        };
        let (Some(arch), Some(host)) = (
            rimap_container_gate::image_arch(runtime(), &image),
            rimap_container_gate::host_arch(),
        ) else {
            // Stand down for THIS image only — the other service in the
            // loop is still judged independently.
            continue;
        };
        if let Some(reason) = rimap_container_gate::arch_mismatch_reason(&image, &arch, host) {
            compose_down(project, compose_dir);
            panic!("chaos: {reason}");
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
                check_image_arch(&project, &compose_dir);
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
    use super::{RuntimeProbe, gate_reason, is_port_collision};

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

    /// The `RIMAP_CHAOS=1` prefix is what tells the reader the suite was asked
    /// for and could not run, rather than being opted out of.
    #[test]
    fn gate_reason_rejects_a_missing_binary_and_admits_a_ready_runtime() {
        let missing = gate_reason("docker", RuntimeProbe::NoBinary);
        assert!(
            missing
                .as_deref()
                .is_some_and(|r| r.contains("RIMAP_CHAOS=1") && r.contains("docker")),
            "got {missing:?}"
        );
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
