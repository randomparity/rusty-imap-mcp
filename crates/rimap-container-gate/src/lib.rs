//! The container-runtime gate every container-backed test harness runs before
//! it touches a fixture: pick a runtime, prove its daemon answers, and say
//! whether the host can run containers at all.
//!
//! This crate owns the *prerequisite* decision only. Compose files, readiness
//! probes, port reservation, and `Drop` teardown stay with each fixture, and so
//! does the mapping from [`unusable_reason`] onto that fixture's own error
//! type — the harnesses do not share an error enum.
//!
//! It used to be four byte-identical copies (`rimap-imap`'s Dovecot harness,
//! `rimap-server`'s Dovecot, Mailpit, and chaos harnesses). Two bugs in a row
//! had to be fixed in all four — #636 (probe the daemon, not just the binary)
//! and #674 (select the first runtime that *works*, not the first installed) —
//! with nothing detecting a copy that got missed. See issue #675.
//!
//! `scripts/prune-containers.sh` mirrors this contract in shell rather than
//! calling it: the `just test` recipe prunes stale networks before any test
//! binary starts, so there is no Rust to call at that point (issue #689). Any
//! change to the selection contract here has to land there too.
//!
//! # Environment
//!
//! - `RIMAP_CONTAINER_TOOL={docker,podman}` forces a runtime. It is honoured
//!   verbatim: only the named runtime is probed and no alternative is tried.
//!   A value naming neither is not an override and falls through to autodetect.
//! - `RIMAP_REQUIRE_DOCKER=1` turns an unusable runtime from a silent skip into
//!   a loud failure. CI sets it; developer hosts do not.

use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Runtimes tried, in order, when `RIMAP_CONTAINER_TOOL` is unset.
const AUTODETECT_ORDER: [&str; 2] = ["docker", "podman"];

/// Budget for the daemon probe. A stopped daemon refuses its socket
/// immediately, but one that is mid-restart can accept the connection and then
/// never answer, so the probe needs a deadline of its own.
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the container runtime can or cannot be used. `NoBinary` and
/// `DaemonDown` are both silent-skip reasons — the host genuinely cannot run
/// the fixture — and differ only in the message they produce under
/// `RIMAP_REQUIRE_DOCKER=1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProbe {
    /// The runtime's daemon answered, or failed for a reason of its own that
    /// belongs to `compose up` rather than to this gate.
    Ready,
    /// No such CLI on `PATH`.
    NoBinary,
    /// The CLI is present but could not reach its engine at all.
    DaemonDown,
}

/// Name of the container runtime binary to invoke (`docker` or `podman`).
/// Detected once per process. Falls back to `"docker"` even when nothing is
/// usable — callers gate on [`probe_runtime`] before using it.
#[must_use]
pub fn runtime() -> &'static str {
    selection().0
}

/// State of the runtime [`runtime`] selected. Cached alongside that choice in
/// [`selection`], because the verdict cannot usefully change within one test
/// process: a daemon that dies after the probe surfaces at `compose up`, which
/// is a hard error at every posture.
#[must_use]
pub fn probe_runtime() -> RuntimeProbe {
    selection().1
}

/// Whether the caller must fail loudly instead of skipping when the runtime is
/// unusable — that is, whether `RIMAP_REQUIRE_DOCKER` is set. CI sets it.
#[must_use]
pub fn require_runtime() -> bool {
    std::env::var("RIMAP_REQUIRE_DOCKER").is_ok()
}

/// Why `tool` cannot be used, or `None` when it can.
///
/// The returned reason names the runtime actually probed, so an override
/// pointing at an uninstalled runtime does not read as "nothing is installed".
/// Each harness decides what to *do* with it: silently skip, or — under
/// [`require_runtime`] — turn it into that harness's own hard error.
///
/// This covers only *prerequisites*. A failure after the gate — `compose up`
/// refusing an image, or exhausting its address pools — is never a skip.
#[must_use]
pub fn unusable_reason(tool: &str, probe: RuntimeProbe) -> Option<String> {
    match probe {
        RuntimeProbe::Ready => None,
        RuntimeProbe::NoBinary => Some(format!("{tool} is not installed")),
        RuntimeProbe::DaemonDown => {
            Some(format!("{tool} is installed but its daemon is unreachable"))
        }
    }
}

/// The runtime this process uses and what probing it found. A single cache for
/// both: [`runtime`] and [`probe_runtime`] must agree on the selected tool, and
/// the probes are process-wide — the container test binaries must not each
/// re-run them, and a binary linking two harnesses must not run them twice.
fn selection() -> (&'static str, RuntimeProbe) {
    static SELECTION: OnceLock<(&'static str, RuntimeProbe)> = OnceLock::new();
    *SELECTION.get_or_init(|| {
        select_runtime(
            std::env::var("RIMAP_CONTAINER_TOOL").ok().as_deref(),
            &probe_tool,
        )
    })
}

/// Pick the runtime to use and report what probing it found.
///
/// An explicit `RIMAP_CONTAINER_TOOL` is honoured verbatim: only that runtime
/// is probed and no alternative is tried, so a typo'd or deliberately-unusable
/// override fails on its own terms instead of silently running elsewhere.
/// Otherwise each runtime in [`AUTODETECT_ORDER`] is probed in turn and the
/// first usable one wins — selecting on binary presence alone let a stopped
/// Docker Desktop mask a working podman (#674). Probing stops at the first
/// `Ready`, so the common docker-is-up case costs one `--version` plus one
/// `info`.
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

/// The host architecture in OCI image naming, or `None` when this build's
/// target architecture is not one the check can judge. Test binaries are
/// never cross-compiled here (CI builds every platform natively), so the
/// compile-time arch is the host arch.
#[must_use]
pub fn host_arch() -> Option<&'static str> {
    oci_arch_name(std::env::consts::ARCH)
}

fn oci_arch_name(arch: &str) -> Option<&'static str> {
    match arch {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("amd64"),
        _ => None,
    }
}

/// The loud-failure reason when the fixture image's architecture differs
/// from the host's, naming the pin, both arches, and the symptom the
/// mismatch produces downstream. `None` when they match.
#[must_use]
pub fn arch_mismatch_reason(image_ref: &str, image_arch: &str, host_arch: &str) -> Option<String> {
    if image_arch == host_arch {
        return None;
    }
    Some(format!(
        "fixture image {image_ref} is linux/{image_arch} but this host is \
         {host_arch}: the container would run under emulation, which breaks \
         the fixture (doveadm auth-userdb disconnects, TLS handshake EOFs). \
         Re-pin the compose image to a manifest whose architecture list \
         covers {host_arch}."
    ))
}

/// The pinned image reference for `service` in a compose file, parsed by
/// line scan — no YAML dependency for a two-field need. The reference is
/// read at runtime, never duplicated as a constant, so a Dependabot digest
/// bump cannot leave the arch check validating a ref nobody runs. `None`
/// when the file, the service, or its `image:` key cannot be found.
#[must_use]
pub fn pinned_image(compose: &std::path::Path, service: &str) -> Option<String> {
    let text = std::fs::read_to_string(compose).ok()?;
    let service_key = format!("{service}:");
    let mut in_service = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_service = false;
        } else if line.starts_with("  ") && !line.starts_with("   ") {
            in_service = line.trim() == service_key;
        } else if in_service && let Some(value) = line.trim_start().strip_prefix("image:") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
            // Any other property line inside the service falls through —
            // a `?` on the strip_prefix would abort the whole scan on the
            // first non-`image:` key (e.g. `container_name:`) and return
            // `None` for every real compose file.
        }
    }
    None
}

/// The architecture of a *local* image as `<tool> image inspect` reports
/// it. The harnesses call this only after `compose up -d` succeeded, so
/// the image is local by construction and one inspect is authoritative.
/// `None` on any inspect failure — the check then stands down and compose
/// keeps owning the failure, per the gate's documented asymmetry.
#[must_use]
pub fn image_arch(tool: &str, image_ref: &str) -> Option<String> {
    let output = Command::new(tool)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Architecture}}",
            image_ref,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if arch.is_empty() { None } else { Some(arch) }
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

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]

    use std::cell::RefCell;

    use super::{
        DAEMON_PROBE_TIMEOUT, Duration, Instant, RuntimeProbe, arch_mismatch_reason,
        classify_probe, oci_arch_name, pinned_image, run_daemon_probe, select_runtime,
        unusable_reason, wait_bounded,
    };
    use std::process::Command;

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
        // The phrasing `docker compose` emits, which is what #636 reported.
        assert_eq!(
            classify_probe(Some((
                false,
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. \
                 Is the docker daemon running?"
                    .into()
            ))),
            RuntimeProbe::DaemonDown
        );
    }

    /// The other half of the contract: a *live* daemon refusing work is
    /// `Ready`, so it reaches `compose up` and fails there, loudly. Silently
    /// skipping these would hide exactly the breakage this gate exists to keep
    /// visible.
    #[test]
    fn classify_probe_reads_a_daemon_refusing_work_as_ready() {
        // The concurrent-test-run failure mode: several `just ci` runs at once.
        assert_eq!(
            classify_probe(Some((
                false,
                "Error response from daemon: all predefined address pools have been \
                 fully subnetted"
                    .into()
            ))),
            RuntimeProbe::Ready
        );
        // A broken client config, not an absent engine.
        assert_eq!(
            classify_probe(Some((false, "context \"missing\" does not exist".into()))),
            RuntimeProbe::Ready
        );
    }

    /// The rest of the non-`DaemonDown` space: a daemon that answers, and a
    /// probe that outlives its budget — too busy to answer in ten seconds is
    /// busy, not missing.
    #[test]
    fn classify_probe_reads_every_other_outcome_as_ready() {
        assert_eq!(
            classify_probe(Some((true, String::new()))),
            RuntimeProbe::Ready
        );
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

    /// Every harness formats its skip-or-fail message from this reason, so it
    /// has to name the runtime probed and distinguish the two failure modes.
    #[test]
    fn unusable_reason_names_the_runtime_and_the_cause() {
        assert_eq!(unusable_reason("docker", RuntimeProbe::Ready), None);

        let no_binary = unusable_reason("podman", RuntimeProbe::NoBinary).expect("a reason");
        assert!(no_binary.contains("podman"), "{no_binary:?}");
        assert!(no_binary.contains("not installed"), "{no_binary:?}");

        let down = unusable_reason("podman", RuntimeProbe::DaemonDown).expect("a reason");
        assert!(down.contains("podman"), "{down:?}");
        assert!(down.contains("daemon"), "{down:?}");
        assert_ne!(
            down, no_binary,
            "the two skip reasons must read differently"
        );
    }

    #[test]
    fn run_daemon_probe_reports_exit_status() {
        let (ok, _) = run_daemon_probe("false", DAEMON_PROBE_TIMEOUT).expect("probe ran");
        assert!(!ok, "a non-zero exit must be reported as failure");
        let (ok, _) = run_daemon_probe("true", DAEMON_PROBE_TIMEOUT).expect("probe ran");
        assert!(ok, "a zero exit must be reported as success");
    }

    #[test]
    fn run_daemon_probe_reports_an_unspawnable_binary_as_no_outcome() {
        assert_eq!(
            run_daemon_probe("rimap-no-such-runtime-636", DAEMON_PROBE_TIMEOUT),
            None
        );
    }

    #[test]
    fn wait_bounded_reports_the_exit_status_of_a_prompt_child() {
        let mut ok = Command::new("true").spawn().expect("spawn true");
        assert!(
            wait_bounded(&mut ok, DAEMON_PROBE_TIMEOUT).is_some_and(|s| s.success()),
            "a prompt child must report its status"
        );
    }

    /// A daemon mid-restart can leave the probe hanging; the budget must cut it
    /// short rather than stall the whole suite.
    #[test]
    fn wait_bounded_kills_a_child_that_outlives_its_budget() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        assert!(wait_bounded(&mut child, Duration::from_millis(200)).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "wait_bounded must return near its budget, took {:?}",
            started.elapsed()
        );
        // Killed and reaped by wait_bounded, so no zombie is left behind.
        assert!(
            child.try_wait().is_ok_and(|s| s.is_some()),
            "child was not reaped"
        );
    }

    // ── arch gate (#811) ─────────────────────────────────────────────

    #[test]
    fn host_arch_maps_rust_names_to_oci_names() {
        // Compile-time arch on this host is whatever built the tests; the
        // mapping itself is what the check depends on. Both known values
        // must map; the function must never guess at anything else.
        let mapped = ["aarch64", "x86_64"]
            .into_iter()
            .filter_map(oci_arch_name)
            .collect::<Vec<_>>();
        assert_eq!(mapped, ["arm64", "amd64"]);
    }

    #[test]
    fn arch_mismatch_reason_names_both_arches_and_the_pin() {
        let reason = arch_mismatch_reason(
            "docker.io/dovecot/dovecot:2.4.4-root@sha256:34c8425",
            "amd64",
            "arm64",
        )
        .expect("a mismatch is a reason");
        assert!(reason.contains("34c8425"), "{reason:?}");
        assert!(reason.contains("amd64"), "{reason:?}");
        assert!(reason.contains("arm64"), "{reason:?}");
        assert!(
            reason.contains("emulation"),
            "the symptom hint must be there: {reason:?}"
        );
    }

    #[test]
    fn arch_mismatch_reason_is_none_on_a_match() {
        assert_eq!(
            arch_mismatch_reason("some@sha256:1", "arm64", "arm64"),
            None
        );
    }

    const COMPOSE_ONE_SERVICE: &str = "\
services:
  dovecot:
    image: docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80
    container_name: rimap-it-dovecot
    ports: []
";

    const COMPOSE_TWO_SERVICES: &str = "\
services:
  dovecot:
    image: docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80
  toxiproxy:
    image: ghcr.io/shopify/toxiproxy:2.12.0
";

    /// Unique per-process scratch dir under `std::env::temp_dir` — no
    /// `tempfile` dependency: the gate crate's manifest says "No
    /// dependencies, by design" and a dev-dep would amend that contract
    /// for no gain. The pid+counter name cannot collide across parallel
    /// test threads; tests only ever read files they just wrote.
    fn scratch_compose(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rimap-gate-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir.join(name)
    }

    #[test]
    fn pinned_image_reads_the_named_service() {
        let path = scratch_compose("compose.yml");
        std::fs::write(&path, COMPOSE_ONE_SERVICE).expect("write");
        assert_eq!(
            pinned_image(&path, "dovecot").as_deref(),
            Some("docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80")
        );
        std::fs::write(&path, COMPOSE_TWO_SERVICES).expect("write");
        assert_eq!(
            pinned_image(&path, "toxiproxy").as_deref(),
            Some("ghcr.io/shopify/toxiproxy:2.12.0"),
            "the second service must not inherit the first"
        );
    }

    #[test]
    fn pinned_image_is_none_for_a_missing_service_or_file() {
        let path = scratch_compose("compose.yml");
        std::fs::write(&path, COMPOSE_TWO_SERVICES).expect("write");
        assert_eq!(pinned_image(&path, "mailpit"), None);
        let dir = path.parent().expect("scratch dir");
        assert_eq!(pinned_image(&dir.join("absent.yml"), "dovecot"), None);
    }
}
