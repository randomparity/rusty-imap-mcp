//! `DovecotHarness`: hand-rolled `compose up`/`down` lifecycle with a Drop
//! guard. Supports both `docker compose` and `podman compose` — the first
//! runtime whose daemon answers wins, or `RIMAP_CONTAINER_TOOL={docker,podman}`
//! forces a choice. Each test run gets a unique compose project name so
//! parallel tests don't collide.
//!
//! Runtime selection, the daemon probe, and the skip-or-fail verdict come from
//! `rimap-container-gate`, shared with `rimap-server`'s harnesses (#675); only
//! the mapping onto [`HarnessError`] is local. See `AGENTS.md` "Container
//! runtime for integration tests".

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_container_gate::{
    RuntimeProbe, probe_runtime, require_runtime, runtime, unusable_reason,
};
use rimap_core::TlsFingerprint;

/// Failure modes for `DovecotHarness::try_start`. `DockerUnavailable`
/// is the silent-skip signal: the host genuinely cannot run the fixture.
/// `ArchMismatch` fails loudly at every posture (ADR-0023).
#[derive(Debug)]
pub enum HarnessError {
    DockerUnavailable,
    DockerCommandFailed(String),
    FingerprintReadFailed(String),
    PortReadFailed(String),
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
            Self::DockerCommandFailed(s) => write!(f, "{} command failed: {s}", runtime()),
            Self::FingerprintReadFailed(s) => write!(f, "fingerprint read failed: {s}"),
            Self::PortReadFailed(s) => write!(f, "port read failed: {s}"),
            Self::ArchMismatch(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for HarnessError {}

pub struct DovecotHarness {
    project: String,
    compose_dir: PathBuf,
    fingerprint: TlsFingerprint,
    port: u16,
    starttls_port: u16,
}

impl DovecotHarness {
    /// Start a fresh Dovecot container. Returns `Err(DockerUnavailable)`
    /// and skips the test silently when the host cannot run containers at
    /// all — no `docker`/`podman` binary, or a binary whose daemon does not
    /// answer (unless `RIMAP_REQUIRE_DOCKER=1` is set, in which case either
    /// becomes a hard error). Pick a specific runtime with
    /// `RIMAP_CONTAINER_TOOL={docker,podman}`. Failures once the container
    /// is being brought up are never skipped.
    pub fn try_start() -> Result<Self, HarnessError> {
        check_prerequisites()?;

        let compose_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("integration")
            .join("dovecot");

        prune_stale_projects(&compose_dir);

        let project = format!("rimap-it-{}", uuid_like());
        let mut host_port = ReservedPort::acquire()?;
        let mut host_starttls_port = ReservedPort::acquire()?;

        let runner = DockerComposeRunner;
        compose_up_with_retry(
            &runner,
            &project,
            &compose_dir,
            &mut host_port,
            &mut host_starttls_port,
        )?;

        check_image_arch(&project, &compose_dir, "dovecot")?;

        let result = wait_for_ready(
            &project,
            &compose_dir,
            host_port.port(),
            host_starttls_port.port(),
        );
        match result {
            Ok((fingerprint, port)) => Ok(Self {
                project,
                compose_dir,
                fingerprint,
                port,
                starttls_port: host_starttls_port.port(),
            }),
            Err(e) => {
                compose_down(&project, &compose_dir);
                Err(e)
            }
        }
    }

    #[must_use]
    pub fn host() -> &'static str {
        "127.0.0.1"
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn starttls_port(&self) -> u16 {
        self.starttls_port
    }

    #[must_use]
    pub fn pinned_fingerprint(&self) -> TlsFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn username() -> &'static str {
        "rimap-test"
    }

    // Must match crates/rimap-imap/tests/integration/dovecot/users (source of
    // truth) and canary::DOVECOT_CANARY_PASSWORD (#528). High-entropy sentinel so
    // the canary sweep detects a leak without coincidental substring false hits.
    #[must_use]
    pub fn password() -> &'static str {
        "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2"
    }

    /// Run an arbitrary command inside the running dovecot container.
    /// Goes through `<runtime> exec` directly against the pinned container
    /// name rather than `compose exec`, for the same reason the readiness
    /// probe does: podman-compose's exec is unreliable under parallel load.
    pub fn exec(&self, args: &[&str]) -> Result<std::process::Output, HarnessError> {
        let mut cmd = Command::new(runtime());
        cmd.arg("exec").arg(container_name(&self.project));
        for a in args {
            cmd.arg(a);
        }
        cmd.output()
            .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))
    }

    /// Recreate the dovecot container, killing every in-flight TCP
    /// session the test client may have cached. Used by `case_11` to
    /// deterministically trigger the half-open recovery path.
    ///
    /// Previous attempts used `pkill -9 imap` (too racy — master
    /// respawns) and `docker compose stop + start` (dovecot's imap-login
    /// failed to come back online inside the recycled container on CI).
    /// `docker compose up -d --force-recreate` destroys the container
    /// and rebuilds it cleanly, which sidesteps both bugs. The cert is
    /// persisted on the `shared` named volume (which is not touched by
    /// recreate) so the pinned fingerprint is unchanged and the
    /// post-disconnect reconnect works.
    ///
    /// On failure, dumps the last container logs into the error message
    /// so CI runners can diagnose entrypoint regressions.
    pub fn restart(&self) -> Result<(), HarnessError> {
        let status = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("up")
            .arg("-d")
            .arg("--force-recreate")
            .arg("--no-deps")
            .arg("dovecot")
            .env("RIMAP_DOVECOT_HOST_PORT", self.port.to_string())
            .env(
                "RIMAP_DOVECOT_HOST_PORT_STARTTLS",
                self.starttls_port.to_string(),
            )
            .current_dir(&self.compose_dir)
            .status()
            .map_err(|e| HarnessError::DockerCommandFailed(format!("recreate: {e}")))?;
        if !status.success() {
            return Err(HarnessError::DockerCommandFailed(format!(
                "compose up --force-recreate exit {status}"
            )));
        }
        // Wait for dovecot to be ready. Two gates: (1) the new entrypoint
        // must rewrite /shared/ready (which it only touches AFTER dovecot
        // has bound 993 inside the container), and (2) a direct TCP probe
        // from the host must succeed (catches the case where docker's
        // userland proxy is lagging the actual container state).
        let started = Instant::now();
        let timeout = Duration::from_secs(45);
        loop {
            if started.elapsed() > timeout {
                let logs = dump_logs(&self.project, &self.compose_dir);
                return Err(HarnessError::DockerCommandFailed(format!(
                    "dovecot did not rebind ports {} and {} within 45s after recreate. \
                     Last container logs:\n{logs}",
                    self.port, self.starttls_port
                )));
            }
            if probe_ready_marker(&self.project)
                && std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], self.port)),
                    Duration::from_millis(500),
                )
                .is_ok()
                && std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], self.starttls_port)),
                    Duration::from_millis(500),
                )
                .is_ok()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

fn check_prerequisites() -> Result<(), HarnessError> {
    gate(runtime(), probe_runtime(), require_runtime())
}

/// Map `rimap_container_gate`'s verdict onto this harness's error type. Pure,
/// so every combination is unit-testable without a container runtime. Note this
/// covers only *prerequisites*: a failure after the gate — `compose up`
/// refusing an image, or exhausting its address pools — stays a
/// `DockerCommandFailed` that no caller silent-skips on.
fn gate(tool: &str, probe: RuntimeProbe, require_runtime: bool) -> Result<(), HarnessError> {
    let Some(reason) = unusable_reason(tool, probe) else {
        return Ok(());
    };
    if require_runtime {
        Err(HarnessError::DockerCommandFailed(format!(
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
fn check_image_arch(project: &str, compose_dir: &Path, service: &str) -> Result<(), HarnessError> {
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

/// Minimal interface over `docker compose up` so the retry wrapper
/// can be unit-tested without a real docker.
trait ComposeRunner {
    fn up(
        &self,
        project: &str,
        compose_dir: &Path,
        tls_port: u16,
        starttls_port: u16,
    ) -> Result<(), HarnessError>;
}

/// Production runner: shells out to `docker compose up -d` (or podman).
struct DockerComposeRunner;

impl ComposeRunner for DockerComposeRunner {
    fn up(
        &self,
        project: &str,
        compose_dir: &Path,
        tls_port: u16,
        starttls_port: u16,
    ) -> Result<(), HarnessError> {
        compose_up(project, compose_dir, tls_port, starttls_port)
    }
}

/// Drive `runner.up(...)` with a bounded retry on host-port collisions.
///
/// Three attempts total (initial + 2 retries). Each retry tears down
/// the partial compose project, sleeps with increasing backoff, and
/// acquires fresh `ReservedPort`s. Non-collision errors propagate
/// immediately on the first failure. If all three attempts hit
/// collisions, the most recent stderr is preserved in the error
/// message.
fn compose_up_with_retry(
    runner: &dyn ComposeRunner,
    project: &str,
    compose_dir: &Path,
    tls: &mut ReservedPort,
    starttls: &mut ReservedPort,
) -> Result<(), HarnessError> {
    const BACKOFF_MS: [u64; 2] = [50, 250];
    const MAX_ATTEMPTS: usize = BACKOFF_MS.len() + 1;
    let mut last_collision: Option<String> = None;

    // Attempt 0 is the initial try (no prior sleep). Attempts 1 and 2 are
    // retries preceded by teardown + backoff sleep + fresh port acquisition.
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            compose_down(project, compose_dir);
            std::thread::sleep(Duration::from_millis(BACKOFF_MS[attempt - 1]));
            *tls = ReservedPort::acquire()?;
            *starttls = ReservedPort::acquire()?;
        }
        tls.release();
        starttls.release();
        let result = runner.up(project, compose_dir, tls.port(), starttls.port());
        match result {
            Ok(()) => return Ok(()),
            Err(HarnessError::DockerCommandFailed(s)) if is_port_collision(&s) => {
                last_collision = Some(s);
            }
            Err(e) => return Err(e),
        }
    }
    Err(HarnessError::DockerCommandFailed(format!(
        "compose up: exhausted {MAX_ATTEMPTS} attempts on port collision; last error: {}",
        last_collision.unwrap_or_else(|| "<no error captured>".into()),
    )))
}

fn compose_up(
    project: &str,
    compose_dir: &Path,
    host_port: u16,
    host_starttls_port: u16,
) -> Result<(), HarnessError> {
    let output = Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("up")
        .arg("-d")
        .env("RIMAP_DOVECOT_HOST_PORT", host_port.to_string())
        .env(
            "RIMAP_DOVECOT_HOST_PORT_STARTTLS",
            host_starttls_port.to_string(),
        )
        .current_dir(compose_dir)
        .output()
        .map_err(|e| HarnessError::DockerCommandFailed(e.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HarnessError::DockerCommandFailed(format!(
            "compose up exit {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

/// Classify a stderr blob from a failed `compose up`: `true` when the
/// failure looks like a host-port bind collision, `false` otherwise.
///
/// Covers three observed phrasings:
///   - docker engine: "Bind for 127.0.0.1:NNNN failed: port is already allocated"
///   - libc EADDRINUSE: "address already in use"
///   - podman rootlessport: "Bind for 127.0.0.1:NNNN failed"
fn is_port_collision(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("port is already allocated")
        || s.contains("address already in use")
        || s.contains("bind for 127.0.0.1")
}

fn wait_for_ready(
    project: &str,
    compose_dir: &Path,
    host_port: u16,
    host_starttls_port: u16,
) -> Result<(TlsFingerprint, u16), HarnessError> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    loop {
        if started.elapsed() > timeout {
            let logs = dump_logs(project, compose_dir);
            return Err(HarnessError::DockerCommandFailed(format!(
                "dovecot container did not become ready within 60s. \
                 Last container logs:\n{logs}"
            )));
        }
        if let Ok(fp) = read_fingerprint(project)
            && std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], host_port)),
                Duration::from_millis(500),
            )
            .is_ok()
            && std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], host_starttls_port)),
                Duration::from_millis(500),
            )
            .is_ok()
        {
            return Ok((fp, host_port));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn dump_logs(project: &str, compose_dir: &std::path::Path) -> String {
    match Command::new(runtime())
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("logs")
        .arg("--tail")
        .arg("200")
        .arg("dovecot")
        .current_dir(compose_dir)
        .output()
    {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                out.push_str("\n--- stderr ---\n");
                out.push_str(&err);
            }
            if out.trim().is_empty() {
                "<no container logs>".into()
            } else {
                out
            }
        }
        Err(e) => format!("logs fetch failed: {e}"),
    }
}

/// The compose file pins `container_name: ${COMPOSE_PROJECT_NAME}-dovecot`,
/// so we can talk to the container directly via `<runtime> exec` and skip
/// `compose exec` entirely. podman-compose's `compose exec -T` has been
/// observed to return success without actually executing the command
/// against the service container when multiple compose projects are
/// running in parallel (nextest spawns 11 at once), which wedged the
/// readiness polling until the 60s harness timeout even though dovecot
/// was up and ready. `<runtime> exec` hits the container name directly
/// and has no such failure mode.
fn container_name(project: &str) -> String {
    format!("{project}-dovecot")
}

fn probe_ready_marker(project: &str) -> bool {
    Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
        .arg("test")
        .arg("-f")
        .arg("/shared/ready")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

/// Parse a compose project name into the embedded creation timestamp.
/// Returns `Some(SystemTime)` if the name follows the
/// `rimap-it-<hex-nanos>[-<other-segments>]` format, where the leading
/// hex segment (before any `-`) is interpreted as nanoseconds since
/// `UNIX_EPOCH`. Returns `None` for any name that does not start with
/// `rimap-it-`, has no hex prefix, or whose hex prefix doesn't parse.
fn project_creation_time(name: &str) -> Option<std::time::SystemTime> {
    let suffix = name.strip_prefix("rimap-it-")?;
    let hex_nanos = suffix.split('-').next()?;
    if hex_nanos.is_empty() {
        return None;
    }
    let nanos = u128::from_str_radix(hex_nanos, 16).ok()?;
    let secs = u64::try_from(nanos / 1_000_000_000).ok()?;
    let sub_nanos = u32::try_from(nanos % 1_000_000_000).ok()?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, sub_nanos))
}

/// Best-effort cleanup of leaked `rimap-it-*` compose projects from previous
/// runs that died via SIGKILL or power loss (Drop doesn't fire on either).
/// Skips projects younger than `STALE_PROJECT_AGE` to avoid disturbing
/// in-flight parallel runs. All errors are silent — this is opportunistic.
fn prune_stale_projects(compose_dir: &std::path::Path) {
    let output = match Command::new(runtime())
        .arg("compose")
        .arg("ls")
        .arg("--all")
        .arg("--format")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let projects: Vec<serde_json::Value> = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => return,
    };

    let now = std::time::SystemTime::now();
    for project in projects {
        let Some(name) = project.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(created) = project_creation_time(name) else {
            continue;
        };
        let age = now.duration_since(created).unwrap_or_default();
        if age < STALE_PROJECT_AGE {
            continue;
        }
        // Stale enough to prune. Errors are silent.
        let _ = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(name)
            .arg("down")
            .arg("-v")
            .arg("--remove-orphans")
            .current_dir(compose_dir)
            .status();
    }
}

fn read_fingerprint(project: &str) -> Result<TlsFingerprint, HarnessError> {
    let out = Command::new(runtime())
        .arg("exec")
        .arg(container_name(project))
        .arg("cat")
        .arg("/shared/fingerprint.hex")
        .output()
        .map_err(|e| HarnessError::FingerprintReadFailed(e.to_string()))?;
    if !out.status.success() {
        return Err(HarnessError::FingerprintReadFailed("not yet ready".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    TlsFingerprint::from_hex(&s).map_err(|e| HarnessError::FingerprintReadFailed(e.to_string()))
}

/// A host port reserved by binding `127.0.0.1:0` and reading the
/// kernel-assigned number. The `TcpListener` is kept open until
/// `release()` is called, holding the kernel-level lease so docker
/// (or any other process) cannot bind the same port in the meantime.
///
/// Lifecycle: callers acquire two `ReservedPort`s, then pass `&mut`
/// references to the retry wrapper, which releases them just before
/// invoking `docker compose up`. If `compose up` fails with a port
/// collision (the residual race window), the wrapper drops the
/// reservations and acquires fresh ones for the next attempt.
struct ReservedPort {
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl ReservedPort {
    fn acquire() -> Result<Self, HarnessError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| HarnessError::PortReadFailed(format!("bind: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| HarnessError::PortReadFailed(format!("local_addr: {e}")))?
            .port();
        Ok(Self {
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

/// Maximum age of a `rimap-it-*` compose project before it is considered
/// stale and pruned at the start of a new test session. Projects younger
/// than this are left alone so parallel test runs do not stomp on each
/// other.
const STALE_PROJECT_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 60);

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

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringCredentialResolver};
use rimap_core::auth_sink::AuthEventSink;
use rimap_core::credential::CredentialResolver;
use rimap_imap::{Connection, ConnectionConfig};
use std::sync::Arc;
use tempfile::TempDir;

pub struct StaticCreds(pub String);

impl CredentialStore for StaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
        Ok(Some(secrecy::SecretString::from(self.0.clone())))
    }

    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}

pub struct ConnectedHarness {
    pub harness: DovecotHarness,
    pub audit_dir: TempDir,
    pub audit: AuditWriter,
    pub connection: Connection,
}

impl ConnectedHarness {
    /// Build a harness using implicit TLS on port 993. For STARTTLS, call
    /// `new_with_encryption` explicitly.
    pub fn new(pin_with: PinChoice) -> Result<Self, HarnessError> {
        Self::new_with_encryption(pin_with, rimap_imap::ImapEncryption::Tls)
    }

    pub fn new_with_encryption(
        pin_with: PinChoice,
        encryption: rimap_imap::ImapEncryption,
    ) -> Result<Self, HarnessError> {
        let harness = DovecotHarness::try_start()?;
        let audit_dir = TempDir::new().expect("tempdir");
        let audit_path = audit_dir.path().join("audit.jsonl");
        let audit =
            AuditWriter::open(&AuditOptions::new(audit_path, Seq::FIRST)).expect("audit open");

        let pinned = match pin_with {
            PinChoice::Correct => Some(harness.pinned_fingerprint()),
            PinChoice::Wrong => Some(rimap_core::TlsFingerprint::from_cert_der(
                b"deliberately-wrong",
            )),
            PinChoice::None => None,
        };

        let port = match encryption {
            rimap_imap::ImapEncryption::Tls => harness.port(),
            rimap_imap::ImapEncryption::Starttls => harness.starttls_port(),
        };

        let mut cfg = ConnectionConfig::new(
            rimap_core::account::AccountId::default_account(),
            DovecotHarness::host().to_string(),
            port,
            encryption,
            DovecotHarness::username().to_string(),
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(10),
            5_242_880,
            10_485_760,
        );
        cfg.pinned_fingerprint = pinned;
        let store: Arc<dyn CredentialStore> =
            Arc::new(StaticCreds(DovecotHarness::password().to_string()));
        let creds: Arc<dyn CredentialResolver> = Arc::new(KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
        ));
        let sink: Arc<dyn AuthEventSink> = Arc::new(audit.clone());
        let connection = Connection::new(cfg, sink, creds);
        Ok(Self {
            harness,
            audit_dir,
            audit,
            connection,
        })
    }

    pub fn audit_path(&self) -> std::path::PathBuf {
        self.audit_dir.path().join("audit.jsonl")
    }

    pub fn starttls_port(&self) -> u16 {
        self.harness.starttls_port()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PinChoice {
    Correct,
    Wrong,
    None,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]
    #![expect(clippy::expect_used, reason = "tests")]
    #![expect(clippy::panic, reason = "test failure path")]

    use super::*;

    const PORT_COLLISION_STDERR: &str =
        "Bind for 127.0.0.1:12345 failed: port is already allocated";

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
        let Err(HarnessError::DockerCommandFailed(msg)) =
            gate("podman", RuntimeProbe::DaemonDown, true)
        else {
            panic!("RIMAP_REQUIRE_DOCKER=1 must turn a dead daemon into a hard error");
        };
        assert!(
            msg.contains("podman"),
            "must name the runtime probed: {msg:?}"
        );
        assert!(msg.contains("daemon"), "must name the cause: {msg:?}");
        assert!(msg.contains("RIMAP_REQUIRE_DOCKER"), "got {msg:?}");
    }

    #[test]
    fn gate_skips_when_no_runtime_binary_is_installed() {
        let err = gate("docker", RuntimeProbe::NoBinary, false).expect_err("must not pass");
        assert!(matches!(err, HarnessError::DockerUnavailable), "{err:?}");
    }

    /// The message names the runtime actually selected, so an override pointing
    /// at an uninstalled runtime does not read as "nothing is installed".
    #[test]
    fn gate_is_loud_when_no_binary_and_docker_required() {
        let Err(HarnessError::DockerCommandFailed(msg)) =
            gate("podman", RuntimeProbe::NoBinary, true)
        else {
            panic!("RIMAP_REQUIRE_DOCKER=1 must turn a missing binary into a hard error");
        };
        assert!(
            msg.contains("podman"),
            "must name the runtime probed: {msg:?}"
        );
        assert!(msg.contains("RIMAP_REQUIRE_DOCKER"), "got {msg:?}");
    }

    #[test]
    fn gate_admits_a_ready_runtime_under_both_postures() {
        assert!(gate("docker", RuntimeProbe::Ready, false).is_ok());
        assert!(gate("docker", RuntimeProbe::Ready, true).is_ok());
    }

    /// The gate only covers prerequisites. A daemon that dies *after* the probe
    /// surfaces at `compose up`, and must stay a hard error — silent-skipping
    /// there would hide real breakage.
    #[test]
    fn compose_up_daemon_error_stays_a_hard_failure() {
        let runner = FlakyComposeRunner::always_fail_with(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. \
             Is the docker daemon running?",
        );
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        let Err(HarnessError::DockerCommandFailed(msg)) = result else {
            panic!("a compose-time daemon failure must not be a skip: {result:?}");
        };
        assert!(
            msg.contains("Cannot connect to the Docker daemon"),
            "{msg:?}"
        );
        assert_eq!(
            runner.attempts(),
            1,
            "daemon errors are not port collisions"
        );
    }

    /// Address-pool exhaustion is what concurrent container test runs actually
    /// hit. It is a live daemon refusing work, not an absent one, so it must
    /// neither be retried as a port collision nor skipped.
    #[test]
    fn address_pool_exhaustion_is_not_a_port_collision() {
        assert!(!is_port_collision(
            "Error response from daemon: all predefined address pools have been fully subnetted"
        ));
    }

    #[test]
    fn is_port_collision_matches_docker_engine_error() {
        let stderr = "Error response from daemon: failed to set up container networking: \
            driver failed programming external connectivity on endpoint rimap-it-abc-dovecot \
            (...): Bind for 127.0.0.1:35615 failed: port is already allocated";
        assert!(is_port_collision(stderr));
    }

    #[test]
    fn is_port_collision_matches_libc_eaddrinuse() {
        assert!(is_port_collision("bind: address already in use"));
    }

    #[test]
    fn is_port_collision_matches_podman_variant() {
        assert!(is_port_collision(
            "Error: rootlessport listen tcp 127.0.0.1:1234: bind: address already in use"
        ));
    }

    #[test]
    fn is_port_collision_rejects_unrelated_error() {
        assert!(!is_port_collision(
            "no such image: docker.io/dovecot/dovecot:9.9.9"
        ));
        assert!(!is_port_collision("dovecot exited with non-zero status"));
    }

    #[test]
    fn is_port_collision_is_case_insensitive() {
        assert!(is_port_collision("PORT IS ALREADY ALLOCATED"));
        assert!(is_port_collision("Bind FOR 127.0.0.1:80 failed"));
    }

    #[test]
    fn reserved_port_acquires_distinct_ports() {
        let a = ReservedPort::acquire().expect("acquire a");
        let b = ReservedPort::acquire().expect("acquire b");
        assert_ne!(
            a.port(),
            b.port(),
            "two reservations must yield different ports"
        );
    }

    #[test]
    fn reserved_port_release_drops_lease() {
        let mut p = ReservedPort::acquire().expect("acquire");
        let port = p.port();
        p.release();
        // After release, another bind on the same port should succeed.
        let bound_again = std::net::TcpListener::bind(("127.0.0.1", port));
        assert!(
            bound_again.is_ok(),
            "should be able to bind {port} after release: {:?}",
            bound_again.err()
        );
    }

    #[test]
    fn reserved_port_release_is_idempotent() {
        let mut p = ReservedPort::acquire().expect("acquire");
        p.release();
        p.release(); // must not panic
    }

    #[test]
    fn project_creation_time_parses_legacy_hex_only_format() {
        // Old format before Task 6a: "rimap-it-<hex-nanos>".
        // This may still appear for projects created before this fix is
        // deployed.
        let t = project_creation_time("rimap-it-18af360a97189210");
        assert!(t.is_some(), "legacy hex-only format must parse");
    }

    #[test]
    fn project_creation_time_parses_new_pid_counter_format() {
        // New format from Task 6a: "rimap-it-<hex-nanos>-<hex-pid>-<hex-counter>".
        let t = project_creation_time("rimap-it-18af360a97189210-3f0-0");
        assert!(t.is_some(), "new pid+counter format must parse");
    }

    #[test]
    fn project_creation_time_matches_for_both_formats() {
        // Same leading hex must produce the same SystemTime regardless
        // of trailing -pid-counter segments.
        let legacy = project_creation_time("rimap-it-18af360a97189210");
        let new = project_creation_time("rimap-it-18af360a97189210-3f0-0");
        assert_eq!(legacy, new);
    }

    #[test]
    fn project_creation_time_rejects_missing_prefix() {
        assert!(project_creation_time("other-project-deadbeef").is_none());
    }

    #[test]
    fn project_creation_time_rejects_non_hex_prefix() {
        assert!(project_creation_time("rimap-it-not-hex-here").is_none());
    }

    #[test]
    fn project_creation_time_rejects_empty_suffix() {
        assert!(project_creation_time("rimap-it-").is_none());
    }

    #[test]
    fn project_creation_time_rejects_empty_hex_segment_before_dash() {
        // "rimap-it--3f0-0" — leading hex segment is empty.
        assert!(project_creation_time("rimap-it--3f0-0").is_none());
    }

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Test double for `ComposeRunner`. Records every observed
    /// `(tls_port, starttls_port)` pair and returns a programmable
    /// sequence of results.
    struct FlakyComposeRunner {
        fail_first_n: AtomicU32,
        observed_ports: Mutex<Vec<(u16, u16)>>,
        port_collision_stderr: String,
        terminal_error: Option<String>,
    }

    impl FlakyComposeRunner {
        /// Fail the first `n` attempts with a port-collision stderr;
        /// succeed afterward.
        fn fail_first_n_with_port_collision(n: u32) -> Self {
            Self {
                fail_first_n: AtomicU32::new(n),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: PORT_COLLISION_STDERR.into(),
                terminal_error: None,
            }
        }

        /// Always fail with a port-collision stderr.
        fn always_fail_with_port_collision() -> Self {
            Self {
                fail_first_n: AtomicU32::new(u32::MAX),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: PORT_COLLISION_STDERR.into(),
                terminal_error: None,
            }
        }

        /// Always fail with a non-collision stderr.
        fn always_fail_with(msg: &str) -> Self {
            Self {
                fail_first_n: AtomicU32::new(u32::MAX),
                observed_ports: Mutex::new(Vec::new()),
                port_collision_stderr: String::new(),
                terminal_error: Some(msg.into()),
            }
        }

        fn observed_ports(&self) -> Vec<(u16, u16)> {
            self.observed_ports.lock().unwrap().clone()
        }

        fn attempts(&self) -> usize {
            self.observed_ports.lock().unwrap().len()
        }
    }

    impl ComposeRunner for FlakyComposeRunner {
        fn up(
            &self,
            _project: &str,
            _compose_dir: &Path,
            tls_port: u16,
            starttls_port: u16,
        ) -> Result<(), HarnessError> {
            self.observed_ports
                .lock()
                .unwrap()
                .push((tls_port, starttls_port));

            if let Some(msg) = self.terminal_error.as_ref() {
                return Err(HarnessError::DockerCommandFailed(msg.clone()));
            }

            let remaining = self.fail_first_n.load(Ordering::SeqCst);
            if remaining > 0 {
                self.fail_first_n.fetch_sub(1, Ordering::SeqCst);
                return Err(HarnessError::DockerCommandFailed(
                    self.port_collision_stderr.clone(),
                ));
            }
            Ok(())
        }
    }

    fn dummy_compose_dir() -> &'static Path {
        Path::new("/tmp/rimap-it-test")
    }

    #[test]
    fn compose_up_retries_on_port_collision_then_succeeds() {
        let runner = FlakyComposeRunner::fail_first_n_with_port_collision(2);
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        assert!(
            result.is_ok(),
            "should succeed on third attempt: {:?}",
            result.err()
        );
        let ports = runner.observed_ports();
        assert_eq!(ports.len(), 3, "should have attempted three times");
        // Each retry uses a fresh port pair (proves the reacquire path).
        assert_ne!(ports[0], ports[1], "attempt 1 vs 2 ports identical");
        assert_ne!(ports[1], ports[2], "attempt 2 vs 3 ports identical");
    }

    #[test]
    fn compose_up_gives_up_after_max_attempts() {
        let runner = FlakyComposeRunner::always_fail_with_port_collision();
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        let Err(HarnessError::DockerCommandFailed(msg)) = result else {
            panic!("expected DockerCommandFailed, got: {result:?}");
        };
        assert!(msg.contains("exhausted"), "missing 'exhausted' in {msg:?}");
        assert!(
            msg.contains("port is already allocated"),
            "underlying stderr should be preserved in {msg:?}"
        );
        assert_eq!(runner.attempts(), 3, "should have attempted three times");
    }

    #[test]
    fn compose_up_propagates_non_port_errors_immediately() {
        let runner = FlakyComposeRunner::always_fail_with("no such image: dovecot:9.9.9");
        let mut tls = ReservedPort::acquire().expect("tls");
        let mut starttls = ReservedPort::acquire().expect("starttls");

        let result = compose_up_with_retry(
            &runner,
            "test-proj",
            dummy_compose_dir(),
            &mut tls,
            &mut starttls,
        );

        assert!(result.is_err());
        assert_eq!(
            runner.attempts(),
            1,
            "non-collision errors should not retry"
        );
    }
}
