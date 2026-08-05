//! Stdio JSON-RPC harness used by both Phase 1 (`mcp_wire_conformance.rs`)
//! and Phase 3 (`e2e_wire.rs`). Spawns the production `rusty-imap-mcp`
//! binary (compiled with the `test-support` feature via the dev-dependency
//! in Cargo.toml) and exchanges line-delimited JSON-RPC envelopes over stdin/stdout. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`
//! and the Phase 3 sibling spec for the design context.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

/// MCP protocol version pinned by this harness. Matches the
/// directory under `tests/fixtures/mcp-spec/` and the `LATEST` value
/// in `rmcp 1.5`. Update both when bumping.
pub const PINNED_PROTOCOL_VERSION: &str = "2025-11-25";

/// Vendored MCP spec schema, compiled in at build time so tests run
/// hermetically (no network, no filesystem dependency beyond the
/// crate source).
pub(crate) const MCP_SCHEMA_JSON: &str =
    include_str!("../../fixtures/mcp-spec/2025-11-25/schema.json");

/// Budget for a **steady-state** response read: the child is already serving,
/// so the request is in-process work plus at most one round trip to an
/// already-connected IMAP session. Measured at 0.4-6 ms for a `tools/call`
/// against the in-process fake, so 2 s fails fast on a real hang with three
/// orders of magnitude of headroom. Does NOT cover the first read after spawn
/// — see [`COLD_START_TIMEOUT`] — and is raised to a floor on CI's coverage
/// arm, where the same 2 s proved too tight in #671; see
/// [`INSTRUMENTED_READ_FLOOR`]. This value is what the uninstrumented arm
/// keeps, and keeping it tight there is the point of scoping the floor.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Budget for the **first** response read of a freshly spawned child, which is
/// the only read that pays for process start-up.
///
/// Everything the binary does before it can answer anything lands inside this
/// one read: `exec` and dynamic linking, config parse, credential resolution
/// (the keyring miss and `RUSTY_IMAP_MCP_PASSWORD` fallback that CI runners
/// always take), and — for the e2e wire binaries — a full IMAP boot of TCP
/// connect, TLS handshake, `CAPABILITY`, `LOGIN` and the catalog `LIST`. That
/// is a different cost class from a steady-state request, not a slower
/// instance of one, so it gets its own budget rather than inflating
/// [`REQUEST_TIMEOUT`] for every read.
///
/// Value: measured at 220-270 ms unloaded (`e2e_wire_uidvalidity`, in-process
/// fake). Issue #621 recorded a CI run that blew a 2 s budget mid-`LOGIN`,
/// i.e. start-up alone took >9x its unloaded cost under `nextest` contention.
/// 10 s is ~40x the unloaded measurement, which absorbs that contention while
/// still failing a genuinely hung boot in single-digit seconds — the same
/// trade-off, and the same order of magnitude, as [`SHUTDOWN_TIMEOUT`].
pub const COLD_START_TIMEOUT: Duration = Duration::from_secs(10);

// Under `cargo nextest run` with the full workspace suite (~1100 tests
// in parallel), the EOF-to-exit slice for `wire_clean_eof_shutdown_exits_zero`
// can exceed a tight 1 s budget on CPU-contended runners. 5 s remains
// tight enough to fail-fast on a real hang while absorbing scheduling
// jitter when other tests are spawning binaries / parsers concurrently.
//
// Deliberately NOT floored on the coverage arm the way the read budgets are
// (`INSTRUMENTED_READ_FLOOR`), and that is a measured decision rather than a
// scope boundary. An instrumented process dumps a `.profraw` on the way out, so
// the exit path is where instrumentation plausibly costs the most — but across
// the same paired full-workspace runs, the wait this budget covers ran to a
// 6.3 ms instrumented median against 5.4 ms uninstrumented (1.18x), and the
// instrumented worst case was *lower* than the uninstrumented one (249 vs
// 308 ms). There is nothing here to absorb. `DETACHED_EXIT_TIMEOUT` is left
// alone for the same reason.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Budget for reaping a [`DetachedStdoutHarness`] child, which is the only wait
/// in this harness that spans the process's **entire** lifetime — spawn, the
/// request, and exit — in a single call.
///
/// [`Harness::spawn_with_closed_stdout`] drops the stdout read end before the
/// child writes anything, which is the whole point of that variant. So there is
/// no *stdout* readiness handshake, and [`read_deadline`] — which keys off
/// stdout output — cannot pay for start-up on a separate read the way it does
/// for a piped harness. Cold start is therefore inside the exit wait.
///
/// Hence the sum: [`COLD_START_TIMEOUT`] for `exec`, dynamic linking, config
/// parse and credential resolution, plus [`SHUTDOWN_TIMEOUT`] for the exit slice
/// that follows the failed envelope write.
///
/// What #638 actually establishes about the size: the child had **not** exited
/// 5 s after the request write, and `nextest` reported 8.826 s for the whole
/// case — of which 5 s was that elapsed timeout. The child's true exit time was
/// never observed, so the run bounds the envelope from below and no further.
/// The size argument is therefore the cost model, not that log line: start-up
/// is the cost class [`COLD_START_TIMEOUT`] is calibrated for, and the exit
/// slice that follows it is what [`SHUTDOWN_TIMEOUT`] is calibrated for.
///
/// The remaining ~3.8 s of that case is **unattributed**, and worth resisting
/// the urge to assign. It is not the parent-side prefix: measured with the
/// instrument `wait_for_exit` now prints, that prefix is single-digit
/// milliseconds (6.7 ms observed), which even at the ~20x amplification below
/// reaches ~0.13 s. Two costs inside `nextest`'s per-case number sit outside
/// this harness's own clock entirely and are the plausible homes for it:
/// `nextest`'s spawn of the debug test binary, and post-panic teardown —
/// unwinding, then the `kill_on_drop` SIGKILL and reap of a child that by
/// construction had *not* exited, then tempdir removal. If the residue is
/// teardown, that is seconds spent reaping a live child, which is weak
/// affirmative evidence for the stall hypothesis below rather than for
/// contention. #660 carries that.
///
/// Be precise about how far that model goes, because it does not go all the
/// way. Measured here, this case costs 0.22-0.28 s end to end across 12 samples
/// at host load 20-119, so a 5 s timeout implies roughly 20x amplification —
/// more than the >9x #621 recorded. This harness is also cheaper at boot than
/// the ones #621 measured: `accounts = []` with `--allow-empty-accounts` skips
/// credential resolution and the IMAP boot entirely, so it pays only `exec`,
/// dynamic linking and config parse. The budget is sized on the assumption that
/// the failing runner was contended well past anything reproduced locally. The
/// competing explanation — an intermittent stall in the server's own
/// broken-pipe shutdown path, which a wider budget would mask rather than fix —
/// is *not* excluded by anything here; it is tracked in #660.
///
/// The discriminator is the distribution of the exit wait: clustered near 0.2 s
/// supports contention, bimodal with multi-second outliers supports a stall.
/// `wait_for_exit` prints that number — but **CI cannot supply the
/// distribution** under the current profile, because `nextest` drops a passing
/// test's stderr by default (see the call site). Collecting it takes a
/// deliberate instrumented run on a contended host, not passive accumulation
/// over green CI, and #660 says so.
///
/// Note what this budget does *not* cover. It starts at the `wait_for_exit`
/// call, so the parent-side prefix — tempdir, config write, `cargo_bin`
/// resolution, `Command::spawn`, the request write — sits outside it. That
/// prefix is small (single-digit ms measured), and leaving it unbudgeted is
/// deliberate: `nextest`'s slow-timeout is
/// advisory and `.config/nextest.toml` sets no `terminate-after`, so a slow
/// prefix produces a SLOW marker rather than a failure, and wrapping it in a
/// second timeout would cost more than the risk it removes. Its duration
/// reaches a reader through the `wait_for_exit` panic message on the timeout
/// path, and through the explicit-output run named at that call site otherwise.
///
/// Composed from the two named constants rather than hand-tuned to a third
/// number so each cost stays individually documented and tunable. Widening
/// `SHUTDOWN_TIMEOUT` to cover this instead would also loosen the two waits
/// that are correctly scoped today (`response_or_close` and
/// [`Harness::shutdown_and_wait`]), whose callers have already paid start-up.
///
/// **Considered and rejected:** the child fsyncs a `process_start` audit record
/// during boot and this harness already holds `audit_path`, so polling that file
/// under `COLD_START_TIMEOUT` *would* give a readiness handshake off stdout and
/// let the exit wait keep the tight `SHUTDOWN_TIMEOUT`.
///
/// State its benefit accurately, because it is not mainly about latency: with
/// the exit slice back on `SHUTDOWN_TIMEOUT`, a 5-15 s stall between the failed
/// envelope write and process exit stays a *test failure*, whereas a summed
/// budget cannot fail one. That is the cost being accepted here — the summed
/// budget masks the very hypothesis #660 is open on, and the printed
/// measurement is a weaker substitute for a failing assertion. Not built
/// anyway: a polling loop is materially more code than a summed constant, and
/// #660 is the place to weigh it once the distribution is known. Revisit this
/// if that distribution turns out bimodal.
pub const DETACHED_EXIT_TIMEOUT: Duration = COLD_START_TIMEOUT.saturating_add(SHUTDOWN_TIMEOUT);

/// Environment variable `cargo llvm-cov` exports into the processes it runs.
/// Its value is a profile-output pattern, not a flag, so only its presence is
/// meaningful here.
const LLVM_PROFILE_FILE_ENV: &str = "LLVM_PROFILE_FILE";

/// Floor applied to every stdout read budget while this test process is
/// running under `cargo llvm-cov` — in CI, the `SonarQube` job and nothing
/// else.
///
/// **Name it for what it is scoped to, not for a cost it was measured from.**
/// #671 proposed this as an instrumentation-overhead allowance. Measurement
/// does not support that reading, so the constant is deliberately documented
/// against the weaker claim it can actually carry.
///
/// What was measured (two full-workspace runs, 2219 tests each, same host at
/// load average ~96 on 18 cores, matched 2161-sample read distributions —
/// `cargo nextest` with and without `cargo llvm-cov`):
///
/// - steady-state read, median 0.10 ms both ways — instrumented/uninstrumented
///   ratio **1.08x**; at p99, 5.5 vs 5.3 ms, **1.02x**; worst sample 22.2 vs
///   17.6 ms, **1.27x**.
/// - the first read after spawn: 240 vs 226 ms median, **1.06x**.
/// - not one read of 2115 steady-state samples reached even 100 ms under
///   instrumentation.
///
/// So [`REQUEST_TIMEOUT`] already carried **90x** headroom over the worst
/// instrumented read observed, and instrumentation contributes 1.27x of the
/// ~90x outlier the #671 failure required. Scaling the budget by the measured
/// ratio would yield ~2.5 s and would not have saved that run. **The cause of
/// that failure is not established, and this constant does not claim to
/// address it** — see the follow-up note below.
///
/// What the floor *is* good for is scoping. `LLVM_PROFILE_FILE` is a reliable
/// proxy for "this is the coverage job", and that job differs from
/// `test (stable)` in three ways at once, only one of which is instrumentation:
/// it drives `cargo test` rather than `cargo nextest --profile ci`, so every
/// test in a binary is co-scheduled inside one process and none of
/// `.config/nextest.toml`'s concurrency groups apply; and it passes
/// `--all-features`. Under `cargo test` the three `e2e_wire` cases run
/// together — three `worker_threads = 4` Tokio runtimes and three Dovecot
/// containers — on a 4-vCPU runner. Widening on this signal widens exactly the
/// arm that flaked and leaves every other arm's budget alone; it does not
/// assert which of the three differences did the damage.
///
/// Value: 10 s, i.e. 5x [`REQUEST_TIMEOUT`]. Not computed from the ratios
/// above — they would justify no widening at all. It is a tail allowance for a
/// cost that measurement could not reproduce, sized to the same order as
/// [`COLD_START_TIMEOUT`] for the same reason that one is 10 s: large enough
/// that it is not the thing that fails, small enough that a genuinely hung
/// `tools/call` still fails the coverage job in single-digit seconds rather
/// than hanging it. The numeric match with [`COLD_START_TIMEOUT`] is a
/// coincidence of order, not a shared derivation, which is why this is its own
/// constant and not a reuse of that one.
///
/// **Known limit, stated because a widened timeout always looks like a fix.**
/// The #671 run timed out at 2 s, so how long the read would have taken is
/// unobserved — the same epistemic hole [`DETACHED_EXIT_TIMEOUT`] documents for
/// #638. A discrete intermittent stall in the `tools/call` path is *not*
/// excluded by anything measured here, and if that is what happened, this floor
/// masks it for stalls under 10 s and does not help at all beyond that. The
/// evidence for shipping it is a soak plus the scoping argument, not a
/// reproduced failure.
const INSTRUMENTED_READ_FLOOR: Duration = Duration::from_secs(10);

/// True when this test process was launched by `cargo llvm-cov`.
///
/// `cargo llvm-cov` exports [`LLVM_PROFILE_FILE_ENV`] into the test process,
/// which then inherits down to the spawned server binary — that inheritance is
/// how the child's own coverage is collected, and it was confirmed for this
/// harness rather than assumed: the binary `cargo_bin` resolves under
/// `target/llvm-cov-target/` carries `__llvm_prf_*` sections, and a single
/// `e2e_wire` run produced 63 `.profraw` files across parent and children.
fn coverage_instrumented() -> bool {
    std::env::var_os(LLVM_PROFILE_FILE_ENV).is_some()
}

/// Deadline to apply to one stdout read: the caller's `requested` budget,
/// widened to [`COLD_START_TIMEOUT`] while the child has not yet produced any
/// output, and to [`INSTRUMENTED_READ_FLOOR`] on the coverage arm.
///
/// Reads the ambient environment, so it is a thin wrapper over
/// [`read_deadline_for`], which holds the logic and the tests. Callers want the
/// wrapper; the unit tests want the pure function, because they themselves run
/// under `cargo llvm-cov` in the `SonarQube` job.
fn read_deadline(first_output_seen: bool, requested: Duration) -> Duration {
    read_deadline_for(first_output_seen, requested, coverage_instrumented())
}

/// The two graces, applied to `requested` independently.
///
/// `max` rather than a substitution, for both: chaos scenarios pass deadlines
/// well above either grace via `request_within` (15 s today), and shrinking
/// those would reintroduce the fast-fail cap they exist to escape. Composing
/// with `max` also means the graces stack correctly rather than one shadowing
/// the other — a first read on the coverage arm takes whichever is larger, not
/// whichever is checked last.
fn read_deadline_for(first_output_seen: bool, requested: Duration, instrumented: bool) -> Duration {
    let mut deadline = requested;
    if !first_output_seen {
        deadline = deadline.max(COLD_START_TIMEOUT);
    }
    if instrumented {
        deadline = deadline.max(INSTRUMENTED_READ_FLOOR);
    }
    deadline
}

/// Possible outcomes when probing the server for "either a
/// response or a close." Codex review finding #1 verified that
/// a simple `Option<String>` could not distinguish a panic
/// (stdout closed but child exited with non-zero status) from
/// an orderly shutdown — the malformed-input contract demands
/// that distinction, so this enum is required.
#[derive(Debug)]
pub enum CloseOrResponse {
    /// The server produced a line of output (newline-terminated).
    Response(String),
    /// EOF observed AND `child.wait()` returned exit code 0
    /// within `SHUTDOWN_TIMEOUT`. The server shut down
    /// cleanly. Harness is now poisoned (process reaped).
    CleanClose,
    /// EOF observed AND either: the child exited with a non-zero
    /// status, was killed by a signal, `child.wait()` itself
    /// errored, OR the child failed to exit within `SHUTDOWN_TIMEOUT`
    /// after stdout closed. The server crashed or got stuck post-
    /// EOF. Includes a diagnostic string with the precise sub-
    /// reason and captured stderr. Harness poisoned.
    Crashed(String),
    /// Stdout did NOT yield EOF AND no line arrived within the budget
    /// carried here. The server is hung or unresponsive. Harness poisoned.
    ///
    /// The budget is reported rather than left to the caller to name, because
    /// it is not always the `request_dur` the caller passed: a first read after
    /// spawn is widened to `COLD_START_TIMEOUT`, and on CI's coverage arm every
    /// read is floored at `INSTRUMENTED_READ_FLOOR`. A caller interpolating its
    /// own constant into the panic message would understate how long the server
    /// actually had — by 5x on the arm where that matters most.
    Hung(Duration),
}

/// Owns the spawned child plus its piped stdio.
pub struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    /// Path to the file capturing the child's stderr. Read on assertion
    /// failure so the binary's `tracing::error!` output surfaces in the
    /// panic message instead of being silently lost. Using a `File`-backed
    /// stdio target (rather than an async drain) avoids the runtime
    /// contention that made the prior `Stdio::piped()` capture hang every
    /// wire test on the 2-second `REQUEST_TIMEOUT` (see commit 3a58304).
    stderr_log: PathBuf,
    /// Out-of-order response envelopes parked here by `recv_until_id`
    /// when a response for a not-yet-awaited id arrives ahead of the
    /// one the caller is waiting for. Keyed by the JSON-RPC `id`
    /// (always a u64 in this harness because `next_id` is u64).
    buffered_responses: std::collections::VecDeque<(u64, Value)>,
    /// Set to true once the harness has observed an unrecoverable
    /// session state: stdout EOF, child exit (clean or crash),
    /// timeout where stdout is still open but the server is
    /// unresponsive, or schema validation failure on a parsed
    /// envelope. Once poisoned the harness MUST NOT be used for
    /// further requests. A future `is_usable` accessor (Task 6)
    /// will consult this flag for the proptest restart-on-close
    /// discipline. Codex review finding #2 verified the flag is
    /// necessary because a closed-stdout child may not yet be
    /// reaped, so `try_wait` alone is insufficient.
    poisoned: bool,
    /// False until the child has written its first byte to stdout. While
    /// false, response reads are widened to `COLD_START_TIMEOUT` because they
    /// are still paying for process start-up; once true every read runs on the
    /// caller's own budget so genuine hangs stay fast-fail. Start-up is a
    /// once-per-process cost, so it is charged to exactly one read. The
    /// coverage arm's `INSTRUMENTED_READ_FLOOR` is independent of this flag —
    /// it applies to every read, not just the first.
    first_output_seen: bool,
    // Hold the tempdir until the harness drops so the audit log path
    // remains valid for the lifetime of the spawned process.
    _tempdir: TempDir,
}

/// Suppress per-binary dead-code warnings on items consumed by some but not all
/// integration-test binaries. Each binary compiles this file independently; items
/// used by `mcp_wire_negative.rs` appear dead in `mcp_wire_conformance.rs` and
/// vice-versa. Referencing them here marks them as used in every compilation unit,
/// eliminating the need for `#[expect(dead_code)]` annotations that would fire as
/// "unfulfilled" in the binary that DOES call the item.
///
/// Mirrors the `force_use_for_dead_code_link` function in `schema.rs`.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code in binaries that don't call these items"
)]
fn force_use_for_dead_code_link() {
    // Harness::spawn: used by mcp_wire_conformance / e2e_wire / mcp_wire_negative /
    // mcp_wire_proptest, but not by mcp_audit_failure (which always uses
    // spawn_with_config to inject the env var).
    let _ = Harness::spawn;
    // CloseOrResponse and its associated methods: used by mcp_wire_negative,
    // unused by mcp_wire_conformance / e2e_wire. The inner String fields of
    // Response and Crashed must also be referenced to suppress the
    // "field `0` is never read" lint in binaries that don't pattern-match
    // on the enum.
    if let CloseOrResponse::Response(s) | CloseOrResponse::Crashed(s) =
        CloseOrResponse::Response(String::new())
    {
        let _ = s;
    }
    if let CloseOrResponse::Hung(budget) = CloseOrResponse::Hung(Duration::ZERO) {
        let _ = budget;
    }
    // Method used by mcp_wire_proptest, not by other binaries.
    let _ = Harness::is_usable;
    // Methods used by mcp_wire_negative, not by other binaries.
    let _ = Harness::response_or_close;
    let _ = Harness::send_line;
    // Method used by mcp_wire_negative (pre-initialize tests), not by
    // other binaries.
    let _ = Harness::audit_path;
    // Method used by mcp_wire_negative (pre-initialize write-failure
    // test), not by other binaries.
    let _ = Harness::spawn_with_closed_stdout;
    // DetachedStdoutHarness methods used by mcp_wire_negative, not by
    // other binaries. The pub `stdin` field is written by the
    // pre-initialize write-failure test only; reference it here so
    // every test-binary compilation sees it as used.
    let _ = DetachedStdoutHarness::audit_path;
    let _ = DetachedStdoutHarness::captured_stderr;
    let _ = DetachedStdoutHarness::wait_for_exit;
    let _ = |h: &DetachedStdoutHarness| {
        let _ = &h.stdin;
    };
    // Methods used by mcp_wire_negative and e2e_wire_cancellation, not
    // by other binaries.
    let _ = Harness::send_request_no_wait;
    let _ = Harness::recv_until_id;
    // No current callers in any binary — suppressed here for the same
    // per-binary dead-code reason.
    let _ = Harness::recv_line_within;
    // Method used by mcp_wire_conformance and e2e_wire_cancellation,
    // not by other binaries.
    let _ = Harness::assert_no_response_within;
    // Method used by mcp_wire_conformance and e2e_wire, not by
    // mcp_wire_negative.
    let _ = Harness::shutdown_and_wait;
    // JSON-RPC session drivers used by every wire binary that reaches the
    // serve loop, but NOT by e2e_wire_tls_pin_mismatch — a pin mismatch fails
    // the boot closed, so that binary spawns the child and reaps its exit
    // status without ever sending `initialize` or a request.
    let _ = Harness::request;
    let _ = Harness::request_within;
    let _ = Harness::notify;
    let _ = Harness::initialize_handshake;
    let _ = Harness::send_initialized;
    // Constant used by mcp_wire_conformance / e2e_wire, not by mcp_wire_negative.
    let _ = PINNED_PROTOCOL_VERSION;
}

impl Harness {
    /// Spawn with the legacy zero-account config (Phase 1 default).
    /// Builds a multi-account TOML with `accounts = []`, an audit
    /// path under a fresh tempdir, and calls `spawn_with_config`.
    pub async fn spawn() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();
        let config = format!(
            r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");
        Self::spawn_with_config(&config_path, tempdir, &[]).await
    }

    /// Spawn the binary against a caller-supplied config. The
    /// `tempdir` is held by the returned `Harness` so its lifetime
    /// covers the child process's audit path.
    ///
    /// `extra_envs` is forwarded to the child verbatim. Phase 3 uses
    /// this to inject `RUSTY_IMAP_MCP_PASSWORD` (the env-var
    /// fallback for the keyring) without polluting the test
    /// process's env.
    #[expect(clippy::unused_async, reason = "uniform async surface")]
    pub async fn spawn_with_config(
        config_path: &std::path::Path,
        tempdir: TempDir,
        extra_envs: &[(&str, &str)],
    ) -> Self {
        let stderr_log = tempdir.path().join("rusty-imap-mcp.stderr.log");
        let stderr_file = File::create(&stderr_log).expect("create stderr log file");

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true);
        for (k, v) in extra_envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));

        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            stderr_log,
            buffered_responses: std::collections::VecDeque::new(),
            poisoned: false,
            first_output_seen: false,
            _tempdir: tempdir,
        }
    }

    /// Spawn the binary with the legacy zero-account config, then
    /// immediately drop the `BufReader<ChildStdout>` read handle. The
    /// child's stdout pipe write end is now connected to a closed
    /// reader; the next write the server attempts will fail with
    /// `BrokenPipe`. Used by `pre_initialize_envelope_write_failure`
    /// to exercise the propagated-error path on transport failure.
    #[expect(clippy::unused_async, reason = "uniform async surface")]
    pub async fn spawn_with_closed_stdout() -> DetachedStdoutHarness {
        // Before the tempdir, so `setup_began` covers every parent-side item
        // the #638 log lumped in with the child's lifetime.
        let setup_began = Instant::now();
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();
        let config = format!(
            r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");

        let stderr_log = tempdir.path().join("rusty-imap-mcp.stderr.log");
        let stderr_file = File::create(&stderr_log).expect("create stderr log file");

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        // Take the read end of the stdout pipe and drop it immediately.
        // The child's write end is now connected to a closed reader.
        let stdout = child.stdout.take().expect("stdout");
        drop(stdout);

        DetachedStdoutHarness {
            child,
            stdin,
            stderr_log,
            audit_path,
            setup_began,
            _tempdir: tempdir,
        }
    }

    /// Returns true if the harness can be used for another request:
    /// the child process is still running AND the harness has not
    /// observed an unrecoverable session state (EOF, crash, hang,
    /// schema-validation failure on a parsed envelope). Codex
    /// review finding #2 verified that `try_wait` alone is
    /// insufficient — a child whose stdout closed but whose process
    /// has not yet been reaped would otherwise pass the "alive"
    /// check while subsequent reads return EOF immediately.
    ///
    /// Always check this before reusing a harness across cases.
    /// The proptest restart-on-close discipline (this task)
    /// consults it; if false, the helper drops the poisoned
    /// harness and spawns a fresh one.
    pub fn is_usable(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_status)) => {
                self.poisoned = true;
                false
            }
            Err(_) => {
                self.poisoned = true;
                false
            }
        }
    }

    /// Read whatever the child has written to its stderr log so far.
    /// Used in assertion diagnostics; tolerates a missing or unreadable
    /// file (returns an empty string) so callers can rely on it inside
    /// panic messages.
    pub fn captured_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }

    /// Path to the audit log file for this harness. Used by tests
    /// that need to read `process_end` records post-shutdown.
    #[expect(
        clippy::used_underscore_binding,
        reason = "the leading underscore on `_tempdir` is a visual convention to flag that the \
                  field is held purely for its drop guard; this accessor exposes its path on \
                  purpose so audit-log assertions can read the file before the guard drops"
    )]
    pub fn audit_path(&self) -> std::path::PathBuf {
        self._tempdir.path().join("audit.jsonl")
    }

    /// Read exactly one parsed envelope from stdout under the default 2s
    /// `REQUEST_TIMEOUT` — subject to both widenings in [`read_deadline`].
    /// Shared by `request` and `recv_until_id`.
    async fn read_one_envelope(&mut self, caller: &str) -> Value {
        self.read_one_envelope_within(caller, REQUEST_TIMEOUT).await
    }

    /// Read exactly one parsed envelope from stdout, bounding the read by
    /// `read_timeout` — widened to `COLD_START_TIMEOUT` if the child has not
    /// produced any output yet, and to `INSTRUMENTED_READ_FLOOR` on CI's
    /// coverage arm. Skips notifications (which have a `method` and
    /// absent/null `id`) but does NOT skip responses; returns the first
    /// response observed. Panics on timeout, EOF, or parse failure with stderr
    /// included in the diagnostic.
    ///
    /// The deadline is resolved once, before the notification-skipping loop, so
    /// a start-up notification arriving ahead of the response cannot consume
    /// the cold-start grace and leave the response itself on the tight budget.
    async fn read_one_envelope_within(&mut self, caller: &str, read_timeout: Duration) -> Value {
        let read_timeout = read_deadline(self.first_output_seen, read_timeout);
        loop {
            let mut buf = String::new();
            let read_result = timeout(read_timeout, self.stdout.read_line(&mut buf)).await;
            self.first_output_seen |= read_result.is_ok();
            let read = match read_result {
                Ok(io_result) => io_result.unwrap_or_else(|e| {
                    panic!(
                        "read response error on {caller}: {e}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )
                }),
                Err(elapsed) => panic!(
                    "response to {caller} did not arrive within {read_timeout:?} ({elapsed})\n\
                     --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                ),
            };
            assert!(
                read > 0,
                "stdout closed before responding to {caller}\n\
                 --- captured child stderr ---\n{}",
                self.captured_stderr(),
            );
            let envelope: Value = serde_json::from_str(buf.trim_end()).unwrap_or_else(|e| {
                panic!(
                    "failed to parse envelope JSON from server on {caller}: {e}\n\
                         raw line: {buf:?}\n\
                         --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                )
            });
            let is_notification =
                envelope.get("method").is_some() && envelope.get("id").is_none_or(Value::is_null);
            if is_notification {
                assert_eq!(
                    envelope["jsonrpc"],
                    json!("2.0"),
                    "notification must declare jsonrpc=\"2.0\"; got {envelope}",
                );
                continue;
            }
            return envelope;
        }
    }

    /// Send a JSON-RPC request and return the parsed response value, bounding the
    /// response read by the shared [`REQUEST_TIMEOUT`] — or by
    /// [`COLD_START_TIMEOUT`] if this is the first read after spawn, which is
    /// still paying for process start-up, or by [`INSTRUMENTED_READ_FLOOR`] when
    /// running under coverage. Panics on timeout, EOF before a response arrives,
    /// or non-JSON output.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        self.request_within(method, params, REQUEST_TIMEOUT).await
    }

    /// Like `request`, but bounds the response read by `deadline` instead of the
    /// shared 2s `REQUEST_TIMEOUT`. For chaos scenarios whose server-side timeout
    /// budget (connect/command) is >= 2s and would otherwise trip the fast-fail
    /// cap — used for both the fault call and reconnect-bearing recovery calls.
    ///
    /// A `deadline` below [`COLD_START_TIMEOUT`] is still widened to it on the
    /// first read after spawn, and one below [`INSTRUMENTED_READ_FLOOR`] is
    /// widened to that under coverage; larger ones are passed through
    /// untouched, which is the case these callers rely on. The 15 s the chaos
    /// scenarios pass today clears both graces, so they are unaffected by
    /// either.
    pub async fn request_within(
        &mut self,
        method: &str,
        params: Value,
        deadline: Duration,
    ) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");

        let envelope = self.read_one_envelope_within(method, deadline).await;
        assert_eq!(envelope["id"], json!(id), "response id must match request");
        super::schema::assert_envelope_valid(&envelope);
        envelope
    }

    /// Send a JSON-RPC request and return the assigned id WITHOUT
    /// awaiting a response. Pair with `recv_until_id` to drive
    /// multiple in-flight requests deterministically.
    pub async fn send_request_no_wait(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");
        id
    }

    /// Drain stdout (skipping notifications) until a response envelope
    /// with `id == target` arrives. Out-of-order responses for other
    /// requests already in flight are buffered and can be retrieved by
    /// later `recv_until_id` calls. Panics if the response envelope
    /// fails schema validation.
    pub async fn recv_until_id(&mut self, target: u64) -> Value {
        // Fast path: target already buffered.
        if let Some(pos) = self
            .buffered_responses
            .iter()
            .position(|(id, _)| *id == target)
        {
            let (_, env) = self.buffered_responses.remove(pos).expect("indexed");
            super::schema::assert_envelope_valid(&env);
            return env;
        }
        // Slow path: read until we see target, parking other ids.
        loop {
            let envelope = self
                .read_one_envelope(&format!("recv_until_id({target})"))
                .await;
            let id = envelope["id"].as_u64().unwrap_or_else(|| {
                panic!("response envelope missing numeric id while awaiting {target}: {envelope}")
            });
            if id == target {
                super::schema::assert_envelope_valid(&envelope);
                return envelope;
            }
            self.buffered_responses.push_back((id, envelope));
        }
    }

    /// Probe-based contract helper: within `request_dur`, observe
    /// one of `Response`/`CleanClose`/`Crashed`/`Hung`. On any
    /// non-`Response` outcome, the harness is marked `poisoned`
    /// so the restart-on-close discipline (Task 6) won't reuse it.
    /// Callers MUST `match` the result; `_` matches are a code-
    /// review failure because they re-introduce the original
    /// Option-shaped bug.
    pub async fn response_or_close(&mut self, request_dur: Duration) -> CloseOrResponse {
        let request_dur = read_deadline(self.first_output_seen, request_dur);
        let mut buf = String::new();
        let read = timeout(request_dur, self.stdout.read_line(&mut buf)).await;
        self.first_output_seen |= read.is_ok();
        match read {
            Ok(Ok(0)) => {
                // EOF. Verify the child exited cleanly within
                // SHUTDOWN_TIMEOUT and distinguish CleanClose from Crashed.
                self.poisoned = true;
                let wait = timeout(SHUTDOWN_TIMEOUT, self.child.wait()).await;
                match wait {
                    Ok(Ok(status)) if status.success() => CloseOrResponse::CleanClose,
                    Ok(Ok(status)) => CloseOrResponse::Crashed(format!(
                        "{status:?}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                    Ok(Err(e)) => CloseOrResponse::Crashed(format!(
                        "child.wait() error: {e}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                    Err(_elapsed) => CloseOrResponse::Crashed(format!(
                        "child did not exit within {SHUTDOWN_TIMEOUT:?} after EOF\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                }
            }
            Ok(Ok(_)) => CloseOrResponse::Response(buf),
            Ok(Err(e)) => {
                self.poisoned = true;
                CloseOrResponse::Crashed(format!(
                    "read error while waiting for response-or-close: {e}\n\
                     --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                ))
            }
            Err(_elapsed) => {
                self.poisoned = true;
                CloseOrResponse::Hung(request_dur)
            }
        }
    }

    /// Send a JSON-RPC notification (no `id`, no response expected).
    pub async fn notify(&mut self, method: &str, params: Value) {
        let envelope = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write notification");
        self.stdin.flush().await.expect("flush notification");
    }

    /// Write arbitrary bytes to the child's stdin verbatim. No newline
    /// is appended; the caller is responsible for framing. Used by
    /// fuzz / malformed-input tests that need to send bytes the
    /// normal `request` / `notify` API would reject.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).await.expect("write raw bytes");
        self.stdin.flush().await.expect("flush raw bytes");
    }

    /// Convenience wrapper: write `line` followed by `\n`. The
    /// `line` itself MUST NOT contain a `\n` (MCP framing is one
    /// JSON envelope per line; embedded newlines would split the
    /// envelope across lines).
    pub async fn send_line(&mut self, line: &str) {
        assert!(
            !line.contains('\n'),
            "send_line: caller-supplied content must not contain a newline; got {line:?}",
        );
        let mut framed = String::with_capacity(line.len() + 1);
        framed.push_str(line);
        framed.push('\n');
        self.send_raw(framed.as_bytes()).await;
    }

    /// Read one line of stdout under `dur`. Returns `Some(line)` on
    /// success, `None` if `dur` elapsed before a newline arrived OR
    /// the child closed stdout. Unlike `request`, this does NOT parse
    /// or validate the line; fuzz tests use it to observe whatever
    /// the server actually emitted (which may be malformed by design).
    ///
    /// The returned string retains the trailing `\n`. Callers that
    /// need to parse or compare the payload should strip it via
    /// `line.trim_end_matches('\n')` or `line.trim_end()`.
    pub async fn recv_line_within(&mut self, dur: Duration) -> Option<String> {
        let mut buf = String::new();
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => None, // EOF, I/O error, or timeout
            Ok(Ok(_)) => Some(buf),              // line read; buf ends with '\n'
        }
    }

    /// Assert no bytes arrive on stdout for the given duration.
    ///
    /// Bypasses [`read_deadline`] on purpose: this is a negative assertion, so
    /// the coverage arm's floor would only make it wait longer to prove the
    /// same thing. Instrumentation delays responses, which can only make an
    /// "expected nothing" window easier to satisfy, never harder.
    pub async fn assert_no_response_within(&mut self, dur: Duration) {
        let mut buf = String::new();
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Err(_) => {} // timeout → no response, as expected
            Ok(Ok(0)) => panic!("stdout closed unexpectedly"),
            Ok(Ok(_)) => panic!("expected no response within {dur:?}, got: {buf:?}"),
            Ok(Err(e)) => panic!("read error: {e}"),
        }
    }

    /// Send an MCP `initialize` request with the pinned protocol
    /// version and return the response.
    pub async fn initialize_handshake(&mut self) -> Value {
        self.request(
            "initialize",
            json!({
                "protocolVersion": ProtocolVersion::LATEST.as_str(),
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-conformance-harness",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }),
        )
        .await
    }

    /// Send `notifications/initialized` after the handshake.
    pub async fn send_initialized(&mut self) {
        self.notify("notifications/initialized", json!({})).await;
    }

    /// Close stdin, await the child, and hand the audit-log tempdir
    /// back to the caller along with the exit status.
    ///
    /// The tempdir is kept alive only by the returned [`TempDir`] guard
    /// — once it drops, the audit log path becomes invalid. Callers
    /// that need to read the audit file after shutdown must bind the
    /// returned `TempDir` to a variable that outlives those reads.
    /// Callers that only care about the exit status can drop the
    /// tempdir immediately with `let (status, _) = ...`.
    pub async fn shutdown_and_wait(self) -> (std::process::ExitStatus, TempDir) {
        let Self {
            mut child,
            stdin,
            stdout: _,
            next_id: _,
            stderr_log: _,
            buffered_responses: _,
            poisoned: _,
            first_output_seen: _,
            _tempdir: tempdir,
        } = self;
        drop(stdin);
        let status = timeout(SHUTDOWN_TIMEOUT, child.wait())
            .await
            .expect("clean exit within timeout")
            .expect("wait");
        (status, tempdir)
    }
}

/// Lightweight harness variant used by transport-failure regression
/// tests that intentionally close the server's stdout read end before
/// sending input. The server's pre-initialize envelope write will
/// fail with `BrokenPipe`. This struct cannot read stdout responses;
/// it exists only to drive stdin, wait for the child exit, and read
/// the resulting audit log + captured stderr.
pub struct DetachedStdoutHarness {
    child: Child,
    pub stdin: ChildStdin,
    stderr_log: PathBuf,
    audit_path: PathBuf,
    // Start of `spawn_with_closed_stdout`, i.e. before the tempdir, config
    // write, `cargo_bin` resolution and `Command::spawn`. Read on the
    // `wait_for_exit` timeout path to separate that parent-side setup from the
    // budgeted wait — #638 was hard to attribute precisely because the failing
    // run reported one wall-clock number covering both.
    setup_began: Instant,
    // Held until drop so the audit log path stays valid.
    _tempdir: TempDir,
}

impl DetachedStdoutHarness {
    /// Path to the audit log produced by the spawned binary.
    pub fn audit_path(&self) -> &std::path::Path {
        &self.audit_path
    }

    /// Read the captured stderr file. Empty string on read failure.
    pub fn captured_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }

    /// Await the child's exit on the whole-lifetime budget
    /// ([`DETACHED_EXIT_TIMEOUT`]) and return its status.
    ///
    /// The wait lives here rather than at the call site so the budget is chosen
    /// next to the rationale for its size — a caller reaching for a bare
    /// `timeout(.., child.wait())` has no way to see that this harness has no
    /// readiness handshake and so pays start-up inside the exit wait.
    ///
    /// Panics if the child has not exited within the budget (a genuine hang) or
    /// if the wait itself fails, reporting captured stderr either way.
    ///
    /// The timeout message separates the budgeted wait from the parent-side
    /// setup that precedes it, because the budget starts here — at the call —
    /// not at spawn. #638's log conflated the two, which is what made the
    /// failure read as an 8.8 s child lifetime when 5 s of it was the elapsed
    /// timeout; see [`DETACHED_EXIT_TIMEOUT`] for why the remainder is
    /// unattributed.
    pub async fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let wait_began = Instant::now();
        let waited = timeout(DETACHED_EXIT_TIMEOUT, self.child.wait()).await;
        let setup = wait_began.saturating_duration_since(self.setup_began);
        let Ok(reaped) = waited else {
            panic!(
                "child did not exit within {DETACHED_EXIT_TIMEOUT:?} of the exit wait; \
                 harness setup and the request write took {setup:?} before it\n\
                 --- captured stderr ---\n{}",
                self.captured_stderr(),
            );
        };
        // Record the distribution on the success path too. The budget was
        // widened here without the exit wait ever having been measured on a
        // failing run (#638 timed out, so it observed only a lower bound); this
        // is the number that says whether 15 s is generous, marginal, or hiding
        // a real server-side stall.
        //
        // This line does NOT appear in an ordinary run. `nextest` captures a
        // passing test's stderr and then drops it under its `success-output =
        // "never"` default, which `--profile ci` inherits and
        // `.config/nextest.toml` does not override. #660 must therefore collect
        // the distribution with an explicit run:
        //
        //   cargo nextest run -p rimap-server \
        //     -E 'binary(mcp_wire_negative)' --success-output final
        //
        // The timeout path does not reach here at all — it panics above, and
        // that panic carries the budget and the setup prefix instead.
        #[expect(
            clippy::print_stderr,
            reason = "budget calibration measurement collected by #660"
        )]
        {
            eprintln!(
                "detached child exited after {:?} of exit wait ({setup:?} of setup before it, \
                 budget {DETACHED_EXIT_TIMEOUT:?})",
                wait_began.elapsed(),
            );
        }
        reaped.unwrap_or_else(|err| {
            panic!(
                "wait for child exit failed: {err}\n\
                 --- captured stderr ---\n{}",
                self.captured_stderr(),
            )
        })
    }
}

#[cfg(test)]
mod read_deadline_tests {
    use super::{
        COLD_START_TIMEOUT, Duration, INSTRUMENTED_READ_FLOOR, REQUEST_TIMEOUT,
        coverage_instrumented, read_deadline, read_deadline_for,
    };

    /// Every case below drives [`read_deadline_for`] with an explicit
    /// `instrumented` argument rather than [`read_deadline`], which reads the
    /// ambient environment. That is not stylistic: CI's `SonarQube` job runs
    /// this very unit test under `cargo llvm-cov`, so an assertion keyed off
    /// the env-reading wrapper would flip its expected value depending on
    /// which job ran it. Only `wiring_matches_the_detected_environment` below
    /// touches the wrapper, and it asserts agreement rather than a value.
    const UNINSTRUMENTED: bool = false;
    const INSTRUMENTED: bool = true;

    /// The flake in #621: the first read after spawn pays for process
    /// start-up, so it must not run on the steady-state budget.
    #[test]
    fn first_read_is_widened_to_the_cold_start_budget() {
        assert_eq!(
            read_deadline_for(false, REQUEST_TIMEOUT, UNINSTRUMENTED),
            COLD_START_TIMEOUT,
            "the first read after spawn must get the cold-start grace",
        );
    }

    /// The other half of the split: once the child has spoken, start-up is
    /// paid for and a genuine hang must still fail fast.
    #[test]
    fn later_reads_keep_the_callers_budget() {
        assert_eq!(
            read_deadline_for(true, REQUEST_TIMEOUT, UNINSTRUMENTED),
            REQUEST_TIMEOUT,
            "the grace is a once-per-process cost, not a blanket increase",
        );
    }

    /// Chaos scenarios pass deadlines above the grace through
    /// `request_within`; widening must never shrink one, in either state.
    #[test]
    fn a_larger_caller_budget_is_never_shrunk() {
        let chaos = COLD_START_TIMEOUT + Duration::from_secs(20);
        assert_eq!(read_deadline_for(false, chaos, UNINSTRUMENTED), chaos);
        assert_eq!(read_deadline_for(true, chaos, UNINSTRUMENTED), chaos);
        assert_eq!(read_deadline_for(false, chaos, INSTRUMENTED), chaos);
        assert_eq!(read_deadline_for(true, chaos, INSTRUMENTED), chaos);
    }

    /// #671: on the coverage arm a steady-state read gets the instrumented
    /// floor, because that arm's whole cost profile — not just instrumentation
    /// — differs from the uninstrumented one.
    #[test]
    fn steady_reads_get_the_instrumented_floor_on_the_coverage_arm() {
        assert_eq!(
            read_deadline_for(true, REQUEST_TIMEOUT, INSTRUMENTED),
            INSTRUMENTED_READ_FLOOR,
            "a tools/call under coverage must not run on the bare 2s budget",
        );
    }

    /// The half of #671 that matters most: the floor is scoped to the arm that
    /// flaked. An uninstrumented steady-state read keeps the tight fast-fail
    /// budget, so a real hang still fails in 2s on `test (stable)`.
    #[test]
    fn the_floor_does_not_loosen_the_uninstrumented_case() {
        assert_eq!(
            read_deadline_for(true, REQUEST_TIMEOUT, UNINSTRUMENTED),
            REQUEST_TIMEOUT,
            "the instrumented floor must not leak into the uninstrumented arm",
        );
        assert!(
            REQUEST_TIMEOUT < INSTRUMENTED_READ_FLOOR,
            "the floor is only meaningful if it is above the bare budget",
        );
    }

    /// The two graces compose rather than override: the first read on the
    /// coverage arm pays start-up *and* the arm's tail, so it must clear both
    /// lower bounds.
    ///
    /// Asserted as two bounds rather than against
    /// `COLD_START_TIMEOUT.max(INSTRUMENTED_READ_FLOOR)`, which would only
    /// restate the implementation — and, while both constants sit at 10 s,
    /// would hold even if one grace overrode the other. These bounds keep
    /// biting if either constant moves.
    #[test]
    fn the_cold_start_grace_and_the_floor_compose() {
        let deadline = read_deadline_for(false, REQUEST_TIMEOUT, INSTRUMENTED);
        assert!(
            deadline >= COLD_START_TIMEOUT,
            "the first instrumented read must still cover process start-up; \
             got {deadline:?}",
        );
        assert!(
            deadline >= INSTRUMENTED_READ_FLOOR,
            "the first instrumented read must still clear the coverage-arm \
             floor; got {deadline:?}",
        );
    }

    /// Pins the wrapper to the pure function without asserting a value, so
    /// this case holds under either CI arm. Without it, nothing checks that
    /// `read_deadline` actually consults `coverage_instrumented()` — the two
    /// could drift apart and every other case here would still pass.
    #[test]
    fn wiring_matches_the_detected_environment() {
        for first_output_seen in [false, true] {
            assert_eq!(
                read_deadline(first_output_seen, REQUEST_TIMEOUT),
                read_deadline_for(first_output_seen, REQUEST_TIMEOUT, coverage_instrumented()),
                "read_deadline must be read_deadline_for under the detected environment",
            );
        }
    }
}
