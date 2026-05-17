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
use std::time::Duration;

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

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
// Under `cargo nextest run` with the full workspace suite (~1100 tests
// in parallel), the EOF-to-exit slice for `wire_clean_eof_shutdown_exits_zero`
// can exceed a tight 1 s budget on CPU-contended runners. 5 s remains
// tight enough to fail-fast on a real hang while absorbing scheduling
// jitter when other tests are spawning binaries / parsers concurrently.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Stdout did NOT yield EOF AND no line arrived within
    /// `request_dur`. The server is hung or unresponsive.
    /// Harness poisoned.
    Hung,
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
    // other binaries. The pub `child` / `stdin` fields are read by the
    // pre-initialize write-failure test only; reference them here so
    // every test-binary compilation sees them as used.
    let _ = DetachedStdoutHarness::audit_path;
    let _ = DetachedStdoutHarness::captured_stderr;
    let _ = |h: &DetachedStdoutHarness| {
        let _ = &h.child;
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

    /// Read exactly one parsed envelope from stdout. Skips
    /// notifications (which have a `method` and absent/null `id`) but
    /// does NOT skip responses; returns the first response observed.
    /// Panics on timeout, EOF, or parse failure with stderr included
    /// in the diagnostic. Shared by `request` and `recv_until_id`.
    async fn read_one_envelope(&mut self, caller: &str) -> Value {
        loop {
            let mut buf = String::new();
            let read_result = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf)).await;
            let read = match read_result {
                Ok(io_result) => io_result.unwrap_or_else(|e| {
                    panic!(
                        "read response error on {caller}: {e}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )
                }),
                Err(elapsed) => panic!(
                    "response to {caller} did not arrive within {REQUEST_TIMEOUT:?} ({elapsed})\n\
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

    /// Send a JSON-RPC request and return the parsed response value.
    /// Panics on timeout, EOF before a response arrives, or non-JSON output.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
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

        let envelope = self.read_one_envelope(method).await;
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
        let mut buf = String::new();
        let read = timeout(request_dur, self.stdout.read_line(&mut buf)).await;
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
                CloseOrResponse::Hung
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
    pub child: Child,
    pub stdin: ChildStdin,
    stderr_log: PathBuf,
    audit_path: PathBuf,
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
}
