//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

use rimap_server::boot::{audit_init, logging, registry};
use rimap_server::mcp::server;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::FromArgMatches;
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::ConfigError;
use rimap_config::credential::{CredentialStore, KeyringStore, Protocol};
use rimap_config::loader::{load_and_validate, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_imap::Connection;
use rmcp::model::ErrorCode as McpErrorCode;
use rmcp::service::ServerInitializeError;
use secrecy::ExposeSecret;
use tokio::io::AsyncWriteExt;

use rimap_server::cli::{self, AuditAction, Cli, Command};

fn parse_cli() -> Result<Cli, clap::Error> {
    let matches = cli::command().get_matches();
    Cli::from_arg_matches(&matches)
}

fn main() -> ExitCode {
    logging::init();
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(e) => {
            e.exit();
        }
    };
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            emit_startup_error(&e);
            ExitCode::FAILURE
        }
    }
}

/// Report a startup failure and return exit failure.
///
/// A missing config file on first launch is an operator setup problem, not a
/// server fault, so it bypasses the `tracing` subscriber — whose output GUI
/// and stdio MCP clients routinely discard or bury — and writes clean,
/// actionable setup guidance directly to stderr. Every other error keeps the
/// structured `tracing::error!` path. stdout is never touched: it is reserved
/// for the MCP transport.
fn emit_startup_error(err: &anyhow::Error) {
    if let Some(ConfigError::NotFound { path }) = err.downcast_ref::<ConfigError>() {
        // stderr is unbuffered; a failed write has nowhere left to go, so drop it.
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "{}", format_missing_config_guidance(path));
    } else {
        tracing::error!("{err:#}");
    }
}

/// Compose the first-run "no config file" guidance: name the resolved path and
/// point the operator at the annotated example config and the provider
/// quickstart guides. Pure and newline-terminated so callers only `write!` it.
fn format_missing_config_guidance(path: &std::path::Path) -> String {
    format!(
        "No configuration file was found at:\n    \
         {path}\n\n\
         Create one to get started. See the annotated example configuration and \
         the quickstart guide for your provider:\n    \
         config.example.toml               - annotated example configuration\n    \
         docs/quickstart-gmail.md          - Gmail setup\n    \
         docs/quickstart-proton-bridge.md  - Proton Mail Bridge setup\n\n\
         You can point at a different location with --config <PATH> or the \
         RUSTY_IMAP_MCP_CONFIG environment variable.\n",
        path = path.display(),
    )
}

/// Disambiguates the failure source of the init-phase `tokio::select!`
/// in `serve_mcp`: either a validator bridge errored before init
/// completed, or rmcp's `serve_server` returned an init failure. `Rmcp`
/// is boxed because `ServerInitializeError` is significantly larger than
/// the `io::Result<()>` variant (`clippy::large_enum_variant`).
enum InitOutcome {
    Bridge(std::io::Result<()>),
    Rmcp(Box<ServerInitializeError>),
}

/// Everything `serve_mcp` hands back to `run_server`.
///
/// The transport result cannot carry the drain residue on its own: `run_server`
/// consumes it twice — once as [`emit_process_end`]'s input and once as its own
/// return value — and the count has to reach `process_end` on *both* arms,
/// because a run that failed still drained. Folding the count into the `Ok`
/// variant would drop it exactly where a residue matters most (#680).
///
/// A named struct rather than a `(Result, u64)` tuple: the count is a bare
/// integer built at three exits, and a tuple offers nothing that catches one
/// assembled in the wrong order.
struct ServeOutcome {
    /// Outcome of the MCP transport, and `run_server`'s return value.
    result: anyhow::Result<()>,
    /// Registrations still outstanding when the dispatch drain's budget
    /// expired. Zero on every clean shutdown, and measured rather than assumed
    /// on every exit path — see [`drain_dispatches`].
    undrained_dispatches: u64,
}

/// How long `serve_mcp` waits for in-flight tool dispatches to unwind after
/// cancelling them. They are cancelled, not merely awaited, so the wait covers
/// only the unwind — a synchronous `AuthEmitGuard` audit write and its `fsync`,
/// plus any `spawn_blocking` call that has to return before its task can be
/// polled again. Two seconds is well clear of that and still an order of
/// magnitude below the point an operator would call the exit hung.
const DISPATCH_DRAIN_BUDGET: Duration = Duration::from_secs(2);

/// How long `serve_mcp` waits for the cancellation drainer to finish after the
/// dispatch drain. On the clean path every cancellation sender is already gone
/// and the join returns at once; the bound only matters when the dispatch drain
/// timed out, because a dispatch still holding a sender would otherwise keep
/// the join — and so the whole process exit — waiting for that command's own
/// timeout (#645).
const DRAINER_JOIN_BUDGET: Duration = Duration::from_secs(1);

/// The dispatch drain's budget for this process.
///
/// Under `test-support` only, `RIMAP_TEST_DISPATCH_DRAIN_BUDGET_MS` shortens it.
/// A non-zero `process_end.undrained_dispatches` is otherwise unreachable from
/// the wire — every dispatch a test can park is cancellable and unwinds well
/// inside two seconds — so without this lever the suite that pins the count
/// would only ever observe zero, which is the vacuous case. Same shape and same
/// gating as `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE`; a malformed value is
/// ignored in favour of the production budget.
fn dispatch_drain_budget() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = std::env::var("RIMAP_TEST_DISPATCH_DRAIN_BUDGET_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    DISPATCH_DRAIN_BUDGET
}

/// Cancel every in-flight tool dispatch, wait out the drain budget, and report
/// the residue.
///
/// Called on every exit from [`serve_mcp`], including the init-failure paths
/// that never reached a dispatch: an idle drain returns `0` without parking, so
/// the zero those paths record is measured rather than assumed. That matters
/// because `ProcessEnd::new` treats a zero as an affirmative durable claim.
async fn drain_dispatches(dispatch_drain: &server::DispatchDrain) -> u64 {
    let budget = dispatch_drain_budget();
    let undrained = dispatch_drain.shutdown(budget).await;
    if undrained > 0 {
        tracing::warn!(
            undrained,
            budget = ?budget,
            "tool dispatches outlived the shutdown drain; any audit record they \
             still write is sequenced after process_end or lost",
        );
    }
    // Lossless on every supported target: `usize` is at most 64 bits.
    u64::try_from(undrained).unwrap_or(u64::MAX)
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    if let Some(result) = dispatch_subcommand(cli) {
        return result;
    }
    run_server(cli)
}

/// Route the non-server invocations. Returns `Some(result)` when a
/// subcommand or `--dry-run` handled the request; `None` when the caller
/// should fall through and start the MCP server.
fn dispatch_subcommand(cli: &Cli) -> Option<anyhow::Result<()>> {
    if let Some(Command::Login {
        account,
        host,
        username,
    }) = &cli.command
    {
        return Some(run_login_command(account, username, host));
    }

    if let Some(Command::MigrateKeyring {
        account,
        host,
        username,
    }) = &cli.command
    {
        return Some(run_migrate_keyring(account, username, host));
    }

    if let Some(Command::Audit {
        action:
            AuditAction::Merge {
                path,
                since,
                until,
                tool,
                kind,
                process,
                account,
            },
    }) = &cli.command
    {
        return Some(cli::audit_merge::run(
            path,
            cli::audit_merge::RunArgs {
                since: since.as_deref(),
                until: until.as_deref(),
                tool: tool.as_deref(),
                kind: kind.as_deref(),
                process: process.as_deref(),
                account: account.as_deref(),
            },
        ));
    }

    #[cfg(feature = "test-support")]
    if let Some(result) = run_test_support_subcommands(cli) {
        return Some(result);
    }

    if cli.dry_run {
        return Some(run_dry_run(cli));
    }

    None
}

/// Execute `--dry-run`: validate the config and print the resolved plan.
fn run_dry_run(cli: &Cli) -> anyhow::Result<()> {
    let path = resolve_cli_config_path(cli)?;
    let mut stdout = std::io::stdout().lock();
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(cli::dry_run::run(&path, &mut stdout))
}

/// Assemble the server subsystems and own the tokio runtime lifecycle.
/// Loading, audit-writer and credential wiring live here; the
/// load-bearing transport choreography is delegated to [`serve_mcp`].
fn run_server(cli: &Cli) -> anyhow::Result<()> {
    let config_path = resolve_cli_config_path(cli)?;
    let multi = load_validated_multi(cli, &config_path)?;
    let audit = audit_init::init_audit_writer_multi(&multi, &config_path)
        .with_context(|| format!("opening audit log at {}", multi.audit.path.display()))?;

    #[cfg(feature = "test-support")]
    maybe_arm_audit_write_failure(&audit);

    let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    let download_dir: Arc<std::path::Path> =
        Arc::from(resolve_download_dir_multi(&multi)?.into_boxed_path());

    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;

    let ServeOutcome {
        result: mcp_result,
        undrained_dispatches,
    } = rt.block_on(serve_mcp(&multi, &audit, &credentials, &download_dir));

    emit_process_end(&audit, &mcp_result, undrained_dispatches);

    // Shut down the runtime without waiting for blocking tasks. The
    // validator's `validate_inbound` bridge owns a `tokio::io::stdin()`
    // handle whose underlying blocking read of real stdin is
    // uncancelable (per tokio docs, `spawn_blocking` tasks cannot be
    // aborted). The implicit `Runtime::drop` would otherwise block
    // forever waiting for that read to return on a client that
    // legitimately keeps stdin open after the server has decided to
    // shut down — the regression observed when the #277 envelope
    // validator wraps stdio. Using `shutdown_background` makes the
    // process exit promptly; pending blocking reads are abandoned and
    // the OS reaps the threads when the process terminates.
    rt.shutdown_background();

    mcp_result
}

/// Build the account registry, wrap stdio with the #277 envelope
/// validator, and drive the two-phase init/serve race against the
/// validator bridges. The `select!` / `drop` / dispatch-drain /
/// supervisor-shutdown / drainer-join ordering here is load-bearing
/// (#277, #645) and must not be reordered. In particular the whole
/// function must complete before `run_server` writes `process_end`,
/// which is what makes that record terminal (see `docs/audit-log.md`
/// and ADR-0015).
///
/// Returns a [`ServeOutcome`] rather than a bare `Result` so the drain's
/// residue reaches `process_end` on the error path too (#680).
async fn serve_mcp(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> ServeOutcome {
    // Before the drain exists there is nothing to report, so a registry
    // failure is the one exit that states its zero without measuring it.
    let registry = match build_registry(multi, audit, credentials, download_dir)
        .await
        .context("building account registry")
    {
        Ok(registry) => registry,
        Err(e) => {
            return ServeOutcome {
                result: Err(e),
                undrained_dispatches: 0,
            };
        }
    };

    let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
    let drainer_handle = rimap_audit::spawn_drainer(cancellation_rx, audit.clone());

    let mcp_server = server::ImapMcpServer::new(registry, audit.clone(), cancellation_tx);
    // Taken before `rmcp::serve_server` consumes the server below.
    let dispatch_drain = mcp_server.dispatch_drain();
    // Wrap stdio with #277 envelope validator: rejects malformed frames
    // before rmcp sees them. Destructure so `supervisor` is its own
    // binding (its methods take `&mut self` / consume `self`).
    let rimap_server::mcp::wire_validator::ValidatedStdio {
        transport,
        stdout,
        mut supervisor,
    } = rimap_server::mcp::wire_validator::stdio_with_validation();
    let stdout_for_preinit = std::sync::Arc::clone(&stdout);

    let mut init_fut = Box::pin(rmcp::serve_server(mcp_server, transport));
    let init_result: Result<_, InitOutcome> = tokio::select! {
        biased;
        bridge = supervisor.watch_for_error() => Err(InitOutcome::Bridge(bridge)),
        result = &mut init_fut => match result {
            Ok(svc) => Ok(svc),
            Err(e) => Err(InitOutcome::Rmcp(Box::new(e))),
        },
    };
    drop(init_fut);

    let service = match init_result {
        Ok(svc) => svc,
        Err(InitOutcome::Bridge(bridge_result)) => {
            let primary = bridge_result.err().map_or_else(
                || anyhow::anyhow!("validator bridges exited before init completed"),
                |e| anyhow::anyhow!("validator bridge during init: {e}"),
            );
            let _ = supervisor.shutdown_after_failure().await;
            return ServeOutcome {
                result: Err(primary),
                undrained_dispatches: drain_dispatches(&dispatch_drain).await,
            };
        }
        Err(InitOutcome::Rmcp(boxed)) => {
            let result = handle_init_failure(*boxed, &stdout_for_preinit, supervisor).await;
            return ServeOutcome {
                result,
                undrained_dispatches: drain_dispatches(&dispatch_drain).await,
            };
        }
    };
    // waiting() takes ownership of service, consuming it and dropping the
    // ImapMcpServer (including all cancellation sender clones) when it
    // returns. The drainer task exits once all senders have dropped.
    //
    // Phase 1: race service against bridge errors so a validator
    // BrokenPipe (e.g. closed stdout) during normal operation
    // surfaces as a non-zero exit rather than silently leaving rmcp
    // wedged on an unwritable transport.
    let mut service_fut = Box::pin(service.waiting());
    let service_outcome: anyhow::Result<()> = tokio::select! {
        biased;
        bridge = supervisor.watch_for_error() => match bridge {
            Err(e) => Err(anyhow::anyhow!("validator bridge: {e}")),
            Ok(()) => {
                // Both bridges exited cleanly while service is still
                // running (exotic). Let service finish — it'll see EOF.
                (&mut service_fut)
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))
            }
        },
        result = &mut service_fut =>
            result.map(|_| ()).map_err(|e| anyhow::anyhow!("MCP server error: {e}")),
    };

    // Phase 2: drop service future to release rmcp's transport ends,
    // then shut down the supervisor. On success, `drain()` awaits
    // both bridges (inbound already saw EOF via rmcp); on failure,
    // `shutdown_after_failure()` aborts inbound first because the
    // client may keep stdin open while waiting for the error
    // response.
    drop(service_fut);

    // rmcp spawns each request handler as a detached task, so the drop above
    // released the transport but not the handlers. Cancel and drain them here,
    // while the process is still inside `serve_mcp` — that is, before the
    // drainer join below and before `run_server` writes `process_end`. Leaving
    // them to `Runtime::shutdown_background` sequenced a shutdown-cut connect's
    // `auth` record *after* the `process_end` of its own process (#645), and a
    // dispatch still holding a cancellation sender kept the drainer join
    // waiting for that command's full timeout.
    let undrained = drain_dispatches(&dispatch_drain).await;

    let shutdown_outcome = match &service_outcome {
        Ok(()) => supervisor.drain().await,
        Err(_) => supervisor.shutdown_after_failure().await,
    }
    .map_err(|e| anyhow::anyhow!("validator bridge shutdown: {e}"));

    let mcp_result: anyhow::Result<()> = match (service_outcome, shutdown_outcome) {
        // Race-phase failure dominates; otherwise shutdown-phase
        // surfaces. The `|` arm collapses both Err shapes because
        // the resulting `Err(e)` has identical type.
        (Err(e), _) | (Ok(()), Err(e)) => Err(e),
        (Ok(()), Ok(())) => Ok(()),
    };

    // All senders dropped above. Wait for the drainer to flush any
    // remaining queued cancellation records before the runtime exits.
    // Bounded: an undrained dispatch still owns a sender clone, and an
    // unbounded join would then hold the whole process exit for that
    // command's timeout.
    //
    // `abort` on expiry, not just a dropped handle: dropping a `JoinHandle`
    // *detaches* the task, so the drainer would keep looping and keep appending
    // `tool_end` records — after `process_end`, which is the ordering this
    // whole path exists to establish.
    let mut drainer_handle = drainer_handle;
    match tokio::time::timeout(DRAINER_JOIN_BUDGET, &mut drainer_handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "cancellation drainer join error"),
        Err(_) => {
            drainer_handle.abort();
            tracing::warn!(
                undrained,
                "cancellation drainer did not finish within the join budget; \
                 queued cancellation records are lost, and any write already \
                 handed to the blocking pool is sequenced after process_end",
            );
        }
    }
    ServeOutcome {
        result: mcp_result,
        undrained_dispatches: undrained,
    }
}

/// Emit the `process_end` audit record at process shutdown. Reason
/// reflects whether the MCP server loop completed cleanly (`Eof`)
/// or with an error (`Error`). Failures to write are logged but do
/// not propagate.
///
/// `undrained_dispatches` is [`ServeOutcome::undrained_dispatches`], threaded
/// out of `serve_mcp` rather than read off the writer: unlike the other two
/// counters it is not the audit writer's to know (#680).
fn emit_process_end(
    audit: &rimap_audit::AuditWriter,
    mcp_result: &anyhow::Result<()>,
    undrained_dispatches: u64,
) {
    let reason = match mcp_result {
        Ok(()) => rimap_audit::ProcessEndReason::Eof,
        Err(_) => rimap_audit::ProcessEndReason::Error,
    };
    // Last chance to state that this file has a hole in it, or that it is not
    // terminal for this process: both counters live only in memory, and the
    // process is about to exit (#647, #680).
    let process_end = rimap_audit::ProcessEnd::new(
        reason,
        audit.total_tool_calls(),
        audit.suppressed_failures(),
        undrained_dispatches,
    );
    match audit.log_process_end(process_end) {
        Ok(seq) => tracing::info!(seq = %seq, "process_end audit record written"),
        Err(e) => tracing::error!(error = %e, "failed to write process_end audit record"),
    }
}

/// Write the JSON-RPC -32002 error envelope for a pre-initialize request
/// to stdout (newline-terminated, flushed). Notification / Response /
/// Error variants synthesize no envelope (per JSON-RPC §4.1) and this
/// helper is a no-op. Write failures (broken pipe, closed reader) are
/// propagated via `?` so the caller records `process_end.reason: Error`.
///
/// Holds the shared stdout mutex for the duration of the write+flush so
/// it serializes against the validator and passthrough bridge tasks
/// added in #277 (see `mcp::wire_validator`). Callers MUST pass the
/// same `Arc<Mutex<Stdout>>` that `wire_validator::stdio_with_validation`
/// returned in `ValidatedStdio.stdout`.
async fn emit_pre_init_error_envelope(
    msg: &rmcp::model::ClientJsonRpcMessage,
    stdout: &std::sync::Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
) -> anyhow::Result<()> {
    let Some(line) = rimap_server::mcp::preinit::synthesize_pre_init_error_envelope(msg) else {
        return Ok(());
    };
    let mut out = stdout.lock().await;
    out.write_all(line.as_bytes())
        .await
        .context("writing pre-init error envelope to stdout")?;
    out.flush()
        .await
        .context("flushing pre-init error envelope")?;
    tracing::info!("rejected pre-initialize request with -32002 envelope");
    Ok(())
}

/// Dispatch an `rmcp::serve_server` init failure: emit the pre-init
/// envelope (when applicable), classify `InitializeFailed`, then shut
/// down the validator supervisor. `shutdown_after_failure` awaits (or
/// aborts) the bridge tasks before the runtime drops; otherwise
/// inbound's blocking stdin read can prevent the process from exiting
/// promptly.
///
/// **The pre-init write-failure arm is the one exception.** When
/// `emit_pre_init_error_envelope` itself fails — broken pipe, i.e. the
/// client's stdout reader is already gone — `?` propagates before
/// `shutdown_after_failure` is reached, detaching both bridge
/// `JoinHandle`s. Left as-is on purpose (#722): the shutdown would be
/// inert on this arm. `drop(init_fut)` above has already dropped rmcp's
/// write half, so outbound has reached EOF on its own, and the inbound
/// abort could not stop a blocking stdin read anyway — `run_server`'s
/// `Runtime::shutdown_background` is what makes this process exit. What
/// the operator needs from this arm is the write error, undisplaced by
/// any bridge-shutdown outcome; `mcp_wire_negative`'s
/// `pre_initialize_envelope_write_failure_records_error` pins that.
async fn handle_init_failure(
    error: ServerInitializeError,
    stdout_for_preinit: &std::sync::Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
    supervisor: rimap_server::mcp::wire_validator::ValidatorSupervisor,
) -> anyhow::Result<()> {
    match error {
        ServerInitializeError::ExpectedInitializeRequest(Some(msg)) => {
            emit_pre_init_error_envelope(&msg, stdout_for_preinit).await?;
            match supervisor.shutdown_after_failure().await {
                Ok(()) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("validator bridge after pre-init: {e}")),
            }
        }
        ServerInitializeError::InitializeFailed(error_data) => {
            let handled = handle_initialize_failed(&error_data);
            match supervisor.shutdown_after_failure().await {
                Ok(()) => handled,
                Err(e) => Err(anyhow::anyhow!("validator bridge after init failure: {e}")),
            }
        }
        other => {
            let _ = supervisor.shutdown_after_failure().await;
            Err(anyhow::anyhow!("MCP server init: {other}"))
        }
    }
}

/// Classify a `ServerInitializeError::InitializeFailed` outcome by its
/// inner `ErrorData.code`. Returns `true` for client-side bad-input
/// codes that the wire envelope already communicated cleanly; the
/// caller treats these as handled rejections (exit 0, audit `Eof`).
/// Returns `false` for server-fault classes (`INTERNAL_ERROR` and
/// anything else) so they propagate as non-zero exit with audit
/// `Error`, keeping initialize-time outages observable. (#276)
fn initialize_failure_is_handled_rejection(code: McpErrorCode) -> bool {
    matches!(code, McpErrorCode::INVALID_PARAMS)
}

/// Classify and react to a `ServerInitializeError::InitializeFailed`
/// outcome. `INVALID_PARAMS` is a handled client rejection (rmcp already
/// sent the wire envelope — log at info and exit clean). Anything else
/// is a server-fault class that must propagate as a non-zero exit so
/// `process_end.reason: Error` is recorded. (#276)
fn handle_initialize_failed(error_data: &rmcp::model::ErrorData) -> anyhow::Result<()> {
    if initialize_failure_is_handled_rejection(error_data.code) {
        tracing::info!(
            code = error_data.code.0,
            "rejected initialize with error envelope",
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "MCP server init failed: code {}: {}",
            error_data.code.0,
            error_data.message,
        ))
    }
}

/// Resolve the config file path from `--config` or the
/// `RUSTY_IMAP_MCP_CONFIG` environment variable, erroring if neither is set.
fn resolve_cli_config_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    cli.config
        .clone()
        .or_else(|| resolve_config_path(None))
        .ok_or_else(|| {
            anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
        })
}

/// Load and validate the multi-account config, optionally relaxing the
/// empty-accounts rejection when `--allow-empty-accounts` is set.
///
/// `--allow-empty-accounts` is a `#[cfg(feature = "test-support")]` CLI
/// flag (#263 Codex adversarial review). In production builds the field
/// does not exist and we always hit the strict loader.
fn load_validated_multi(
    cli: &Cli,
    config_path: &std::path::Path,
) -> anyhow::Result<rimap_config::validate::ValidatedMultiConfig> {
    #[cfg(feature = "test-support")]
    let result = if cli.allow_empty_accounts {
        rimap_config::loader::load_and_validate_allowing_empty(config_path)
    } else {
        load_and_validate(config_path)
    };
    #[cfg(not(feature = "test-support"))]
    let result = {
        let _ = cli; // suppress unused-binding warning when flag is compiled out
        load_and_validate(config_path)
    };
    result.with_context(|| format!("loading config {}", config_path.display()))
}

/// Build the account registry from a validated multi-account config.
async fn build_registry(
    multi: &rimap_config::validate::ValidatedMultiConfig,
    audit: &rimap_audit::AuditWriter,
    credentials: &Arc<dyn CredentialStore>,
    download_dir: &Arc<std::path::Path>,
) -> anyhow::Result<registry::AccountRegistry> {
    let mut account_states = std::collections::BTreeMap::new();
    let auth_sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    for (id, acfg) in &multi.accounts {
        // Emitted before the guard is built so an account that fails to come
        // up still leaves its effective matrix on the record (#632).
        rimap_server::boot::tool_matrix::log_account_matrix(
            &rimap_server::boot::tool_matrix::account_tool_matrix(acfg),
        );
        let guard = build_account_guard(acfg).context("building dispatch guard")?;
        let conn_cfg = registry::build_account_connection(id, acfg);
        let resolver: Arc<dyn rimap_core::CredentialResolver> =
            Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
                credentials.clone(),
                acfg.fallback_mode,
                Protocol::Imap,
            ));
        let imap = Connection::new(conn_cfg, auth_sink.clone(), resolver);

        let folders = imap
            .list_folders("*")
            .await
            .with_context(|| format!("listing folders for account {}", id.as_str()))?;
        let special_use = rimap_server::boot::discovery::resolve_special_use(&folders);
        let protected = rimap_server::boot::discovery::merge_protected_folders(
            &acfg.security.protected_folders,
            special_use.all_discovered(),
        );

        let smtp = build_smtp_client(acfg, credentials)?;

        let folder_guard =
            rimap_authz::FolderGuard::new(&protected, &acfg.security.expunge_folders);

        let state = registry::AccountState {
            id: id.clone(),
            imap,
            smtp,
            guard,
            folder_guard,
            download_dir: Arc::clone(download_dir),
            special_use,
            tool_call_timeout: Duration::from_secs(u64::from(
                acfg.limits.tool_call_timeout_seconds,
            )),
        };
        account_states.insert(id.clone(), state);
    }
    Ok(registry::AccountRegistry::new(account_states))
}

/// Build an SMTP client from account config, if SMTP is configured.
fn build_smtp_client(
    acfg: &ValidatedAccountConfig,
    credentials: &Arc<dyn CredentialStore>,
) -> anyhow::Result<Option<Box<dyn rimap_smtp::SmtpSender>>> {
    let Some(ref smtp_cfg) = acfg.smtp else {
        return Ok(None);
    };
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        rimap_config::credential::ResolutionPolicy {
            fallback_mode: acfg.fallback_mode,
            protocol: Protocol::Smtp,
        },
    )
    .with_context(|| format!("resolving SMTP credential for account {}", acfg.id.as_str()))?;
    let client = rimap_smtp::SmtpClient::new(smtp_cfg, smtp_password.expose_secret())
        .with_context(|| format!("building SMTP client for account {}", acfg.id.as_str()))?;
    drop(smtp_password);
    Ok(Some(Box::new(client)))
}

/// Build the composed authz guard from a per-account config.
fn build_account_guard(
    acfg: &ValidatedAccountConfig,
) -> anyhow::Result<DispatchGuard<SystemClock>> {
    let matrix = EffectiveMatrix::build(acfg.security.posture, &acfg.tool_overrides);
    let breaker_cfg = BreakerConfig {
        error_threshold: acfg.limits.circuit_breaker_error_threshold,
        window: Duration::from_secs(u64::from(acfg.limits.circuit_breaker_window_seconds)),
        ..BreakerConfig::default_spec()
    };
    let breaker = CircuitBreaker::new(SystemClock::new(), breaker_cfg);
    let governor = Governor::new(
        acfg.limits.commands_per_second,
        acfg.limits.drafts_per_minute,
        acfg.limits.sends_per_minute,
    )
    .map_err(|e| anyhow::anyhow!("governor: {e}"))?;
    Ok(DispatchGuard::new(matrix, breaker, governor))
}

/// Resolve the attachment download directory from a multi-account config.
///
/// If `attachments.download_dir` is set, the path is created (if needed) and
/// locked down to 0700 on Unix. Otherwise a per-process tempdir is created
/// via `tempfile` (TOCTOU-safe) and then locked down to 0700 on Unix. The
/// per-process dir is intentionally leaked (no automatic cleanup) so that
/// downloaded attachments remain readable for the server's lifetime.
fn resolve_download_dir_multi(
    multi: &rimap_config::validate::ValidatedMultiConfig,
) -> anyhow::Result<PathBuf> {
    let dir_str = &multi.attachments.download_dir;
    if !dir_str.is_empty() {
        let dir = PathBuf::from(dir_str);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating attachment download_dir at {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
        }
        return Ok(dir);
    }

    let dir = tempfile::Builder::new()
        .prefix("rusty-imap-mcp-")
        .tempdir()
        .context("creating per-process tempdir for attachments")?
        .keep();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 perms on {}", dir.display()))?;
    }
    Ok(dir)
}

/// Arm the `AuditWriter`'s forced-write-failure hook when the
/// `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1` env var is set.
///
/// Used by `mcp_audit_failure.rs` to exercise the real
/// lock/append/error-mapping path without adding a sentinel sink.
/// This hook changes the audit write OUTCOME, not the wire shape,
/// so it complies with the `test-support` convention.
#[cfg(feature = "test-support")]
fn maybe_arm_audit_write_failure(audit: &rimap_audit::AuditWriter) {
    if std::env::var("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        audit.force_next_write_failure();
    }
}

/// Dispatch subcommands that are gated behind `#[cfg(feature = "test-support")]`.
///
/// Returns `Some(result)` if a test-support subcommand handled the request,
/// or `None` if `cli.command` is not a test-support subcommand and normal
/// dispatch should continue. Kept as a separate function (rather than
/// inlined in `run`) so the test-only branch lives outside the production
/// code path and the `run` body stays under the workspace 100-line cap.
#[cfg(feature = "test-support")]
fn run_test_support_subcommands(cli: &Cli) -> Option<anyhow::Result<()>> {
    match cli.command {
        Some(Command::DumpToolCatalog) => {
            let mut stdout = std::io::stdout().lock();
            Some(
                cli::dump_tool_catalog::dump_tool_catalog(&mut stdout)
                    .context("dumping tool catalog"),
            )
        }
        // cargo-mutants: best-effort — deleting this arm drops the
        // `dump-tool-schemas` subcommand to normal server startup. It is a
        // `#[cfg(feature = "test-support")]` diagnostic dispatch exercised by
        // `just regen-tool-schemas` in CI, not by any in-process Rust test.
        Some(Command::DumpToolSchemas) => {
            let mut stdout = std::io::stdout().lock();
            Some(
                cli::dump_tool_schemas::dump_tool_schemas(&mut stdout)
                    .context("dumping tool schemas"),
            )
        }
        Some(Command::DumpToolDoc) => {
            let mut stdout = std::io::stdout().lock();
            Some(cli::dump_tool_doc::dump_tool_doc(&mut stdout).context("dumping tool doc"))
        }
        _ => None,
    }
}

/// Handle the `login` subcommand: store the credential and print confirmation.
fn run_login_command(account: &str, username: &str, host: &str) -> anyhow::Result<()> {
    let store = KeyringStore;
    let account_id = rimap_core::account::AccountId::new(account)
        .with_context(|| format!("invalid account name `{account}`"))?;
    run_login(&store, &account_id, username, host, tty_prompt)
        .with_context(|| format!("storing credential for {username}@{host}"))?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "credential stored for {username}@{host}")?;
    Ok(())
}

/// Handle the `migrate-keyring` subcommand.
// cargo-mutants: best-effort — the `-> Ok(())` stub bypasses the whole
// migration. This is CLI wiring over the OS keyring (`KeyringStore`); the
// underlying `migrate_keyring::migrate_one` is unit-tested, but exercising this
// handler needs a live keyring the unit suite has no portable access to.
fn run_migrate_keyring(account: &str, username: &str, host: &str) -> anyhow::Result<()> {
    let store = KeyringStore;
    let account_id = rimap_core::account::AccountId::new(account)
        .with_context(|| format!("invalid account name `{account}`"))?;
    let migrated = cli::migrate_keyring::migrate_one(&store, &account_id, username, host)
        .with_context(|| format!("migrating credential for account `{account}`, host `{host}`"))?;
    let mut stdout = std::io::stdout().lock();
    if migrated {
        writeln!(stdout, "migrated credential for account `{account}`")?;
    } else {
        writeln!(
            stdout,
            "no legacy credential found for account `{account}` (host `{host}`); nothing to migrate"
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[expect(clippy::expect_used, reason = "tests")]
mod resolve_download_dir_tests {
    use super::resolve_download_dir_multi;
    use rimap_config::model::{AttachmentsConfig, AuditConfig};
    use rimap_config::validate::ValidatedMultiConfig;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn minimal_multi(download_dir: String) -> ValidatedMultiConfig {
        ValidatedMultiConfig::new_for_tests(
            AuditConfig::new(PathBuf::from("/tmp/unused-audit.log")),
            {
                let mut attachments = AttachmentsConfig::default();
                attachments.download_dir = download_dir;
                attachments
            },
        )
    }

    #[test]
    fn default_tempdir_has_0700_perms() {
        let multi = minimal_multi(String::new());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        let meta = std::fs::metadata(&dir).expect("metadata");
        assert!(meta.is_dir(), "expected a directory at {}", dir.display());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_dir_is_locked_down_to_0700() {
        let base = tempfile::tempdir().expect("tempdir");
        let target = base.path().join("attachments");
        let multi = minimal_multi(target.to_string_lossy().into_owned());
        let dir = resolve_download_dir_multi(&multi).expect("resolve ok");
        assert_eq!(dir, target);
        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
    }
}

#[cfg(test)]
mod startup_error_tests {
    use std::path::{Path, PathBuf};

    use rimap_config::ConfigError;

    use super::format_missing_config_guidance;

    #[test]
    fn missing_config_guidance_is_actionable() {
        let msg = format_missing_config_guidance(Path::new("/opt/rimap/config.toml"));
        assert!(
            msg.contains("/opt/rimap/config.toml"),
            "names the path: {msg}"
        );
        assert!(
            msg.contains("config.example.toml"),
            "points at the example config: {msg}"
        );
        assert!(
            msg.contains("docs/quickstart-gmail.md"),
            "points at the Gmail quickstart: {msg}"
        );
        assert!(
            msg.contains("docs/quickstart-proton-bridge.md"),
            "points at the Proton Bridge quickstart: {msg}"
        );
        assert!(
            msg.contains("RUSTY_IMAP_MCP_CONFIG"),
            "mentions the env-var override: {msg}"
        );
    }

    #[test]
    fn not_found_survives_context_wrapping() {
        // `load_validated_multi` wraps the config error with `.with_context`;
        // `emit_startup_error` must still recover `NotFound` from the chain.
        let err = anyhow::Error::from(ConfigError::NotFound {
            path: PathBuf::from("/x/config.toml"),
        })
        .context("loading config /x/config.toml");
        assert!(matches!(
            err.downcast_ref::<ConfigError>(),
            Some(ConfigError::NotFound { .. })
        ));
    }
}

#[cfg(test)]
mod initialize_failure_classifier_tests {
    use rmcp::model::ErrorCode as McpErrorCode;

    use super::initialize_failure_is_handled_rejection;

    #[test]
    fn invalid_params_is_handled_rejection() {
        assert!(initialize_failure_is_handled_rejection(
            McpErrorCode::INVALID_PARAMS
        ));
    }

    #[test]
    fn internal_error_is_not_handled_rejection() {
        assert!(!initialize_failure_is_handled_rejection(
            McpErrorCode::INTERNAL_ERROR
        ));
    }

    #[test]
    fn method_not_found_is_not_handled_rejection() {
        assert!(!initialize_failure_is_handled_rejection(
            McpErrorCode::METHOD_NOT_FOUND
        ));
    }

    #[test]
    fn unknown_codes_are_not_handled_rejection() {
        // Future-proofing: any code we haven't explicitly allow-listed
        // must propagate as a server fault.
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(
            -32099
        )));
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(
            -32603 - 1
        )));
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(
            -32700
        )));
    }
}
