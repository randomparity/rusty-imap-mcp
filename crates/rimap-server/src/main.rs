//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;

use rimap_server::boot::{audit_init, logging, registry};
use rimap_server::mcp::server;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{CommandFactory, FromArgMatches};
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::{CredentialStore, KeyringStore};
use rimap_config::loader::{load_and_validate, resolve_config_path};
use rimap_config::login::{run_login, tty_prompt};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_imap::Connection;
use rmcp::model::ErrorCode as McpErrorCode;
use rmcp::service::ServerInitializeError;
use secrecy::ExposeSecret;
use tokio::io::AsyncWriteExt;

use crate::cli::{AuditAction, Cli, Command};

fn parse_cli() -> Result<Cli, clap::Error> {
    let matches = Cli::command()
        .version(rimap_core::version::version())
        .get_matches();
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
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    if let Some(Command::Login {
        account,
        host,
        username,
    }) = &cli.command
    {
        return run_login_command(account, username, host);
    }

    if let Some(Command::MigrateKeyring {
        account,
        host,
        username,
    }) = &cli.command
    {
        return run_migrate_keyring(account, username, host);
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
    }) = cli.command
    {
        return cli::audit_merge::run(
            &path,
            cli::audit_merge::RunArgs {
                since: since.as_deref(),
                until: until.as_deref(),
                tool: tool.as_deref(),
                kind: kind.as_deref(),
                process: process.as_deref(),
                account: account.as_deref(),
            },
        );
    }

    #[cfg(feature = "test-support")]
    if let Some(result) = run_test_support_subcommands(&cli) {
        return result;
    }

    if cli.dry_run {
        let path = resolve_cli_config_path(&cli)?;
        let mut stdout = std::io::stdout().lock();
        let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
        return rt.block_on(cli::dry_run::run(&path, &mut stdout));
    }

    // Server mode: load config, build subsystems, run MCP transport.
    let config_path = resolve_cli_config_path(&cli)?;
    let multi = load_validated_multi(&cli, &config_path)?;
    let audit = audit_init::init_audit_writer_multi(&multi, &config_path)
        .with_context(|| format!("opening audit log at {}", multi.audit.path.display()))?;

    #[cfg(feature = "test-support")]
    maybe_arm_audit_write_failure(&audit);

    let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    let download_dir: Arc<std::path::Path> =
        Arc::from(resolve_download_dir_multi(&multi)?.into_boxed_path());

    let audit_for_shutdown = audit.clone();
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;

    let mcp_result: anyhow::Result<()> = rt.block_on(async {
        let registry = build_registry(&multi, &audit, &credentials, &download_dir)
            .await
            .context("building account registry")?;

        let (cancellation_tx, cancellation_rx) = rimap_audit::cancellation_channel();
        let drainer_handle = rimap_audit::spawn_drainer(cancellation_rx, audit.clone());

        let mcp_server = server::ImapMcpServer::new(registry, audit, cancellation_tx);
        let transport = rmcp::transport::io::stdio();
        let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
            Ok(svc) => svc,
            Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
                // TODO Task 3.2: replace this temporary local with validated.stdout
                // once the transport swap to wire_validator::stdio_with_validation lands.
                let stdout_for_preinit =
                    std::sync::Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
                emit_pre_init_error_envelope(&msg, &stdout_for_preinit).await?;
                return Ok(());
            }
            Err(ServerInitializeError::InitializeFailed(error_data)) => {
                return handle_initialize_failed(&error_data);
            }
            Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
        };
        // waiting() takes ownership of service, consuming it and dropping the
        // ImapMcpServer (including all cancellation sender clones) when it
        // returns. The drainer task exits once all senders have dropped.
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

        // All senders dropped above. Wait for the drainer to flush any
        // remaining queued cancellation records before the runtime exits.
        if let Err(e) = drainer_handle.await {
            tracing::error!(error = %e, "cancellation drainer join error");
        }
        Ok(())
    });

    emit_process_end(&audit_for_shutdown, &mcp_result);

    mcp_result
}

/// Emit the `process_end` audit record at process shutdown. Reason
/// reflects whether the MCP server loop completed cleanly (`Eof`)
/// or with an error (`Error`). Failures to write are logged but do
/// not propagate.
fn emit_process_end(audit: &rimap_audit::AuditWriter, mcp_result: &anyhow::Result<()>) {
    let reason = match mcp_result {
        Ok(()) => rimap_audit::ProcessEndReason::Eof,
        Err(_) => rimap_audit::ProcessEndReason::Error,
    };
    // total_tool_calls is not tracked yet — use 0 as placeholder.
    // A future PR can add an AtomicU64 counter to ImapMcpServer.
    let process_end = rimap_audit::ProcessEnd {
        reason,
        total_tool_calls: 0,
    };
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
        let guard = build_account_guard(acfg).context("building dispatch guard")?;
        let conn_cfg = registry::build_account_connection(id, acfg);
        let resolver: Arc<dyn rimap_core::CredentialResolver> =
            Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
                credentials.clone(),
                acfg.fallback_mode,
            ));
        let imap = Connection::new(conn_cfg, auth_sink.clone(), resolver);

        let special_use = rimap_server::boot::discovery::resolve_special_use(&imap)
            .await
            .with_context(|| {
                format!("resolving special-use folders for account {}", id.as_str())
            })?;

        // Expand the config-supplied protected-folders list with any
        // server-declared RFC 6154 names (e.g. Gmail's `[Gmail]/Sent Mail`).
        // The merge is case-insensitive so user-configured literals
        // (`"Sent"`) are not duplicated when the server also reports
        // `"Sent"` on the same mailbox.
        let mut protected = acfg.security.protected_folders.clone();
        for discovered in special_use.all_discovered() {
            if !protected
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&discovered))
            {
                protected.push(discovered);
            }
        }

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
        };
        account_states.insert(id.clone(), state);
    }
    Ok(registry::AccountRegistry::new(account_states))
}

/// Build an SMTP client from account config, if SMTP is configured.
fn build_smtp_client(
    acfg: &ValidatedAccountConfig,
    credentials: &Arc<dyn CredentialStore>,
) -> anyhow::Result<Option<rimap_smtp::SmtpClient>> {
    let Some(ref smtp_cfg) = acfg.smtp else {
        return Ok(None);
    };
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        acfg.fallback_mode,
    )
    .with_context(|| format!("resolving SMTP credential for account {}", acfg.id.as_str()))?;
    let client = rimap_smtp::SmtpClient::new(smtp_cfg, smtp_password.expose_secret())
        .with_context(|| format!("building SMTP client for account {}", acfg.id.as_str()))?;
    drop(smtp_password);
    Ok(Some(client))
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
        Some(Command::DumpToolSchemas) => {
            let mut stdout = std::io::stdout().lock();
            Some(
                cli::dump_tool_schemas::dump_tool_schemas(&mut stdout)
                    .context("dumping tool schemas"),
            )
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
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn minimal_multi(download_dir: String) -> ValidatedMultiConfig {
        ValidatedMultiConfig {
            accounts: BTreeMap::new(),
            audit: AuditConfig {
                path: PathBuf::from("/tmp/unused-audit.log"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: None,
            },
            attachments: AttachmentsConfig { download_dir },
        }
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
