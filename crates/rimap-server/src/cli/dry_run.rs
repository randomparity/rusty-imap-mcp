//! `--dry-run` path: load + validate config, build effective matrix, print it
//! to stdout, exit 0.
//!
//! Stdout is reserved for MCP transport, but `--dry-run` is an *out-of-band*
//! mode that terminates the process before any MCP wiring happens, so writing
//! the matrix to stdout is both acceptable and the most useful destination
//! (it can be piped to `less`, etc.).
//!
//! Output format is stable text: one header line and one row per content
//! tool in declaration order, followed by a separate section listing
//! infrastructure tools (which bypass the posture matrix at runtime and
//! are always available). Sample:
//!
//! ```text
//! Effective matrix (posture = draft-safe)
//!   [ok ] list_folders
//!   [ok ] search
//!   [deny] search.advanced_query
//!   ...
//! Infrastructure tools (always available):
//!   [ok ] use_account
//!   [ok ] list_accounts
//! Explicit tool overrides:
//!   delete_message=allow(inherited)
//!   search=deny(account)
//! Protected folders (configured; server special-use folders are added at boot):
//!   INBOX(inherited)
//!   Sent(inherited)
//! Expunge folders:
//!   Trash(inherited)
//! Capabilities (imap.example.com:993):
//!   [ok ] IMAP4REV1
//!   [ok ] IDLE
//! TLS fingerprint (sha256):
//!   ab:cd:...:ef
//!   (add `tls_fingerprint_sha256 = "ab:cd:...:ef"` under [imap] in config.toml to pin)
//! ```

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_config::loader::load_and_validate;
use rimap_core::tool::ToolName;

/// Print the `TLS fingerprint (sha256):` section for one account, given the
/// preflight outcome and the (optional) pinned fingerprint from config. Four
/// branches:
///
/// - `Ok(info)` + no pin: print observed fingerprint with a paste-into-config
///   hint (onboarding path).
/// - `Ok(info)` + matching pin: print observed fingerprint with `(matches
///   configured pin)` confirmation.
/// - `Ok(info)` + mismatched pin: defensive unreachable-in-production print
///   (see arm comment).
/// - `Err(ImapError::Tls { observed, expected })`: print both values plus a
///   diagnostic hint pointing at the quickstart.
///
/// All other error variants (`Connect`, `Timeout`, `TlsHandshake` for
/// non-mismatch reasons, `Protocol`) silently print nothing — there is no
/// fingerprint to surface when the verifier never ran or the value is not
/// meaningfully informative.
fn write_fingerprint_section<W: Write>(
    out: &mut W,
    result: &Result<rimap_imap::preflight::PreflightInfo, rimap_imap::error::ImapError>,
    pinned: Option<rimap_core::TlsFingerprint>,
) -> std::io::Result<()> {
    match (result, pinned) {
        (Ok(info), None) => {
            let fp = info.tls_fingerprint.to_hex();
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  {fp}")?;
            writeln!(
                out,
                "  (add `tls_fingerprint_sha256 = \"{fp}\"` under [imap] in config.toml to pin)"
            )?;
        }
        (Ok(info), Some(pin)) if info.tls_fingerprint == pin => {
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  {}  (matches configured pin)", info.tls_fingerprint)?;
        }
        (Ok(info), Some(_)) => {
            // Unreachable in production: probe_preflight returns Err(Tls) on
            // mismatch. Defensive branch flags the anomalous state instead of
            // silently mimicking the matching-pin output.
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(
                out,
                "  {}  (pin mismatch — unexpected state, please report)",
                info.tls_fingerprint
            )?;
        }
        (Err(rimap_imap::error::ImapError::Tls { observed, expected }), _) => {
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  observed: {observed}")?;
            writeln!(out, "  expected: {expected}  (configured pin)")?;
            writeln!(
                out,
                "  hint: re-run the openssl command from the quickstart and update tls_fingerprint_sha256"
            )?;
        }
        (Err(_), _) => {
            // Connect / Timeout / TlsHandshake-non-mismatch / Protocol: nothing
            // to print. The capabilities-section already shows the error.
        }
    }
    Ok(())
}

/// Print the `Explicit tool overrides:` section for one account.
///
/// Rows come from [`crate::boot::tool_matrix::account_tool_matrix`], the same
/// producer the boot log line and the `process_start` audit record use, so
/// the three renderings cannot report different provenance (#632).
fn write_explicit_overrides_section<W: Write>(
    out: &mut W,
    matrix: &rimap_audit::record::AccountToolMatrix,
) -> std::io::Result<()> {
    if matrix.tools.is_empty() {
        writeln!(out, "Explicit tool overrides: none")?;
        return Ok(());
    }
    writeln!(out, "Explicit tool overrides:")?;
    for verdict in &matrix.tools {
        writeln!(
            out,
            "  {}",
            crate::boot::tool_matrix::render_verdict(verdict)
        )?;
    }
    Ok(())
}

/// Print the two folder-policy sections for one account.
///
/// Rows come from the same producer as the boot log line and the
/// `process_start` record, so an `inherited` entry reads identically wherever
/// an operator meets it (#696).
///
/// `--dry-run` has no IMAP session, so `matrix` was built without one and the
/// header says so outright. Printing the configured list under a bare
/// `Protected folders:` would understate what the running server protects,
/// because boot appends the server's RFC 6154 special-use folders to it — and
/// understating protection is the direction that misleads.
fn write_folder_policy_sections<W: Write>(
    out: &mut W,
    matrix: &rimap_audit::record::AccountToolMatrix,
) -> std::io::Result<()> {
    // Header derived from the matrix rather than hard-coded, so the caveat
    // cannot outlive the state it describes.
    let header = match matrix.special_use_discovery {
        rimap_audit::record::SpecialUseDiscovery::NotRun => {
            "Protected folders (configured; server special-use folders are added at boot)"
        }
        rimap_audit::record::SpecialUseDiscovery::Ran => "Protected folders",
    };
    write_folder_section(out, header, &matrix.protected_folders)?;
    write_folder_section(out, "Expunge folders", &matrix.expunge_folders)
}

/// Print one folder list under `header`, or `<header>: none` when empty.
///
/// An empty `expunge_folders` prints `none` rather than an empty section:
/// "nothing in this account may be expunged" is the single most reassuring
/// line in this output and it should be stated, not inferred from silence.
fn write_folder_section<W: Write>(
    out: &mut W,
    header: &str,
    entries: &[rimap_audit::record::FolderEntry],
) -> std::io::Result<()> {
    if entries.is_empty() {
        writeln!(out, "{header}: none")?;
        return Ok(());
    }
    writeln!(out, "{header}:")?;
    for entry in entries {
        writeln!(
            out,
            "  {}",
            crate::boot::tool_matrix::render_folder_entry(entry)
        )?;
    }
    Ok(())
}

/// Load `path`, validate, acquire an exclusive audit lock, build the effective
/// matrix, print to `out`, and return. The audit lock is held for the duration
/// of the call and released on return.
///
/// # Errors
/// Propagates config load/validate errors, audit lock acquisition errors, and
/// I/O errors from the writer.
pub async fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
    let multi =
        load_and_validate(path).with_context(|| format!("loading config {}", path.display()))?;

    let audit_path = multi.audit.path.clone();
    // dry-run is a one-shot diagnostic path that exits immediately after
    // printing the matrix. Chain-of-history continuation (trailing state) is
    // not useful here; Seq::FIRST — `AuditOptions::new`'s default, left
    // unassigned below — is correct.
    let mut options = AuditOptions::new(audit_path.clone(), Seq::FIRST);
    options.rotate_bytes = multi.audit.rotate_bytes;
    options.rotate_keep = multi.audit.rotate_keep;
    options.retention_seconds = multi.audit.retention_seconds;
    options.fail_open = multi.audit.fail_open;
    let _audit_writer = AuditWriter::open(&options)
        .with_context(|| format!("opening audit log at {}", audit_path.display()))?;

    for (id, acfg) in &multi.accounts {
        let matrix = EffectiveMatrix::build(acfg.security.posture, &acfg.tool_overrides);
        if multi.accounts.len() > 1 {
            writeln!(out, "Account: {}", id.as_str())?;
        }
        writeln!(out, "Effective matrix (posture = {})", matrix.posture())?;
        for (tool, allowed) in matrix.rows() {
            if tool.is_infrastructure() {
                continue;
            }
            let tag = if allowed { "[ok ]" } else { "[deny]" };
            writeln!(out, "  {tag} {tool}")?;
        }
        writeln!(out, "Infrastructure tools (always available):")?;
        for tool in ToolName::all()
            .into_iter()
            .filter(|t| t.is_infrastructure())
        {
            writeln!(out, "  [ok ] {tool}")?;
        }
        // `None`: this path opens no IMAP session, so no special-use folder
        // is known. Both sections below say so rather than presenting the
        // configured list as the one boot will build the guard from (#696).
        let policy = crate::boot::tool_matrix::account_tool_matrix(acfg, None);
        write_explicit_overrides_section(out, &policy)?;
        write_folder_policy_sections(out, &policy)?;

        // Errors are reported inline but do not abort the dry-run — a
        // multi-account config may have one unreachable host and still
        // want to print the matrix for the others.
        let conn_cfg = crate::boot::registry::build_account_connection(id, acfg);
        let preflight_result = rimap_imap::preflight::probe_preflight(&conn_cfg).await;
        match &preflight_result {
            Ok(info) => {
                writeln!(out, "Capabilities ({}:{}):", conn_cfg.host, conn_cfg.port)?;
                for cap in &info.capabilities {
                    writeln!(out, "  [ok ] {cap}")?;
                }
            }
            Err(e) => {
                writeln!(
                    out,
                    "Capabilities ({}:{}): unavailable ({e})",
                    conn_cfg.host, conn_cfg.port,
                )?;
            }
        }
        write_fingerprint_section(out, &preflight_result, conn_cfg.pinned_fingerprint)?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::cli::dry_run::run;
    use rimap_core::TlsFingerprint;
    use rimap_imap::error::ImapError;
    use rimap_imap::preflight::PreflightInfo;

    /// Build a `TempDir` whose mode is 0o700. The audit-writer requires tight
    /// modes after #147 and `tempfile::TempDir::new()` may inherit the system
    /// `umask` (often 0755). Unix-only because `PermissionsExt::from_mode` is.
    #[cfg(unix)]
    fn tight_tempdir() -> TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write_minimal_config(dir: &TempDir) -> PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit.display(),
            dir.path().display()
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    fn synth_fp(seed: &[u8]) -> TlsFingerprint {
        TlsFingerprint::from_cert_der(seed)
    }

    #[tokio::test]
    async fn dry_run_prints_matrix_with_default_posture() {
        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("draft-safe"));
        assert!(text.contains("list_folders"));
        assert!(text.contains("search.advanced_query"));
        // The advanced_query cell is denied under draft-safe.
        assert!(text.contains("[deny] search.advanced_query"));
        assert!(text.contains("[ok ] list_folders"));
    }

    #[tokio::test]
    async fn second_dry_run_against_same_audit_fails_with_config_error() {
        use rimap_audit::{AuditOptions, AuditWriter, Seq};

        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);

        // First dry-run acquires the lock for the duration of the call.
        let mut out1 = Vec::new();
        run(&path, &mut out1).await.unwrap();

        // Hold the audit file open with a direct writer so the second dry-run
        // collides with us.
        let audit_path = dir.path().join("audit.jsonl");
        let _held = AuditWriter::open(&AuditOptions::new(audit_path, Seq::FIRST)).unwrap();

        let err = run(&path, &mut Vec::new()).await.unwrap_err();
        let chain: String = err
            .chain()
            .map(|c| format!("{c}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            chain.contains("already locked") || chain.contains("opening audit log"),
            "unexpected error chain: {chain}",
        );
    }

    #[tokio::test]
    async fn dry_run_lists_infrastructure_tools_separately() {
        // Infrastructure tools (use_account, list_accounts) bypass the posture
        // matrix at runtime, so printing them as `[deny]` alongside content
        // tools misleads users into thinking the tools are unavailable. They
        // should appear in their own "always available" section instead.
        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            !text.contains("[deny] use_account"),
            "use_account must not appear as denied in the matrix:\n{text}"
        );
        assert!(
            !text.contains("[deny] list_accounts"),
            "list_accounts must not appear as denied in the matrix:\n{text}"
        );
        assert!(
            text.contains("Infrastructure tools (always available)"),
            "expected infrastructure section header:\n{text}"
        );
        assert!(
            text.contains("use_account"),
            "use_account must still be listed somewhere:\n{text}"
        );
        assert!(
            text.contains("list_accounts"),
            "list_accounts must still be listed somewhere:\n{text}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_marks_inherited_and_account_written_overrides() {
        // Same rows the boot log line and the process_start record carry, so
        // an operator reading either sees the same provenance (#632).
        let dir = tight_tempdir();
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[defaults.security]
posture = "full"

[defaults.security.tools]
delete_message = "allow"

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[accounts.security.tools]
search = "deny"

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        );
        std::fs::write(&config_path, body).unwrap();

        let mut out = Vec::new();
        run(&config_path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            text.contains("Explicit tool overrides:"),
            "overrides section missing:\n{text}"
        );
        assert!(
            text.contains("delete_message=allow(inherited)"),
            "inherited allow not marked:\n{text}"
        );
        assert!(
            text.contains("search=deny(account)"),
            "account-written deny not marked:\n{text}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_prints_inherited_folder_lists() {
        // Acceptance criteria for #696: the two folder lists the #624
        // migration note told operators to review by hand are now printed,
        // each entry marked with the layer that put it there.
        let dir = tight_tempdir();
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent"]
expunge_folders = ["Trash"]

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[[accounts]]
name = "personal"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@personal.test"

[accounts.security]
expunge_folders = ["Junk"]

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        );
        std::fs::write(&config_path, body).unwrap();

        let mut out = Vec::new();
        run(&config_path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            text.contains(
                "Protected folders (configured; server special-use folders are added at boot):"
            ),
            "protected section header missing:\n{text}"
        );
        assert!(
            text.contains("  INBOX(inherited)"),
            "inherited protected entry missing:\n{text}"
        );
        // `work` never wrote expunge_folders; post-#624 it holds one anyway.
        assert!(
            text.contains("Expunge folders:") && text.contains("  Trash(inherited)"),
            "inherited expunge entry missing:\n{text}"
        );
        // `personal` wrote its own, and reads differently.
        assert!(
            text.contains("  Junk(account)"),
            "account-written expunge entry missing:\n{text}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_reports_an_empty_expunge_list_as_none() {
        // The default config makes nothing expungeable. Saying so is the
        // point — an absent section would read as missing information.
        let dir = tight_tempdir();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Expunge folders: none"),
            "expected the empty-expunge line:\n{text}"
        );
        // A flat config has no `[defaults]` layer to inherit from.
        assert!(
            text.contains("  INBOX(account)"),
            "flat-config protected entry missing:\n{text}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_reports_no_explicit_overrides_as_none() {
        let dir = tight_tempdir();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Explicit tool overrides: none"),
            "expected the empty-overrides line:\n{text}"
        );
    }

    #[tokio::test]
    async fn dry_run_surfaces_parse_errors_as_anyhow() {
        let dir = TempDir::new().unwrap();
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not valid toml =\n").unwrap();
        let err = run(&bad, &mut Vec::new()).await.unwrap_err();
        // anyhow chains context; the bottom-most error comes from rimap-config.
        let mut chain = String::new();
        for cause in err.chain() {
            use std::fmt::Write as _;
            writeln!(chain, "{cause}").unwrap();
        }
        assert!(chain.contains("loading config") || chain.contains("parse"));
    }

    #[test]
    fn write_fingerprint_section_unpinned_prints_paste_hint() {
        let fp = synth_fp(b"unpinned-test");
        let info = PreflightInfo::new(vec!["IMAP4REV1".into()], fp);
        let result: Result<PreflightInfo, ImapError> = Ok(info);
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("TLS fingerprint (sha256):"),
            "header missing:\n{text}"
        );
        assert!(
            text.contains(&fp.to_string()),
            "fingerprint missing:\n{text}"
        );
        assert!(
            text.contains("tls_fingerprint_sha256 ="),
            "paste hint missing:\n{text}"
        );
    }

    #[test]
    fn write_fingerprint_section_pinned_match_prints_confirmation() {
        let fp = synth_fp(b"matched-pin");
        let info = PreflightInfo::new(vec!["IMAP4REV1".into()], fp);
        let result: Result<PreflightInfo, ImapError> = Ok(info);
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, Some(fp)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("matches configured pin"),
            "match confirmation missing:\n{text}"
        );
        // Paste hint must NOT appear when already pinned-and-matched.
        assert!(
            !text.contains("tls_fingerprint_sha256 ="),
            "paste hint should not appear on match:\n{text}"
        );
    }

    #[test]
    fn write_fingerprint_section_pinned_mismatch_prints_diagnostic() {
        let observed = synth_fp(b"observed-cert");
        let expected = synth_fp(b"expected-pin");
        let result: Result<PreflightInfo, ImapError> = Err(ImapError::Tls { observed, expected });
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, Some(expected)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("observed:"), "observed: missing:\n{text}");
        assert!(text.contains("expected:"), "expected: missing:\n{text}");
        assert!(
            text.contains(&observed.to_string()),
            "observed hex missing:\n{text}"
        );
        assert!(
            text.contains(&expected.to_string()),
            "expected hex missing:\n{text}"
        );
        assert!(text.contains("hint:"), "hint line missing:\n{text}");
    }

    #[test]
    fn write_fingerprint_section_other_error_prints_nothing() {
        let result: Result<PreflightInfo, ImapError> =
            Err(ImapError::Timeout { op: "tcp_connect" });
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, None).unwrap();
        assert!(
            out.is_empty(),
            "fingerprint section must be silent on non-TLS error"
        );
    }

    #[test]
    fn write_fingerprint_section_pinned_ok_mismatch_defensive_prints_observed() {
        // Defensive branch: an `Ok(info)` from probe_preflight where the
        // observed fingerprint disagrees with the configured pin should be
        // unreachable in production (the verifier rejects the handshake on
        // mismatch, producing Err(Tls) instead). The branch is kept as a
        // future-proofing guard. This test exercises the branch with a
        // synthesized state to pin its behavior.
        let observed = synth_fp(b"observed-defensive");
        let pinned = synth_fp(b"different-pin-defensive");
        assert_ne!(observed, pinned, "test setup: fingerprints must differ");
        let info = PreflightInfo::new(vec!["IMAP4REV1".into()], observed);
        let result: Result<PreflightInfo, ImapError> = Ok(info);
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, Some(pinned)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("TLS fingerprint (sha256):"),
            "header missing:\n{text}"
        );
        assert!(
            text.contains(&observed.to_string()),
            "observed hex missing:\n{text}"
        );
        assert!(
            text.contains("pin mismatch") && text.contains("unexpected"),
            "anomaly annotation missing:\n{text}"
        );
        // The defensive arm prints observed only — no paste hint, no match
        // confirmation, no observed/expected diagnostic.
        assert!(
            !text.contains("tls_fingerprint_sha256 ="),
            "paste hint must not appear:\n{text}"
        );
        assert!(
            !text.contains("matches configured pin"),
            "match confirmation must not appear:\n{text}"
        );
        assert!(
            !text.contains("expected:"),
            "mismatch diagnostic must not appear:\n{text}"
        );
    }

    fn write_multi_account_config(dir: &TempDir) -> PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[[accounts]]
name = "personal"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@personal.test"

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = audit.display(),
            base = dir.path().display(),
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_single_account_omits_account_header() {
        // With exactly one account the "Account: <name>" header should be
        // absent — it is only useful when multiple accounts share the output.
        let dir = tight_tempdir();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("Account:"),
            "single-account output must not contain 'Account:' header:\n{text}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_multi_account_prints_account_headers() {
        // With two accounts each section must be prefixed with
        // "Account: <name>" so users can tell the sections apart.
        let dir = tight_tempdir();
        let path = write_multi_account_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Account: work"),
            "multi-account output must contain 'Account: work':\n{text}"
        );
        assert!(
            text.contains("Account: personal"),
            "multi-account output must contain 'Account: personal':\n{text}"
        );
    }
}
