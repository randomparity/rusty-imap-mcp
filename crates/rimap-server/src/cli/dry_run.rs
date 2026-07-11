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
use rimap_audit::{AuditOptions, AuditWriter};
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
    // not useful here; Seq::FIRST is correct.
    let _audit_writer = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
        rotate_bytes: multi.audit.rotate_bytes,
        rotate_keep: multi.audit.rotate_keep,
        retention_seconds: multi.audit.retention_seconds,
        fail_open: multi.audit.fail_open,
        initial_seq: rimap_audit::Seq::FIRST,
    })
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
        use rimap_audit::{AuditOptions, AuditWriter};

        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);

        // First dry-run acquires the lock for the duration of the call.
        let mut out1 = Vec::new();
        run(&path, &mut out1).await.unwrap();

        // Hold the audit file open with a direct writer so the second dry-run
        // collides with us.
        let audit_path = dir.path().join("audit.jsonl");
        let _held = AuditWriter::open(&AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .unwrap();

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
