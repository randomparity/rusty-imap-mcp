//! Per-kind `log_*` family that wraps the [`super::AuditWriter::emit`]
//! skeleton with a typed shape per record kind.
//!
//! ## `log_*` family input convention
//!
//! All `log_*` methods take a single argument so the family stays
//! uniform at the call site. Two shapes are accepted:
//!
//! - **Record struct directly** (`Auth`, `ProcessEnd`) — the on-disk
//!   record has no derived fields and the caller can construct it
//!   verbatim. Adding a `<Kind>Inputs` shim would be a redirect with
//!   no behavior.
//! - **`<Kind>Inputs` shim** ([`ProcessStartInputs`], [`ToolStartInputs`],
//!   [`ToolEndInputs`]) — the on-disk record carries derived state
//!   (`PostureEffective::from_optional`, inode-change computation) that the
//!   caller would otherwise have to re-derive at every site.
//!
//!   [`ToolStartInputs`] and [`ToolEndInputs`] convert through
//!   `From<Inputs> for record::<Kind>`. [`ProcessStartInputs`] does not: its
//!   conversion is written out inside [`AuditWriter::log_process_start`],
//!   because the derivation needs `trailing` and `current_inode` together to
//!   compute `audit_file_inode_changed` and to split `trailing` across three
//!   record fields. That hand-written mapping is the one place a field can be
//!   miswired without the compiler noticing — it moves three `String`s whose
//!   order the type system cannot check — so it is pinned field-by-field in
//!   `tests/non_exhaustive_record.rs`.
//!
//! New `log_*` methods MUST follow this rule: pick the record struct
//! directly when no translation is needed; introduce a `*Inputs` shim
//! when it is. Do not pass positional arguments. The rule is also
//! pinned in `AGENTS.md` so future additions do not drift.

use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};

use crate::AuditError;

use super::AuditWriter;

impl AuthEventSink for AuditWriter {
    /// Record `event` as an `auth` audit record. Maps
    /// [`AuditError`] into [`AuthSinkError`] using the underlying
    /// audit error code; the sanitized `message` deliberately omits
    /// the audit file path (operator-configured layout) so it can
    /// flow into transport-layer error chains without leaking it.
    fn emit_auth(&self, event: rimap_core::AuthEvent) -> Result<(), AuthSinkError> {
        match self.log_auth(event) {
            Ok(_seq) => Ok(()),
            Err(err) => {
                let code = err.code();
                let message = format!("audit emit_auth: {code}");
                // The full `AuditError` carries the audit-file path
                // (operator-configured filesystem layout) in its
                // Display chain. Log the raw error with
                // `error_code = %code` at error level here — the
                // `AuthSinkError` handed to callers carries only an
                // opaque source that stringifies to the same stable
                // code, so a downstream `tracing::error!(error = ?e)`
                // or `anyhow::Error::chain()` walk can never leak
                // the path.
                tracing::error!(
                    error_code = %code,
                    path = %self.path().display(),
                    "audit emit_auth failed",
                );
                let opaque = std::io::Error::other(format!("rimap-audit emit_auth: {code}"));
                Err(AuthSinkError::new(code, message, Box::new(opaque)))
            }
        }
    }

    /// Count an `auth` record the caller could not surface a failure for.
    ///
    /// Folded into the same counter as a `fail_open` suppression: both mean
    /// "a record that should be on disk is not, and no caller was told".
    /// Distinguishing them would need a second counter for no decision an
    /// operator makes differently — either way the audit trail has a hole and
    /// the cause is in the logs. That merged count is what `process_end`
    /// persists as `records_lost` (#647).
    fn note_auth_write_lost(&self) {
        self.count_suppressed_failure();
    }
}

impl AuditWriter {
    /// Build an `auth` record from `payload`, allocate a seq, and write it.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_auth(
        &self,
        payload: crate::record::AuthEvent,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::Auth(payload))
    }

    /// Build a `tool_start` record, allocate a seq, and write it. Returns
    /// the allocated `seq` — the caller should retain this value and pass
    /// it back to [`AuditWriter::log_tool_end`] as `start_seq` so the two
    /// records can be paired.
    ///
    /// `tool_start` is NOT fsynced per existing policy; see the private
    /// `needs_fsync` helper in `writer/emit.rs`.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_tool_start(
        &self,
        inputs: ToolStartInputs,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        // `inputs.account = None` + `inputs.posture_effective = None` models
        // the infrastructure-tool dispatch path (`use_account`,
        // `list_accounts`) which bypasses per-account posture gating by
        // design. `PostureEffective` serializes as the historical on-disk
        // strings (`"infrastructure"` or the kebab-case posture) so readers
        // can distinguish these records from per-account tool calls.
        let seq = self.emit(crate::record::Payload::ToolStart(inputs.into()))?;
        // One increment per dispatched tool call; read at shutdown to fill
        // `ProcessEnd::total_tool_calls`. `Relaxed` is sufficient — the
        // count is a monotonic process-lifetime metric, not a happens-before
        // signal.
        self.tool_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(seq)
    }

    /// Build a `tool_end` record, allocate a seq, and write it.
    /// `inputs.start_seq` must be the seq returned by the paired
    /// [`AuditWriter::log_tool_start`].
    ///
    /// `tool_end` is NOT fsynced per existing policy.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_tool_end(
        &self,
        inputs: ToolEndInputs,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::ToolEnd(inputs.into()))
    }

    /// Build a `process_end` record from `payload`, allocate a seq, and
    /// write it. Stamps the record with the writer's stable `process_id`
    /// and `Timestamp::now()`. Returns the allocated `seq` on success.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_process_end(
        &self,
        payload: crate::record::ProcessEnd,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        self.emit(crate::record::Payload::ProcessEnd(payload))
    }

    /// Build a `process_start` record from `inputs` and the writer's own
    /// `process_id`, allocate a seq, and write it. Computes the
    /// `audit_file_inode_changed` tamper signal from
    /// `inputs.trailing.last_recorded_inode` vs `inputs.current_inode`.
    ///
    /// # Errors
    /// Propagates any error from `allocate_seq` or `write_record`.
    pub fn log_process_start(
        &self,
        inputs: ProcessStartInputs,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        let inode_changed = inputs
            .trailing
            .last_recorded_inode
            .is_some_and(|prior| prior != inputs.current_inode);
        let payload = crate::record::ProcessStart {
            version: inputs.version,
            git_commit: inputs.git_commit,
            posture: inputs.posture,
            accounts: inputs.accounts,
            tool_matrix: inputs.tool_matrix,
            config_path: inputs.config_path,
            config_hash_sha256: inputs.config_hash_sha256,
            previous_last_seq: inputs.trailing.last_seq,
            previous_process_id: inputs.trailing.last_process_id,
            previous_file_inode: inputs.current_inode,
            audit_file_inode_changed: inode_changed,
        };
        self.emit(crate::record::Payload::ProcessStart(payload))
    }
}

/// Inputs to [`AuditWriter::log_tool_end`].
///
/// `#[non_exhaustive]` for the same reason the record it builds is: this is
/// the seam a new `tool_end` field arrives through, and #632 showed that
/// widening only the record leaves the inputs struct as a second break.
#[derive(Debug)]
#[non_exhaustive]
pub struct ToolEndInputs {
    /// Seq returned by the paired [`AuditWriter::log_tool_start`].
    pub start_seq: crate::record::ids::Seq,
    /// Which tool completed.
    pub tool: rimap_core::tool::ToolName,
    /// Account scope (`None` for infrastructure tools).
    pub account: Option<String>,
    /// Terminal outcome (ok / error / ...).
    pub status: crate::record::ToolStatus,
    /// Error classification, if any.
    pub error_code: Option<rimap_core::ErrorCode>,
    /// Wall-clock milliseconds.
    pub duration_ms: u64,
    /// Outbound result counts and sizes.
    pub result_summary: crate::record::ResultSummary,
    /// Recently-read message IDs and window.
    pub provenance: crate::record::Provenance,
}

impl ToolEndInputs {
    /// Describe a completed tool call.
    ///
    /// `account` and `error_code` start `None` (an infrastructure tool has no
    /// account; a success has no error code) and `result_summary` starts
    /// empty, which is the correct record for a tool that returned nothing.
    /// Assign whichever apply.
    ///
    /// Unlike [`ToolStartInputs::new`], `account` is defaulted here rather
    /// than required: `start_seq` names the paired `tool_start`, which carries
    /// the account and the posture that governed the dispatch, so a `tool_end`
    /// that omits it is recoverable rather than misleading. It is duplicated
    /// onto this record only so a single line reads on its own. Nothing on a
    /// `tool_end` makes a security claim the way `posture_effective` does.
    #[must_use]
    pub fn new(
        start_seq: crate::record::ids::Seq,
        tool: rimap_core::tool::ToolName,
        status: crate::record::ToolStatus,
        duration_ms: u64,
        provenance: crate::record::Provenance,
    ) -> Self {
        Self {
            start_seq,
            tool,
            account: None,
            status,
            error_code: None,
            duration_ms,
            result_summary: crate::record::ResultSummary::default(),
            provenance,
        }
    }
}

impl From<ToolEndInputs> for crate::record::ToolEnd {
    fn from(i: ToolEndInputs) -> Self {
        Self {
            account: i.account,
            start_seq: i.start_seq,
            tool: i.tool,
            status: i.status,
            error_code: i.error_code,
            duration_ms: i.duration_ms,
            result_summary: i.result_summary,
            provenance: i.provenance,
        }
    }
}

/// Inputs to [`AuditWriter::log_tool_start`].
///
/// Mirrors [`ToolEndInputs`] so the call sites use a consistent
/// construction shape instead of a long positional argument list.
#[derive(Debug)]
#[non_exhaustive]
pub struct ToolStartInputs {
    /// Which tool is being dispatched.
    pub tool: rimap_core::tool::ToolName,
    /// Account scope (`None` for infrastructure tools like `use_account` /
    /// `list_accounts`, which bypass per-account posture gating).
    pub account: Option<String>,
    /// Effective posture at dispatch time (`None` for infrastructure tools).
    /// Serializes as the historical on-disk strings (`"infrastructure"` or
    /// the kebab-case posture) via [`crate::record::PostureEffective`].
    pub posture_effective: Option<rimap_core::Posture>,
    /// Redacted arguments object produced by `redact::Redactor`.
    pub arguments_redacted: serde_json::Value,
    /// SHA-256 of the canonical JSON serialization of the *unredacted*
    /// payload, hex-encoded.
    pub arguments_hash_sha256: String,
}

impl ToolStartInputs {
    /// Describe a tool call entering dispatch.
    ///
    /// `account` and `posture_effective` are parameters rather than defaulted
    /// fields, for the reason [`crate::record::ProcessEnd::new`] takes
    /// `records_lost`: `None` is not an absent value here. It is rendered on
    /// disk as the literal `"infrastructure"`, whose documented meaning is
    /// that this dispatch bypassed per-account posture gating by design
    /// (`use_account`, `list_accounts`). A caller that left the field to a
    /// default would record an account-scoped, posture-gated call as exempt
    /// from gating. They travel together -- an infrastructure tool has
    /// neither, an account-scoped dispatch has both -- so passing
    /// `(None, None)` is the explicit way to say "infrastructure".
    #[must_use]
    pub fn new(
        tool: rimap_core::tool::ToolName,
        account: Option<String>,
        posture_effective: Option<rimap_core::Posture>,
        arguments_redacted: serde_json::Value,
        arguments_hash_sha256: String,
    ) -> Self {
        Self {
            tool,
            account,
            posture_effective,
            arguments_redacted,
            arguments_hash_sha256,
        }
    }
}

impl From<ToolStartInputs> for crate::record::ToolStart {
    fn from(i: ToolStartInputs) -> Self {
        Self {
            account: i.account,
            tool: i.tool,
            posture_effective: crate::record::PostureEffective::from_optional(i.posture_effective),
            arguments_redacted: i.arguments_redacted,
            arguments_hash_sha256: i.arguments_hash_sha256,
        }
    }
}

/// Inputs to [`AuditWriter::log_process_start`]. Caller computes the
/// inode-tamper signal by passing the trailing state from
/// [`crate::writer::self_check::read_trailing_state`] (run before `open`) and the
/// current inode (run after `open`, via [`crate::writer::self_check::current_inode`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProcessStartInputs {
    /// `CARGO_PKG_VERSION` of the running binary.
    pub version: String,
    /// Short git SHA of the running binary (7 hex chars, optionally
    /// suffixed `-dirty`, or `unknown` when no git information is
    /// available). Populated by callers via `rimap_core::version::commit`.
    pub git_commit: String,
    /// Effective base posture at startup (single-account mode).
    /// Typed at the construction seam to keep the on-disk string form
    /// in sync with the [`rimap_core::Posture`] taxonomy.
    pub posture: Option<rimap_core::Posture>,
    /// Per-account summaries (multi-account mode).
    pub accounts: Option<Vec<crate::record::AccountSummary>>,
    /// Per-account posture and explicit per-tool verdicts with provenance
    /// (#632). One entry per account regardless of single- or
    /// multi-account mode.
    pub tool_matrix: Vec<crate::record::AccountToolMatrix>,
    /// Absolute path of the loaded config file.
    pub config_path: std::path::PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Trailing state read from the audit file BEFORE this writer was opened.
    pub trailing: crate::writer::self_check::TrailingState,
    /// Inode of the audit file as observed AFTER this writer was opened
    /// (call `crate::writer::self_check::current_inode` on the path).
    pub current_inode: u64,
}

impl ProcessStartInputs {
    /// Describe a starting process.
    ///
    /// `posture`, `accounts` and `tool_matrix` start empty: they are the
    /// mode-dependent fields (`posture` for single-account, `accounts` for
    /// multi-account, `tool_matrix` for both), and boot assigns whichever it
    /// resolved. The six parameters are the ones every start has.
    ///
    /// They stay defaulted rather than joining the signature the way
    /// [`ToolStartInputs::new`]'s `posture_effective` did, for two reasons. An
    /// empty `tool_matrix` is not a claim: it is `#[serde(default)]` precisely
    /// because records written before #632 carry no such field, so a reader
    /// already cannot distinguish "no overrides" from "written by an older
    /// build" and does not read it as "no account had an override". And at
    /// nine parameters a constructor is harder to call correctly than the
    /// struct it builds, which is the problem this type exists to solve.
    #[must_use]
    pub fn new(
        version: String,
        git_commit: String,
        config_path: std::path::PathBuf,
        config_hash_sha256: String,
        trailing: crate::writer::self_check::TrailingState,
        current_inode: u64,
    ) -> Self {
        Self {
            version,
            git_commit,
            posture: None,
            accounts: None,
            tool_matrix: Vec::new(),
            config_path,
            config_hash_sha256,
            trailing,
            current_inode,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use rimap_core::auth_event::{AuthEvent, AuthResult};
    use rimap_core::auth_sink::AuthEventSink;
    use tempfile::TempDir;

    use crate::writer::{AuditOptions, AuditWriter};

    /// `note_auth_write_lost` is how a caller with nowhere to return an audit
    /// failure — `rimap-imap`'s cut-connect drop guard, and its auth-failure
    /// branch — keeps the loss countable. It must reach the same counter a
    /// `fail_open` suppression does, or the stricter `fail_open = false`
    /// leaves an operator with less evidence than the laxer setting.
    #[test]
    fn note_auth_write_lost_increments_the_lost_record_counter() {
        let dir = TempDir::new().unwrap();
        let writer = AuditWriter::open(&AuditOptions {
            path: dir.path().join("audit.jsonl"),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::Seq::FIRST,
        })
        .expect("audit open");

        assert_eq!(writer.suppressed_failures(), 0);
        writer.note_auth_write_lost();
        writer.note_auth_write_lost();
        assert_eq!(
            writer.suppressed_failures(),
            2,
            "each reported loss must be counted",
        );
    }

    #[test]
    fn auth_event_sink_emit_auth_writes_a_record_to_disk() {
        // Pin `<impl AuthEventSink for AuditWriter>::emit_auth -> Ok(())`
        // mutation: routing through the trait must produce an on-disk auth
        // record. The `Ok(())` stub would silently drop the record.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let event = AuthEvent {
            account: Some("alice".to_string()),
            result: AuthResult::Success,
            host: "127.0.0.1".to_string(),
            port: 993,
            username: "alice@example.test".to_string(),
            tls_fingerprint_sha256: None,
            fingerprint_match: None,
            error_code: None,
            credential_source: None,
        };

        // Drive through the trait method, not the inherent `log_auth`, so
        // the impl block under test is exercised.
        AuthEventSink::emit_auth(&writer, event).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents
            .lines()
            .next()
            .expect("emit_auth must persist a line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["account"], "alice");
    }
}
