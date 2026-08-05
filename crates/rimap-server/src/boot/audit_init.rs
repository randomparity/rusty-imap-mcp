//! Initialize the audit writer for a long-running process: pre-scan trailing
//! state, open the writer, capture the current inode, emit `process_start`.

use std::path::Path;

use rimap_audit::record::AccountSummary;
use rimap_audit::{AuditError, AuditOptions, AuditWriter, ProcessStartInputs, Seq};
use rimap_config::validate::ValidatedMultiConfig;
use sha2::{Digest, Sha256};

/// Open the audit writer for a multi-account config and emit the
/// `process_start` record with per-account summaries.
///
/// # Errors
/// Propagates any `AuditError` from the trailing-state read, open, inode
/// fetch, or `process_start` write.
pub fn init_audit_writer_multi(
    multi: &ValidatedMultiConfig,
    config_file_path: &Path,
) -> Result<AuditWriter, AuditError> {
    let audit_path = &multi.audit.path;
    let trailing = rimap_audit::read_trailing_state(audit_path)?;
    let initial_seq = trailing.last_seq.map_or(Seq::FIRST, Seq::next);

    let writer = AuditWriter::open(&AuditOptions {
        path: audit_path.clone(),
        rotate_bytes: multi.audit.rotate_bytes,
        rotate_keep: multi.audit.rotate_keep,
        retention_seconds: multi.audit.retention_seconds,
        fail_open: multi.audit.fail_open,
        initial_seq,
    })?;

    if let Some(parent) = writer.path().parent() {
        rimap_audit::reader::backup_exclude::exclude_from_backup(parent);
    }

    let current = rimap_audit::current_inode(audit_path)?;
    let config_hash = compute_config_hash(config_file_path);

    let single_account = multi.accounts.len() == 1;
    let posture = if single_account {
        multi.accounts.values().next().map(|a| a.security.posture)
    } else {
        None
    };
    let accounts = if single_account {
        None
    } else {
        Some(
            multi
                .accounts
                .values()
                .map(|a| {
                    AccountSummary::new(
                        a.id.as_str().to_string(),
                        a.security.posture,
                        a.imap.host.clone(),
                    )
                })
                .collect(),
        )
    };

    // Unlike `posture` / `accounts`, this is populated for single- and
    // multi-account configs alike: the provenance of a tool verdict is
    // exactly as worth recording for one account as for five, and a reader
    // reconstructing a boot should not have to branch on account count to
    // find it (#632).
    let tool_matrix = multi
        .accounts
        .values()
        .map(crate::boot::tool_matrix::account_tool_matrix)
        .collect();

    writer.log_process_start(ProcessStartInputs {
        version: rimap_core::version::version().to_string(),
        git_commit: rimap_core::version::commit().to_string(),
        posture,
        accounts,
        tool_matrix,
        config_path: config_file_path.to_path_buf(),
        config_hash_sha256: config_hash,
        trailing,
        current_inode: current,
    })?;

    Ok(writer)
}

fn compute_config_hash(path: &Path) -> String {
    // Intentional: if the config file disappears between load and hash,
    // record an empty hash rather than panic. The config was already
    // successfully loaded earlier in the boot sequence; this is a startup
    // hot path, not user-facing input validation. Log the failure so an
    // operator investigating an empty hash can see why.
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to read config for hash; audit record will have empty hash",
        );
        Vec::new()
    });
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    use super::init_audit_writer_multi;

    fn write_config(dir: &TempDir) -> std::path::PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
posture = "readonly"

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

    #[test]
    fn process_start_emitted_as_first_record() {
        use sha2::{Digest, Sha256};

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);

        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate_legacy_as_multi(raw).unwrap();

        // Scope the writer so the file lock is released before reading.
        let audit_path = validated.audit.path.clone();
        {
            init_audit_writer_multi(&validated, &config_path).unwrap();
        }
        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let first_line = contents.lines().next().unwrap();
        let first: serde_json::Value = serde_json::from_str(first_line).unwrap();

        assert_eq!(first["kind"], "process_start");
        assert_eq!(first["seq"], 1);
        assert_eq!(first["posture"], "readonly");

        // config_path in the record must be the TOML file, not the audit log.
        assert_eq!(
            first["config_path"].as_str().unwrap(),
            config_path.to_str().unwrap()
        );

        // config_hash_sha256 must be the hash of the config file contents.
        let config_bytes = std::fs::read(&config_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&config_bytes);
        let expected_hash = hex::encode(hasher.finalize());
        assert_eq!(first["config_hash_sha256"].as_str().unwrap(), expected_hash);
    }

    /// Two-account config whose `[defaults.security.tools]` allows
    /// `delete_message` and whose `work` account tightens posture to
    /// `readonly` without restating that tool. This is the #632 case: the
    /// account holds a destructive tool purely by inheritance.
    fn write_inherited_allow_config(dir: &TempDir) -> std::path::PathBuf {
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
        config_path
    }

    #[test]
    fn process_start_records_inherited_allow_on_tightened_posture() {
        // Acceptance criteria for #632. Asserted against the raw JSONL line
        // rather than a parsed `AuditRecord`: the field is
        // `#[serde(default)]`, so a lenient parse would report an empty
        // matrix as a successful read.
        let dir = TempDir::new().unwrap();
        let config_path = write_inherited_allow_config(&dir);
        let validated = rimap_config::loader::load_and_validate(&config_path).unwrap();
        let audit_path = validated.audit.path.clone();
        {
            init_audit_writer_multi(&validated, &config_path).unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let line = contents.lines().next().unwrap();
        assert!(
            line.contains(r#""tool_matrix""#),
            "process_start must carry tool_matrix:\n{line}",
        );
        let first: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(first["kind"], "process_start");

        let matrix = &first["tool_matrix"];
        assert_eq!(matrix.as_array().unwrap().len(), 1);
        assert_eq!(matrix[0]["account"], "work");
        assert_eq!(matrix[0]["posture"], "readonly");

        let tools = matrix[0]["tools"].as_array().unwrap();
        let deletion = tools
            .iter()
            .find(|t| t["tool"] == "delete_message")
            .expect("inherited delete_message verdict missing");
        assert_eq!(deletion["allow"], true);
        assert_eq!(deletion["source"], "inherited");

        let search = tools
            .iter()
            .find(|t| t["tool"] == "search")
            .expect("account-written search verdict missing");
        assert_eq!(search["allow"], false);
        assert_eq!(search["source"], "account");
    }

    #[test]
    fn single_account_process_start_carries_the_same_tool_matrix_shape() {
        // The `posture` / `accounts` fields branch on account count; the
        // tool matrix deliberately does not, so a reader never has to.
        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate_legacy_as_multi(raw).unwrap();
        let audit_path = validated.audit.path.clone();
        {
            init_audit_writer_multi(&validated, &config_path).unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let line = contents.lines().next().unwrap();
        let first: serde_json::Value = serde_json::from_str(line).unwrap();
        // Single-account mode: `accounts` is omitted, `tool_matrix` is not.
        assert!(first.get("accounts").is_none());
        let matrix = first["tool_matrix"].as_array().unwrap();
        assert_eq!(matrix.len(), 1);
        assert_eq!(matrix[0]["account"], "default");
        assert_eq!(matrix[0]["posture"], "readonly");
        assert_eq!(
            matrix[0]["tools"].as_array().unwrap().len(),
            0,
            "this config declares no explicit verdicts",
        );
    }

    #[test]
    fn process_end_writes_after_start() {
        use rimap_audit::{ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate_legacy_as_multi(raw).unwrap();
        let audit_path = validated.audit.path.clone();

        {
            let writer = init_audit_writer_multi(&validated, &config_path).unwrap();
            writer
                .log_process_end(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: 0,
                    records_lost: 0,
                })
                .unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["kind"], "process_start");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["kind"], "process_end");
        assert_eq!(second["seq"], 2);
    }

    #[test]
    fn seq_continues_from_trailing_state() {
        use rimap_audit::{
            AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason,
            ProcessId, Seq, Timestamp,
        };

        let dir = TempDir::new().unwrap();
        let config_path = write_config(&dir);
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let validated = rimap_config::validate::validate_legacy_as_multi(raw).unwrap();
        let audit_path = validated.audit.path.clone();

        // Pre-populate the audit file with some records so trailing state is non-empty.
        {
            let writer = AuditWriter::open(&AuditOptions {
                path: audit_path.clone(),
                rotate_bytes: 0,
                rotate_keep: 0,
                retention_seconds: None,
                fail_open: false,
                initial_seq: Seq::FIRST,
            })
            .unwrap();
            let pid = ProcessId::new_now();
            writer
                .write_record(&AuditRecord {
                    seq: Seq(1),
                    ts: Timestamp::now(),
                    process_id: pid,
                    payload: Payload::ProcessEnd(ProcessEnd {
                        reason: ProcessEndReason::Eof,
                        total_tool_calls: 0,
                        records_lost: 0,
                    }),
                })
                .unwrap();
        }

        // init_audit_writer should resume from seq 2.
        {
            init_audit_writer_multi(&validated, &config_path).unwrap();
        }

        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert!(lines.len() >= 2, "expected at least 2 records");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["kind"], "process_start");
        assert_eq!(second["seq"], 2);
    }
}
