//! Downstream-construction and on-disk contract for `rimap_audit::record` (#706).
//!
//! `#[non_exhaustive]` is a no-op inside the crate that defines the type, so
//! an in-crate `#[cfg(test)]` module can never exercise it. An integration
//! test is a separate crate, which makes this file the only place in the
//! workspace where the attribute is actually in force on the record types --
//! every construction below is compiled under exactly the rules a downstream
//! consumer gets.
//!
//! Two properties are pinned here, and the second is the one that matters
//! most: these records are an **append-only on-disk format**, and a silent
//! format change to an audit trail is far worse than a compile break.
//!
//! 1. The `T::new(..)` constructors are the only downstream way to mint these
//!    types. `..Default::default()` is not an alternative: functional-update
//!    syntax is still a struct expression, which `#[non_exhaustive]` rejects
//!    across a crate boundary (rustc E0639). Downstream pattern matches need
//!    a rest pattern.
//! 2. A record built through those constructors serializes to a byte-exact
//!    JSONL line. `#[non_exhaustive]` is a Rust-visibility construct that
//!    does not reach serde, so adding it must not have moved a single byte --
//!    and any future field addition, which the attribute now makes an
//!    *additive* change at the API level, must still leave these lines alone
//!    or it is not additive on disk. `docs/audit-log.md` ("Compatibility
//!    contract") is the normative statement; these are its teeth.
//!
//! Sibling of `rimap-config`'s `non_exhaustive_model.rs` (#665) and
//! `non_exhaustive_validate.rs` (#707).

#![expect(clippy::expect_used, reason = "integration test")]

use rimap_audit::record::{
    AccountToolMatrix, AttachmentProvenance, AuditRecord, Payload, ProcessEnd, ProcessEndReason,
    Provenance, ResultSummary, ToolEnd, ToolStatus, ToolVerdict, VerdictSource,
};
use rimap_audit::{ProcessId, Seq, Timestamp};
use rimap_core::{Posture, tool::ToolName};

/// A fixed timestamp, parsed through the public serde surface.
///
/// `Timestamp`'s inner `OffsetDateTime` is private, so this is the only way a
/// downstream crate pins one -- which is also what makes the golden lines
/// below reproducible rather than wall-clock dependent.
fn fixed_ts() -> Timestamp {
    serde_json::from_str(r#""2026-05-05T12:00:00.234Z""#).expect("fixed RFC 3339 timestamp parses")
}

/// A fixed process ULID, likewise parsed rather than generated.
fn fixed_pid() -> ProcessId {
    serde_json::from_str(r#""01HM0000000000000000000000""#).expect("fixed ULID parses")
}

// ---------------------------------------------------------------------------
// 1. Downstream construction contract
// ---------------------------------------------------------------------------

/// The constructor plus field assignment is the downstream idiom. Writing
/// `ProcessEnd { reason, total_tool_calls, records_lost }` here, or
/// `ProcessEnd { reason, ..Default::default() }`, is rejected by rustc
/// (E0639) -- both are struct expressions.
#[test]
fn record_types_are_built_through_constructors_and_field_assignment() {
    let matrix = {
        let mut m = AccountToolMatrix::new("work".to_string(), Posture::Readonly);
        m.tools = vec![ToolVerdict::new(
            ToolName::DeleteMessage,
            false,
            VerdictSource::Account,
        )];
        m
    };
    assert_eq!(matrix.account, "work");
    assert_eq!(matrix.tools.len(), 1);

    // `ResultSummary` is the one type whose constructor is `Default`: every
    // field is `#[serde(default)]`, so there is nothing a `new` would have to
    // take. Assignment reaches the rest.
    let mut summary = ResultSummary::default();
    summary.bytes_returned = 4821;
    summary.attachments_sent = vec![AttachmentProvenance::new("report.pdf".to_string(), 1024)];
    assert_eq!(summary.attachments_sent[0].filename, "report.pdf");

    let record = AuditRecord::new(
        Seq(1),
        fixed_ts(),
        fixed_pid(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 7, 3)),
    );
    assert_eq!(record.seq, Seq(1));
}

/// `ProcessEnd::new` takes `records_lost` even though the field is
/// `#[serde(default)]`, because a zero there is a durable claim that the
/// process's record stream has no hole in it. The constructor records what
/// the caller passed rather than assuming the reassuring value.
#[test]
fn process_end_constructor_records_the_loss_count_it_was_given() {
    let lost = ProcessEnd::new(ProcessEndReason::Error, 12, 4);
    assert_eq!(lost.records_lost, 4);
    assert_eq!(lost.total_tool_calls, 12);

    let clean = ProcessEnd::new(ProcessEndReason::Eof, 12, 0);
    assert_eq!(clean.records_lost, 0);
}

/// A downstream match on a `#[non_exhaustive]` struct needs a rest pattern.
/// Without the `..` this does not compile, which is the whole point: a field
/// added later cannot silently change what this destructuring means.
#[test]
fn downstream_pattern_matches_need_a_rest_pattern() {
    let end = ProcessEnd::new(ProcessEndReason::SignalTerm, 3, 0);
    let ProcessEnd { reason, .. } = end;
    assert_eq!(reason, ProcessEndReason::SignalTerm);

    let provenance = Provenance::new(60, vec!["<a@example>".to_string()]);
    let Provenance { window_seconds, .. } = provenance;
    assert_eq!(window_seconds, 60);
}

// ---------------------------------------------------------------------------
// 2. On-disk format: byte-exact golden lines
// ---------------------------------------------------------------------------

/// Every golden below is one line of the append-only JSONL file. A diff here
/// is a change to a format that already-written files are in, so treat a
/// failure as "the format moved", not "the fixture is stale" -- see
/// `docs/audit-log.md`.
fn assert_golden(record: &AuditRecord, expected: &str) {
    let actual = serde_json::to_string(record).expect("record serializes");
    assert_eq!(
        actual, expected,
        "on-disk JSONL changed.\n  expected: {expected}\n    actual: {actual}\n\
         Adding a field is additive only if existing records keep their bytes; \
         see docs/audit-log.md (Compatibility contract).",
    );
}

#[test]
fn process_end_line_is_byte_exact() {
    let record = AuditRecord::new(
        Seq(1),
        fixed_ts(),
        fixed_pid(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 7, 3)),
    );
    assert_golden(
        &record,
        r#"{"seq":1,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":7,"records_lost":3}"#,
    );
}

#[test]
fn tool_end_line_is_byte_exact() {
    let mut summary = ResultSummary::default();
    summary.message_ids_returned = vec!["<abc@example>".to_string()];
    summary.bytes_returned = 4821;

    let mut inputs_end = ToolEnd::from(rimap_audit::ToolEndInputs::new(
        Seq(10),
        ToolName::FetchMessage,
        ToolStatus::Ok,
        47,
        Provenance::new(60, vec!["<abc@example>".to_string()]),
    ));
    inputs_end.result_summary = summary;

    let record = AuditRecord::new(
        Seq(11),
        fixed_ts(),
        fixed_pid(),
        Payload::ToolEnd(inputs_end),
    );
    assert_golden(
        &record,
        r#"{"seq":11,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"tool_end","start_seq":10,"tool":"fetch_message","status":"ok","error_code":null,"duration_ms":47,"result_summary":{"message_ids_returned":["<abc@example>"],"bytes_returned":4821,"truncated":false,"security_warnings_emitted":[]},"provenance":{"window_seconds":60,"message_ids_recently_read":["<abc@example>"]}}"#,
    );
}

/// The fields `#[serde(skip_serializing_if)]` omits stay omitted. This is the
/// half of "additive" that the attribute cannot enforce: a new field without
/// a skip or default would appear in every line written from then on, and
/// every reader of the old shape would have to be taught about it.
#[test]
fn unpopulated_optional_fields_stay_off_the_line() {
    let record = AuditRecord::new(
        Seq(11),
        fixed_ts(),
        fixed_pid(),
        Payload::ToolEnd(ToolEnd::from(rimap_audit::ToolEndInputs::new(
            Seq(10),
            ToolName::FetchMessage,
            ToolStatus::Ok,
            47,
            Provenance::new(60, Vec::new()),
        ))),
    );
    let line = serde_json::to_string(&record).expect("record serializes");

    for absent in [
        "account",
        "artifact_path",
        "artifact_sha256",
        "artifact_bytes",
        "uids_exported",
        "uids_failed",
        "attachments_sent",
    ] {
        assert!(
            !line.contains(absent),
            "`{absent}` must stay off a tool_end that did not populate it; got {line}",
        );
    }
}

/// A whole-second timestamp does **not** survive a read-rewrite byte-for-byte:
/// `time`'s RFC 3339 formatter elides a zero subsecond, so `12:00:00.000Z`
/// comes back as `12:00:00Z`. Pinned here as known, pre-existing behaviour
/// (it predates #706 and is untouched by it) so that the round-trip claim
/// below is not read as unconditional. Roughly one record in a thousand lands
/// on a second boundary, and `audit merge` rewrites every line it copies.
///
/// The value is stable under repeated rewrites -- the elision happens once,
/// on the first pass -- so a merged file does not drift further.
#[test]
fn whole_second_timestamps_lose_their_zero_millis_on_rewrite() {
    let on_second = r#"{"seq":1,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":0,"records_lost":0}"#;

    let record: AuditRecord = serde_json::from_str(on_second).expect("golden line parses");
    let once = serde_json::to_string(&record).expect("record serializes");
    assert!(
        once.contains(r#""ts":"2026-05-05T12:00:00Z""#),
        "expected the zero subsecond to be elided; got {once}",
    );

    let reread: AuditRecord = serde_json::from_str(&once).expect("elided line parses");
    let twice = serde_json::to_string(&reread).expect("record serializes");
    assert_eq!(
        twice, once,
        "rewrite must reach a fixed point after one pass"
    );
}

/// A record read off disk and written straight back out is byte-identical,
/// for every timestamp except the whole-second case pinned above.
/// Serialization and deserialization have to agree about the format, not just
/// each be self-consistent -- a round-trip through the struct is exactly what
/// `audit merge` does to every line it copies.
#[test]
fn a_line_read_off_disk_reserializes_unchanged() {
    let goldens = [
        r#"{"seq":1,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_start","version":"0.2.0-dev","git_commit":"","posture":"readonly","tool_matrix":[],"config_path":"/etc/rimap/config.toml","config_hash_sha256":"00","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":7,"audit_file_inode_changed":false}"#,
        r#"{"seq":2,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"signal_int","total_tool_calls":0,"records_lost":0}"#,
        r#"{"seq":3,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"config","path":"/etc/rimap/config.toml","hash_sha256":"00"}"#,
    ];

    for golden in goldens {
        let record: AuditRecord = serde_json::from_str(golden).expect("golden line parses");
        let round_tripped = serde_json::to_string(&record).expect("record serializes");
        assert_eq!(
            round_tripped, golden,
            "reading and rewriting a line moved bytes; `audit merge` rewrites every line it copies",
        );
    }
}
