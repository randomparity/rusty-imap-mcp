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
//! Provenance of the golden strings below: they are not this branch's output
//! written down after the fact. Each was produced independently by pre-change
//! code -- a worktree at the merge-base, where these types are still plain
//! structs -- built with struct literals and compared byte-for-byte. They
//! matched, which is what makes "the format did not move" an executed result
//! rather than an argument from the shape of the diff.
//!
//! Section 3 extends the same construction contract to the crate's non-record
//! `pub` structs -- `AuditOptions`, `Filter`, `TrailingState` (#715), and
//! `StreamSummary` (#717). They have no on-disk component, so only property 1
//! applies to them; the file keeps its name because renaming it would break
//! every inbound reference for no gain.
//!
//! ## Convention for new `pub` structs in this crate
//!
//! **Every `pub` struct `rimap-audit` adds is born `#[non_exhaustive]`, with
//! a `compile_fail,E0639` doctest on the type itself and a construction case
//! in section 3 below.** Retrofitting one costs a breaking change and a
//! call-site sweep (#706, #715); adding the attribute at birth costs a line.
//! The doctest is the load-bearing half: an integration test here compiles
//! just as well without the attribute, so it documents the idiom but enforces
//! nothing, while a `compile_fail` doctest fails loudly the moment the
//! attribute is dropped -- see `record/mod.rs` for the established shape.
//! #717 was the first change to arrive under this rule: `StreamSummary` was
//! born `#[non_exhaustive]`, with its doctest on the type and its case below.
//! #696's `FolderEntry` is the second, and it is a *record* component rather
//! than a helper, so its construction case belongs with the record types in
//! section 1 and its bytes are pinned by the golden in section 2 — section 3
//! is only for `pub` structs with no on-disk component.
//!
//! Sibling of `rimap-config`'s `non_exhaustive_model.rs` (#665) and
//! `non_exhaustive_validate.rs` (#707).

#![expect(clippy::expect_used, reason = "integration test")]

use rimap_audit::record::{
    AccountToolMatrix, AttachmentProvenance, AuditRecord, FolderEntry, FolderSource, Payload,
    ProcessEnd, ProcessEndReason, Provenance, ResultSummary, ToolEnd, ToolStatus, ToolVerdict,
    VerdictSource,
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
/// `ProcessEnd { reason, total_tool_calls, records_lost, undrained_dispatches }`
/// here, or
/// `ProcessEnd { reason, ..Default::default() }`, is rejected by rustc
/// (E0639) -- both are struct expressions.
#[test]
fn record_types_are_built_through_constructors_and_field_assignment() {
    let matrix = AccountToolMatrix::new(
        "work".to_string(),
        Posture::Readonly,
        vec![ToolVerdict::new(
            ToolName::DeleteMessage,
            false,
            VerdictSource::Account,
        )],
        vec![FolderEntry::new(
            "INBOX".to_string(),
            FolderSource::Inherited,
        )],
        vec![FolderEntry::new("Trash".to_string(), FolderSource::Account)],
    );
    assert_eq!(matrix.account, "work");
    assert_eq!(matrix.tools.len(), 1);
    assert_eq!(matrix.protected_folders.len(), 1);
    assert_eq!(matrix.expunge_folders[0].source, FolderSource::Account);

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
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 7, 3, 0)),
    );
    assert_eq!(record.seq, Seq(1));
}

/// `ProcessEnd::new` takes `records_lost` and `undrained_dispatches` even
/// though both fields are `#[serde(default)]`, because a zero in either is a
/// durable claim -- that the record stream has no hole in it, and that no tool
/// dispatch outlived the shutdown drain. The constructor records what the
/// caller passed rather than assuming the reassuring value.
#[test]
fn process_end_constructor_records_the_loss_count_it_was_given() {
    let lost = ProcessEnd::new(ProcessEndReason::Error, 12, 4, 2);
    assert_eq!(lost.records_lost, 4);
    assert_eq!(lost.total_tool_calls, 12);
    assert_eq!(lost.undrained_dispatches, 2);

    let clean = ProcessEnd::new(ProcessEndReason::Eof, 12, 0, 0);
    assert_eq!(clean.records_lost, 0);
    assert_eq!(clean.undrained_dispatches, 0);
}

/// Three adjacent `u64` parameters are transposable without a compile error,
/// and each lands on a field an operator alerts on. Distinct values in a known
/// order are the only thing that catches a swap -- the sibling pin
/// `ProcessStartInputs` carries for the same reason.
#[test]
fn process_end_constructor_maps_each_count_to_its_own_field() {
    let end = ProcessEnd::new(ProcessEndReason::SignalInt, 11, 22, 33);
    assert_eq!(end.reason, ProcessEndReason::SignalInt);
    assert_eq!(end.total_tool_calls, 11);
    assert_eq!(end.records_lost, 22);
    assert_eq!(end.undrained_dispatches, 33);
}

/// A downstream match on a `#[non_exhaustive]` struct needs a rest pattern.
/// Without the `..` this does not compile, which is the whole point: a field
/// added later cannot silently change what this destructuring means.
#[test]
fn downstream_pattern_matches_need_a_rest_pattern() {
    let end = ProcessEnd::new(ProcessEndReason::SignalTerm, 3, 0, 0);
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
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 7, 3, 5)),
    );
    assert_golden(
        &record,
        r#"{"seq":1,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":7,"records_lost":3,"undrained_dispatches":5}"#,
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
        None,
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

/// `tool_start` is the record with the most reason to be pinned and was the
/// last to get a golden. It is the only kind whose payload goes through a
/// hand-written `Serialize` ([`rimap_audit::record::PostureEffective`]), the
/// only one carrying a security-relevant field, and the one whose constructor
/// this change altered most.
///
/// The pre-existing in-crate test asserts through a parsed
/// `serde_json::Value`, which is field-order-insensitive and so passes
/// straight through a reordering. This does not.
#[test]
fn tool_start_line_is_byte_exact() {
    let record = AuditRecord::new(
        Seq(10),
        fixed_ts(),
        fixed_pid(),
        Payload::ToolStart(rimap_audit::record::ToolStart::from(
            rimap_audit::ToolStartInputs::new(
                ToolName::FetchMessage,
                Some("work".to_string()),
                Some(Posture::Readonly),
                serde_json::json!({"folder": "INBOX", "uid": 12345}),
                "de".repeat(32),
            ),
        )),
    );
    assert_golden(
        &record,
        r#"{"seq":10,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"tool_start","account":"work","tool":"fetch_message","posture_effective":"readonly","arguments_redacted":{"folder":"INBOX","uid":12345},"arguments_hash_sha256":"dededededededededededededededededededededededededededededededede"}"#,
    );
}

/// The infrastructure dispatch, whose `posture_effective` is the literal
/// `"infrastructure"` -- the string that records "this call bypassed
/// per-account posture gating by design". Pinned separately because it comes
/// from the hand-written `Serialize`'s other arm, and because editing that
/// literal would silently redefine what every such record on disk means.
#[test]
fn tool_start_infrastructure_line_is_byte_exact() {
    let record = AuditRecord::new(
        Seq(11),
        fixed_ts(),
        fixed_pid(),
        Payload::ToolStart(rimap_audit::record::ToolStart::from(
            rimap_audit::ToolStartInputs::new(
                ToolName::UseAccount,
                None,
                None,
                serde_json::json!({}),
                "ab".repeat(32),
            ),
        )),
    );
    assert_golden(
        &record,
        r#"{"seq":11,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"tool_start","tool":"use_account","posture_effective":"infrastructure","arguments_redacted":{},"arguments_hash_sha256":"abababababababababababababababababababababababababababababababab"}"#,
    );
}

/// The `auth` kind. Its payload is [`rimap_audit::record::AuthEvent`], which
/// lives in `rimap-core` and is the one payload this change could not mark
/// `#[non_exhaustive]` (#716) -- which makes pinning its bytes more important
/// here, not less, since a field added to it is still a silent format change.
///
/// `username` carries a login identity and must never carry credential
/// material; the golden uses an obvious placeholder.
#[test]
fn auth_line_is_byte_exact() {
    let record = AuditRecord::new(
        Seq(2),
        fixed_ts(),
        fixed_pid(),
        Payload::Auth(rimap_audit::record::AuthEvent {
            account: Some("work".to_string()),
            result: rimap_audit::record::AuthResult::Success,
            host: "imap.example.com".to_string(),
            port: 993,
            username: "alice@example.com".to_string(),
            tls_fingerprint_sha256: Some("ab".repeat(32)),
            fingerprint_match: Some(true),
            error_code: None,
            credential_source: None,
        }),
    );
    assert_golden(
        &record,
        r#"{"seq":2,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"auth","account":"work","result":"success","host":"imap.example.com","port":993,"username":"alice@example.com","tls_fingerprint_sha256":"abababababababababababababababababababababababababababababababab","fingerprint_match":true,"error_code":null}"#,
    );
}

/// `process_start` in its multi-account shape, with a populated `accounts`
/// array and a populated `tool_matrix`. The single-account, empty-matrix shape
/// is covered by the round-trip goldens; this pins the nested structures --
/// including `tool_matrix`, the #632 field whose addition is the reason this
/// issue exists, and its `protected_folders` / `expunge_folders` (#696).
///
/// This golden moved once, in #696, and only by gaining those two keys on the
/// `tool_matrix` entry. That is what an additive change looks like on disk:
/// every byte that was here before is still here, in the same order.
#[test]
fn process_start_multi_account_line_is_byte_exact() {
    let mut inputs = rimap_audit::ProcessStartInputs::new(
        "0.2.0-dev".to_string(),
        "abc123".to_string(),
        std::path::PathBuf::from("/etc/rimap/config.toml"),
        "00".to_string(),
        rimap_audit::read_trailing_state(std::path::Path::new(
            "/nonexistent/rimap-golden-absent.jsonl",
        ))
        .expect("absent file yields an empty trailing state"),
        7,
    );
    inputs.accounts = Some(vec![rimap_audit::record::AccountSummary::new(
        "work".to_string(),
        Posture::Readonly,
        "imap.example.com".to_string(),
    )]);
    inputs.tool_matrix = vec![AccountToolMatrix::new(
        "work".to_string(),
        Posture::Readonly,
        vec![ToolVerdict::new(
            ToolName::DeleteMessage,
            true,
            VerdictSource::Inherited,
        )],
        vec![
            FolderEntry::new("INBOX".to_string(), FolderSource::Inherited),
            FolderEntry::new("[Gmail]/Sent Mail".to_string(), FolderSource::Discovered),
        ],
        vec![FolderEntry::new(
            "Trash".to_string(),
            FolderSource::Inherited,
        )],
    )];

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let writer = rimap_audit::AuditWriter::open(&rimap_audit::AuditOptions::new(
        path.clone(),
        rimap_audit::Seq::FIRST,
    ))
    .expect("writer opens");
    writer
        .log_process_start(inputs)
        .expect("process_start write succeeds");
    drop(writer);

    let written = std::fs::read_to_string(&path).expect("audit file readable");
    let mut record: AuditRecord =
        serde_json::from_str(written.trim_end()).expect("written line parses");
    // The writer stamps a live `ts`/`process_id`; replace them so the golden
    // is about the payload shape rather than the clock.
    record.ts = fixed_ts();
    record.process_id = fixed_pid();
    assert_golden(
        &record,
        r#"{"seq":1,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_start","version":"0.2.0-dev","git_commit":"abc123","accounts":[{"name":"work","posture":"readonly","imap_host":"imap.example.com"}],"tool_matrix":[{"account":"work","posture":"readonly","tools":[{"tool":"delete_message","allow":true,"source":"inherited"}],"protected_folders":[{"folder":"INBOX","source":"inherited"},{"folder":"[Gmail]/Sent Mail","source":"discovered"}],"expunge_folders":[{"folder":"Trash","source":"inherited"}]}],"config_path":"/etc/rimap/config.toml","config_hash_sha256":"00","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":7,"audit_file_inode_changed":false}"#,
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
            None,
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

/// `ProcessStartInputs::new` takes three `String` parameters in a row --
/// `version`, `git_commit`, `config_hash_sha256` -- and the mapping onto the
/// record happens inside `log_process_start`, not through a `From` impl any
/// other test exercises. Swapping two of them compiles, type-checks, and
/// passes every other test in the workspace, while writing a config hash into
/// the version field of a forensic record forever.
///
/// So each value here is self-identifying: a transposition names itself in the
/// failure. This is the one construction site in the diff where the compiler
/// offers no protection at all, which is exactly why it gets a test rather
/// than a careful reading.
#[test]
fn process_start_inputs_map_onto_the_fields_they_name() {
    use rimap_audit::{AuditOptions, AuditWriter, ProcessStartInputs};
    use rimap_audit::{current_inode, read_trailing_state};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    let trailing = read_trailing_state(&path).expect("empty file has trailing state");
    let writer =
        AuditWriter::open(&AuditOptions::new(path.clone(), Seq::FIRST)).expect("writer opens");
    let inode = current_inode(&path).expect("inode readable after open");

    writer
        .log_process_start(ProcessStartInputs::new(
            "VERSION-goes-here".to_string(),
            "GITCOMMIT-goes-here".to_string(),
            std::path::PathBuf::from("/etc/rimap/CONFIGPATH.toml"),
            "CONFIGHASH-goes-here".to_string(),
            trailing,
            inode,
        ))
        .expect("process_start write succeeds");
    drop(writer);

    let line = std::fs::read_to_string(&path).expect("audit file readable");
    let v: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("written line is valid JSON");

    assert_eq!(v["kind"], "process_start");
    assert_eq!(v["version"], "VERSION-goes-here");
    assert_eq!(v["git_commit"], "GITCOMMIT-goes-here");
    assert_eq!(v["config_path"], "/etc/rimap/CONFIGPATH.toml");
    assert_eq!(v["config_hash_sha256"], "CONFIGHASH-goes-here");
    assert_eq!(
        v["previous_file_inode"], inode,
        "current_inode maps onto previous_file_inode, not onto a seq field",
    );
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
        r#"{"seq":2,"ts":"2026-05-05T12:00:00.234Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"signal_int","total_tool_calls":0,"records_lost":0,"undrained_dispatches":0}"#,
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

// ---------------------------------------------------------------------------
// 3. Downstream construction contract: the non-record pub structs (#715, #717)
// ---------------------------------------------------------------------------

/// `AuditOptions::new(path, initial_seq)` plus field assignment is the only
/// downstream way to configure the writer, and what it leaves unassigned is
/// part of the contract: the three policy knobs come out inert -- rotation
/// off, no retention, fail-closed. Those are deliberately *not* the
/// config-layer defaults (`AuditConfig::new` fills 10 MiB / keep 5), so this
/// pins the values rather than leaving "the defaults" to mean whichever layer
/// the reader had in mind.
///
/// `initial_seq` is a parameter, not a defaulted field, and the assertion at
/// the bottom is why: `AuditWriter::open` plumbs it into the sequence counter
/// unchecked, so a defaulted `Seq::FIRST` against a file that already has
/// records would put duplicate `seq` values into an append-only log. This
/// test passes a non-first value and proves it reaches the record on disk.
///
/// Note `rotate_keep` defaults to `0`, which means "delete every rotated
/// sibling immediately" -- so a test that provoked a rotation here would have
/// nothing on disk to find. Rotation has its own suite in `tests/rotation.rs`;
/// what this one owes is that an assigned field reaches the writer.
///
/// The `AuditWriter::open` call is what makes this more than a field check:
/// the options built here have to be accepted by the real constructor, on the
/// real path, from outside the crate.
#[test]
fn audit_options_new_configures_a_working_writer() {
    use rimap_audit::{AuditOptions, AuditWriter, Seq};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    let mut options = AuditOptions::new(path.clone(), Seq(41));
    assert_eq!(options.path, path);
    assert_eq!(options.rotate_bytes, 0, "rotation is off unless asked for");
    assert_eq!(options.rotate_keep, 0);
    assert_eq!(options.retention_seconds, None);
    assert!(!options.fail_open, "fail-closed is the safe default");
    assert_eq!(options.initial_seq, Seq(41), "the constructor took this");

    // Field assignment is the supported way to depart from those values, and
    // `rotate_bytes` is the one departure the writer exposes an accessor for,
    // so the assignment is observed rather than merely written.
    options.rotate_bytes = 4096;

    let writer = AuditWriter::open(&options).expect("writer opens");
    assert_eq!(
        writer.rotate_bytes(),
        4096,
        "the assigned rotate_bytes must reach the writer, not `new`'s default",
    );

    writer
        .log_process_end(ProcessEnd::new(ProcessEndReason::Eof, 0, 0, 0))
        .expect("process_end write succeeds");
    drop(writer);

    let line = std::fs::read_to_string(&path).expect("audit file readable");
    let record: AuditRecord = serde_json::from_str(line.trim_end()).expect("written line parses");
    assert_eq!(
        record.seq,
        Seq(41),
        "the initial_seq passed to `new` must reach the file, not Seq::FIRST",
    );
}

/// `Filter` keeps its `Default` -- the all-`None` "match everything"
/// predicate -- and downstream narrows it by field assignment. No
/// constructor: nothing on this type is required, so one would only offer a
/// second way to spell `default()`.
#[test]
fn filter_default_plus_assignment_narrows_a_match() {
    use rimap_audit::Filter;

    let record = AuditRecord::new(
        Seq(1),
        fixed_ts(),
        fixed_pid(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 0, 0, 0)),
    );

    let permissive = Filter::default();
    assert!(
        permissive.matches(&record),
        "an unconstrained filter matches everything",
    );

    let mut by_kind = Filter::default();
    by_kind.kind = Some("process_end".to_owned());
    assert!(by_kind.matches(&record));

    by_kind.kind = Some("tool_end".to_owned());
    assert!(!by_kind.matches(&record));
}

/// `StreamSummary` is the other output type, and stricter than
/// `TrailingState`: it has no `Default` either, so there is no downstream way
/// to mint an all-zero summary at all. That is deliberate -- a zeroed summary
/// asserts *this pass skipped nothing*, and only a completed pass is entitled
/// to say so (#715's constructor rule, applied to a defaulted field rather
/// than a constructor parameter).
///
/// Its `skipped_unknown_kind` is also the #717 behaviour seen from outside the
/// crate: a line whose `kind` this build does not know is skipped and counted,
/// while a line malformed for any other reason still aborts.
#[test]
fn stream_summary_is_read_from_a_pass_and_destructured_with_a_rest_pattern() {
    use rimap_audit::{Filter, StreamSummary, stream_records};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    let known = serde_json::to_string(&AuditRecord::new(
        Seq(1),
        fixed_ts(),
        fixed_pid(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 0, 0, 0)),
    ))
    .expect("record serializes");
    // A kind no version of this binary defines, in the shape a later one might.
    let future = r#"{"seq":2,"ts":"2026-05-05T12:00:01.000Z","process_id":"01HM0000000000000000000000","kind":"policy","rule":"deny-all"}"#;
    std::fs::write(&path, format!("{known}\n{future}\n")).expect("fixture written");

    let summary = stream_records(&path, &Filter::default(), |_| Ok(()))
        .expect("an unknown kind is not fatal");
    assert_eq!(summary.matched, 1);
    assert_eq!(summary.skipped_unknown_kind, 1);

    // The rest pattern is the pinned downstream idiom; without it this
    // destructuring is rejected (E0639).
    let StreamSummary {
        matched,
        skipped_unknown_kind,
        ..
    } = summary;
    assert_eq!(matched, 1);
    assert_eq!(skipped_unknown_kind, 1);
}

/// A line malformed for any reason *other* than an unrecognized `kind` must
/// still abort. This is the half of #717 that is easy to lose: widening the
/// tolerance to "skip anything unparseable" would make the reader hide the
/// corruption an audit trail exists to expose. Pinned from outside the crate
/// because it is a promise to downstream readers, not an implementation
/// detail.
#[test]
fn a_line_malformed_for_any_other_reason_still_aborts() {
    use rimap_audit::{Filter, stream_records};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");

    let known = serde_json::to_string(&AuditRecord::new(
        Seq(1),
        fixed_ts(),
        fixed_pid(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, 0, 0, 0)),
    ))
    .expect("record serializes");
    // A `kind` this build *does* know, whose payload will not deserialize.
    let corrupt = r#"{"seq":2,"ts":"2026-05-05T12:00:01.000Z","process_id":"01HM0000000000000000000000","kind":"auth"}"#;
    std::fs::write(&path, format!("{corrupt}\n{known}\n")).expect("fixture written");

    let err = stream_records(&path, &Filter::default(), |_| Ok(()))
        .expect_err("a corrupt known-kind line must still abort");
    assert!(
        format!("{err}").contains("line 1"),
        "the error must name the offending line: {err}",
    );
}

/// `TrailingState` is an output type: downstream reads it from
/// `read_trailing_state` and never builds one. Field *reads* are unaffected
/// by the attribute, which is the whole point -- the type can grow a tamper
/// signal without breaking the boot path that consumes it.
///
/// Destructuring is the one downstream form the attribute does constrain, so
/// the rest pattern below is the pinned idiom rather than incidental style.
#[test]
fn trailing_state_is_read_and_destructured_with_a_rest_pattern() {
    use rimap_audit::{Seq, TrailingState, read_trailing_state};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let absent = dir.path().join("never-written.jsonl");

    let state = read_trailing_state(&absent).expect("absent file yields an empty trailing state");
    assert_eq!(state, TrailingState::default());

    // Reading a field, and the boot path's own expression, both still compile.
    assert_eq!(state.last_seq.map_or(Seq::FIRST, Seq::next), Seq::FIRST);

    let TrailingState {
        last_seq,
        last_recorded_inode,
        ..
    } = state;
    assert_eq!(last_seq, None);
    assert_eq!(last_recorded_inode, None);
}
