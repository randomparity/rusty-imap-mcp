//! The `folder_policy` audit record carries the list the `FolderGuard` was
//! actually built from (#761).
//!
//! `process_start` cannot: it is written before any IMAP session exists, so
//! its `protected_folders` is the *configured* list and it says
//! `special_use_discovery: not_run` to admit that (#696). The gap this file
//! closes is that the discovery-derived union — the one `check_protected`
//! enforces — reached only a `tracing` line and never the audit trail.
//!
//! Why here and not in `rimap-audit/tests/`: the claim under test is a
//! *wiring* claim, not a serialization one. `rimap-audit` can pin the bytes of
//! a record it is handed, but it has no IMAP surface, so it cannot show that
//! the bytes came from the same list the guard was built with. That needs a
//! server that declares a special-use folder, which is what
//! `rimap-fake-imap` provides.
//!
//! The bite: pass `None` instead of `Some(&protected)` to
//! `account_tool_matrix` inside `resolve_folder_policy`, or hand `FolderGuard::
//! new` the configured list rather than the merged one, and
//! [`discovered_special_use_folder_reaches_the_folder_policy_record`] fails —
//! on the `discovered` entry in the first case, on the guard/record agreement
//! in the second.

#![expect(clippy::expect_used, reason = "integration test")]

use std::path::Path;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::loader::load_and_validate;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::account::AccountId;
use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_server::boot::discovery::resolve_folder_policy;
use serde_json::Value;
use tempfile::TempDir;

/// The server-native name the fake declares `\Sent` on. Deliberately a name
/// no config in this file mentions and no operator would type — if it reaches
/// the record, it came from `LIST`.
const DISCOVERED_SENT: &str = "[Gmail]/Sent Mail";

/// A `LIST "" "*"` reply advertising `INBOX` plus one `\Sent` special-use
/// mailbox under a server-native name.
fn list_with_special_use_sent() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Send(
            format!("* LIST (\\HasNoChildren \\Sent) \"/\" \"{DISCOVERED_SENT}\"\r\n").into_bytes(),
        ),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    steps
}

/// Write a single-account config whose `protected_folders` names `INBOX`
/// alone, so anything else on the record's protected list can only have come
/// from discovery.
fn account_config(dir: &TempDir) -> ValidatedAccountConfig {
    let config_path = dir.path().join("config.toml");
    let body = format!(
        r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"
protected_folders = ["INBOX"]
expunge_folders = ["Trash"]

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
        audit = dir.path().join("config-audit.jsonl").display(),
        base = dir.path().display(),
    );
    std::fs::write(&config_path, body).expect("config writes");
    let multi = load_and_validate(&config_path).expect("config validates");
    multi.accounts[&AccountId::new("work").expect("account id")].clone()
}

/// Open a writer on `path`, leaving the caller to drop it before reading.
fn writer_at(path: &Path) -> AuditWriter {
    AuditWriter::open(&AuditOptions::new(path.to_path_buf(), Seq::FIRST)).expect("writer opens")
}

/// The single `folder_policy` line in `path`, parsed.
fn folder_policy_line(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path).expect("audit file readable");
    let mut found: Vec<Value> = contents
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|rec| rec.get("kind").and_then(Value::as_str) == Some("folder_policy"))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one folder_policy record expected, file was:\n{contents}",
    );
    found.remove(0)
}

/// The acceptance criterion: a server advertises a special-use folder absent
/// from config, and the audit record carries it tagged `discovered`.
#[tokio::test]
async fn discovered_special_use_folder_reaches_the_folder_policy_record() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let fake = FakeImapServer::start(list_with_special_use_sent()).await;
    let acfg = account_config(&dir);

    {
        let audit = writer_at(&audit_path);
        let imap = fake.connection("alice@work.test");
        resolve_folder_policy(&acfg, &imap, &audit)
            .await
            .expect("folder policy resolves against a healthy server");
    }

    let record = folder_policy_line(&audit_path);
    assert_eq!(record["account"], "work");
    assert_eq!(
        record["special_use_discovery"], "ran",
        "the record is written after discovery, so it must never claim otherwise",
    );
    assert_eq!(
        record["protected_folders"],
        serde_json::json!([
            {"folder": "INBOX", "source": "account"},
            {"folder": DISCOVERED_SENT, "source": "discovered"},
        ]),
        "the configured entry keeps its layer and the server-declared one is \
         tagged `discovered`, in the order the guard was handed them",
    );
    assert_eq!(
        record["expunge_folders"],
        serde_json::json!([{"folder": "Trash", "source": "account"}]),
        "expunge_folders never grows from discovery",
    );
}

/// The record and the guard are two renderings of one list, so a folder the
/// record calls protected must actually be refused. Without this, the record
/// could be built from a correctly-merged list while the guard was handed a
/// different one and every assertion above would still pass.
#[tokio::test]
async fn the_guard_returned_enforces_every_folder_the_record_lists() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let fake = FakeImapServer::start(list_with_special_use_sent()).await;
    let acfg = account_config(&dir);

    let outcome = {
        let audit = writer_at(&audit_path);
        let imap = fake.connection("alice@work.test");
        resolve_folder_policy(&acfg, &imap, &audit)
            .await
            .expect("folder policy resolves against a healthy server")
    };

    let record = folder_policy_line(&audit_path);
    let listed = record["protected_folders"]
        .as_array()
        .expect("protected_folders is an array");

    // `check_protected` refuses `INBOX` unconditionally, whatever the guard
    // was built from, so iterating the list alone would pass on a guard built
    // from nothing. Require at least one entry that is not INBOX.
    let mut discriminating = 0_usize;
    for entry in listed {
        let folder = entry["folder"].as_str().expect("folder is a string");
        if !folder.eq_ignore_ascii_case("INBOX") {
            discriminating += 1;
        }
        assert!(
            outcome
                .folder_guard
                .check_protected(folder, "delete_folder")
                .is_err(),
            "`{folder}` is on the record's protected list, so the guard the \
             same call returned must refuse it",
        );
    }
    assert!(
        discriminating > 0,
        "every listed folder was INBOX, which the guard refuses regardless of \
         how it was built -- this pass would have been vacuous",
    );

    // The control: a guard that refused everything would satisfy the loop
    // above. A folder on neither list must still be allowed.
    assert!(
        outcome
            .folder_guard
            .check_protected("Archive", "delete_folder")
            .is_ok(),
        "`Archive` is on no list, so a guard built from the recorded policy \
         must permit it -- otherwise the loop above proves only that the \
         guard refuses everything",
    );

    assert!(
        outcome
            .special_use
            .sent()
            .is_some_and(|name| name == DISCOVERED_SENT),
        "the returned map is the one discovery produced",
    );
}

/// A `LIST` reply with no special-use attribute anywhere -- the ordinary case
/// on a plain IMAP server.
fn list_without_special_use() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"Archive\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    steps
}

/// A server that declares nothing special-use still gets `ran`, and the list
/// is the configured one with no `discovered` entry.
///
/// This is the case where a `Some(&protected)`-vs-`None` miswiring is hardest
/// to see: the folder list looks identical either way, and only
/// `special_use_discovery` distinguishes them. It is also the common
/// production shape, so leaving it untested would mean the acceptance test
/// covers only the exotic path.
#[tokio::test]
async fn a_server_declaring_no_special_use_folders_still_records_ran() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let fake = FakeImapServer::start(list_without_special_use()).await;
    let acfg = account_config(&dir);

    {
        let audit = writer_at(&audit_path);
        let imap = fake.connection("alice@work.test");
        resolve_folder_policy(&acfg, &imap, &audit)
            .await
            .expect("folder policy resolves");
    }

    let record = folder_policy_line(&audit_path);
    assert_eq!(
        record["special_use_discovery"], "ran",
        "discovery ran and found nothing; `not_run` would be the claim that \
         nobody asked, which is a different and false statement",
    );
    assert_eq!(
        record["protected_folders"],
        serde_json::json!([{"folder": "INBOX", "source": "account"}]),
        "nothing was discovered, so the list is the configured one",
    );
}

/// One record per account, which is what makes an account's *absence* from the
/// log readable as "it did not boot" (`docs/audit-log.md`).
#[tokio::test]
async fn each_account_gets_its_own_record() {
    let dir = TempDir::new().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let fake = FakeImapServer::start(list_with_special_use_sent()).await;
    let acfg = account_config(&dir);

    {
        let audit = writer_at(&audit_path);
        // Two accounts differing only in name: the same config re-labelled, so
        // any difference in the two records can only come from the emitter.
        for name in ["work", "personal"] {
            let mut acfg = acfg.clone();
            acfg.id = AccountId::new(name).expect("account id");
            let imap = fake.connection("alice@work.test");
            resolve_folder_policy(&acfg, &imap, &audit)
                .await
                .expect("folder policy resolves");
        }
    }

    let contents = std::fs::read_to_string(&audit_path).expect("audit file readable");
    let accounts: Vec<String> = contents
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|rec| rec.get("kind").and_then(Value::as_str) == Some("folder_policy"))
        .filter_map(|rec| rec["account"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        accounts,
        vec!["work".to_string(), "personal".to_string()],
        "one record per account, in boot order, each naming its own account",
    );
}
