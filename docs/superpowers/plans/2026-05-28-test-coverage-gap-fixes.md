# Test Coverage Gap Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four high-severity coverage gaps from the test-coverage-gap review: FolderGuard Modified-UTF-7 normalization, the fail-closed audit envelope (no-orphan `tool_start`), breaker service-vs-user error tripping, and the non-UIDPLUS folder-wide `EXPUNGE` data-loss fallback.

**Architecture:** Issues 1–3 are pure test additions against code believed correct (TDD characterization tests; if any test goes red it has found a real defect to fix). Issue 4 makes a known, documented data-loss path observable: extract the UIDPLUS branch into a pure `expunge_strategy` function (unit-tested), emit a `tracing::warn!` on the folder-wide branch, and add a `used_fallback` signal to `DeleteResult` to match `MoveOutcome`. Current delete/expunge behavior is preserved — only observability changes.

**Tech Stack:** Rust 2024, tokio, `cargo nextest`, `utf7-imap` 0.3.2, `rimap-audit` test-injection feature, `rimap-authz` `ManualClock`.

**Branch:** `fix/repo-bug-sweep` (already created; not main).

**Ground rules:**
- One issue per commit. Run that crate's tests + `cargo clippy --all-targets --all-features -- -D warnings` for the touched crate before each commit.
- Commit only (do not push); the user pushes separately.
- Do NOT run `cargo-mutants` or full-workspace content runs (host RAM constraint).

---

### Task 1: FolderGuard Modified-UTF-7 normalization tests

**Issue:** `FolderGuard::normalize` (`crates/rimap-authz/src/folder_guard.rs:17-20`) decodes Modified UTF-7 then lowercases, but every existing test uses ASCII only. A protected folder configured in one form (raw mUTF-7 wire form or decoded Unicode) must still be rejected when the request arrives in the other form, and a malformed encoding must not bypass the guard or panic.

**Files:**
- Modify (tests only): `crates/rimap-authz/src/folder_guard.rs` (append to the existing `#[cfg(test)] mod tests` block, which ends at the file's last `}`)

- [ ] **Step 1: Write the failing/characterization tests**

Append these tests inside `mod tests` in `crates/rimap-authz/src/folder_guard.rs`, after `rename_allows_unprotected_both`:

```rust
    #[test]
    fn protected_non_ascii_folder_rejected_in_both_mutf7_and_decoded_forms() {
        // "Café" — the é forces a Modified-UTF-7 base64 run.
        let decoded = "Caf\u{00e9}";
        let encoded = utf7_imap::encode_utf7_imap(decoded.to_string());
        assert_ne!(encoded, decoded, "test input must actually be mUTF-7 encoded");

        // Configured in WIRE (encoded) form; request arrives DECODED.
        let g = FolderGuard::new(&[encoded.clone()], &[]);
        assert!(
            matches!(
                g.check_protected(decoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "decoded form must match an encoded protected entry",
        );
        assert!(
            matches!(
                g.check_protected(&encoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "encoded form must match an encoded protected entry",
        );

        // Configured in DECODED form; request arrives ENCODED (and vice versa).
        let g2 = FolderGuard::new(&[decoded.to_string()], &[]);
        assert!(
            matches!(
                g2.check_protected(&encoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "encoded form must match a decoded protected entry",
        );
        assert!(
            matches!(
                g2.check_protected(decoded, "rename"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "decoded form must match a decoded protected entry",
        );
    }

    #[test]
    fn expunge_allowlist_matches_across_mutf7_forms() {
        let decoded = "Caf\u{00e9}";
        let encoded = utf7_imap::encode_utf7_imap(decoded.to_string());
        let g = FolderGuard::new(&[], &[encoded.clone()]);
        // Allowlisted in encoded form; both request forms must be allowed.
        assert!(g.check_expunge(decoded).is_ok());
        assert!(g.check_expunge(&encoded).is_ok());
        // A different non-ASCII folder must still be denied.
        assert!(matches!(
            g.check_expunge("Sp\u{00e4}m"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn malformed_mutf7_does_not_panic_and_does_not_bypass() {
        // A dangling shift sequence ("&" with no terminating "-") is
        // malformed mUTF-7. normalize() must not panic, and such a name
        // must not be treated as an unlisted (allowed) folder when it is
        // in fact the protected one in encoded form.
        let g = FolderGuard::new(&["Drafts".into()], &[]);
        // Should not panic; result may be Ok or ProtectedFolder/InvalidFolderName,
        // but must never panic and must not silently succeed on "Drafts".
        let _ = g.check_protected("&malformed", "delete");
        assert!(
            g.check_protected("Drafts", "delete").is_err(),
            "plain protected name must remain protected after a malformed probe",
        );
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo nextest run -p rimap-authz folder_guard`
Expected: PASS. If `protected_non_ascii_folder_rejected_in_both_mutf7_and_decoded_forms` FAILS, a real normalization defect exists — fix `normalize` so config and request forms converge (likely: decode both sides, which it already does — investigate the `utf7_imap` round-trip) before proceeding. If `malformed_mutf7_does_not_panic_and_does_not_bypass` panics, wrap/validate the decode in `normalize` to fall back to the ASCII-lowercased input (matching the existing doc comment).

- [ ] **Step 3: Confirm the tests are meaningful (verify they can fail)**

Temporarily change `normalize` (`folder_guard.rs:18`) to skip decoding:
```rust
fn normalize(folder: &str) -> String {
    folder.to_lowercase()  // TEMPORARY — decode removed
}
```
Run: `cargo nextest run -p rimap-authz folder_guard`
Expected: the two cross-form tests FAIL (proving they exercise the decode path). Then REVERT `normalize` to its original two-line body and re-run — Expected: PASS.

- [ ] **Step 4: Lint**

Run: `cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/folder_guard.rs
git commit -m "test(authz): cover Modified-UTF-7 normalization in FolderGuard"
```

---

### Task 2: Fail-closed audit envelope + no-orphan tool_start tests

**Issue:** `run_with_audit_envelope` (`crates/rimap-server/src/mcp/audit_envelope.rs:38`) emits `tool_start` BEFORE constructing the drop-guard and minting the `DispatchTicket`. When the `tool_start` write fails and `fail_open = false`, the call must fail, the body must never run, and ZERO records must reach disk (no orphan `tool_start`). When `fail_open = true`, the failure is suppressed, the body runs, and the call succeeds. Existing tests (`audit_fail_open.rs`, `mcp_audit_failure.rs`) cover the writer counter and the wire-level rejection, but not the on-disk no-orphan property through the envelope.

**Files:**
- Modify (tests only): `crates/rimap-server/src/mcp/audit_envelope.rs` (append to `#[cfg(test)] mod tests`, after `tool_end_records_export_provenance_from_result`)

`force_next_write_failure()` is reachable: `crates/rimap-server/Cargo.toml:106` dev-deps `rimap-audit` with `features = ["test-injection"]`.

- [ ] **Step 1: Add a fail-open-parameterized writer helper**

In `crates/rimap-server/src/mcp/audit_envelope.rs`, just after the existing `fn test_writer` (ends at line ~302), add:

```rust
    fn test_writer_fail_open(path: std::path::PathBuf, fail_open: bool) -> AuditWriter {
        AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open,
            initial_seq: Seq::FIRST,
        })
        .unwrap()
    }
```

- [ ] **Step 2: Write the failing/characterization tests**

Append inside `mod tests`:

```rust
    /// fail_open = false: an injected `tool_start` write failure must abort
    /// the call with an "audit write failed" error, never run the body, and
    /// leave ZERO records on disk (no orphan tool_start).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_start_failure_fail_closed_aborts_with_no_orphan() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer_fail_open(path.clone(), false);
        writer.force_next_write_failure();

        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let body_ran = Arc::new(AtomicBool::new(false));
        let body_ran_clone = Arc::clone(&body_ran);
        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ListAccounts,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async move {
                    body_ran_clone.store(true, Ordering::SeqCst);
                    Ok(serde_json::Value::Null)
                },
            )
            .await;

        let err = result.expect_err("fail-closed audit failure must abort the call");
        assert!(
            err.message.contains("audit write failed"),
            "expected audit-write-failed error, got: {}",
            err.message,
        );
        assert!(
            !body_ran.load(Ordering::SeqCst),
            "body must not run when tool_start fails fail-closed",
        );

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            contents.lines().count(),
            0,
            "a failed tool_start must leave zero records on disk (no orphan):\n{contents}",
        );
    }

    /// fail_open = true: the injected `tool_start` write failure is
    /// suppressed (counted), the body runs, and the call succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_start_failure_fail_open_proceeds_and_counts() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer_fail_open(path.clone(), true);
        writer.force_next_write_failure();
        // Hold a clone so we can read the suppressed-failure counter after.
        let writer_probe = writer.clone();

        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let body_ran = Arc::new(AtomicBool::new(false));
        let body_ran_clone = Arc::clone(&body_ran);
        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ListAccounts,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async move {
                    body_ran_clone.store(true, Ordering::SeqCst);
                    Ok(serde_json::Value::Null)
                },
            )
            .await;

        assert!(result.is_ok(), "fail-open must let the call succeed");
        assert!(
            body_ran.load(Ordering::SeqCst),
            "body must run when the tool_start failure is suppressed",
        );
        assert!(
            writer_probe.suppressed_failures() >= 1,
            "fail-open must increment the suppressed-failure counter",
        );
    }
```

- [ ] **Step 3: Run the tests**

Run: `cargo nextest run -p rimap-server --lib audit_envelope`
Expected: PASS. If `tool_start_failure_fail_closed_aborts_with_no_orphan` finds records on disk or the body ran, the fail-closed ordering is broken — that is a real defect; fix `run_with_audit_envelope` so `emit_tool_start`'s `Err` returns before the body/guard.

- [ ] **Step 4: Confirm meaningfulness**

Temporarily change `audit_envelope.rs:55` from `.await?;` to `.await.unwrap_or(rimap_audit::Seq::FIRST);` (swallow the error). Run the test — Expected: `tool_start_failure_fail_closed_aborts_with_no_orphan` FAILS (body runs / record written). REVERT to `.await?;` and re-run — Expected: PASS.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/mcp/audit_envelope.rs
git commit -m "test(server): cover fail-closed audit envelope no-orphan tool_start"
```

---

### Task 3: Breaker reason mapping + service-vs-user tripping tests

**Issue:** `rimap_error_to_breaker_reason` (`crates/rimap-server/src/mcp/dispatch.rs:83-109`) decides which errors trip the circuit breaker. It is exhaustive over all 19 `ErrorCode`s, but existing tests assert only 3 service codes and 2 user codes. The dispatch-level wiring (`server.rs:128-135`: `Ok → on_success`, service `Err → on_failure`, user `Err → no-op`) is only exercised behind Docker e2e. Add an exhaustive mapping table and a `DispatchGuard<ManualClock>` sequence test.

**Files:**
- Modify (tests only): `crates/rimap-server/src/mcp/dispatch.rs` (the `#[cfg(test)] mod tests`, replacing the two partial tests at lines 284-315 and 343-354)
- Modify (tests only): `crates/rimap-authz/src/guard.rs` (append to `#[cfg(test)] mod tests`)

- [ ] **Step 1: Replace the partial mapping tests with an exhaustive table**

In `crates/rimap-server/src/mcp/dispatch.rs`, replace `breaker_reason_maps_service_failures` (lines 284-315) and `breaker_reason_ignores_user_errors` (lines 343-354) with one table-driven test:

```rust
    #[test]
    fn breaker_reason_maps_every_error_code() {
        use rimap_authz::breaker::FailureReason;
        use rimap_core::{ErrorCode, RimapError};

        // Exhaustive table over all 19 ErrorCode variants. The mapping fn's
        // own `match` is compile-exhaustive, so a NEW ErrorCode breaks the
        // build there; this table pins the SEMANTICS (service trips, user
        // errors do not).
        let cases: &[(ErrorCode, Option<FailureReason>)] = &[
            (ErrorCode::ConnectionLost, Some(FailureReason::ConnectionLost)),
            (ErrorCode::Auth, Some(FailureReason::Auth)),
            (ErrorCode::Timeout, Some(FailureReason::Timeout)),
            (ErrorCode::ImapProtocol, Some(FailureReason::Protocol)),
            (ErrorCode::SmtpProtocol, Some(FailureReason::Protocol)),
            (ErrorCode::Tls, Some(FailureReason::Tls)),
            (ErrorCode::InvalidInput, None),
            (ErrorCode::PostureDenied, None),
            (ErrorCode::RateLimited, None),
            (ErrorCode::CircuitOpen, None),
            (ErrorCode::NotFound, None),
            (ErrorCode::AttachmentTooLarge, None),
            (ErrorCode::ProtectedFolder, None),
            (ErrorCode::ExpungeDenied, None),
            (ErrorCode::Config, None),
            (ErrorCode::Internal, None),
            (ErrorCode::NoAccount, None),
            (ErrorCode::UnknownAccount, None),
            (ErrorCode::Cancelled, None),
            (ErrorCode::UidValidityChanged, None),
        ];

        for (code, expected) in cases {
            let err = RimapError::Imap {
                code: *code,
                message: "x".into(),
                source: None,
            };
            assert_eq!(
                rimap_error_to_breaker_reason(&err),
                *expected,
                "mapping mismatch for {code:?}",
            );
        }
        assert_eq!(cases.len(), 20, "table must list all variants (6 service + 14 user)");
    }
```

Note: confirm the `ErrorCode` variant list against `crates/rimap-core/src/error.rs` while editing; if a variant name differs, fix the literal. (`cases.len()` is 20 here — 6 `Some` + 14 `None`; adjust the assert to the real count if the enum has changed.)

- [ ] **Step 2: Run the mapping test**

Run: `cargo nextest run -p rimap-server --lib dispatch::tests::breaker_reason_maps_every_error_code`
Expected: PASS. A mismatch means a service error is misclassified as user (breaker would never trip) or vice versa — a real defect; fix the mapping arm in `dispatch.rs`.

- [ ] **Step 3: Add the guard tripping-sequence test**

In `crates/rimap-authz/src/guard.rs`, append inside `mod tests` (after `matrix_accessor_returns_effective_matrix`):

```rust
    #[test]
    fn service_failures_trip_breaker_user_errors_do_not() {
        let g = guard(Posture::DraftSafe);

        // A tool that DraftSafe permits, so admission is gated only by the breaker.
        g.pre_dispatch(ToolName::ListFolders).unwrap();

        // One non-auth service failure is below threshold (2): still Closed.
        g.on_failure(FailureReason::Timeout);
        g.pre_dispatch(ToolName::ListFolders)
            .expect("one failure is below the threshold; breaker stays Closed");

        // Second non-auth failure reaches threshold → Open.
        g.on_failure(FailureReason::Timeout);
        assert!(
            matches!(
                g.pre_dispatch(ToolName::ListFolders),
                Err(AuthzError::CircuitOpen { .. })
            ),
            "two service failures must trip the breaker Open",
        );

        // After cooldown, a probe + success closes it again.
        g.breaker().clock.advance(Duration::from_secs(5));
        g.pre_dispatch(ToolName::ListFolders).unwrap(); // HalfOpen probe
        g.on_success();
        g.pre_dispatch(ToolName::ListFolders)
            .expect("on_success after a half-open probe must close the breaker");
    }

    #[test]
    fn single_auth_failure_trips_breaker_immediately() {
        let g = guard(Posture::DraftSafe);
        g.pre_dispatch(ToolName::ListFolders).unwrap();
        g.on_failure(FailureReason::Auth);
        assert!(
            matches!(
                g.pre_dispatch(ToolName::ListFolders),
                Err(AuthzError::CircuitOpen { .. })
            ),
            "a single Auth failure must trip the breaker Open immediately",
        );
    }
```

Note on user errors: user/policy errors (e.g. `InvalidInput`) map to `None` in `rimap_error_to_breaker_reason`, so `on_failure` is NEVER called for them — the breaker cannot observe them. The "user errors do not trip" guarantee is therefore enforced at the mapping layer (Step 1's table), not via the guard. Do not call `g.on_failure` with a user reason; there is no such `FailureReason` variant.

- [ ] **Step 4: Run the guard tests**

Run: `cargo nextest run -p rimap-authz guard`
Expected: PASS.

- [ ] **Step 5: Lint both crates**

Run: `cargo clippy -p rimap-server -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/mcp/dispatch.rs crates/rimap-authz/src/guard.rs
git commit -m "test(server): exhaustively cover breaker reason mapping and tripping"
```

---

### Task 4: Make non-UIDPLUS folder-wide EXPUNGE observable

**Issue (real data loss):** When the server advertises neither MOVE nor UIDPLUS, both `delete_message` (`crates/rimap-imap/src/ops/delete.rs:69-79`) and `copy_delete_fallback` (`crates/rimap-imap/src/ops/move_message.rs:189-198`) issue a bare `session.expunge()`, which removes EVERY `\Deleted` message in the selected folder — not only the targeted UIDs. This is unreachable against Dovecot (always UIDPLUS), uncovered, silent (no warning), and `DeleteResult` carries no fallback signal (unlike `MoveOutcome`).

**Decision (from review):** keep current behavior, but (a) extract the branch into a pure, unit-tested `expunge_strategy` function, (b) emit a `tracing::warn!` on the folder-wide branch, (c) add `used_fallback` to `DeleteResult` to match `MoveOutcome`. No mock server; no functional change to which messages are deleted.

**Files:**
- Create: `crates/rimap-imap/src/ops/expunge.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs` (register the module)
- Modify: `crates/rimap-imap/src/ops/delete.rs` (use the helper; add `used_fallback`)
- Modify: `crates/rimap-imap/src/ops/move_message.rs` (use the helper; thread `src_folder` for the warn)

- [ ] **Step 1: Write the failing unit test for the strategy function**

Create `crates/rimap-imap/src/ops/expunge.rs` with the test first (the types it references are added in Step 2):

```rust
//! EXPUNGE strategy selection shared by delete and move fallbacks.
//!
//! After flagging messages `\Deleted`, the server's UIDPLUS capability
//! decides whether we can scope the expunge to specific UIDs (RFC 4315
//! `UID EXPUNGE`, safe) or must issue a folder-wide RFC 3501 `EXPUNGE`
//! that removes ALL `\Deleted` messages in the selected mailbox.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;

/// Which EXPUNGE form to issue after flagging messages `\Deleted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpungeStrategy {
    /// `UID EXPUNGE` (RFC 4315): removes only the named UIDs. Safe.
    Scoped,
    /// Plain `EXPUNGE` (RFC 3501): removes ALL `\Deleted` messages in the
    /// selected folder. Data-loss risk when other messages are flagged
    /// `\Deleted` by concurrent clients.
    FolderWide,
}

/// Choose the EXPUNGE strategy from the server's UIDPLUS capability.
pub(crate) fn expunge_strategy(has_uidplus: bool) -> ExpungeStrategy {
    if has_uidplus {
        ExpungeStrategy::Scoped
    } else {
        ExpungeStrategy::FolderWide
    }
}

/// Execute the chosen EXPUNGE against the currently selected mailbox,
/// draining the response stream. Emits a `warn!` on the folder-wide
/// (data-loss) path so operators can see when the unsafe fallback ran.
pub(crate) async fn run_expunge(
    session: &mut ImapSession,
    uid_set: &str,
    strategy: ExpungeStrategy,
    selected_folder: &str,
) -> Result<(), ImapError> {
    match strategy {
        ExpungeStrategy::Scoped => {
            let stream = session
                .uid_expunge(uid_set)
                .await
                .map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _uid = item.map_err(super::folders::map_err)?;
            }
        }
        ExpungeStrategy::FolderWide => {
            tracing::warn!(
                folder = %selected_folder,
                "issuing folder-wide EXPUNGE because the server lacks UIDPLUS; \
                 every message flagged \\Deleted in this folder is removed, not \
                 only the targeted UIDs",
            );
            let stream = session.expunge().await.map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _seq = item.map_err(super::folders::map_err)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ExpungeStrategy, expunge_strategy};

    #[test]
    fn uidplus_present_selects_scoped() {
        assert_eq!(expunge_strategy(true), ExpungeStrategy::Scoped);
    }

    #[test]
    fn uidplus_absent_selects_folder_wide() {
        assert_eq!(expunge_strategy(false), ExpungeStrategy::FolderWide);
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/rimap-imap/src/ops/mod.rs`, add the module declaration alongside the other `mod`/`pub(crate) mod` lines (match the surrounding visibility style; `delete` and `move_message` are `pub(crate) mod`):

```rust
pub(crate) mod expunge;
```

- [ ] **Step 3: Run the strategy unit test**

Run: `cargo nextest run -p rimap-imap expunge`
Expected: PASS (both `uidplus_present_selects_scoped` and `uidplus_absent_selects_folder_wide`).

- [ ] **Step 4: Use the helper in `delete_message` and add `used_fallback`**

In `crates/rimap-imap/src/ops/delete.rs`, replace the fallback block (lines 52-80, the `} else {` COPY+EXPUNGE branch) so it delegates to `run_expunge`:

```rust
    } else {
        // Fallback: COPY + scoped-or-folder-wide EXPUNGE.
        session
            .uid_copy(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
        // The \Deleted flag was already set in step 1.
        let strategy = super::expunge::expunge_strategy(has_uidplus);
        super::expunge::run_expunge(session, &uid_set, strategy, source_folder).await?;
    }
```

Update the `DeleteResult` struct (lines 89-96) to add the signal:

```rust
/// Result of a `delete_message` operation.
#[derive(Debug)]
#[non_exhaustive]
pub struct DeleteResult {
    /// The UID of the deleted message (in its original folder).
    pub uid: Uid,
    /// `true` if the message was moved to Trash; `false` if it was
    /// already in Trash and only flagged.
    pub moved_to_trash: bool,
    /// `true` when the non-atomic COPY+EXPUNGE fallback was used instead
    /// of server-side `UID MOVE`. When the server also lacks UIDPLUS this
    /// fallback issues a folder-wide EXPUNGE (data-loss risk); callers
    /// should surface a security warning. Mirrors `MoveOutcome::used_fallback`.
    pub used_fallback: bool,
}
```

Update BOTH `DeleteResult` construction sites. The early `in_trash` return (lines 39-42):

```rust
        return Ok(DeleteResult {
            uid,
            moved_to_trash: false,
            used_fallback: false,
        });
```

The final return (lines 82-85) — `used_fallback` is true exactly when the COPY+EXPUNGE path ran, i.e. `!has_move`:

```rust
    Ok(DeleteResult {
        uid,
        moved_to_trash: true,
        used_fallback: !has_move,
    })
```

- [ ] **Step 5: Use the helper in `copy_delete_fallback` and thread `src_folder`**

In `crates/rimap-imap/src/ops/move_message.rs`, change `copy_delete_fallback`'s signature (line 144-149) to accept the source folder for the warn, and replace the UIDPLUS branch (lines 178-198) with the helper:

```rust
async fn copy_delete_fallback(
    session: &mut ImapSession,
    src_folder: &str,
    dest_folder: &str,
    uids: &[Uid],
    has_uidplus: bool,
) -> Result<(Vec<MoveResult>, Option<u32>), ImapError> {
```

Replace lines 175-200 (the STORE + the `if has_uidplus { … } else { … }` block + the final `Ok(...)`) with:

```rust
    // Step 3: STORE +FLAGS \Deleted on the originals.
    store::store(session, uids, &[Flag::Deleted], FlagAction::Add).await?;

    // Step 4: Remove the flagged messages from the source folder.
    let strategy = crate::ops::expunge::expunge_strategy(has_uidplus);
    crate::ops::expunge::run_expunge(session, &uid_set, strategy, src_folder).await?;

    Ok((build_results(uids), destination_uid_validity))
```

Update the single call site (line 111-112) to pass `src_folder`:

```rust
    if !has_move {
        let (results, destination_uid_validity) =
            copy_delete_fallback(session, src_folder, dest_folder, uids, has_uidplus).await?;
```

- [ ] **Step 6: Build and run the imap crate tests**

Run: `cargo nextest run -p rimap-imap`
Expected: PASS. The pre-existing `delete.rs` / `move_message.rs` unit tests still pass; the new `expunge::tests` pass. (The Dovecot integration cases require Docker — skip them here; they are run separately.)

- [ ] **Step 7: Verify consumers still compile**

The MCP tool reads `result.moved_to_trash` (`crates/rimap-server/src/tools/mailbox/delete_message.rs:82`); adding a field keeps it compiling. Confirm:

Run: `cargo check -p rimap-server --all-targets`
Expected: success (no error about missing `used_fallback` — that field is internal to the IMAP result and not required by the tool's own output struct).

- [ ] **Step 8: Lint**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: no warnings. (If clippy flags `run_expunge` for too many arguments or the `match` for a single-arm style, address per the repo's lint config; 4 params is within the ≤5 limit.)

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-imap/src/ops/expunge.rs crates/rimap-imap/src/ops/mod.rs \
        crates/rimap-imap/src/ops/delete.rs crates/rimap-imap/src/ops/move_message.rs
git commit -m "feat(imap): surface non-UIDPLUS folder-wide EXPUNGE via strategy enum"
```

---

## Self-Review

**Spec coverage:**
- Issue 1 (FolderGuard mUTF-7) → Task 1. ✓
- Issue 2 (envelope fail-closed, no-orphan) → Task 2. ✓
- Issue 3 (breaker service-vs-user tripping) → Task 3 (mapping table + guard sequence). ✓
- Issue 4 (non-UIDPLUS EXPUNGE) → Task 4 (pure strategy fn + warn + `DeleteResult.used_fallback`, per the chosen "pure fn + observe" options). ✓

**Type consistency:** `ExpungeStrategy`/`expunge_strategy`/`run_expunge` defined in Task 4 Step 1 and used with the same names/signatures in Steps 4–5. `DeleteResult.used_fallback` defined in Step 4 and set at all three construction points. `FailureReason` (not `BreakerReason`) used throughout Task 3. `test_writer_fail_open` defined before use in Task 2.

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code. Run commands have explicit expected outcomes.

**Open follow-ups (out of scope, noted not silently dropped):**
- Threading `DeleteResult.used_fallback` / `MoveOutcome.used_fallback` into the MCP tool *output* so the agent sees the security signal would change a tool output schema and require `just regen-tool-schemas`; deferred.
- Whether to *refuse* (fail-closed) on neither-MOVE-nor-UIDPLUS instead of observing was explicitly declined in favor of the observe approach.
