# Secret-leak canary sweep Implementation Plan (#528)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every wire-driven e2e suite a post-run sweep that fails the test if the harness's password appears verbatim in any artifact the run produced, with a positive control that authentication actually happened.

**Architecture:** A shared `support/canary.rs` module (per-run `fresh_canary()`, fixed `DOVECOT_CANARY_PASSWORD`, a pure `scan`, and asserting wrappers `assert_absent` / `assert_login_frame_only`). Each wire suite injects a canary and sweeps its `TempDir` artifacts + fake `recorded()` frames at teardown. Two meta-test binaries make AC1 (coverage) and AC2 (the sweep bites) falsifiable.

**Tech Stack:** Rust 2024, `tokio` integration tests, `tempfile`, the wire `Harness` and `FakeImapServer` test-support. Pure `std` in the new module — no new deps.

**Spec:** `docs/superpowers/specs/2026-07-14-issue-528-secret-leak-canary-design.md`
**ADR:** `docs/ADR/0010-secret-leak-canary-sweep.md`

## Global Constraints

- **Toolchain 1.94.0, MSRV 1.88.0, edition 2024.** No syntax/deps that break MSRV.
- **Zero warnings.** `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must be clean.
- **No `matches!` macro; no wildcard matches** — explicit destructuring.
- **No `unwrap()` in non-test code**; test modules may `#[expect(clippy::unwrap_used)]`. Support modules already `#![expect(clippy::expect_used, ...)]` / `#![expect(clippy::panic, ...)]`.
- **No `#[allow(...)]`** — use `#[expect(..., reason = "...")]`.
- **Per-binary dead-code:** each `#[path=...]` support module compiles into every including test binary; items used by some binaries look dead in others. The module MUST carry a `force_use_for_dead_code_link()` referencing every public item (mirror `support/wire/harness.rs`).
- **Sentinel value (fixed, colon-free):** `RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2`. Must match byte-for-byte in `crates/rimap-imap/tests/integration/dovecot/users`, `crates/rimap-imap/tests/integration/support/container.rs`, and `canary::DOVECOT_CANARY_PASSWORD`.
- **Guardrails:** `just fmt-check`, `just lint`, `just test` (full nextest; Dovecot suites silent-skip without a container runtime — set `RIMAP_REQUIRE_DOCKER=1` when a runtime is present to force them), `just deny`, `just ci` before pushing.
- **Commits:** conventional-commit prefixes (`test:`, `feat:`, `refactor:`), imperative ≤72-char subject, one logical change per commit. End each commit body with the `Co-Authored-By` trailer the repo requires.

---

### Task 1: Canary module core — `scan` / `assert_absent` + AC2 file-leak meta-test

**Files:**
- Create: `crates/rimap-server/tests/support/canary.rs`
- Create: `crates/rimap-server/tests/canary_sweep_meta.rs`

**Interfaces:**
- Produces: `canary::DOVECOT_CANARY_PASSWORD: &str`, `canary::fresh_canary() -> String`, `canary::CanaryHit { source: String, excerpt: String }`, `canary::ScanReport { hits: Vec<CanaryHit>, errors: Vec<String> }`, `canary::scan(canary: &str, roots: &[&Path], extra: &[String]) -> ScanReport`, `canary::assert_absent(canary: &str, roots: &[&Path], extra: &[String])`.

- [ ] **Step 1: Write the failing AC2 meta-test (`canary_sweep_meta.rs`)**

```rust
//! Meta-test for the canary sweep (issue #528, AC2). Proves the sweep detects a
//! deliberately-seeded leak and stays clean on a leak-free tree. Host-runnable,
//! no container, PR-blocking.
// Only `unwrap_used` is expected: this file uses `.unwrap()` but no `.expect()`
// and no literal `panic!` (assert!/assert_eq!/#[should_panic] do NOT trigger
// clippy::panic). Declaring expect_used/panic here would be unfulfilled → error.
#![expect(clippy::unwrap_used, reason = "test")]

use std::path::Path;

use tempfile::TempDir;

#[path = "support/canary.rs"]
mod canary;

#[test]
fn scan_flags_a_seeded_file_leak() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    let leaky = dir.path().join("audit.jsonl");
    std::fs::write(&leaky, format!("{{\"pw\":\"{canary}\"}}\n")).unwrap();

    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert_eq!(report.errors.len(), 0, "no read errors expected");
    assert!(
        report.hits.iter().any(|h| h.source.contains("audit.jsonl")),
        "seeded leak must be reported, got {:?}",
        report.hits.iter().map(|h| &h.source).collect::<Vec<_>>(),
    );
}

#[test]
fn scan_flags_an_extra_string_leak() {
    let canary = canary::fresh_canary();
    let frame = format!("a1 LOGIN rimap-test {canary}\r\n");
    let report = canary::scan(&canary, &[], &[frame]);
    assert_eq!(report.hits.len(), 1, "extra-string leak must be reported");
}

#[test]
fn scan_is_clean_on_a_leak_free_tree() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("audit.jsonl"), b"{\"ok\":true}\n").unwrap();
    std::fs::write(dir.path().join("server.stderr.log"), b"info: ready\n").unwrap();
    std::fs::create_dir(dir.path().join("downloads")).unwrap();
    std::fs::write(dir.path().join("downloads/msg.eml"), b"Subject: hi\r\n\r\nbody").unwrap();

    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert_eq!(report.hits.len(), 0, "no leak expected");
    assert_eq!(report.errors.len(), 0, "no read errors expected");
}

#[cfg(unix)]
#[test]
fn scan_reports_unreadable_artifact() {
    use std::os::unix::fs::PermissionsExt;

    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    let secret = dir.path().join("locked.log");
    std::fs::write(&secret, b"whatever").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Root can read a 0o000 file, so only assert the error path when the OS
    // actually denies the read (non-root). Keeps the test non-flaky under both.
    if std::fs::read(&secret).is_ok() {
        // running as root; restore perms so TempDir cleanup succeeds.
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert!(
        report.errors.iter().any(|e| e.contains("locked.log")),
        "unreadable file must surface in errors, not be silently skipped: {:?}",
        report.errors,
    );
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
#[should_panic(expected = "canary sweep failed")]
fn assert_absent_panics_on_a_leak() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("stderr.log"), canary.as_bytes()).unwrap();
    canary::assert_absent(&canary, &[dir.path()], &[]);
}

// Referenced so the `Path` import and const stay live in this binary.
#[test]
fn dovecot_sentinel_is_colon_free() {
    let p: &Path = Path::new(".");
    let _ = p;
    assert!(!canary::DOVECOT_CANARY_PASSWORD.contains(':'), "sentinel must be a valid passwd-file password");
}
```

- [ ] **Step 2: Run it to verify it fails (module missing)**

Run: `cargo nextest run -p rimap-server -E 'binary(canary_sweep_meta)' 2>&1 | tail -20`
Expected: FAIL — `canary.rs` does not exist / unresolved module.

- [ ] **Step 3: Create `support/canary.rs` (core)**

```rust
//! Secret-leak canary sweep shared by the wire e2e suites (issue #528, ADR-0010).
//! Each suite injects a canary password and, at teardown, asserts it appears in
//! no artifact the run produced. See
//! `docs/superpowers/specs/2026-07-14-issue-528-secret-leak-canary-design.md`.
// NOTE: declare ONLY lints this file actually triggers — an unfulfilled
// `#[expect]` is itself an error under `-D warnings`. This module uses `panic!`
// (in `assert_absent`) but no `.expect()` and no `.unwrap()`, so only
// `clippy::panic` is expected.
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed high-entropy sentinel that IS the Dovecot fixture password. MUST match,
/// byte for byte:
///   crates/rimap-imap/tests/integration/dovecot/users   (source of truth)
///   crates/rimap-imap/tests/integration/support/container.rs
/// Contains no ':' — the passwd-file field separator.
pub const DOVECOT_CANARY_PASSWORD: &str = "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2";

/// Mint a unique, high-entropy, per-run canary password for fake-backed / env-fed
/// suites (the fake accepts any LOGIN). The `RIMAP-CANARY-` prefix makes any leak
/// instantly attributable in an artifact dump. Same entropy recipe as the Dovecot
/// harness's `uuid_like` (SystemTime nanos + pid + process-local counter).
pub fn fresh_canary() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("RIMAP-CANARY-{nanos:x}-{pid:x}-{n:x}")
}

/// One place the canary appeared.
pub struct CanaryHit {
    /// A file path, or `extra[N]` for an in-memory string.
    pub source: String,
    /// Context window around the match, canary masked as `<CANARY>`.
    pub excerpt: String,
}

/// Outcome of a scan: hits found + artifacts that could not be read. A detector
/// that "could not look" must never be reported as clean, so both are surfaced.
pub struct ScanReport {
    pub hits: Vec<CanaryHit>,
    pub errors: Vec<String>,
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn excerpt_at(bytes: &[u8], at: usize, needle_len: usize, canary: &str) -> String {
    let start = at.saturating_sub(24);
    let end = (at + needle_len + 24).min(bytes.len());
    String::from_utf8_lossy(&bytes[start..end]).replace(canary, "<CANARY>")
}

/// Recursively scan regular files under each root (as bytes), plus each `extra`
/// string, for `canary`. Does not follow symlinks. Surfaces read/traversal
/// errors rather than swallowing them. Never panics.
pub fn scan(canary: &str, roots: &[&Path], extra: &[String]) -> ScanReport {
    let needle = canary.as_bytes();
    let mut report = ScanReport { hits: Vec::new(), errors: Vec::new() };
    for root in roots {
        scan_path(root, needle, canary, &mut report);
    }
    for (i, s) in extra.iter().enumerate() {
        if let Some(at) = find_bytes(s.as_bytes(), needle) {
            report.hits.push(CanaryHit {
                source: format!("extra[{i}]"),
                excerpt: excerpt_at(s.as_bytes(), at, needle.len(), canary),
            });
        }
    }
    report
}

fn scan_path(path: &Path, needle: &[u8], canary: &str, report: &mut ScanReport) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.errors.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return;
    }
    if file_type.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(rd) => rd,
            Err(e) => {
                report.errors.push(format!("{}: {e}", path.display()));
                return;
            }
        };
        for entry in entries {
            match entry {
                Ok(e) => scan_path(&e.path(), needle, canary, report),
                Err(e) => report.errors.push(format!("{}: {e}", path.display())),
            }
        }
        return;
    }
    if !file_type.is_file() {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            report.errors.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    if let Some(at) = find_bytes(&bytes, needle) {
        report.hits.push(CanaryHit {
            source: path.display().to_string(),
            excerpt: excerpt_at(&bytes, at, needle.len(), canary),
        });
    }
}

/// Assert the canary is absent from every file artifact AND that every artifact
/// was readable; panic listing all hits and read errors otherwise. Thin wrapper
/// over `scan`. An unreadable root/file is a hard failure, not a silent skip.
pub fn assert_absent(canary: &str, roots: &[&Path], extra: &[String]) {
    let report = scan(canary, roots, extra);
    if report.hits.is_empty() && report.errors.is_empty() {
        return;
    }
    let mut lines = Vec::new();
    for h in &report.hits {
        lines.push(format!("  LEAK in {}: {}", h.source, h.excerpt));
    }
    for e in &report.errors {
        lines.push(format!("  UNREADABLE {e}"));
    }
    panic!(
        "canary sweep failed ({} leak(s), {} unreadable):\n{}",
        report.hits.len(),
        report.errors.len(),
        lines.join("\n"),
    );
}

/// Reference every public item so no e2e binary sees a partially-used module as
/// dead code. Mirrors the `force_use_for_dead_code_link` pattern in
/// `support/wire/harness.rs`. `assert_login_frame_only` is added in Task 2.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code across e2e_wire binaries"
)]
fn force_use_for_dead_code_link() {
    let _ = DOVECOT_CANARY_PASSWORD;
    let _ = fresh_canary;
    let _ = scan;
    let _ = assert_absent;
    let hit = CanaryHit { source: String::new(), excerpt: String::new() };
    let _ = (&hit.source, &hit.excerpt);
    let rep = ScanReport { hits: Vec::new(), errors: Vec::new() };
    let _ = (&rep.hits, &rep.errors);
}
```

- [ ] **Step 4: Run the meta-test to verify it passes**

Run: `cargo nextest run -p rimap-server -E 'binary(canary_sweep_meta)'`
Expected: PASS (5–6 tests; the unix-only unreadable test runs on macOS/Linux).

- [ ] **Step 5: Lint + format**

Run: `just fmt && cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/support/canary.rs crates/rimap-server/tests/canary_sweep_meta.rs
git commit -m "test(server): add canary file-sweep core + AC2 meta-test (#528)"
```

---

### Task 2: Wire-frame positive/negative control — `assert_login_frame_only`

**Files:**
- Modify: `crates/rimap-server/tests/support/canary.rs`
- Modify: `crates/rimap-server/tests/canary_sweep_meta.rs`

**Interfaces:**
- Produces: `canary::assert_login_frame_only(canary: &str, recorded: &[String])`.

- [ ] **Step 1: Add the failing control meta-tests to `canary_sweep_meta.rs`**

```rust
#[test]
fn login_frame_only_accepts_canary_in_login() {
    let canary = canary::fresh_canary();
    let recorded = vec![
        "a1 CAPABILITY\r\n".to_string(),
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        "a3 SELECT INBOX\r\n".to_string(),
    ];
    canary::assert_login_frame_only(&canary, &recorded); // must not panic
}

#[test]
#[should_panic(expected = "non-LOGIN")]
fn login_frame_only_rejects_canary_outside_login() {
    let canary = canary::fresh_canary();
    let recorded = vec![
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        format!("a3 APPEND INBOX {{10}}\r\n{canary}\r\n"),
    ];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
#[should_panic(expected = "positive control failed")]
fn login_frame_only_rejects_missing_login() {
    let canary = canary::fresh_canary();
    let recorded = vec!["a1 CAPABILITY\r\n".to_string()];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
#[should_panic(expected = "non-LOGIN")]
fn login_frame_predicate_matches_command_position_only() {
    let canary = canary::fresh_canary();
    // Command is SEARCH, not LOGIN, even though the arg contains "LOGIN".
    let recorded = vec![
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        format!("a3 SEARCH SUBJECT \"LOGIN {canary}\"\r\n"),
    ];
    canary::assert_login_frame_only(&canary, &recorded);
}
```

- [ ] **Step 2: Run to verify failure (fn missing)**

Run: `cargo nextest run -p rimap-server -E 'binary(canary_sweep_meta)' 2>&1 | tail -20`
Expected: FAIL — `assert_login_frame_only` not found.

- [ ] **Step 3: Add the predicate + assertion to `support/canary.rs`** (insert above `force_use_for_dead_code_link`)

```rust
/// A recorded frame is a LOGIN frame iff, after the leading tag (first token),
/// the command token equals LOGIN (case-insensitive). Matches command position
/// only — a SELECT/APPEND/SEARCH arg containing "LOGIN" is non-LOGIN.
fn is_login_frame(frame: &str) -> bool {
    let mut tokens = frame.split_whitespace();
    let _tag = tokens.next();
    match tokens.next() {
        Some(cmd) => cmd.eq_ignore_ascii_case("LOGIN"),
        None => false,
    }
}

/// Positive + negative control over the fake's recorded client dialog. The
/// credential legitimately appears exactly once — in the plaintext LOGIN frame —
/// so a blanket `assert_absent` over `recorded()` would always fire. Instead:
///   - positive control: at least one recorded LOGIN frame contains the canary
///     (proof the run authenticated and the credential reached the wire);
///   - negative control: no non-LOGIN recorded frame contains the canary.
/// Panics on either violation. Do NOT call for suites that never reach LOGIN
/// (e.g. a TLS-pin failure) — use `assert_absent` there.
pub fn assert_login_frame_only(canary: &str, recorded: &[String]) {
    let needle = canary.as_bytes();
    let mut login_hits = 0usize;
    let mut leaks = Vec::new();
    for frame in recorded {
        if find_bytes(frame.as_bytes(), needle).is_none() {
            continue;
        }
        if is_login_frame(frame) {
            login_hits += 1;
        } else {
            leaks.push(frame.trim_end().replace(canary, "<CANARY>"));
        }
    }
    assert!(
        leaks.is_empty(),
        "canary leaked into {} non-LOGIN recorded frame(s):\n{}",
        leaks.len(),
        leaks.join("\n"),
    );
    assert!(
        login_hits >= 1,
        "positive control failed: canary never appeared in a LOGIN frame — the \
         run did not authenticate (recorded {} frame(s))",
        recorded.len(),
    );
}
```

Then add to `force_use_for_dead_code_link`: `let _ = assert_login_frame_only;` and `let _ = is_login_frame;`.

- [ ] **Step 4: Run the meta-test to verify it passes**

Run: `cargo nextest run -p rimap-server -E 'binary(canary_sweep_meta)'`
Expected: PASS (all cases, including the 3 `should_panic`).

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/support/canary.rs crates/rimap-server/tests/canary_sweep_meta.rs
git commit -m "test(server): add LOGIN-frame positive/negative control (#528)"
```

---

### Task 3: Rename the Dovecot fixture password to the sentinel

Purpose: change the fixture password everywhere it appears so nothing breaks (Dovecot still authenticates) and every credential-under-test is a high-entropy canary. This is a pure value rename — no sweeps yet — so the risk "does Dovecot accept the new password" is isolated and verified alone. The tree stays green after this task.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot/users`
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` (the `"testpass"` at ~line 160)
- Modify (each `const DOVECOT_PASSWORD: &str = "testpass";` → `= "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2";`):
  `e2e_wire.rs`, `e2e_wire_cancellation.rs`, `e2e_wire_chaos.rs`, `e2e_wire_destructive.rs`, `e2e_wire_fault_injection.rs`, `e2e_wire_folder_management.rs`, `e2e_wire_tool_advertisement.rs`, `e2e_wire_multi_account_advertisement.rs`
- Modify (in-process suites, `StaticCreds("testpass")` and SMTP `"testpass"` → the sentinel):
  `e2e.rs`, `server_capabilities.rs`, `e2e_smtp.rs`, `e2e_smtp_real.rs`

- [ ] **Step 1: Edit the passwd-file source of truth**

`crates/rimap-imap/tests/integration/dovecot/users` becomes exactly:
```
rimap-test:{PLAIN}RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2
```

- [ ] **Step 2: Update `container.rs`** — change the `"testpass"` literal to `"RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2"`. Add a comment: `// Must match dovecot/integration/dovecot/users and canary::DOVECOT_CANARY_PASSWORD.`

- [ ] **Step 3: Update every server-side literal.** Replace each `const DOVECOT_PASSWORD: &str = "testpass";` and each `StaticCreds("testpass".into())` / `SmtpClient::new(&cfg, "testpass")` with the sentinel string literal. (These stay local literals for now; the wire suites are de-duplicated to `canary::DOVECOT_CANARY_PASSWORD` in Tasks 6–7.)

Find them all:
```bash
rg -n '"testpass"' crates/rimap-server/tests crates/rimap-imap/tests
```
Expected after edits: no `"testpass"` remains under `crates/` (the two `docs/…plans` occurrences are historical and out of scope).

- [ ] **Step 4: Verify formatting**

Run: `just fmt-check`
Expected: clean (or run `just fmt`).

- [ ] **Step 5: Verify Dovecot still authenticates.** If a container runtime is present, force the Dovecot suites to run:

Run both crates that authenticate against the renamed passwd-file — `rimap-server`'s wire e2e AND `rimap-imap`'s own Dovecot integration tests (which consume `container.rs::password()` and the same `users` file):
```
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire)' 2>&1 | tail -30
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap 2>&1 | tail -30
```
Expected: PASS — login round-trips against the renamed passwd-file in both crates. If no runtime is available locally, run without `RIMAP_REQUIRE_DOCKER` (silent-skip) and rely on CI's Dovecot lane; do not proceed to Task 6 until a Dovecot run has gone green somewhere (locally or on the PR). A rename typo shows up here as a login failure.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot/users \
        crates/rimap-imap/tests/integration/support/container.rs \
        crates/rimap-server/tests/e2e_wire.rs crates/rimap-server/tests/e2e_wire_cancellation.rs \
        crates/rimap-server/tests/e2e_wire_chaos.rs crates/rimap-server/tests/e2e_wire_destructive.rs \
        crates/rimap-server/tests/e2e_wire_fault_injection.rs crates/rimap-server/tests/e2e_wire_folder_management.rs \
        crates/rimap-server/tests/e2e_wire_tool_advertisement.rs crates/rimap-server/tests/e2e_wire_multi_account_advertisement.rs \
        crates/rimap-server/tests/e2e.rs crates/rimap-server/tests/server_capabilities.rs \
        crates/rimap-server/tests/e2e_smtp.rs crates/rimap-server/tests/e2e_smtp_real.rs
git commit -m "test: rename Dovecot fixture password to high-entropy sentinel (#528)"
```

---

### Task 4: Wire the fake `login-frame` suites (6)

Suites (all backed by `FakeImapServer`, all inject `"fake-password"` today, all authenticate): `e2e_wire_fetch_skipped`, `e2e_wire_folder_not_found`, `e2e_wire_transcript_cleanup`, `e2e_wire_transcript_triage`, `e2e_wire_uidvalidity`, `e2e_wire_login_rejected`.

**Files:** each of the 6 `crates/rimap-server/tests/e2e_wire_<name>.rs`.

**Per-suite edits (apply the identical pattern to all 6):**

1. Add the module include near the other `#[path = ...] mod ...;` lines:
   ```rust
   #[path = "support/canary.rs"]
   mod canary;
   ```
2. In **every** `#[tokio::test]` that spawns a harness: bind the canary once and inject it instead of the literal:
   ```rust
   let password = canary::fresh_canary();
   // ...
   let mut harness = Harness::spawn_with_config(
       &config_path,
       tempdir,
       &[(PASSWORD_ENV_VAR, password.as_str())],
   ).await;
   ```
   (Replace the existing `&[(PASSWORD_ENV_VAR, "fake-password")]`.)
3. Capture the fake's recorded frames and sweep at teardown, **after** the child is reaped:
   ```rust
   let recorded = server.recorded();
   let (_status, tempdir) = harness.shutdown_and_wait().await;
   canary::assert_login_frame_only(&password, &recorded);
   canary::assert_absent(&password, &[tempdir.path()], &[]);
   ```
   If a suite already ends by dropping the harness without `shutdown_and_wait`, add the `shutdown_and_wait` call so the reap-and-flush barrier holds before the sweep (see §4.4 of the spec). The fake `server` variable is already in scope in each (it is the `FakeImapServer::start(...)` local, sometimes wrapped in `DumpOnPanic`).

- [ ] **Step 1: Wire `e2e_wire_fetch_skipped.rs` first** (it has one authenticating test, `search_reports_fetch_skipped_on_short_page_over_wire`). Apply edits 1–3. `PASSWORD_ENV_VAR` is a file-local `const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";` in the fake suites (imported from `rimap_config` in the Dovecot suites) — either form already resolves, no import change needed.

- [ ] **Step 2: Run it**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_fetch_skipped)'`
Expected: PASS — LOGIN-frame positive control holds (fake records the LOGIN), file sweep clean.

- [ ] **Step 3: Wire the remaining 5** the same way. For each, identify every harness-spawning `#[tokio::test]` and add the canary binding + teardown sweep to each. `e2e_wire_login_rejected` sends a rejected password — it still records a LOGIN frame, so `assert_login_frame_only` applies unchanged. `e2e_wire_uidvalidity` has 3 tests: wire all 3.

- [ ] **Step 4: Run all 6**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_fetch_skipped) | binary(e2e_wire_folder_not_found) | binary(e2e_wire_transcript_cleanup) | binary(e2e_wire_transcript_triage) | binary(e2e_wire_uidvalidity) | binary(e2e_wire_login_rejected)'`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire_fetch_skipped.rs crates/rimap-server/tests/e2e_wire_folder_not_found.rs \
        crates/rimap-server/tests/e2e_wire_transcript_cleanup.rs crates/rimap-server/tests/e2e_wire_transcript_triage.rs \
        crates/rimap-server/tests/e2e_wire_uidvalidity.rs crates/rimap-server/tests/e2e_wire_login_rejected.rs
git commit -m "test(server): sweep canary in fake login-frame e2e suites (#528)"
```

---

### Task 5: Wire the fake hygiene suite `e2e_wire_tls_pin_mismatch`

This suite fails the TLS pin **before** LOGIN, so `recorded()` is empty and there is no positive control — absence-only. It **already** calls `shutdown_and_wait` (`let (status, tempdir) = harness.shutdown_and_wait().await;` at ~line 127 and reads `tempdir.path()` for audit/stderr assertions), so no new accessor is needed: sweep the tempdir it already returns.

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire_tls_pin_mismatch.rs`

- [ ] **Step 1: Wire the suite.** Add `#[path = "support/canary.rs"] mod canary;`. Bind `let password = canary::fresh_canary();` and inject it (replace `"fake-password"`). Capture `let recorded = server.recorded();` before `shutdown_and_wait`. After the existing audit/stderr assertions on the returned `tempdir`, add:
   ```rust
   canary::assert_absent(&password, &[tempdir.path()], &recorded);
   ```
   `recorded` is empty of the canary (no LOGIN sent). Do **not** call `assert_login_frame_only` here.

- [ ] **Step 2: Run**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_tls_pin_mismatch)'`
Expected: PASS.

- [ ] **Step 3: Lint**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire_tls_pin_mismatch.rs
git commit -m "test(server): sweep canary in tls-pin-mismatch suite (#528)"
```

---

### Task 6: Wire the Dovecot `tool-success` suites (3)

Suites: `e2e_wire` (3 tests), `e2e_wire_destructive`, `e2e_wire_folder_management`. Each authenticates and asserts successful tool responses (the positive control), so no wire-frame check is available (TLS to the container) — sweep the tempdir only.

**Files:** the 3 `crates/rimap-server/tests/e2e_wire*.rs` above.

**Per-suite edits:**
1. Add `#[path = "support/canary.rs"] mod canary;`.
2. Replace the file's local `const DOVECOT_PASSWORD: &str = "…";` usage with `canary::DOVECOT_CANARY_PASSWORD` (delete the local const, or set it to `canary::DOVECOT_CANARY_PASSWORD`). Keep the in-file credential-store resolver returning that value.
3. In **every** harness-spawning `#[tokio::test]`, after `shutdown_and_wait`, sweep:
   ```rust
   let (_status, tempdir) = harness.shutdown_and_wait().await;
   canary::assert_absent(canary::DOVECOT_CANARY_PASSWORD, &[tempdir.path()], &[]);
   ```
   Some `e2e_wire.rs` tests already destructure `shutdown_and_wait` to read the audit log (`let (_status, tempdir) = ...`); reuse that `tempdir` binding and add the sweep after the existing audit assertions. Do not drop the tempdir before the sweep.

- [ ] **Step 1: Wire `e2e_wire.rs`** (all 3 authenticating tests). Ensure each test's `shutdown_and_wait` tempdir is swept.

- [ ] **Step 2: Run (with a runtime if available)**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire)' 2>&1 | tail -30`
Expected: PASS (or silent-skip without a runtime — then rely on CI's Dovecot lane).

- [ ] **Step 3: Wire `e2e_wire_destructive.rs` and `e2e_wire_folder_management.rs`** the same way; sweep every harness-spawning test.

- [ ] **Step 4: Run**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_destructive) | binary(e2e_wire_folder_management)' 2>&1 | tail -30`
Expected: PASS or silent-skip.

- [ ] **Step 5: Lint (compiles regardless of runtime)**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire.rs crates/rimap-server/tests/e2e_wire_destructive.rs crates/rimap-server/tests/e2e_wire_folder_management.rs
git commit -m "test(server): sweep canary in Dovecot tool-success suites (#528)"
```

---

### Task 7: Wire the Dovecot/chaos `hygiene-only` suites (5)

Suites: `e2e_wire_fault_injection`, `e2e_wire_tool_advertisement`, `e2e_wire_multi_account_advertisement`, `e2e_wire_cancellation`, `e2e_wire_chaos` (nightly). These are failure-path, advertisement, race-dependent, or may not complete a LOGIN — so the sweep is absence-only (no positive control asserted). `e2e_wire_chaos` drives the server via the wire `Harness` (`spawn_with_config`) even though `ChaosHarness` supplies the Toxiproxy+Dovecot infra, so the same teardown applies.

**Files:** the 5 suites above.

**Per-suite edits (same as Task 6 but absence-only):**
1. Add `#[path = "support/canary.rs"] mod canary;`.
2. Use `canary::DOVECOT_CANARY_PASSWORD` in place of the local `DOVECOT_PASSWORD`.
3. In every harness-spawning `#[tokio::test]`, sweep the tempdir after the child is reaped via the `TempDir` that `shutdown_and_wait` returns:
   ```rust
   let (_status, tempdir) = harness.shutdown_and_wait().await;
   canary::assert_absent(canary::DOVECOT_CANARY_PASSWORD, &[tempdir.path()], &[]);
   ```
   Suites that currently just drop the harness (`_cancellation`) need `shutdown_and_wait` added to obtain the tempdir. Every wire suite already reaps via `shutdown_and_wait` or `kill_on_drop`; there is no direct-`child.wait` path, so no `artifact_root` accessor is needed.

**`_cancellation` caution:** `shutdown_and_wait` carries a `.expect("clean exit within timeout")` (5 s `SHUTDOWN_TIMEOUT`). The cancellation scenario cancels an in-flight *request*, not the session, so closing stdin still yields a clean EOF-driven exit — but complete the cancellation exchange in the test body **before** calling `shutdown_and_wait`. If the child does not exit cleanly, the added teardown would flake; in that case sweep by capturing the audit/stderr paths before the final drop instead of adding `shutdown_and_wait`.

**During build, confirm the disposition (per spec §4.7):** if any of these suites in fact reliably completes a LOGIN and asserts a successful tool call, it may be promoted to `tool-success` — but absence-only is always safe here, so promotion is optional. Do not add a positive control you cannot guarantee.

- [ ] **Step 1: Wire `e2e_wire_fault_injection.rs`, `e2e_wire_tool_advertisement.rs`, `e2e_wire_multi_account_advertisement.rs`, `e2e_wire_cancellation.rs`.** Sweep every harness-spawning test.

- [ ] **Step 2: Wire `e2e_wire_chaos.rs`** — 5 `#[tokio::test]`s, already 5 `shutdown_and_wait` (one per test body). The sweep must live in the test body (it needs that test's returned `TempDir`), so add `assert_absent` after each of the 5 `shutdown_and_wait` sites — it cannot go in the shared spawn helper (the harness is driven by the test body between spawn and teardown). The coverage floor (§Task 8) requires 5 `assert_absent` for the 5 `#[tokio::test]`s.

- [ ] **Step 3: Run the non-chaos four (with runtime if present)**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_fault_injection) | binary(e2e_wire_tool_advertisement) | binary(e2e_wire_multi_account_advertisement) | binary(e2e_wire_cancellation)' 2>&1 | tail -30`
Expected: PASS or silent-skip.

- [ ] **Step 4: Run chaos (nightly-gated)** if a runtime is present:

Run: `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -30`
Expected: PASS or silent-skip. Chaos compiles under `just lint` regardless.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire_fault_injection.rs crates/rimap-server/tests/e2e_wire_tool_advertisement.rs \
        crates/rimap-server/tests/e2e_wire_multi_account_advertisement.rs crates/rimap-server/tests/e2e_wire_cancellation.rs \
        crates/rimap-server/tests/e2e_wire_chaos.rs
git commit -m "test(server): sweep canary in Dovecot/chaos hygiene suites (#528)"
```

---

### Task 8: AC1 coverage meta-test — `canary_coverage_meta.rs`

Structural enforcement that every `e2e_wire*.rs` references the sweep, and that per file `count(assert_absent) >= count("#[tokio::test]")` (so a single unswept test in a multi-test file also fails). The `#[tokio::test]` denominator is per-test and does not collapse under shared spawn helpers. Runs last, when all suites are wired.

**Files:**
- Create: `crates/rimap-server/tests/canary_coverage_meta.rs`

- [ ] **Step 1: Write the meta-test**

```rust
//! AC1 enforcement (issue #528): every e2e_wire*.rs suite references the canary
//! sweep, and per file its `assert_absent` count is >= its harness-spawn count
//! so no single test can spawn a harness without sweeping. Source-text check;
//! host-runnable, no container.
// Only `unwrap_used` is expected — this file uses `.unwrap()` and `assert!`
// (which is not clippy::panic). A `panic` expectation here would be unfulfilled.
#![expect(clippy::unwrap_used, reason = "test")]

use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn wire_suite_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(tests_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("e2e_wire") && name.ends_with(".rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            out.push((name, text));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn every_wire_suite_references_the_sweep() {
    let suites = wire_suite_sources();
    assert!(!suites.is_empty(), "expected e2e_wire*.rs suites to exist");
    let mut missing = Vec::new();
    for (name, text) in &suites {
        let refs_sweep =
            text.contains("canary::assert_absent") || text.contains("canary::assert_login_frame_only");
        if !refs_sweep {
            missing.push(name.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "these e2e_wire*.rs suites do not reference the canary sweep: {missing:?}",
    );
}

#[test]
fn each_test_sweeps_once() {
    // Per-test coverage floor: every `#[tokio::test]` in a wire suite drives a
    // harness and must sweep once. Require `assert_absent` count >= the number of
    // `#[tokio::test]` fns. The `#[tokio::test]` denominator is per-test — unlike
    // a raw spawn count it does NOT collapse when several tests spawn through a
    // shared helper (cancellation=2 tests/1 spawn, uidvalidity=3/1, chaos=5/1),
    // and unlike a `shutdown_and_wait` count it is not inflated by comments.
    // `assert_absent` is called exactly once per swept test in every backend, so
    // this is an exact 1:1 (fake suites also call `assert_login_frame_only`,
    // which is intentionally NOT counted to keep the ratio exact).
    let mut offenders = Vec::new();
    for (name, text) in wire_suite_sources() {
        let tests = text.matches("#[tokio::test").count();
        let sweeps = text.matches("assert_absent").count();
        if sweeps < tests {
            offenders.push(format!("{name}: {sweeps} assert_absent < {tests} #[tokio::test]"));
        }
    }
    assert!(
        offenders.is_empty(),
        "a harness-driving test lacks a canary sweep in:\n{}",
        offenders.join("\n"),
    );
}
```

- [ ] **Step 2: Run it**

Run: `cargo nextest run -p rimap-server -E 'binary(canary_coverage_meta)'`
Expected: PASS. If `each_test_sweeps_once` fails, the named suite has a `#[tokio::test]` without a matching `assert_absent` — go back and add the sweep to that test (this is the check doing its job).

- [ ] **Step 3: Lint + commit**

```bash
cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings 2>&1 | tail -20
git add crates/rimap-server/tests/canary_coverage_meta.rs
git commit -m "test(server): enforce canary sweep coverage across wire suites (#528)"
```

---

### Task 9: Full guardrail run + triage any real leak

- [ ] **Step 1: Full local CI**

Run: `just ci 2>&1 | tail -40`
Expected: green. Container suites silent-skip if no runtime; run them explicitly if a runtime is available (`RIMAP_REQUIRE_DOCKER=1 just test`).

- [ ] **Step 2: If the sweep reddened a suite, triage the leak.** A hit means a real credential leak into an artifact — that is the sweep working. Investigate the reported `source`/`excerpt`:
  - If it is a genuine redaction bug in scope, fix the redaction (e.g. a `tracing` field, an audit record) and re-run.
  - If it is out of this issue's scope, open a GitHub issue citing the leak, and — only with a documented, reviewed reason — narrow that one suite's sweep. Never weaken the canary or delete the assertion to hide a real leak.

- [ ] **Step 3: Confirm the acceptance criteria hold.**
  - AC1: `canary_coverage_meta` green; both meta-tests present.
  - AC2: `canary_sweep_meta` green (seeded leak caught, clean tree clean, unreadable surfaced, `should_panic` cases fire).

- [ ] **Step 4: Commit any triage fixes** with a descriptive message referencing #528, then proceed to review.

---

## Self-Review notes

- **Spec coverage:** module (Task 1–2) ↔ spec §4.1; sentinel rename (Task 3) ↔ §4.2; per-disposition wiring (Tasks 4–7) ↔ §4.7 table; AC1 enforcement (Task 8) ↔ §4.6; AC2 (Task 1–2 meta-test) ↔ §4.5; triage (Task 9) ↔ §5 real-leak risk. The §4.4 reap-and-flush barrier is satisfied everywhere by `shutdown_and_wait` (which returns the `TempDir`); no separate accessor is needed since no wire suite reaps the child directly.
- **Green between tasks:** Task 3 renames all literals together (no half-renamed login); the module has `force_use_for_dead_code_link` so any binary can include it without dead-code warnings; each wiring task adds `mod canary` and uses its items in the same commit.
- **Type consistency:** `scan` returns `ScanReport { hits, errors }` everywhere; `assert_absent(canary, roots, extra)` and `assert_login_frame_only(canary, recorded)` signatures are used identically in the meta-tests and every suite.
