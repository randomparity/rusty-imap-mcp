# Lenient Integer Coercion Implementation Plan (#292)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept both JSON-integer and JSON-string forms for every integer input field on every MCP tool, so calls from hosts that stringify numbers (Claude Code today, others likely) deserialize cleanly instead of being rejected by the host's pre-flight JSON Schema validator.

**Architecture:** Add one module `crates/rimap-server/src/tools/lenient_int.rs` exporting `deserialize_*` and `schema_*` function pairs per integer type (`usize`, `u32`, `NonZeroU32`, and `Option<*>` variants of each). Apply via `#[serde(deserialize_with = "…")]` + `#[schemars(schema_with = "…")]` attributes on each affected field. The field type stays the canonical Rust type — only deserialization and the published schema change. Schema becomes a `oneOf` over integer, digit-string, and (where nullable) null. Booleans and string fields are untouched.

**Tech Stack:** Rust workspace MSRV 1.88.0, `serde` 1, `schemars` 1.2, `serde_json` 1, existing `rmcp` 1.5 dispatch, no new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-18-issue-292-lenient-int-coercion-design.md`](../specs/2026-05-18-issue-292-lenient-int-coercion-design.md)

---

## File Structure

**Create:**
- `crates/rimap-server/src/tools/lenient_int.rs` — module with `IntOrStr<T>` internal helper, per-type `deserialize_*` functions, per-type `schema_*` functions, and unit tests.

**Modify:**
- `crates/rimap-server/src/tools/mod.rs` — register `pub(crate) mod lenient_int;`.
- `crates/rimap-server/src/tools/retrieval/search.rs` — annotate `limit`, `offset`.
- `crates/rimap-server/src/tools/retrieval/fetch_message.rs` — annotate `uid`, `max_body_bytes`.
- `crates/rimap-server/src/tools/retrieval/download_attachment.rs` — annotate `uid`.
- `crates/rimap-server/src/tools/retrieval/list_attachments.rs` — annotate `uid`.
- `crates/rimap-server/src/tools/mailbox/delete_message.rs` — annotate `uid`.
- `crates/rimap-server/src/tools/mailbox/flags.rs` — annotate `expected_uidvalidity`.
- `crates/rimap-server/src/tools/mailbox/labels.rs` — annotate `uid` and the two `expected_uidvalidity` fields.
- `crates/rimap-server/src/tools/mailbox/move_message.rs` — annotate `expected_source_uidvalidity`.
- `crates/rimap-server/tests/dump_tool_catalog.rs` — extend the integration assertion to check the new `oneOf` shape on each affected field.

**Test (new):**
- `crates/rimap-server/tests/lenient_int_dispatch.rs` — end-to-end dispatch test through `parse_args` for `{"limit":"100"}` on `search`.

---

## Task 0: Pre-flight — confirm branch and clean baseline

**Files:** none (verification only)

**Context:** Issue #292 was filed and branch `feat/issue-292-lenient-int-coercion` was created off `main` at commit `21b6cf7`. This task confirms the working tree is clean and the baseline test suite passes before any code changes.

- [ ] **Step 1: Confirm branch and clean tree**

Run:
```bash
git rev-parse --abbrev-ref HEAD && git status --short
```
Expected: `feat/issue-292-lenient-int-coercion` and empty status (only the two design/plan docs from the issue-filing commit, if already committed).

- [ ] **Step 2: Run baseline tests on the affected crate**

Run:
```bash
cargo test -p rimap-server --features test-support --quiet
```
Expected: all tests pass. (Note from memory: full workspace `cargo test` is slow; scoping to `-p rimap-server` is enough for this work.)

- [ ] **Step 3: Capture pre-change schema for `search.limit`**

Run:
```bash
cargo run -q -p rimap-server --bin rusty-imap-mcp --features test-support -- dump-tool-catalog \
  | python3 -c "import json,sys
for line in sys.stdin:
    t=json.loads(line)
    if t['name']=='search':
        print(json.dumps(t['inputSchema']['properties']['limit'], indent=2))
        break"
```
Expected (current schema):
```json
{
  "description": "Max results to return (default 100, max 100).",
  "format": "uint",
  "minimum": 0,
  "type": ["integer", "null"]
}
```

This is the schema we're widening. Keep the output for comparison after Task 5.

---

## Task 1: Audit — verify the full set of integer input fields

**Files:** none (verification only)

**Context:** The design spec lists 11 fields across 9 files based on a 2026-05-18 audit. This task re-runs the audit to confirm nothing was added in the meantime (or by a parallel change), so the per-field annotation tasks have a complete target list.

- [ ] **Step 1: Enumerate integer input fields**

The earlier name-prefix regex (`pub (uid|limit|offset|max_|…):…`)
filtered by field-name token and missed `in_reply_to_uid` in
`compose/message_builder.rs`. It is **insufficient** and has been
removed. Use the type-driven scan below, which catches *any* field
whose declared type contains an integer primitive or `NonZeroU{32,64}`
wrapper regardless of field name. Note that `NonZeroU32`/`NonZeroU64`
use a capital `U`, so the `NonZeroU(32|64)` branch must be spelled out
explicitly — a naive `(NonZero)?(u32|u64|…)` would fail to match.

Run:
```bash
rg -n 'pub [a-zA-Z_][a-zA-Z0-9_]*:\s*(Option<)?(Vec<)?(core::num::)?(NonZeroU(32|64)|usize|u32|u64|i32|i64|isize)' \
  crates/rimap-server/src/tools/
```
Expected: matches across `search.rs`, `fetch_message.rs`, `download_attachment.rs`, `list_attachments.rs`, `delete_message.rs`, `flags.rs`, `labels.rs`, `move_message.rs`, and `compose/message_builder.rs`. Compare against the design-doc table.

- [ ] **Step 2: Flag any field not in the design table**

If the grep surfaces a new field, add a row to the design doc's scope table and add a corresponding annotation step in Task 6 below. Do not silently extend scope.

- [ ] **Step 3: Confirm `UidSelector` is still out of scope**

Run:
```bash
rg -n 'UidSelector|BoundedUids' crates/rimap-server/src/tools/
```
Expected: usages in `flags.rs`, `labels.rs`, `move_message.rs` via `#[serde(flatten)] pub target: UidSelector`. These are intentionally NOT annotated in this PR — see design doc "Out of scope" section 3.

---

## Task 2: Create the `lenient_int` module skeleton with `Option<usize>` support

**Files:**
- Create: `crates/rimap-server/src/tools/lenient_int.rs`
- Modify: `crates/rimap-server/src/tools/mod.rs`

**Context:** TDD — write the failing test first, then minimal code, then expand. Start with the single type the user's bug report exercises (`Option<usize>` for `search.limit`).

- [ ] **Step 1: Register the module**

Edit `crates/rimap-server/src/tools/mod.rs` to add (alphabetically with siblings):
```rust
pub(crate) mod lenient_int;
```

- [ ] **Step 2: Write the failing test**

Create `crates/rimap-server/src/tools/lenient_int.rs` with only the test module first:

```rust
//! Lenient integer deserializers + schema helpers.
//!
//! Some MCP hosts (notably Claude Code, see issue #292) stringify
//! integer-typed tool arguments before sending them. Strict JSON
//! Schema validators in those hosts then reject the call before it
//! reaches us. This module widens each integer input field's published
//! schema to accept either the integer or a digit-string, and decodes
//! the string form back to the canonical Rust type.

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Wrap {
        #[serde(default, deserialize_with = "super::deserialize_opt_usize")]
        n: Option<usize>,
    }

    #[test]
    fn accepts_integer_form() {
        let w: Wrap = serde_json::from_str(r#"{"n": 100}"#).unwrap();
        assert_eq!(w.n, Some(100));
    }

    #[test]
    fn accepts_string_form() {
        let w: Wrap = serde_json::from_str(r#"{"n": "100"}"#).unwrap();
        assert_eq!(w.n, Some(100));
    }

    #[test]
    fn accepts_null() {
        let w: Wrap = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn accepts_absent() {
        let w: Wrap = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn rejects_non_numeric_string() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": "abc"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn rejects_negative_string() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": "-1"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn rejects_overflow_string() {
        // usize::MAX + 1 on 64-bit, definitely too large
        let err = serde_json::from_str::<Wrap>(r#"{"n": "99999999999999999999"}"#).unwrap_err();
        assert!(err.to_string().contains("integer") || err.to_string().contains("overflow"), "got: {err}");
    }

    #[test]
    fn rejects_float() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": 1.5}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn rejects_boolean() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": true}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
```

- [ ] **Step 3: Run the test to confirm it fails**

Run:
```bash
cargo test -p rimap-server --lib tools::lenient_int 2>&1 | tail -20
```
Expected: compile error — `cannot find function 'deserialize_opt_usize' in module 'super'`.

- [ ] **Step 4: Implement `deserialize_opt_usize` + the internal `IntOrStr` helper**

Add above the `tests` module in `lenient_int.rs`:

```rust
use serde::de::{self, Deserializer};
use serde::Deserialize;

/// Internal wire shape: either a JSON integer or a JSON string. The
/// per-type deserializers below convert this into the canonical Rust
/// integer type.
#[derive(Deserialize)]
#[serde(untagged)]
enum IntOrStr<'a> {
    Int(i128),
    Str(&'a str),
}

/// Parse a digit-string into `usize`. Empty, non-digit, signed, or
/// overflowing strings produce a serde error. Leading zeros are
/// allowed (matches AJV/Zod permissiveness for `^[0-9]+$`).
fn parse_usize_str<E: de::Error>(s: &str) -> Result<usize, E> {
    if s.is_empty() {
        return Err(E::invalid_value(de::Unexpected::Str(s), &"non-empty digit string"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::invalid_value(de::Unexpected::Str(s), &"integer in string form (digits only)"));
    }
    s.parse::<usize>()
        .map_err(|_| E::invalid_value(de::Unexpected::Str(s), &"integer in usize range"))
}

/// Convert an `i128` (the integer arm of `IntOrStr`) to `usize`, or
/// fail with a clear error if it's negative or out of range.
fn i128_to_usize<E: de::Error>(n: i128) -> Result<usize, E> {
    if n < 0 {
        return Err(E::invalid_value(de::Unexpected::Signed(n as i64), &"non-negative integer"));
    }
    usize::try_from(n).map_err(|_| E::invalid_value(de::Unexpected::Other("integer"), &"integer in usize range"))
}

/// Deserialize `Option<usize>` from either a JSON integer, a JSON
/// digit-string, or `null`/absent.
///
/// # Errors
///
/// Returns a serde error when the input is the wrong JSON type, a
/// negative integer, an empty/non-digit string, or numerically out of
/// range for `usize`.
pub fn deserialize_opt_usize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error> {
    let v: Option<IntOrStr<'_>> = Option::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(IntOrStr::Int(n)) => i128_to_usize(n).map(Some),
        Some(IntOrStr::Str(s)) => parse_usize_str(s).map(Some),
    }
}
```

- [ ] **Step 5: Run the tests to confirm they pass**

Run:
```bash
cargo test -p rimap-server --lib tools::lenient_int 2>&1 | tail -20
```
Expected: 9 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/lenient_int.rs crates/rimap-server/src/tools/mod.rs
git commit -m "feat(server): add lenient_int helper for usize coercion (#292)

Internal IntOrStr enum + deserialize_opt_usize accept both JSON integer
and digit-string forms. Unit tests cover happy paths, rejection of
non-numeric strings, negatives, overflow, floats, and booleans."
```

---

## Task 3: Extend `lenient_int` to the remaining types

**Files:**
- Modify: `crates/rimap-server/src/tools/lenient_int.rs`

**Context:** The audit (Task 1) found four more integer types in use: bare `usize` (none currently — defer), bare `u32` (no input fields use this directly today), `Option<u32>`, bare `NonZeroU32`. Implement all currently-needed variants. Skip bare-`usize` / bare-`u32` until a future field needs them — YAGNI.

- [ ] **Step 1: Write tests for `deserialize_opt_u32`**

Append to the `tests` module in `lenient_int.rs`:

```rust
    #[derive(Deserialize)]
    struct WrapOptU32 {
        #[serde(default, deserialize_with = "super::deserialize_opt_u32")]
        n: Option<u32>,
    }

    #[test]
    fn opt_u32_int_form() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": 4294967295}"#).unwrap();
        assert_eq!(w.n, Some(u32::MAX));
    }

    #[test]
    fn opt_u32_string_form() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": "12345"}"#).unwrap();
        assert_eq!(w.n, Some(12345));
    }

    #[test]
    fn opt_u32_rejects_overflow() {
        // u32::MAX + 1
        let err = serde_json::from_str::<WrapOptU32>(r#"{"n": 4294967296}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn opt_u32_rejects_negative_int() {
        let err = serde_json::from_str::<WrapOptU32>(r#"{"n": -1}"#).unwrap_err();
        assert!(err.to_string().contains("non-negative"), "got: {err}");
    }

    #[test]
    fn opt_u32_null_is_none() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }
```

- [ ] **Step 2: Implement `deserialize_opt_u32`**

Add to `lenient_int.rs`:

```rust
fn parse_u32_str<E: de::Error>(s: &str) -> Result<u32, E> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::invalid_value(de::Unexpected::Str(s), &"integer in string form (digits only)"));
    }
    s.parse::<u32>()
        .map_err(|_| E::invalid_value(de::Unexpected::Str(s), &"integer in u32 range"))
}

fn i128_to_u32<E: de::Error>(n: i128) -> Result<u32, E> {
    if n < 0 {
        return Err(E::invalid_value(de::Unexpected::Signed(n as i64), &"non-negative integer"));
    }
    u32::try_from(n).map_err(|_| E::invalid_value(de::Unexpected::Other("integer"), &"integer in u32 range"))
}

/// Deserialize `Option<u32>` from integer, digit-string, or null/absent.
///
/// # Errors
///
/// Same semantics as [`deserialize_opt_usize`], scoped to `u32` range.
pub fn deserialize_opt_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    let v: Option<IntOrStr<'_>> = Option::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(IntOrStr::Int(n)) => i128_to_u32(n).map(Some),
        Some(IntOrStr::Str(s)) => parse_u32_str(s).map(Some),
    }
}
```

- [ ] **Step 3: Write tests for `deserialize_nonzero_u32`**

Append to the `tests` module:

```rust
    use core::num::NonZeroU32;

    #[derive(Deserialize)]
    struct WrapNz {
        #[serde(deserialize_with = "super::deserialize_nonzero_u32")]
        n: NonZeroU32,
    }

    #[test]
    fn nonzero_u32_int_form() {
        let w: WrapNz = serde_json::from_str(r#"{"n": 42}"#).unwrap();
        assert_eq!(w.n.get(), 42);
    }

    #[test]
    fn nonzero_u32_string_form() {
        let w: WrapNz = serde_json::from_str(r#"{"n": "42"}"#).unwrap();
        assert_eq!(w.n.get(), 42);
    }

    #[test]
    fn nonzero_u32_rejects_zero_int() {
        let err = serde_json::from_str::<WrapNz>(r#"{"n": 0}"#).unwrap_err();
        assert!(err.to_string().contains("nonzero") || err.to_string().contains("non-zero"), "got: {err}");
    }

    #[test]
    fn nonzero_u32_rejects_zero_string() {
        let err = serde_json::from_str::<WrapNz>(r#"{"n": "0"}"#).unwrap_err();
        assert!(err.to_string().contains("nonzero") || err.to_string().contains("non-zero"), "got: {err}");
    }
```

- [ ] **Step 4: Implement `deserialize_nonzero_u32`**

Add to `lenient_int.rs`:

```rust
/// Deserialize `NonZeroU32` from integer or digit-string. Rejects 0
/// and overflow.
///
/// # Errors
///
/// In addition to the integer-range errors from `parse_u32_str` /
/// `i128_to_u32`, returns an error when the parsed value is `0`.
pub fn deserialize_nonzero_u32<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<core::num::NonZeroU32, D::Error> {
    let v = IntOrStr::deserialize(d)?;
    let n: u32 = match v {
        IntOrStr::Int(n) => i128_to_u32(n)?,
        IntOrStr::Str(s) => parse_u32_str(s)?,
    };
    core::num::NonZeroU32::new(n).ok_or_else(|| de::Error::invalid_value(
        de::Unexpected::Unsigned(0),
        &"nonzero u32",
    ))
}
```

- [ ] **Step 4a: Write failing tests for `deserialize_opt_nonzero_u32`**

Append to the `tests` module in `lenient_int.rs`:

```rust
    #[derive(Deserialize)]
    struct WrapOptNz {
        #[serde(default, deserialize_with = "super::deserialize_opt_nonzero_u32")]
        n: Option<NonZeroU32>,
    }

    #[test]
    fn opt_nonzero_u32_int_form() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": 42}"#).unwrap();
        assert_eq!(w.n.map(NonZeroU32::get), Some(42));
    }

    #[test]
    fn opt_nonzero_u32_string_form() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": "42"}"#).unwrap();
        assert_eq!(w.n.map(NonZeroU32::get), Some(42));
    }

    #[test]
    fn opt_nonzero_u32_null_is_none() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn opt_nonzero_u32_absent_is_none() {
        let w: WrapOptNz = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn opt_nonzero_u32_rejects_zero_int() {
        let err = serde_json::from_str::<WrapOptNz>(r#"{"n": 0}"#).unwrap_err();
        assert!(err.to_string().contains("nonzero") || err.to_string().contains("non-zero"), "got: {err}");
    }

    #[test]
    fn opt_nonzero_u32_rejects_zero_string() {
        let err = serde_json::from_str::<WrapOptNz>(r#"{"n": "0"}"#).unwrap_err();
        assert!(err.to_string().contains("nonzero") || err.to_string().contains("non-zero"), "got: {err}");
    }
```

- [ ] **Step 4b: Implement `deserialize_opt_nonzero_u32`**

Add to `lenient_int.rs`:

```rust
/// Deserialize `Option<NonZeroU32>` from integer, digit-string, or null/absent.
/// Rejects 0 and overflow with a clear error.
///
/// # Errors
///
/// Same semantics as [`deserialize_nonzero_u32`], plus accepts `null`/absent
/// as `None`.
pub fn deserialize_opt_nonzero_u32<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<core::num::NonZeroU32>, D::Error> {
    let v: Option<IntOrStr<'_>> = Option::deserialize(d)?;
    let Some(int_or_str) = v else { return Ok(None) };
    let n: u32 = match int_or_str {
        IntOrStr::Int(n) => i128_to_u32(n)?,
        IntOrStr::Str(s) => parse_u32_str(s)?,
    };
    let nz = core::num::NonZeroU32::new(n).ok_or_else(|| {
        de::Error::invalid_value(de::Unexpected::Unsigned(0), &"nonzero u32")
    })?;
    Ok(Some(nz))
}
```

- [ ] **Step 5: Run all tests**

Run:
```bash
cargo test -p rimap-server --lib tools::lenient_int 2>&1 | tail -20
```
Expected: 24 tests pass (9 from Task 2 plus 9 from Steps 1–4 plus 6 from Steps 4a–4b).

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/lenient_int.rs
git commit -m "feat(server): extend lenient_int to Option<u32>, NonZeroU32, Option<NonZeroU32> (#292)"
```

---

## Task 4: Add schema generators for each lenient integer type

**Files:**
- Modify: `crates/rimap-server/src/tools/lenient_int.rs`

**Context:** Each deserializer needs a matching `schema_*` function that emits a `oneOf` over integer and digit-string (plus null for the `Option<*>` variants). Without this, the published JSON Schema still says `type: ["integer","null"]` and the host's pre-flight validator continues to reject string-form calls.

- [ ] **Step 1: Add the schema functions**

Append to `lenient_int.rs` (above the `tests` module):

```rust
/// Schema for `Option<usize>` accepted as integer, digit-string, or null.
///
/// Emitted via `#[schemars(schema_with = "lenient_int::schema_opt_usize")]`.
pub fn schema_opt_usize(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 0 },
            { "type": "string", "pattern": "^[0-9]+$" },
            { "type": "null" }
        ]
    })
}

/// Schema for `Option<u32>` accepted as integer, digit-string, or null.
pub fn schema_opt_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 0, "maximum": 4294967295u64 },
            { "type": "string", "pattern": "^[0-9]+$" },
            { "type": "null" }
        ]
    })
}

/// Schema for `NonZeroU32` accepted as positive integer or
/// positive-integer-string. No null branch — the field is required.
pub fn schema_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 1, "maximum": 4294967295u64 },
            { "type": "string", "pattern": "^[1-9][0-9]*$" }
        ]
    })
}

/// Schema for `Option<NonZeroU32>` accepted as positive integer,
/// positive-integer-string, or null.
pub fn schema_opt_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 1, "maximum": 4294967295u64 },
            { "type": "string", "pattern": "^[1-9][0-9]*$" },
            { "type": "null" }
        ]
    })
}
```

- [ ] **Step 2: Write a unit test verifying the emitted schema shape**

Append to the `tests` module:

```rust
    #[test]
    fn schema_opt_usize_has_oneof_with_three_branches() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_usize(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v.get("oneOf").and_then(|x| x.as_array()).expect("oneOf array");
        assert_eq!(one_of.len(), 3, "expected 3 branches, got {one_of:?}");
        let types: Vec<_> = one_of.iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(types.contains(&"null"));
    }

    #[test]
    fn schema_nonzero_u32_has_no_null_branch() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_nonzero_u32(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v.get("oneOf").and_then(|x| x.as_array()).expect("oneOf array");
        assert_eq!(one_of.len(), 2);
        let types: Vec<_> = one_of.iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(!types.contains(&"null"));
    }

    #[test]
    fn schema_opt_nonzero_u32_has_oneof_with_three_branches() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_nonzero_u32(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v.get("oneOf").and_then(|x| x.as_array()).expect("oneOf array");
        assert_eq!(one_of.len(), 3, "expected 3 branches, got {one_of:?}");
        let types: Vec<_> = one_of.iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(types.contains(&"null"));
        let string_branch = one_of.iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("string"))
            .expect("string branch present");
        assert_eq!(string_branch.get("pattern").and_then(|p| p.as_str()), Some("^[1-9][0-9]*$"));
    }
```

- [ ] **Step 3: Run tests**

Run:
```bash
cargo test -p rimap-server --features test-support --lib tools::lenient_int 2>&1 | tail -20
```
Expected: 27 tests pass (24 from Task 3 plus 3 schema tests added here). Confirm the actual count from the test run; adjust if a helper sub-test was renamed.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/lenient_int.rs
git commit -m "feat(server): add lenient_int schema generators (#292)"
```

---

## Task 5: Apply to `search` (the originally-reported failure)

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs`

**Context:** This is the field the user's bug report exercised. Doing it in isolation lets us verify the host pre-flight validator now accepts `{"limit":"100"}` before annotating every other field.

- [ ] **Step 1: Annotate `limit` and `offset`**

Edit `crates/rimap-server/src/tools/retrieval/search.rs`. The struct currently reads:

```rust
    /// Max results to return (default 100, max 100).
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    pub offset: Option<usize>,
```

Change to:

```rust
    /// Max results to return (default 100, max 100).
    #[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    #[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub offset: Option<usize>,
```

- [ ] **Step 2: Build and test the crate**

Run:
```bash
cargo test -p rimap-server --features test-support 2>&1 | tail -10
```
Expected: all tests pass. The handler code never references `limit`/`offset` as `Option<usize>` differently — the type didn't change — so no other source needs editing.

- [ ] **Step 3: Verify the published schema widened**

Run:
```bash
cargo run -q -p rimap-server --bin rusty-imap-mcp --features test-support -- dump-tool-catalog \
  | python3 -c "import json,sys
for line in sys.stdin:
    t=json.loads(line)
    if t['name']=='search':
        print(json.dumps(t['inputSchema']['properties']['limit'], indent=2))
        break"
```
Expected: a `oneOf` with three branches (`integer`/`string`/`null`). Compare with the snapshot from Task 0 Step 3.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs
git commit -m "feat(search): accept string-form limit and offset (#292)

Annotates SearchInput::limit and SearchInput::offset with the
lenient_int deserialize_with + schema_with pair so MCP hosts that
stringify integer arguments (Claude Code) no longer get their calls
rejected at the host's pre-flight schema validator."
```

---

## Task 6: Apply to the remaining integer input fields

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/download_attachment.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/list_attachments.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/delete_message.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/flags.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/labels.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/move_message.rs`

**Context:** Mechanical application of the same attribute pair to each integer field surfaced by Task 1. One sub-step per field, one commit at the end. Field/type/helper mapping:

| File | Field | Type | Deserializer | Schema fn |
|---|---|---|---|---|
| `fetch_message.rs` | `uid` | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
| `fetch_message.rs` | `max_body_bytes` | `Option<usize>` | `deserialize_opt_usize` | `schema_opt_usize` |
| `download_attachment.rs` | `uid` | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
| `list_attachments.rs` | `uid` | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
| `delete_message.rs` | `uid` | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
| `flags.rs` | `expected_uidvalidity` | `Option<u32>` | `deserialize_opt_u32` | `schema_opt_u32` |
| `labels.rs` (`AddLabelInput::uid`) | `uid` | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
| `labels.rs` (4× `expected_uidvalidity` / `uid_validity`) | `Option<u32>` | `deserialize_opt_u32` | `schema_opt_u32` |
| `move_message.rs` | `expected_source_uidvalidity` | `Option<u32>` | `deserialize_opt_u32` | `schema_opt_u32` |
| `compose/message_builder.rs` | `in_reply_to_uid` | `Option<NonZeroU32>` | `deserialize_opt_nonzero_u32` | `schema_opt_nonzero_u32` |

For each field add (replacing or adding to existing serde attributes):

```rust
#[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none")]
#[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
pub expected_uidvalidity: Option<u32>,
```

For required `NonZeroU32`:

```rust
#[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
#[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
pub uid: core::num::NonZeroU32,
```

Preserve any existing `#[serde(default, skip_serializing_if = ...)]` attributes — merge into the same `#[serde(...)]` block.

- [ ] **Step 1: Annotate `fetch_message.rs`**

Edit `crates/rimap-server/src/tools/retrieval/fetch_message.rs`, lines 26–31 (current shape):

```rust
    /// UID of the message to fetch.
    pub uid: core::num::NonZeroU32,
    /// Include sanitized HTML body in the response.
    pub include_html: Option<bool>,
    /// Truncate body text (and HTML if included) to this many bytes.
    pub max_body_bytes: Option<usize>,
```

becomes:

```rust
    /// UID of the message to fetch.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// Include sanitized HTML body in the response.
    pub include_html: Option<bool>,
    /// Truncate body text (and HTML if included) to this many bytes.
    #[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub max_body_bytes: Option<usize>,
```

- [ ] **Step 2: Annotate `download_attachment.rs::uid`**

Open `crates/rimap-server/src/tools/retrieval/download_attachment.rs`. The struct has `pub uid: core::num::NonZeroU32,`. Replace with the two-attribute form shown above.

- [ ] **Step 3: Annotate `list_attachments.rs::uid`**

Same change as Step 2 in `crates/rimap-server/src/tools/retrieval/list_attachments.rs`.

- [ ] **Step 4: Annotate `delete_message.rs::uid`**

Same change as Step 2 in `crates/rimap-server/src/tools/mailbox/delete_message.rs`.

- [ ] **Step 5: Annotate `flags.rs::expected_uidvalidity`**

Open `crates/rimap-server/src/tools/mailbox/flags.rs`. The struct currently reads:

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_uidvalidity: Option<u32>,
```

becomes:

```rust
    #[serde(default,
            deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
            skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_uidvalidity: Option<u32>,
```

- [ ] **Step 6: Annotate every integer field in `labels.rs`**

Open `crates/rimap-server/src/tools/mailbox/labels.rs`. The audit found:
- `AddLabelInput::uid: NonZeroU32` → use `deserialize_nonzero_u32` + `schema_nonzero_u32`.
- Two `expected_uidvalidity: Option<u32>` fields → use `deserialize_opt_u32` + `schema_opt_u32` (preserve existing `#[serde(default, skip_serializing_if = ...)]`).

Verify by re-running the grep from Task 1 Step 1 scoped to this file.

- [ ] **Step 7: Annotate `move_message.rs::expected_source_uidvalidity`**

Same change as Step 5 (with the matching field name) in `crates/rimap-server/src/tools/mailbox/move_message.rs`.

- [ ] **Step 7a: Annotate `compose/message_builder.rs::in_reply_to_uid`**

Edit `crates/rimap-server/src/tools/compose/message_builder.rs`. The current shape (line 42–43):

```rust
    /// UID of message to reply to (for threading headers).
    pub in_reply_to_uid: Option<core::num::NonZeroU32>,
```

becomes:

```rust
    /// UID of message to reply to (for threading headers).
    #[serde(default,
            deserialize_with = "crate::tools::lenient_int::deserialize_opt_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_nonzero_u32")]
    pub in_reply_to_uid: Option<core::num::NonZeroU32>,
```

This single annotation widens the published schema for *both* the
`create_draft` and `send_email` tools, because
`CreateDraftInput` (`create_draft.rs:11`) and `SendEmailInput`
(`send_email.rs:11`) are type aliases for `ComposeInput`.

- [ ] **Step 8: Run the crate test suite**

Run:
```bash
cargo test -p rimap-server --features test-support 2>&1 | tail -10
```
Expected: all tests pass. No handler code changes — the field types were unchanged.

- [ ] **Step 9: Run clippy with the workspace's strict lints**

Run:
```bash
cargo clippy -p rimap-server --all-targets --features test-support -- -D warnings 2>&1 | tail -20
```
Expected: no warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/fetch_message.rs \
        crates/rimap-server/src/tools/retrieval/download_attachment.rs \
        crates/rimap-server/src/tools/retrieval/list_attachments.rs \
        crates/rimap-server/src/tools/mailbox/delete_message.rs \
        crates/rimap-server/src/tools/mailbox/flags.rs \
        crates/rimap-server/src/tools/mailbox/labels.rs \
        crates/rimap-server/src/tools/mailbox/move_message.rs \
        crates/rimap-server/src/tools/compose/message_builder.rs
git commit -m "feat(tools): widen integer-input schemas across remaining tools (#292)

Applies lenient_int deserialize_with + schema_with attributes to every
integer input field surfaced by the audit:

- fetch_message: uid, max_body_bytes
- download_attachment: uid
- list_attachments: uid
- delete_message: uid
- flags: expected_uidvalidity
- labels: uid, two expected_uidvalidity fields
- move_message: expected_source_uidvalidity
- compose: in_reply_to_uid (widens both create_draft and send_email
  because their *Input types are aliases for ComposeInput)

Each affected field's published JSON Schema is now a oneOf over the
integer form, a digit-string form (^[0-9]+$ or ^[1-9][0-9]*$), and (for
Option<*>) null. Handler code is unchanged.

UidSelector / BoundedUids (batch UIDs in flag, mark_read, mark_unread,
unflag, add_label, remove_label, move_message) are intentionally
out of scope — see design doc."
```

---

## Task 7: Extend the schema-shape test in `dump_tool_catalog.rs`

**Files:**
- Modify: `crates/rimap-server/tests/dump_tool_catalog.rs`

**Context:** The existing integration test only asserts each tool's root `inputSchema.type` is `"object"`. Add a focused assertion that the originally-failing field (`search.limit`) now publishes a `oneOf` with the expected branches. This pins the wire shape so a future regression can't silently re-narrow the schema.

- [ ] **Step 1: Add the new assertion**

Append to `crates/rimap-server/tests/dump_tool_catalog.rs` (after the existing test):

```rust
#[test]
fn search_limit_publishes_lenient_int_schema() {
    let output = Command::new(cargo_bin("rusty-imap-mcp"))
        .arg("dump-tool-catalog")
        .output()
        .expect("spawn rusty-imap-mcp dump-tool-catalog");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");

    let mut found = false;
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line).expect("each line is JSON");
        if v["name"] == "search" {
            let limit = &v["inputSchema"]["properties"]["limit"];
            let branches = limit["oneOf"].as_array()
                .unwrap_or_else(|| panic!("search.limit must publish a oneOf, got {limit}"));
            assert_eq!(branches.len(), 3, "expected 3 branches in {branches:?}");

            let types: Vec<&str> = branches.iter()
                .filter_map(|b| b["type"].as_str())
                .collect();
            assert!(types.contains(&"integer"), "missing integer branch: {types:?}");
            assert!(types.contains(&"string"), "missing string branch: {types:?}");
            assert!(types.contains(&"null"), "missing null branch: {types:?}");

            // The string branch must restrict to digits to keep AJV/Zod
            // rejecting "abc" client-side (issue #292 design doc).
            let string_branch = branches.iter()
                .find(|b| b["type"] == "string")
                .expect("string branch present");
            assert_eq!(string_branch["pattern"], "^[0-9]+$");

            found = true;
            break;
        }
    }
    assert!(found, "search tool not present in dump-tool-catalog output");
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cargo test -p rimap-server --features test-support --test dump_tool_catalog 2>&1 | tail -10
```
Expected: 3 tests pass (original 2 + this one).

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/dump_tool_catalog.rs
git commit -m "test(server): pin lenient_int schema shape for search.limit (#292)"
```

---

## Task 8: End-to-end dispatch test

**Files:**
- Create: `crates/rimap-server/tests/lenient_int_dispatch.rs`

**Context:** Task 5 verified the schema widened. This task verifies the deserialization path inside dispatch actually accepts `"limit":"100"` and produces the same `SearchInput` the integer form produces. We can't easily spin up an IMAP server here, so the test deserializes directly through the `SearchInput` type — the same code path `parse_args` runs.

- [ ] **Step 1: Write the test**

Create `crates/rimap-server/tests/lenient_int_dispatch.rs`:

```rust
//! Integration test: confirm `SearchInput` deserializes both
//! integer-form and string-form values for `limit` / `offset`. This
//! is the path `parse_args` in `mcp/tool_catalog.rs` runs.

#![expect(clippy::unwrap_used, reason = "integration tests")]

use rimap_server::tools::retrieval::search::SearchInput;
use serde_json::json;

#[test]
fn search_input_accepts_integer_limit() {
    let v = json!({"folder": "INBOX", "limit": 100});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, Some(100));
}

#[test]
fn search_input_accepts_string_limit() {
    let v = json!({"folder": "INBOX", "limit": "100"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, Some(100));
}

#[test]
fn search_input_accepts_null_limit() {
    let v = json!({"folder": "INBOX", "limit": null});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, None);
}

#[test]
fn search_input_accepts_absent_limit() {
    let v = json!({"folder": "INBOX"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, None);
}

#[test]
fn search_input_accepts_string_offset() {
    let v = json!({"folder": "INBOX", "offset": "5"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.offset, Some(5));
}

#[test]
fn search_input_rejects_non_digit_string() {
    let v = json!({"folder": "INBOX", "limit": "abc"});
    let err = serde_json::from_value::<SearchInput>(v).unwrap_err();
    assert!(err.to_string().contains("integer"), "got: {err}");
}

use rimap_server::tools::compose::create_draft::CreateDraftInput;

#[test]
fn create_draft_input_accepts_integer_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s", "body_text": "b",
        "in_reply_to_uid": 42
    });
    let input: CreateDraftInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.in_reply_to_uid.map(|u| u.get()), Some(42));
}

#[test]
fn create_draft_input_accepts_string_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s", "body_text": "b",
        "in_reply_to_uid": "42"
    });
    let input: CreateDraftInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.in_reply_to_uid.map(|u| u.get()), Some(42));
}

#[test]
fn create_draft_input_rejects_zero_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s", "body_text": "b",
        "in_reply_to_uid": "0"
    });
    let err = serde_json::from_value::<CreateDraftInput>(v).unwrap_err();
    assert!(err.to_string().contains("nonzero") || err.to_string().contains("non-zero"), "got: {err}");
}
```

`SearchInput` may need to be `pub` to be reachable from an integration test. Check `crates/rimap-server/src/lib.rs` — if the path
`rimap_server::tools::retrieval::search::SearchInput` resolves, no change is
needed. If not, add the necessary `pub use` so the type is reachable.
The same reachability check applies to
`rimap_server::tools::compose::create_draft::CreateDraftInput` (a type
alias for `ComposeInput`); extend Step 2 to cover it.

- [ ] **Step 2: Check the type path**

Run:
```bash
rg -n 'pub mod tools|pub mod retrieval|pub mod search|pub mod compose|pub mod create_draft' crates/rimap-server/src/ crates/rimap-server/src/tools/ 2>&1 | head
```

If `tools` / `retrieval` / `search` aren't all `pub` (or `pub(crate)`), add the necessary `pub use rimap_server::tools::retrieval::search::SearchInput;` re-export at the crate root, or convert the test to a `#[cfg(test)] mod tests` inside `search.rs`. Apply the same check to `tools::compose::create_draft::CreateDraftInput`.

- [ ] **Step 3: Run the integration test**

Run:
```bash
cargo test -p rimap-server --features test-support --test lenient_int_dispatch 2>&1 | tail -10
```
Expected: 9 tests pass (6 from `SearchInput` plus 3 from `CreateDraftInput`).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/lenient_int_dispatch.rs
git commit -m "test(server): end-to-end SearchInput accepts string-form limit (#292)"
```

---

## Task 9: Final verification, docs, and PR

**Files:**
- Modify: `crates/rimap-server/src/tools/lenient_int.rs` (module-doc finalization only)

**Context:** Tighten the module-level documentation now that the full helper is in place, then run the full local gate that the pre-push hook runs.

- [ ] **Step 1: Finalize the module doc-comment**

Edit the `//!` block at the top of `crates/rimap-server/src/tools/lenient_int.rs` so it lists the exported helpers and links the design doc:

```rust
//! Lenient integer deserializers + schema helpers (issue #292).
//!
//! Some MCP hosts (notably Claude Code, see
//! [anthropics/claude-code#24599]) stringify integer-typed tool
//! arguments before sending them. Strict JSON Schema validators in
//! those hosts then reject the call before it reaches us. This module
//! widens each integer input field's published schema to accept either
//! the integer form or a digit-string form, and decodes the string
//! form back to the canonical Rust type.
//!
//! # Exported pairs
//!
//! Apply each pair to a struct field via:
//!
//! ```ignore
//! #[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize")]
//! #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
//! pub limit: Option<usize>,
//! ```
//!
//! | Field type | Deserializer | Schema |
//! |---|---|---|
//! | `Option<usize>` | `deserialize_opt_usize` | `schema_opt_usize` |
//! | `Option<u32>` | `deserialize_opt_u32` | `schema_opt_u32` |
//! | `NonZeroU32` | `deserialize_nonzero_u32` | `schema_nonzero_u32` |
//!
//! Booleans and string fields are intentionally NOT covered — see the
//! design doc at `docs/superpowers/specs/2026-05-18-issue-292-lenient-int-coercion-design.md`
//! "Out of scope" section.
//!
//! [anthropics/claude-code#24599]: https://github.com/anthropics/claude-code/issues/24599
```

- [ ] **Step 2: Run the local pre-push gate**

Run:
```bash
cargo check --workspace --all-targets --locked 2>&1 | tail -5 && \
cargo clippy -p rimap-server --all-targets --features test-support -- -D warnings 2>&1 | tail -5 && \
cargo fmt --check 2>&1 | tail -5
```
Expected: each command exits 0. (Full `cargo deny check` is gated in pre-push; the hook will run it on `git push`.)

- [ ] **Step 3: Run the affected-crate test suite once more**

Run:
```bash
cargo test -p rimap-server --features test-support 2>&1 | tail -10
```
Expected: all tests pass, including the new `lenient_int_dispatch` integration test and the extended `dump_tool_catalog` test.

- [ ] **Step 4: Commit the doc finalization**

```bash
git add crates/rimap-server/src/tools/lenient_int.rs
git commit -m "docs(server): finalize lenient_int module documentation (#292)"
```

- [ ] **Step 5: Push the branch and open the PR**

Per the memory note `project_push_ssh_keepalive.md`, cold-cache pushes can exit 0 with no ref transfer. Verify the push landed by checking the GitHub branch state before opening the PR.

Run:
```bash
git push -u origin feat/issue-292-lenient-int-coercion 2>&1 | tail -5
gh api repos/randomparity/rusty-imap-mcp/branches/feat/issue-292-lenient-int-coercion \
   --jq '.commit.sha' 2>&1
```
Expected: the second command prints the same SHA as `git rev-parse HEAD`.

Then open the PR:

```bash
gh pr create --title "feat(server): lenient integer coercion for tool inputs (#292)" \
  --body "$(cat <<'EOF'
Closes #292.

## Summary
- Adds `crates/rimap-server/src/tools/lenient_int.rs` with `deserialize_*` and `schema_*` pairs for `Option<usize>`, `Option<u32>`, and `NonZeroU32`.
- Applies the pair to every integer input field on every tool's `*Input` struct (see design doc table).
- Each affected field's published JSON Schema is now a `oneOf` over the integer form, a digit-string form, and (for `Option<*>`) null.

## Why
Claude Code non-deterministically stringifies integer tool arguments before sending them. The host's pre-flight JSON Schema validator rejects the call before it reaches us. FastMCP, github/github-mcp-server, and the MCP sequential-thinking reference server have all shipped equivalent lenient-coercion fixes.

## Test plan
- [x] `cargo test -p rimap-server --features test-support`
- [x] `cargo clippy -p rimap-server --all-targets --features test-support -- -D warnings`
- [x] `dump-tool-catalog` for `search.limit` now publishes the `oneOf` shape pinned by `tests/dump_tool_catalog.rs`
- [x] `tests/lenient_int_dispatch.rs` end-to-end deserialization through `SearchInput` for both integer and string forms

## Out of scope (deferred)
- Booleans (the `Boolean("false") === true` footgun)
- String fields (FastMCP issue #1873 data-loss risk)
- `UidSelector` / `BoundedUids` (batch UIDs) — lives in `rimap-core`; file as a follow-up if batch-UID tools start failing in the wild
EOF
)"
```

---

## Self-review checklist (run after writing, before handing off)

1. **Spec coverage:** Every field in the design doc's scope table has a corresponding step in Task 6. The two unused helper variants (`deserialize_usize`, `deserialize_u32`) are deliberately omitted per YAGNI — no current field needs them.
2. **Placeholders:** None — every step has either the exact code change, exact command, or exact expected output.
3. **Type consistency:** Helper function names (`deserialize_opt_usize`, `deserialize_opt_u32`, `deserialize_nonzero_u32`, `schema_opt_usize`, `schema_opt_u32`, `schema_nonzero_u32`) are identical in every step that references them. `deserialize_opt_nonzero_u32` and `schema_opt_nonzero_u32` follow the same naming convention as the other three pairs.
4. **Test order:** TDD pattern (write failing test, see it fail, implement, see it pass, commit) is preserved in Tasks 2, 3, 4. Tasks 5–7 are mechanical application + assertion, not feature implementation, so they skip the failing-test-first step where it would be ceremonial.
