# Issue #867 params._meta validation — implementation plan

**Goal:** the envelope validator rejects, with `-32600`, the request/notification `params._meta`
shapes rmcp rejects, so that every `Forward` decision is accepted by rmcp.

**Architecture:** two rules in `crates/rimap-server/src/mcp/wire_validator/envelope.rs`
(spec: `docs/superpowers/specs/2026-10-06-issue-867-params-meta-validation-design.md`; decision:
ADR-0031). `is_valid_params` checks the type of `_meta`. The existing streaming duplicate-key
scan additionally reports a duplicated `_meta` inside top-level `params`.

**Tech stack:** Rust 2024, serde / serde_json visitors, rmcp 3.1.4, tokio wire harness,
cargo-fuzz.

Expected implementation size: 170–230 changed lines (M) — envelope.rs ~60, unit tests ~60, wire
tests ~80, two corpus files, one ADR index row.

## Global Constraints

- MSRV 1.88.0, dev toolchain 1.94.0. No new dependencies; `rmcp` is already a normal dependency
  of `rimap-server`.
- No `#[allow]` (use `#[expect]` with a reason), no `unwrap()` outside tests, no `matches!`, no
  wildcard match arms in new code, 100-char lines, absolute imports.
- Pre-existing contracts that must not change: the duplicate key in an envelope or `error`
  position → `invalid_request(Null)`; the ADR-0025 pre-init interception; the response/error
  branches.

## File map

| File | Change |
|---|---|
| `crates/rimap-server/src/mcp/wire_validator/envelope.rs` | `is_valid_params` `_meta` rule; dup scan returns `DuplicateKeys` |
| `crates/rimap-server/src/mcp/wire_validator/mod.rs` | unit tests (`mod tests`) |
| `crates/rimap-server/tests/conformance/mcp_wire_negative.rs` | two wire tests |
| `crates/rimap-server/fuzz/corpus/validate/regression-867-original` | new: the CI unit, exact bytes |
| `crates/rimap-server/fuzz/corpus/validate/params-meta-string` | new: the minimized unit |
| `docs/ADR/README.md` | ADR-0031 index row |
| `docs/superpowers/specs/test-strategy/mutation-baseline.md` | `unwrap_or(false)` → `unwrap_or_default()` in two rows |

## Task 1: reject malformed `params._meta`

**Verification**

- Contract: `validate`'s Forward decision agrees with rmcp across the spec's probe table, and
  every rejection is `-32600` with the forwardable id echoed. Mode: focused-test. Test:
  `params_meta_decisions_match_rmcp_acceptance` and `params_meta_rejections_echo_id` in
  `wire_validator/mod.rs`. Red: an assertion failure on the `validator decision` message for
  `{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":"x"}}`. Green:
  `cargo nextest run -p rimap-server --lib -E 'test(params_meta)'`.
- Contract: client-visible wire response, before and after `initialize`. Mode: focused-test.
  Tests: `params_meta_string_returns_minus_32600` and
  `params_meta_string_before_initialize_returns_minus_32600` in `mcp_wire_negative.rs`. Red: a
  panic with `id must be echoed, got {"error":{"code":-32600,"message":"Invalid request"},...}`
  (rmcp's own id-less envelope). Green:
  `cargo nextest run -p rimap-server --test mcp_wire_negative -E 'test(params_meta)'`.
- Contract: the corpus files are the regression inputs. Mode: focused-test, covered by the first
  test, which `include_str!`s both files.

**Steps**

1. Download the CI unit with `gh run download 37450028198 -R randomparity/rusty-imap-mcp -n
   crashes-validate -D <scratch-dir>`. This is the issue #867 artifact; it expires 2027-01-04.
   Copy `<scratch-dir>/address/crash-79232b86fb09d5f22522a667fe334593c4f93807` byte-for-byte
   (sha1 `79232b86fb09d5f22522a667fe334593c4f93807`, no trailing newline) to `crates/rimap-server/fuzz/corpus/validate/regression-867-original`. Check it with
   `shasum <file>`; the hash must match. Then write the minimized unit with
   `printf '%s' '{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":"x"}}' >
   crates/rimap-server/fuzz/corpus/validate/params-meta-string`.
2. Append these tests inside `mod tests` in `wire_validator/mod.rs`. `validate`, `Value`,
   `json!`, and `reject` are already in scope there.

```rust
    /// Issue #867 probe table (rmcp 3.1.4): the validator forwards a line exactly when rmcp's
    /// `ClientJsonRpcMessage` accepts it. The rmcp half pins the probe so a future rmcp
    /// relaxation shows up here.
    #[test]
    fn params_meta_decisions_match_rmcp_acceptance() {
        let original = include_str!("../../../fuzz/corpus/validate/regression-867-original");
        let minimized = include_str!("../../../fuzz/corpus/validate/params-meta-string");
        let original_meta_object = original.replace(r#""_meta":"x""#, r#""_meta":{}"#);
        let cases = [
            (original, false),
            (minimized, false),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":1}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":[]}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":"x"}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":1}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":[]}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":{},"_meta":{}}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":null,"_meta":null}}"#, false),
            (
                r#"{"jsonrpc":"2.0","method":"initialize","id":0,"params":{"_meta":"x","protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"a","version":"1"}}}"#,
                false,
            ),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":{},"_meta":{}}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":null,"_meta":null}}"#, false),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":null}}"#, true),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":{"a":1,"a":2}}}"#, true),
            (r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"a":{"_meta":"x"}}}"#, true),
            (r#"{"jsonrpc":"2.0","id":1,"result":{},"params":{"_meta":{},"_meta":{}}}"#, true),
            (original_meta_object.as_str(), true),
        ];
        for (line, forwards) in cases {
            let rmcp_accepts =
                serde_json::from_str::<rmcp::model::ClientJsonRpcMessage>(line).is_ok();
            assert_eq!(rmcp_accepts, forwards, "rmcp acceptance changed for {line}");
            let forwarded = validate(line) == ValidationOutcome::Forward;
            assert_eq!(forwarded, forwards, "validator decision for {line}");
        }
    }

    #[test]
    fn params_meta_rejections_echo_id() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":7,"params":{"_meta":"x"}}"#),
            reject(-32600, json!(7))
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":"a","params":{"_meta":{},"_meta":{}}}"#),
            reject(-32600, json!("a"))
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","params":{"_meta":"x"}}"#),
            reject(-32600, Value::Null)
        );
    }
```

3. Run `cargo nextest run -p rimap-server --lib -E 'test(params_meta)'`. Expect both tests to
   FAIL with `validator decision for ...` and `left: Forward`.
4. Add to `mcp_wire_negative.rs`, after `valid_json_invalid_envelope_returns_minus_32600`:

```rust
/// Issue #867: rmcp rejects a non-object `params._meta`, so the validator must answer -32600
/// itself; forwarding the line used to get rmcp's own id-less -32600.
const META_STRING_REQUEST: &str = r#"{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":"x"}}"#;

fn expect_meta_string_rejection(outcome: CloseOrResponse) {
    let envelope = match outcome {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!("expected one -32600 envelope for a string params._meta, got {other:?}"),
    };
    assert_eq!(envelope["error"]["code"], json!(-32600), "got {envelope}");
    assert_eq!(envelope["id"], json!(0), "id must be echoed, got {envelope}");
    assert_envelope_valid(&envelope);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn params_meta_string_returns_minus_32600() {
    let mut harness = Harness::spawn().await;
    harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness.send_line(META_STRING_REQUEST).await;
    expect_meta_string_rejection(harness.response_or_close(REQUEST_TIMEOUT).await);

    let tools = harness.request("tools/list", json!({})).await;
    assert!(tools["result"]["tools"].is_array(), "session must survive, got {tools}");
}

/// Initialization handling must not mask the case: the ADR-0025 interception parse fails on
/// this line, so it reaches the validator, and the session can still initialize afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn params_meta_string_before_initialize_returns_minus_32600() {
    let mut harness = Harness::spawn().await;

    harness.send_line(META_STRING_REQUEST).await;
    expect_meta_string_rejection(harness.response_or_close(REQUEST_TIMEOUT).await);

    let init = harness.initialize_handshake().await;
    assert!(init["result"].is_object(), "initialize must still succeed, got {init}");
}
```

5. Run `cargo nextest run -p rimap-server --test mcp_wire_negative -E 'test(params_meta)'`.
   Expect both to FAIL with `id must be echoed, got {"error":{"code":-32600,"message":"Invalid
   request"},"jsonrpc":"2.0"}`. That is rmcp's own id-less envelope, observed on 2026-10-06; the
   design originally assumed `Hung`. Record the observed outcome in the PR.
6. In `envelope.rs`, replace `is_valid_params`'s body and append to its doc comment:

```rust
/// rmcp 3.x also rejects a `params._meta` that is neither an object nor
/// null (issue #867, ADR-0031).
pub(crate) fn is_valid_params(v: &Value) -> bool {
    if let Some(obj) = v.as_object() {
        return obj.get("_meta").is_none_or(|meta| meta.is_object() || meta.is_null());
    }
    v.is_null()
}
```

7. In `envelope.rs`, turn `OneLevelDupCheck` into a seed with an optional watched key, and
   delete the `DupCheckOneLevel` newtype and its `Deserialize` impl:

```rust
#[derive(Clone, Copy)]
struct OneLevelDupCheck {
    /// `None` counts every duplicate; `Some(k)` counts only duplicates of `k`.
    only: Option<&'static str>,
}

impl<'de> serde::de::DeserializeSeed<'de> for OneLevelDupCheck {
    type Value = bool;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
        d.deserialize_any(self)
    }
}
```

   Change its `visit_map` loop body to:

```rust
            let _: serde::de::IgnoredAny = map.next_value()?;
            let counted = self.only.is_none_or(|only| only == key);
            if !seen.insert(key) && counted {
                dup = true;
            }
```

8. Add `DuplicateKeys` above `TopAndErrorDupCheck`. Change that visitor's `type Value` and every
   primitive/seq method's return to `DuplicateKeys` (`Ok(DuplicateKeys::default())`). Replace
   its `visit_map` loop with:

```rust
/// Duplicate-key findings from one streaming pass over the raw line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DuplicateKeys {
    /// Duplicate at the top level or inside `error` — rmcp rejects any line.
    envelope: bool,
    /// Duplicate `_meta` directly inside top-level `params` — rmcp rejects it only on
    /// requests and notifications (issue #867).
    params_meta: bool,
}
```

```rust
        let mut found = DuplicateKeys::default();
        while let Some(key) = map.next_key::<String>()? {
            if key == "error" {
                found.envelope |= map.next_value_seed(OneLevelDupCheck { only: None })?;
            } else if key == "params" {
                found.params_meta |=
                    map.next_value_seed(OneLevelDupCheck { only: Some("_meta") })?;
            } else {
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
            if !seen.insert(key) {
                found.envelope = true;
            }
        }
        Ok(found)
```

9. Rename `has_duplicate_keys_in_rmcp_strict_positions` to `scan_duplicate_keys` and change its
   return type to `DuplicateKeys` (`.unwrap_or_default()`). In its doc comment, add
   "`_meta` directly inside `params` (request/notification only)" to "Positions checked", and
   change `params` in "Positions NOT checked" to "other keys inside `params`". In `validate`, change the duplicate guard and `params_ok` to:

```rust
    let duplicates = scan_duplicate_keys(line);
    if duplicates.envelope {
        return ValidationOutcome::Reject(invalid_request(Value::Null));
    }
```

```rust
    let params_ok = !duplicates.params_meta && obj.get("params").is_none_or(is_valid_params);
```

   Update the names `DupCheckOneLevel` and `has_duplicate_keys_in_rmcp_strict_positions` in the
   surrounding comments, and replace `unwrap_or(false)` with `unwrap_or_default()` in the
   envelope.rs cargo-mutants comments and the two `envelope.rs` rows of
   `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Check with
   `rg -n 'DupCheckOneLevel|has_duplicate_keys|unwrap_or\(false\)' crates/rimap-server/src/mcp
   docs/superpowers/specs/test-strategy/mutation-baseline.md`; it must print nothing. In the
   same file, update the `envelope.rs:<line>` annotation-site anchors in the two `envelope.rs`
   rows, and anywhere else that cites them, to the moved line numbers of the cargo-mutants
   comments.
10. Re-run both focused commands from steps 3 and 5. Expect all four tests to pass. Then run
    `cargo nextest run -p rimap-server --lib -E 'test(wire_validator)'` and
    `cargo nextest run -p rimap-server --test mcp_wire_negative`. Expect all to pass, including
    `duplicate_keys_inside_params_still_forwards` and `duplicate_top_level_keys_reject`.
11. Add the ADR-0031 row to `docs/ADR/README.md` after the 0030 row, with `Accepted` status.
12. Run `just fmt-check` and `just lint` (exit 0). `crates/rimap-server/fuzz/.gitignore` ignores
    `corpus`, so stage the two seeds with `git add -f
    crates/rimap-server/fuzz/corpus/validate/{regression-867-original,params-meta-string}`, and
    confirm both appear in `git ls-files crates/rimap-server/fuzz/corpus/validate`. Commit:
    `fix(mcp): reject params._meta shapes rmcp rejects (#867)`.

**Acceptance:** spec Success 1–3 hold; no existing validator or wire test changed.

## Final verification (Success 4 and guardrails)

- From `crates/rimap-server/fuzz`, run `cargo +nightly fuzz run validate
  corpus/validate/regression-867-original` and the same for `corpus/validate/params-meta-string`.
  Expect exit 0 (`Executed ... in N ms`). Before the fix, the original exits 77, as CI reported.
- From the same directory, run `cargo +nightly fuzz run validate -- -max_total_time=60`, a seeded
  smoke run (`just fuzz` targets the root `fuzz/` workspace, which has no `validate`). Then run
  `just check-fuzz-lock-parity`. Expect exit 0 for each. ClusterFuzzLite zips
  `corpus/validate/` into the seed corpus (`.clusterfuzzlite/build.sh`), so the new files reach
  the nightly run. The smoke run writes new inputs into `corpus/validate/`, which are ignored.
  Delete them afterwards with `git clean -fX crates/rimap-server/fuzz/corpus/validate`, which
  removes only the ignored files. Then check that `git status --short --ignored` lists nothing
  under that path.
- `just test` in the background; expect exit 0. Its result goes in the PR.
- Record in the PR body (issue #867 criterion 5): the replay exit codes for both seeds, before
  and after the fix; the smoke-run and parity results; the observed pre-fix wire outcome; and
  the remaining limits. Unobserved rmcp gaps are surfaced only by fuzzing (ADR-0031), and #837
  is excluded.
- Rollback: revert the commit. There is no persisted state.
