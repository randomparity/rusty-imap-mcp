//! Pure JSON-RPC envelope validation. No I/O. The duplicate-key
//! detection (`scan_duplicate_keys`) and the
//! `validate` decision function live here, plus the synthesizer that
//! turns an [`ErrorEnvelope`] into a wire-ready line. The
//! `OneLevelDupCheck` / `TopAndErrorDupCheck`
//! serde visitors back the dup-key scan.

use serde_json::Value;

use super::{ErrorEnvelope, ValidationOutcome};

/// `id` accepted by rmcp's `RxJsonRpcMessage`. rmcp 1.5's
/// `RequestId = NumberOrString` rejects null; strings are unrestricted;
/// numbers must be i64-representable (rejects fractional values and
/// numbers outside i64 range — `serde_json` parses very large ints as
/// f64 which `as_i64` also rejects).
pub(crate) fn is_forwardable_id(v: &Value) -> bool {
    if v.is_string() {
        return true;
    }
    v.as_i64().is_some()
}

/// `params` accepted on JSON-RPC requests and notifications. JSON-RPC §4
/// nominally allows a Structured value (Array OR Object) when present,
/// but rmcp's `CustomRequest` / `CustomNotification` deserializers
/// route `params` through `serde(flatten)` over a `WithMeta { _meta,
/// _rest }` wrapper, which can only deserialize from a map shape —
/// so an `Array` body produces "data did not match any variant of
/// untagged enum `JsonRpcMessage`" and rmcp silently drops the line
/// (server appears hung). The cargo-fuzz oracle (#266) caught
/// `{"jsonrpc":"2.0","method":"x","id":1,"params":[1,2,3]}` on the
/// seed corpus.
///
/// `Null` is accepted because rmcp tolerates it as "no parameters"
/// and rejecting it would over-strict legitimate clients. Number,
/// String, and Boolean shapes are likewise silently dropped by rmcp.
///
/// The same wrapper types `_meta` as an optional object, so rmcp 3.x
/// also rejects a `params._meta` that is neither an object nor null
/// (issue #867, ADR-0031).
pub(crate) fn is_valid_params(v: &Value) -> bool {
    if let Some(obj) = v.as_object() {
        return obj
            .get("_meta")
            .is_none_or(|meta| meta.is_object() || meta.is_null());
    }
    v.is_null()
}

/// `error` body matches JSON-RPC §5.1: an object with i32-representable
/// `code` and string `message`. `data` is optional. rmcp 1.5's
/// `ErrorCode = i32`, so fractional values and numbers outside i32
/// range fail rmcp's deserialization and are rejected here.
pub(crate) fn is_well_formed_error(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    let code_ok = obj
        .get("code")
        .and_then(Value::as_i64)
        .is_some_and(|n| i32::try_from(n).is_ok());
    let message_ok = obj.get("message").is_some_and(Value::is_string);
    code_ok && message_ok
}

/// Read the top-level `id` field for echo on a rejection envelope.
/// Returns `Value::Null` if `id` is missing, present-but-null, or of a
/// disallowed type; otherwise echoes the original value verbatim.
/// JSON-RPC §5 says the id on a synthesized error response MUST be
/// null when the original could not be detected.
///
/// **`is_forwardable_id` symmetry.** Only id shapes that would have
/// been forwardable (string OR i64-representable number) are echoed.
/// Fractional numbers, oversized numbers, arrays, objects, and
/// booleans fall through to `Null`. This matches MCP's `RequestId =
/// integer | string` schema, which the synthesized error envelope
/// must satisfy. Cargo-fuzz oracle (#266) caught `{".sonrpc":"2.0",
/// "id":2.5}`: typo'd `jsonrpc` reaches `extract_id` before the
/// id-validity branch, the lax echo emitted `id: 2.5`, and the MCP
/// schema rejected the resulting envelope ("2.5 is not of types
/// integer, string").
pub(crate) fn extract_id(obj: &serde_json::Map<String, Value>) -> Value {
    match obj.get("id") {
        Some(v) if is_forwardable_id(v) => v.clone(),
        _ => Value::Null,
    }
}

pub(crate) fn parse_error() -> ErrorEnvelope {
    ErrorEnvelope {
        code: -32700,
        message: "Parse error",
        id: Value::Null,
    }
}

pub(crate) fn invalid_request(id: Value) -> ErrorEnvelope {
    ErrorEnvelope {
        code: -32600,
        message: "Invalid Request",
        id,
    }
}

/// Detects duplicates in one map level and drains all keys/values
/// without recursing. For non-map shapes returns `false` —
/// duplicates are a map-level concept. Module-private helper for
/// [`scan_duplicate_keys`], used as a seed so one visitor serves both
/// the `error` body (every key) and `params` (only `_meta`).
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

// cargo-mutants: known-equivalent group — the non-`visit_map` methods
// below have several mutants the test suite does not kill, by design:
//   * `expecting` is invoked only by serde to format error diagnostics;
//     its return value never reaches our control flow.
//   * `visit_string` and `visit_none` are unreachable from
//     `serde_json::Deserializer::from_str` (which is what
//     `scan_duplicate_keys` constructs): the
//     streaming deserializer prefers `visit_str` for JSON strings and
//     `visit_unit` for JSON null, never the owned-String or `Option`
//     paths.
//   * `visit_seq` mutated to a constant return skips the drain loop;
//     the surrounding `map.next_value_seed(...)?` chain
//     then leaves the parser mid-array, the outer
//     `de.deserialize_any(...).unwrap_or_default()` swallows the
//     resulting trailing-data error, and the dup-check signals "no
//     duplicates" — identical to the unmutated outcome (drained,
//     returns `Ok(false)`).
// Inline `visit_<primitive>` mutants (i64/u64/f64/bool/unit) ARE
// killed by `error_body_as_primitive_echoes_id` further down.
impl<'de> serde::de::Visitor<'de> for OneLevelDupCheck {
    type Value = bool;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut dup = false;
        while let Some(key) = map.next_key::<String>()? {
            let _: serde::de::IgnoredAny = map.next_value()?;
            let counted = self.only.is_none_or(|only| only == key);
            if !seen.insert(key) && counted {
                dup = true;
            }
        }
        Ok(dup)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(false)
    }

    fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_str<E>(self, _: &str) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_string<E>(self, _: String) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_unit<E>(self) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_none<E>(self) -> Result<bool, E> {
        Ok(false)
    }
}

/// Duplicate-key findings from one streaming pass over the raw line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DuplicateKeys {
    /// Duplicate at the top level or inside `error` — rmcp rejects any line.
    envelope: bool,
    /// Duplicate `_meta` directly inside top-level `params` — rmcp rejects it only on
    /// requests and notifications (issue #867).
    params_meta: bool,
}

/// Detects duplicates at the top level, inside the `error` subtree, and
/// of `_meta` inside the `params` subtree (one level deep each), but does
/// not recurse further. Module-private helper for [`scan_duplicate_keys`].
struct TopAndErrorDupCheck;

// cargo-mutants: known-equivalent group — every method below except
// `visit_map` produces an observably-equivalent outcome under any
// stub-return mutation. `scan_duplicate_keys`
// is called from `validate(line)` BEFORE the line is parsed into a
// `Value`. For a non-object top-level (string/number/bool/null/array)
// the parsed `Value` later fails `parsed.as_object()` and is rejected
// via `invalid_request(Value::Null)` — the same id used by the
// dup-check rejection path. So whatever `visit_<primitive>` returns,
// the final ValidationOutcome is the same
// `Reject(invalid_request(Value::Null))`. `expecting` only formats
// serde diagnostics. `visit_seq` without drain triggers a trailing-
// data error that the outer `unwrap_or_default()` swallows back to the
// "no duplicates" verdict — same outcome path as drained-then-
// default. `visit_map` (the one we actually care about) IS killed
// by `duplicate_top_level_keys_reject`, `duplicate_keys_inside_error_body_reject`,
// and `params_meta_decisions_match_rmcp_acceptance`.
impl<'de> serde::de::Visitor<'de> for TopAndErrorDupCheck {
    type Value = DuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<DuplicateKeys, A::Error> {
        // Drain ALL keys before returning; early-return would leave
        // the streaming deserializer's input position mid-map and
        // `deserialize_any` would propagate a trailing-data error,
        // surfacing as "no duplicates" here via the outer
        // `unwrap_or_default()`. Accumulate the findings instead.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut found = DuplicateKeys::default();
        while let Some(key) = map.next_key::<String>()? {
            if key == "error" {
                // rmcp's `ErrorData` is a strict struct deserialize.
                found.envelope |= map.next_value_seed(OneLevelDupCheck { only: None })?;
            } else if key == "params" {
                // rmcp's `WithMeta` wrapper holds `_meta` as a strict field.
                found.params_meta |= map.next_value_seed(OneLevelDupCheck {
                    only: Some("_meta"),
                })?;
            } else {
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
            if !seen.insert(key) {
                found.envelope = true;
            }
        }
        Ok(found)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<DuplicateKeys, A::Error> {
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(DuplicateKeys::default())
    }

    fn visit_bool<E>(self, _: bool) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_i64<E>(self, _: i64) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_u64<E>(self, _: u64) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_f64<E>(self, _: f64) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_str<E>(self, _: &str) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_string<E>(self, _: String) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_unit<E>(self) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
    fn visit_none<E>(self) -> Result<DuplicateKeys, E> {
        Ok(DuplicateKeys::default())
    }
}

/// Reports duplicate JSON keys in any position rmcp deserializes via a
/// strict struct.
///
/// `serde_json::from_str::<Value>` silently collapses duplicates
/// (last wins), but rmcp's `serde(untagged)` + `serde(flatten)`
/// machinery on `JsonRpcMessage` rejects duplicate keys at strict-
/// struct positions, so a line that looks valid after dedup gets
/// silently dropped by rmcp. Detected with a streaming visitor on
/// the raw input before any parse-to-`Value` step so the dedup
/// never happens.
///
/// **Positions checked:**
/// - The top-level envelope object (`jsonrpc`, `id`, `method`,
///   `params`, `result`, `error`).
/// - The `error` body if present (`code`, `message`, `data`) —
///   rmcp's `ErrorData` is a strict `#[derive(Deserialize)]` struct.
/// - `_meta` directly inside `params` (request/notification only;
///   reported separately as `params_meta`, issue #867).
///
/// **Positions NOT checked** (rmcp uses lenient `Value` /
/// `JsonObject` here, so duplicates collapse last-wins and don't
/// cause rejection): other keys inside `params`, `result`,
/// `error.data`, and any further-nested subtrees.
///
/// Non-object roots and unparsable input report no duplicates — those
/// shapes are caught by the existing parse-error / non-object
/// branches in `validate`.
///
/// Cargo-fuzz oracle (#266, #867) findings caught by this helper:
/// - Top level: `{"jsonrpc":"2.0","id":99,"res":"2.0","id":99,"result":{"x":1}}`.
/// - `error` body: `{"jsonrpc":"2.0","id":1,"error":{"code":175,"message":75,"message":"x"}}`.
/// - `params`: `{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":{},"_meta":{}}}`.
fn scan_duplicate_keys(line: &str) -> DuplicateKeys {
    use serde::Deserializer as _;
    let mut de = serde_json::Deserializer::from_str(line);
    de.deserialize_any(TopAndErrorDupCheck).unwrap_or_default()
}

/// Validate one line of input and decide what to do with it.
pub(crate) fn validate(line: &str) -> ValidationOutcome {
    if line.trim().is_empty() {
        return ValidationOutcome::Skip;
    }
    // Detect duplicate keys in any rmcp strict-struct position on the
    // raw bytes BEFORE parsing into `Value`, since `Value` collapses
    // duplicates silently and rmcp rejects them. See
    // `scan_duplicate_keys` docstring.
    // Echo `Null` for the id — with envelope-level duplicates, no single
    // id value is safely echoable.
    let duplicates = scan_duplicate_keys(line);
    if duplicates.envelope {
        return ValidationOutcome::Reject(invalid_request(Value::Null));
    }
    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return ValidationOutcome::Reject(parse_error()),
    };
    let Some(obj) = parsed.as_object() else {
        return ValidationOutcome::Reject(invalid_request(Value::Null));
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return ValidationOutcome::Reject(invalid_request(extract_id(obj)));
    }

    // id (if present) must be string|number — null is rejected here
    // because rmcp's RequestId = NumberOrString won't deserialize null.
    let id_present_and_valid = match obj.get("id") {
        None => false,
        Some(v) if is_forwardable_id(v) => true,
        Some(_) => return ValidationOutcome::Reject(invalid_request(Value::Null)),
    };

    let method = obj.get("method");
    let result = obj.get("result");
    let error = obj.get("error");
    let params_ok = !duplicates.params_meta && obj.get("params").is_none_or(is_valid_params);

    match (method, result, error) {
        // Request: method+id, no result, no error, valid params shape
        (Some(m), None, None) if m.is_string() && id_present_and_valid && params_ok => {
            ValidationOutcome::Forward
        }
        // Notification: method, no id, no result, no error, valid params shape
        (Some(m), None, None) if m.is_string() && !id_present_and_valid && params_ok => {
            ValidationOutcome::Forward
        }
        // Response: id+result, no method, no error
        (None, Some(_), None) if id_present_and_valid => ValidationOutcome::Forward,
        // Error response: id+error, no method, no result, error well-formed
        (None, None, Some(err)) if id_present_and_valid && is_well_formed_error(err) => {
            ValidationOutcome::Forward
        }
        // Catch-all: non-string method, empty object, response/error without
        // id, malformed error, both result+error, method mixed with
        // result/error, request/notification with non-structured params.
        _ => ValidationOutcome::Reject(invalid_request(extract_id(obj))),
    }
}

/// Serialize a rejection envelope to a single wire line, terminated
/// with `\n`. The shape matches JSON-RPC §5: `{jsonrpc, id, error}`
/// with `error.{code, message}` and no `data`.
///
/// **`id` is omitted when null**, not emitted as `"id": null`. MCP's
/// `RequestId` schema (`integer | string`) disallows null, so emitting
/// `null` would make the envelope fail the MCP schema validator the
/// test harness applies via `assert_envelope_valid`. JSON-RPC 2.0 §5
/// requires `id: null` for parse / invalid-request errors, but MCP's
/// `JSONRPCErrorResponse` schema marks `id` as OPTIONAL — so omitting
/// it satisfies both the MCP contract (the protocol we serve) and
/// the JSON-RPC §5 intent of "no recoverable id available."
pub(crate) fn synthesize_error_line(env: &ErrorEnvelope) -> String {
    let body = if env.id.is_null() {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": env.code,
                "message": env.message,
            },
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": env.id,
            "error": {
                "code": env.code,
                "message": env.message,
            },
        })
    };
    // Use to_string (not pretty) so it's exactly one line.
    let mut line = body.to_string();
    line.push('\n');
    line
}
