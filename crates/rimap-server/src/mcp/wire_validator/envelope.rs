//! Pure JSON-RPC envelope validation. No I/O. The duplicate-key
//! detection (`has_duplicate_keys_in_rmcp_strict_positions`) and the
//! `validate` decision function live here, plus the synthesizer that
//! turns an [`ErrorEnvelope`] into a wire-ready line. The
//! `OneLevelDupCheck` / `DupCheckOneLevel` / `TopAndErrorDupCheck`
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
pub(crate) fn is_valid_params(v: &Value) -> bool {
    v.is_object() || v.is_null()
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
/// [`has_duplicate_keys_in_rmcp_strict_positions`].
struct OneLevelDupCheck;

// cargo-mutants: known-equivalent group — the non-`visit_map` methods
// below have several mutants the test suite does not kill, by design:
//   * `expecting` is invoked only by serde to format error diagnostics;
//     its return value never reaches our control flow.
//   * `visit_string` and `visit_none` are unreachable from
//     `serde_json::Deserializer::from_str` (which is what
//     `has_duplicate_keys_in_rmcp_strict_positions` constructs): the
//     streaming deserializer prefers `visit_str` for JSON strings and
//     `visit_unit` for JSON null, never the owned-String or `Option`
//     paths.
//   * `visit_seq` mutated to a constant return skips the drain loop;
//     the surrounding `DupCheckOneLevel`/`map.next_value()?` chain
//     then leaves the parser mid-array, the outer
//     `de.deserialize_any(...).unwrap_or(false)` swallows the
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
            if !seen.insert(key) {
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

/// Newtype with a `Deserialize` impl that defers to
/// [`OneLevelDupCheck`]. Lets the outer visitor invoke
/// `map.next_value::<DupCheckOneLevel>()?` to recurse exactly once
/// into the `error` subtree.
struct DupCheckOneLevel(bool);

impl<'de> serde::de::Deserialize<'de> for DupCheckOneLevel {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        d.deserialize_any(OneLevelDupCheck).map(DupCheckOneLevel)
    }
}

/// Detects duplicates at the top level AND inside the `error`
/// subtree (one level deep), but does not recurse further. Module-
/// private helper for
/// [`has_duplicate_keys_in_rmcp_strict_positions`].
struct TopAndErrorDupCheck;

// cargo-mutants: known-equivalent group — every method below except
// `visit_map` produces an observably-equivalent outcome under any
// stub-return mutation. `has_duplicate_keys_in_rmcp_strict_positions`
// is called from `validate(line)` BEFORE the line is parsed into a
// `Value`. For a non-object top-level (string/number/bool/null/array)
// the parsed `Value` later fails `parsed.as_object()` and is rejected
// via `invalid_request(Value::Null)` — the same id used by the
// dup-check rejection path. So whether `visit_<primitive>` returns
// `Ok(true)` or `Ok(false)`, the final ValidationOutcome is the same
// `Reject(invalid_request(Value::Null))`. `expecting` only formats
// serde diagnostics. `visit_seq` without drain triggers a trailing-
// data error that the outer `unwrap_or(false)` swallows back to the
// "no duplicates" verdict — same outcome path as drained-then-
// Ok(false). `visit_map` (the one we actually care about) IS killed
// by `duplicate_top_level_keys_reject` and `duplicate_keys_inside_error_body_reject`.
impl<'de> serde::de::Visitor<'de> for TopAndErrorDupCheck {
    type Value = bool;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        // Drain ALL keys before returning; early-return would leave
        // the streaming deserializer's input position mid-map and
        // `deserialize_any` would propagate a trailing-data error,
        // surfacing as `Ok(false)` here via the outer
        // `unwrap_or(false)`. Accumulate the dup flag instead.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut dup = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "error" {
                // Recurse one level into `error`'s value, since
                // rmcp's `ErrorData` is a strict struct deserialize.
                let nested: DupCheckOneLevel = map.next_value()?;
                if nested.0 {
                    dup = true;
                }
            } else {
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
            if !seen.insert(key) {
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

/// Returns `true` iff `line` contains duplicate JSON keys in any
/// position rmcp deserializes via a strict `#[derive(Deserialize)]`
/// struct.
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
///
/// **Positions NOT checked** (rmcp uses lenient `Value` /
/// `JsonObject` here, so duplicates collapse last-wins and don't
/// cause rejection): `params`, `result`, `error.data`, and any
/// further-nested subtrees.
///
/// Non-object roots and unparsable input return `false` — those
/// shapes are caught by the existing parse-error / non-object
/// branches in `validate`.
///
/// Cargo-fuzz oracle (#266) findings caught by this helper:
/// - Top level: `{"jsonrpc":"2.0","id":99,"res":"2.0","id":99,"result":{"x":1}}`.
/// - `error` body: `{"jsonrpc":"2.0","id":1,"error":{"code":175,"message":75,"message":"x"}}`.
fn has_duplicate_keys_in_rmcp_strict_positions(line: &str) -> bool {
    use serde::Deserializer as _;
    let mut de = serde_json::Deserializer::from_str(line);
    de.deserialize_any(TopAndErrorDupCheck).unwrap_or(false)
}

/// Validate one line of input and decide what to do with it.
pub(crate) fn validate(line: &str) -> ValidationOutcome {
    if line.trim().is_empty() {
        return ValidationOutcome::Skip;
    }
    // Detect duplicate keys in any rmcp strict-struct position
    // (top-level envelope OR `error` body) on the raw bytes BEFORE
    // parsing into `Value`, since `Value` collapses duplicates
    // silently and rmcp rejects them. See
    // `has_duplicate_keys_in_rmcp_strict_positions` docstring.
    // Echo `Null` for the id — with duplicates, no single id value is
    // safely echoable.
    if has_duplicate_keys_in_rmcp_strict_positions(line) {
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
    let params_ok = obj.get("params").is_none_or(is_valid_params);

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
