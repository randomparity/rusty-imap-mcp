//! Fuzz-only oracle helpers for the cargo-fuzz target at
//! `crates/rimap-server/fuzz/`. Production builds (no `--features
//! fuzzing`) compile this file out entirely.
//!
//! Codex's 2026-05-17 adversarial review flagged the previous
//! panic-only oracle as insufficient: a `Forward` decision on an
//! envelope rmcp would reject, or a `Reject` decision producing a
//! schema-invalid synthesized error envelope, both look like success
//! to libFuzzer without these checks. This module supplies the two
//! missing oracles plus a fuzz-side mirror of `ValidationOutcome` so
//! the fuzz target can branch on the validator's decision without
//! widening the `pub(crate)` type's visibility.

use std::sync::OnceLock;

use serde_json::Value;

use super::wire_validator::{ValidationOutcome, synthesize_error_line, validate};

/// Public mirror of the `pub(crate) ValidationOutcome` so the fuzz target
/// can inspect the decision without widening the internal type's visibility.
/// `Reject` carries the synthesized error line so the oracle can schema-check
/// it directly.
#[doc(hidden)]
pub enum FuzzOutcome {
    Skip,
    Forward,
    Reject(String),
}

/// Runs the validator and lifts the outcome into the fuzz-side enum,
/// pre-synthesizing the error line for the `Reject` branch so the
/// oracle has the exact bytes the validator would have written.
#[doc(hidden)]
#[must_use]
pub fn fuzz_validate(line: &str) -> FuzzOutcome {
    match validate(line) {
        ValidationOutcome::Skip => FuzzOutcome::Skip,
        ValidationOutcome::Forward => FuzzOutcome::Forward,
        ValidationOutcome::Reject(env) => FuzzOutcome::Reject(synthesize_error_line(&env)),
    }
}

/// Returns `Ok` if rmcp's `serde` Deserialize would accept `line` as a
/// well-formed inbound JSON-RPC message. The fuzz target asserts this
/// holds for every `Forward` decision; any failure exposes a validator
/// grammar mismatch (rmcp would have silently dropped or rejected the
/// envelope the validator declared forwardable).
///
/// `rmcp::model::ClientJsonRpcMessage` is the alias used elsewhere in
/// this crate (`main.rs::emit_pre_init_error_envelope`,
/// `mcp::preinit::synthesize_pre_init_error_envelope`) to represent
/// "an inbound message a server expects from a client" — i.e. what
/// rmcp's `serve_server` stream would yield once the validator has
/// forwarded a line.
#[doc(hidden)]
pub fn check_rmcp_accepts(line: &str) -> Result<(), String> {
    serde_json::from_str::<rmcp::model::ClientJsonRpcMessage>(line)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

static ERROR_SCHEMA: OnceLock<jsonschema::Validator> = OnceLock::new();

#[expect(
    clippy::expect_used,
    reason = "fuzz-only init: fail-fast if the vendored schema is malformed or missing \
              the JSONRPCErrorResponse fragment — the oracle is worthless without it"
)]
fn error_envelope_validator() -> &'static jsonschema::Validator {
    ERROR_SCHEMA.get_or_init(|| {
        // `include_bytes!` resolves relative to this source file. From
        // `src/mcp/fuzz_oracle.rs` the schema lives at
        // `../../tests/fixtures/mcp-spec/2025-11-25/schema.json`.
        let schema_bytes = include_bytes!("../../tests/fixtures/mcp-spec/2025-11-25/schema.json");
        let schema: Value = serde_json::from_slice(schema_bytes).expect("MCP schema is valid JSON");
        // The MCP schema uses Draft 2020-12's `$defs`, not the older
        // `definitions` keyword.
        let fragment = schema
            .pointer("/$defs/JSONRPCErrorResponse")
            .expect("MCP schema must contain $defs/JSONRPCErrorResponse")
            .clone();
        // Inline the parent schema's `$defs` so the fragment's internal
        // `$ref` lookups (Error, RequestId) resolve when compiled as a
        // standalone root schema.
        let mut full = serde_json::Map::new();
        full.insert("$schema".into(), schema["$schema"].clone());
        full.insert("$defs".into(), schema["$defs"].clone());
        for (k, v) in fragment.as_object().expect("fragment is object") {
            full.insert(k.clone(), v.clone());
        }
        jsonschema::validator_for(&Value::Object(full))
            .expect("JSONRPCErrorResponse fragment compiles to a validator")
    })
}

/// Returns `Ok` if `line` deserializes as JSON and matches the vendored
/// MCP `JSONRPCErrorResponse` schema. The fuzz target asserts this
/// holds for every `Reject` decision the validator makes; any failure
/// means `synthesize_error_line` produced output that would itself
/// fail conformance.
#[doc(hidden)]
pub fn check_error_envelope_valid(line: &str) -> Result<(), String> {
    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
    let v: Value = serde_json::from_str(trimmed).map_err(|e| e.to_string())?;
    let validator = error_envelope_validator();
    if validator.is_valid(&v) {
        Ok(())
    } else {
        let errs: Vec<String> = validator.iter_errors(&v).map(|e| e.to_string()).collect();
        Err(errs.join("; "))
    }
}

#[cfg(test)]
mod tests {
    // These tests PROVE the oracle catches the failure classes Codex
    // flagged — they MUST be present so a future change to the oracle
    // logic that silently breaks detection trips a regression.

    use super::{check_error_envelope_valid, check_rmcp_accepts};

    #[test]
    fn rmcp_accepts_a_well_formed_request() {
        let line = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        assert!(check_rmcp_accepts(line).is_ok());
    }

    #[test]
    fn rmcp_rejects_missing_jsonrpc_version() {
        // rmcp's Deserialize requires the jsonrpc tag; this is the
        // canonical "validator should have caught it but didn't" shape.
        let line = r#"{"method":"tools/list","id":1}"#;
        assert!(check_rmcp_accepts(line).is_err());
    }

    #[test]
    fn rmcp_rejects_envelope_with_no_method_result_or_error() {
        // jsonrpc + id alone matches none of `ClientJsonRpcMessage`'s
        // four untagged variants: Request/Notification's flattened
        // `ClientRequest`/`ClientNotification` enums require a
        // `method` (their `CustomRequest`/`CustomNotification`
        // catch-all variants demand `method: String`); `Response`
        // needs `result`; `Error` needs `error`. The fuzz target
        // asserts rmcp accepts every `Forward` decision, so a
        // hypothetical validator bug that forwarded this exact shape
        // would land here.
        //
        // Aside on fractional numeric ids: at first glance `id: 1.5`
        // looks like a clean rmcp rejection (rmcp's `RequestId =
        // NumberOrString` deserialize rejects non-integer numbers),
        // but the surrounding `JsonRpcMessage` is `#[serde(untagged)]`
        // and falls through to the `Notification` variant, whose
        // flattened `CustomNotification` ignores extra fields like
        // `id`. So `{"jsonrpc":"2.0","method":"x","id":1.5}` actually
        // deserializes successfully as a notification with the id
        // silently dropped — exactly the rmcp behaviour the validator
        // exists to compensate for, but not a usable oracle
        // negative-case.
        let line = r#"{"jsonrpc":"2.0","id":1}"#;
        assert!(check_rmcp_accepts(line).is_err());
    }

    #[test]
    fn error_envelope_schema_accepts_canonical_minus_32600() {
        let line =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#;
        assert!(
            check_error_envelope_valid(line).is_ok(),
            "got: {:?}",
            check_error_envelope_valid(line)
        );
    }

    #[test]
    fn error_envelope_schema_rejects_missing_error_field() {
        let line = r#"{"jsonrpc":"2.0","id":1}"#;
        assert!(check_error_envelope_valid(line).is_err());
    }

    #[test]
    fn error_envelope_schema_rejects_array_id() {
        // MCP RequestId is integer|string, not array.
        let line = r#"{"jsonrpc":"2.0","id":[1,2],"error":{"code":-32600,"message":"x"}}"#;
        assert!(check_error_envelope_valid(line).is_err());
    }
}
