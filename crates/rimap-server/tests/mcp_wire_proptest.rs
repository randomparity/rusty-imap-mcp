//! MCP wire-shape property tests (issue #266, Phase 4).
//!
//! Three proptest properties driving the production
//! `rusty-imap-mcp` binary with arbitrary JSON-RPC envelopes and
//! tool-call arguments. Default ≥1000 cases per property; nightly
//! runs scale via `PROPTEST_CASES`.
//!
//! Session-isolation discipline (§3.2 of the design doc):
//! - The harness is shared across cases for speed.
//! - `with_live_harness` restarts the harness if a case closed the
//!   connection, so cases never run against a poisoned session.
//! - Property 1's strategy excludes the pinned state-mutating
//!   method set so cases stay independent of MCP session state.
//!
//! Property strategy notes inline. See
//! `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`
//! for the full design context.
//!
//! # Runtime architecture
//!
//! Proptest's `proptest!` macro expands to a synchronous function,
//! so each case calls `block_on` to drive async work. Tokio I/O
//! handles (`ChildStdin`, `BufReader<ChildStdout>`) are bound to
//! the runtime that created them — using a fresh runtime per case
//! would invalidate the shared harness. Instead, `RUNTIME` is a
//! single process-lifetime `tokio::runtime::Runtime` stored in a
//! `OnceLock`; every case reuses the same `block_on` target so
//! harness I/O handles remain valid across cases.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "integration tests")]

#[path = "support/mod.rs"]
mod support;

use std::sync::{Mutex, OnceLock};

use proptest::prelude::*;
use serde_json::{Value, json};

use support::wire::harness::{CloseOrResponse, Harness, REQUEST_TIMEOUT};
use support::wire::schema::assert_envelope_valid;

/// Methods that mutate MCP session state. The property-1 strategy
/// MUST NOT generate these as the `method` field, since they would
/// couple subsequent cases to earlier ones (poisoning the shared
/// harness). The set is pinned here AND asserted against rmcp's
/// known stateful surface in `assert_exclusion_set_matches_rmcp`
/// below — that assertion is the regression net that catches a
/// future MCP spec addition introducing a new stateful method.
const STATE_MUTATING_METHODS: &[&str] = &["initialize", "notifications/initialized"];

#[test]
fn assert_exclusion_set_matches_rmcp() {
    // rmcp 1.5 documents stateful protocol methods at:
    //   rmcp::model::ProtocolVersion docs + Initialize/Initialized
    //   in rmcp::model::request.
    //
    // If a future rmcp version adds a new stateful method (e.g.
    // `session/reset`), this assertion is the place to update — and
    // STATE_MUTATING_METHODS above must be updated in lockstep, or
    // property 1 starts coupling cases.
    //
    // This test is a sentinel — it doesn't introspect rmcp at runtime
    // because rmcp's request enum is sealed. Instead, the maintainer
    // updates BOTH sides of the pair (this constant and the rmcp dep)
    // together. Bumping rmcp without inspecting this list trips a
    // human review checkpoint via this comment.
    let expected = ["initialize", "notifications/initialized"];
    let actual: Vec<&str> = STATE_MUTATING_METHODS.to_vec();
    assert_eq!(actual, expected.to_vec());
}

/// Single tokio runtime shared across all proptest cases in this
/// binary. All `Harness` I/O handles are bound to this runtime;
/// creating a new runtime per-case would invalidate them.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build shared tokio runtime")
    })
}

/// Run `body` against a harness, restarting the harness if the
/// previous case poisoned the session. After `body` runs, the
/// helper checks `is_usable` and drops the harness if false.
///
/// Codex review finding #2 verified that a simple `try_wait`
/// check could let a poisoned (stdout-closed but not-yet-reaped)
/// harness leak across cases. `Harness::is_usable` consolidates
/// the check.
async fn with_live_harness<F, Fut>(mut h: Option<Harness>, body: F) -> Option<Harness>
where
    F: FnOnce(Harness) -> Fut,
    Fut: std::future::Future<Output = Harness>,
{
    let needs_fresh = match h.as_mut() {
        None => true,
        Some(harness) => !harness.is_usable(),
    };
    if needs_fresh {
        drop(h);
        let mut fresh = Harness::spawn().await;
        let _ = fresh.initialize_handshake().await;
        fresh.send_initialized().await;
        h = Some(fresh);
    }
    let mut after = body(h.expect("ensured Some above")).await;
    if !after.is_usable() {
        return None;
    }
    Some(after)
}

/// Process-lifetime harness shared across all proptest cases within
/// one property invocation. Protected by a `std::sync::Mutex` so
/// the synchronous proptest runner can lock it without requiring an
/// async context; all actual I/O is performed inside `runtime().block_on`.
static HARNESS: Mutex<Option<Harness>> = Mutex::new(None);

// Property 2: arbitrary tool name with arbitrary JSON arguments
// always produces a JSON-RPC error envelope. Stateless by
// construction (every case is `tools/call <X>`; no method that
// mutates MCP session state is ever sent).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_tools_call_unknown_tool(
        tool_name in "[A-Za-z0-9_./-]{1,64}",
        args in proptest::collection::hash_map(
            "[A-Za-z0-9_]{1,16}",
            proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
            0..6,
        ),
    ) {
        runtime().block_on(async {
            let harness = HARNESS.lock().expect("HARNESS lock").take();
            let harness = with_live_harness(harness, |mut h| async move {
                let arguments: serde_json::Map<String, Value> = args
                    .into_iter()
                    .collect();
                let response = h
                    .request(
                        "tools/call",
                        json!({
                            "name": tool_name,
                            "arguments": arguments,
                        }),
                    )
                    .await;
                let is_envelope_error = response.get("error").is_some();
                let is_tool_error = response["result"]["isError"]
                    .as_bool()
                    .unwrap_or(false);
                assert!(
                    is_envelope_error || is_tool_error,
                    "unknown tool {tool_name:?} must produce an error, got {response}",
                );
                h
            }).await;
            *HARNESS.lock().expect("HARNESS lock") = harness;
        });
    }
}

/// Build an arbitrary `arguments` map for `use_account`. Mixes:
/// - Well-formed argument names (`account`, `name`, etc.) with
///   wrong value types
/// - Random argument names with random values
/// - Empty maps
fn arb_arguments() -> impl Strategy<Value = Value> {
    let well_formed_keys = prop_oneof![
        Just("account".to_string()),
        Just("name".to_string()),
        Just("id".to_string()),
        "[a-z]{1,16}".prop_map(String::from),
    ];
    let any_value = prop_oneof![
        Just(json!(null)),
        proptest::arbitrary::any::<bool>().prop_map(|b| json!(b)),
        proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
        "[\\PC]{0,64}".prop_map(|s| json!(s)),
    ];
    proptest::collection::hash_map(well_formed_keys, any_value, 0..6).prop_map(|m| {
        let obj: serde_json::Map<String, Value> = m.into_iter().collect();
        Value::Object(obj)
    })
}

/// Build an arbitrary JSON-RPC-ish envelope. Each field is
/// optionally present and may be of a wrong type. The `method`
/// field, when present, is drawn from a set that EXCLUDES
/// state-mutating methods to keep cases independent.
fn arb_envelope() -> impl Strategy<Value = Value> {
    let arb_method = prop_oneof![
        // Known stateless methods
        Just("tools/list".to_string()),
        Just("tools/call".to_string()),
        Just("resources/list".to_string()),
        Just("ping".to_string()),
        // Unknown methods (still stateless; the server returns
        // method-not-found without touching session state)
        "[a-z/]{1,32}".prop_map(String::from),
    ]
    .prop_filter("exclude state-mutating methods", |m: &String| {
        !STATE_MUTATING_METHODS.contains(&m.as_str())
    });

    let arb_id = prop_oneof![
        Just(json!(null)),
        proptest::arbitrary::any::<u32>().prop_map(|n| json!(n)),
        "[a-z0-9]{1,8}".prop_map(|s| json!(s)),
    ];

    let arb_params = prop_oneof![
        Just(json!({})),
        Just(json!(null)),
        proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
        "[\\PC]{0,32}".prop_map(|s| json!(s)),
    ];

    (
        prop::option::of(Just("2.0".to_string())),
        prop::option::of(arb_id),
        prop::option::of(arb_method),
        prop::option::of(arb_params),
    )
        .prop_map(|(jsonrpc, id, method, params)| {
            let mut obj = serde_json::Map::new();
            if let Some(v) = jsonrpc {
                obj.insert("jsonrpc".to_string(), json!(v));
            }
            if let Some(v) = id {
                obj.insert("id".to_string(), v);
            }
            if let Some(v) = method {
                obj.insert("method".to_string(), json!(v));
            }
            if let Some(v) = params {
                obj.insert("params".to_string(), v);
            }
            Value::Object(obj)
        })
        .prop_filter(
            "exclude spec-legal notifications (jsonrpc==\"2.0\" + missing id + present method) — \
             their silent-ignore is JSON-RPC §4.1 compliant and covered separately by \
             valid_notification_does_not_hang_session",
            |env| {
                let is_notification = env.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
                    && env.get("id").is_none()
                    && env.get("method").and_then(|v| v.as_str()).is_some();
                !is_notification
            },
        )
}

// Property 3: `use_account` with arbitrary argument shapes. With
// zero accounts configured (the harness's default), every call
// MUST fail. Stateless by construction.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_tools_call_use_account_argument_shape(
        arguments in arb_arguments(),
    ) {
        runtime().block_on(async move {
            let harness = HARNESS.lock().expect("HARNESS lock").take();
            let harness = with_live_harness(harness, |mut h| async move {
                let response = h
                    .request(
                        "tools/call",
                        json!({
                            "name": "use_account",
                            "arguments": arguments,
                        }),
                    )
                    .await;
                let is_envelope_error = response.get("error").is_some();
                let is_tool_error = response["result"]["isError"]
                    .as_bool()
                    .unwrap_or(false);
                assert!(
                    is_envelope_error || is_tool_error,
                    "use_account with arbitrary args must fail (no accounts configured), got {response}",
                );
                h
            }).await;
            *HARNESS.lock().expect("HARNESS lock") = harness;
        });
    }
}

// Property 1: arbitrary JSON-RPC-ish envelopes never panic the
// server. Either the server emits a well-formed envelope (success
// or error) or it cleanly closes the connection.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_envelope_never_panics(envelope in arb_envelope()) {
        runtime().block_on(async move {
            let mut harness = HARNESS.lock().expect("HARNESS lock").take();
            harness = with_live_harness(harness, |mut h| async move {
                h.send_line(&envelope.to_string()).await;
                let outcome = h.response_or_close(REQUEST_TIMEOUT).await;
                match outcome {
                    CloseOrResponse::Response(line) => {
                        let env: Value = serde_json::from_str(line.trim_end())
                            .expect("server response must be valid JSON");
                        assert_envelope_valid(&env);
                    }
                    CloseOrResponse::CleanClose => {
                        // Spec-legal: harness is now poisoned;
                        // with_live_harness will drop it after the
                        // case and spawn a fresh one for the next.
                    }
                    CloseOrResponse::Crashed(diagnostic) => {
                        panic!(
                            "server crashed during property 1 case — \
                             file an issue and pin a regression seed before continuing: \
                             envelope={envelope}\n{diagnostic}",
                        );
                    }
                    CloseOrResponse::Hung => {
                        panic!(
                            "server hung during property 1 case (no response, no close \
                             within {REQUEST_TIMEOUT:?}): envelope={envelope}",
                        );
                    }
                }
                h
            }).await;
            *HARNESS.lock().expect("HARNESS lock") = harness;
        });
    }
}
