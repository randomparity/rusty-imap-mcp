//! MCP wire-shape conformance harness (issue #263, Phase 1).
//!
//! Drives the production `rusty-imap-mcp` binary over stdio with a
//! zero-account config and validates every response against the
//! vendored MCP spec schemas. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "support/mod.rs"]
mod support;

use std::time::Duration;

use rmcp::model::ProtocolVersion;
use serde_json::json;

use support::wire::{Harness, PINNED_PROTOCOL_VERSION, assert_valid};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_smoke_initialize_returns_valid_envelope() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(response["jsonrpc"], json!("2.0"));
    assert!(
        response["result"].is_object(),
        "initialize response must have a result object, got {response}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialize_advertises_tools_capability() {
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;

    let result = &response["result"];
    assert_valid(result, "InitializeResult");

    assert_eq!(
        result["protocolVersion"],
        json!(PINNED_PROTOCOL_VERSION),
        "server must echo the pinned protocol version",
    );

    // Regression net for #261: the capabilities object must contain
    // a `tools` key on the wire. Permissive clients ignore the
    // absence; spec-strict clients (e.g. bobshell) refuse to call
    // tools/list.
    let capabilities = &result["capabilities"];
    assert!(
        capabilities.is_object(),
        "capabilities must be an object, got {capabilities}",
    );
    assert!(
        capabilities.get("tools").is_some(),
        "capabilities.tools must be present on the wire; got {capabilities}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_protocol_version_negotiation_matches_vendored_schema() {
    // Three-way drift check (Codex adversarial review finding #1):
    //
    //   1. rmcp::ProtocolVersion::LATEST.as_str()
    //   2. PINNED_PROTOCOL_VERSION (constant in tests/support/wire/harness.rs)
    //   3. crates/rimap-server/tests/fixtures/mcp-spec/<version>/
    //
    // All three MUST agree. If any one drifts (rmcp bumps LATEST, the
    // pinned constant goes stale, or someone deletes the fixture
    // directory) this test fails first with a precise diagnostic
    // before any fragment-validation test validates against an
    // outdated schema.

    let rmcp_latest = ProtocolVersion::LATEST.as_str();
    assert_eq!(
        rmcp_latest, PINNED_PROTOCOL_VERSION,
        "rmcp::ProtocolVersion::LATEST ({rmcp_latest}) drifted from \
         PINNED_PROTOCOL_VERSION ({PINNED_PROTOCOL_VERSION}). Run \
         `scripts/refresh-mcp-spec.sh {rmcp_latest}` to vendor the new \
         schema, update PINNED_PROTOCOL_VERSION + MCP_SCHEMA_JSON in \
         tests/support/wire/harness.rs, and update the README under \
         tests/fixtures/mcp-spec/.",
    );

    // The fixture directory must exist on disk under the pinned name.
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp-spec")
        .join(PINNED_PROTOCOL_VERSION);
    assert!(
        fixture_dir.is_dir(),
        "expected vendored fixture directory at {} for pinned version \
         {PINNED_PROTOCOL_VERSION}; refresh script may not have run",
        fixture_dir.display(),
    );

    // And rmcp must echo whatever the harness sends as the negotiated
    // version, which the harness now derives from LATEST.
    let mut harness = Harness::spawn().await;
    let response = harness.initialize_handshake().await;
    assert_eq!(
        response["result"]["protocolVersion"],
        json!(rmcp_latest),
        "server must echo the rmcp LATEST version sent by the harness; \
         got {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_initialized_notification_elicits_no_response() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
        .assert_no_response_within(Duration::from_millis(200))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_list_returns_object_schemas() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("tools/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListToolsResult");

    let tools = result["tools"].as_array().expect("tools must be an array");
    assert!(
        !tools.is_empty(),
        "tools/list must return at least the infrastructure tools"
    );

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"list_accounts"),
        "list_accounts must be advertised; got names {names:?}",
    );
    assert!(
        names.contains(&"use_account"),
        "use_account must be advertised; got names {names:?}",
    );

    // Regression net for fix/tool-input-schema-object-type: every
    // tool advertised on the wire must declare an object inputSchema.
    // Permissive MCP clients tolerate the absence; Zod-based clients
    // reject the tool.
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("<missing-name>");
        let schema = &tool["inputSchema"];
        assert!(
            schema.is_object(),
            "tool {name}: inputSchema must be an object, got {schema}",
        );
        assert_eq!(
            schema["type"],
            json!("object"),
            "tool {name}: inputSchema.type must be \"object\" (issue #263 regression net), got {schema}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_resources_list_is_empty_for_no_accounts() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("resources/list", json!({})).await;
    let result = &response["result"];
    assert_valid(result, "ListResourcesResult");

    let resources = result["resources"]
        .as_array()
        .expect("resources must be an array");
    assert!(
        resources.is_empty(),
        "zero accounts must produce zero resources, got {resources:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_tools_call_unknown_tool_returns_error_envelope() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "this_tool_does_not_exist",
                "arguments": {}
            }),
        )
        .await;

    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    // rmcp 1.5 emits INVALID_PARAMS (-32602) with message "tool not found"
    // for unknown tool names; see rmcp-1.5.0/src/handler/server/router/tool.rs.
    // If this code ever changes, update the assertion and document why
    // — silent drift in rmcp's error mapping is exactly what this test
    // is meant to surface.
    assert_eq!(
        response["error"]["code"],
        json!(-32602),
        "expected -32602 INVALID_PARAMS, got {response}",
    );
    assert!(
        response["error"]["message"].is_string(),
        "error.message must be a string, got {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_unknown_method_returns_minus_32601() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness.request("rimap/no_such_method", json!({})).await;
    assert!(
        response["error"].is_object(),
        "expected error envelope, got {response}",
    );
    assert_eq!(
        response["error"]["code"],
        json!(-32601),
        "JSON-RPC method-not-found code, got {response}",
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "error.message must be non-empty, got {response}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_clean_eof_shutdown_exits_zero() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let (status, _tempdir) = harness.shutdown_and_wait().await;
    assert!(
        status.success(),
        "server must exit 0 on clean stdin EOF, got {status:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::panic,
    reason = "integration test: panic on fixture I/O failure"
)]
async fn wire_published_output_schema_matches_fixture() {
    // The wire `outputSchema` MUST be byte-equal to the per-tool fixture
    // under tests/fixtures/rimap-tool-schemas/. Both are generated from
    // the same Rust types via schemars — drift signals either a
    // regenerate-fixtures miss or a divergence between dump_tool_schemas
    // and tool_catalog::tool_def_parts.
    //
    // Scope: the zero-account harness exercises exactly two tools
    // (`list_accounts`, `use_account`). Full-catalog coverage lives in
    // the dovecot e2e harness gated by RIMAP_REQUIRE_DOCKER.
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let resp = harness.request("tools/list", json!({})).await;
    let tools = resp["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array");

    for tool in tools {
        let name = tool["name"].as_str().expect("tool has name");
        // Strip any `<account>.` prefix — namespaced clones share the
        // bare tool's outputSchema and load the same fixture.
        let bare = name.rsplit_once('.').map_or(name, |(_, b)| b);
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rimap-tool-schemas")
            .join(format!("{bare}.schema.json"));
        let fixture_raw = std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|e| panic!("read fixture {fixture_path:?}: {e}"));
        let fixture_value: serde_json::Value = serde_json::from_str(&fixture_raw)
            .unwrap_or_else(|e| panic!("parse fixture {fixture_path:?}: {e}"));

        let published = &tool["outputSchema"];
        assert!(
            published.is_object(),
            "tool {name} must publish outputSchema; got {published}",
        );
        assert_eq!(
            published, &fixture_value,
            "tool {name} published outputSchema diverges from fixture {fixture_path:?}.\n\
             Run `just regen-tool-schemas` and rerun the test.",
        );
    }
}
