//! Integration test for the `dump-tool-catalog` test-support
//! subcommand (issue #264, Phase 2 Codex follow-up).
//!
//! Verifies the CLI subcommand emits the full `TOOL_DEFS` catalog as
//! line-delimited JSON, with each entry's `inputSchema.type` equal
//! to `"object"`. The Node conformance harness consumes this output
//! to drive every tool's schema through the SDK's Zod Tool validator.

#![expect(clippy::expect_used, reason = "integration tests")]

use assert_cmd::cargo::cargo_bin;
use serde_json::Value;
use std::process::Command;

#[test]
fn dump_tool_catalog_emits_object_schemas() {
    let output = Command::new(cargo_bin("rusty-imap-mcp"))
        .arg("dump-tool-catalog")
        .output()
        .expect("spawn rusty-imap-mcp dump-tool-catalog");
    assert!(
        output.status.success(),
        "dump-tool-catalog must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    // 26 ToolName variants minus 2 sub-capabilities (SearchAdvanced,
    // FetchMessageHtml) that share schemas with their parents = 24 defs.
    assert_eq!(
        lines.len(),
        24,
        "expected 24 tool defs (26 ToolName variants - 2 sub-capabilities); got {}",
        lines.len(),
    );

    for line in lines {
        let value: Value = serde_json::from_str(line).expect("each line is JSON");
        let name = value["name"].as_str().expect("name is string");
        let schema = &value["inputSchema"];
        assert!(
            schema.is_object(),
            "tool {name}: inputSchema must be an object, got {schema}",
        );
        assert_eq!(
            schema["type"],
            Value::String("object".to_string()),
            "tool {name}: inputSchema.type must be \"object\", got {}",
            schema["type"],
        );
    }
}

/// Pins the `lenient_int` schema shape (#292): `search.limit` must publish
/// a `oneOf` with `integer`, `string` (digit pattern), and `null`
/// branches so MCP hosts that pre-validate against the cached
/// `inputSchema` accept both `100` and `"100"`.
#[test]
fn search_limit_publishes_lenient_int_schema() {
    assert_search_field_has_lenient_int_schema("limit");
}

/// Pins the `lenient_int` schema shape (#292) for `search.larger`, added
/// to `SearchInput` by PR #295 alongside other expanded search fields.
#[test]
fn search_larger_publishes_lenient_int_schema() {
    assert_search_field_has_lenient_int_schema("larger");
}

/// Pins the `lenient_int` schema shape (#292) for `search.smaller`, added
/// to `SearchInput` by PR #295 alongside other expanded search fields.
#[test]
fn search_smaller_publishes_lenient_int_schema() {
    assert_search_field_has_lenient_int_schema("smaller");
}

#[expect(clippy::panic, reason = "integration test assertion")]
fn assert_search_field_has_lenient_int_schema(field: &str) {
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
            let prop = &v["inputSchema"]["properties"][field];
            let branches = prop["oneOf"]
                .as_array()
                .unwrap_or_else(|| panic!("search.{field} must publish a oneOf, got {prop}"));
            assert_eq!(branches.len(), 3, "expected 3 branches in {branches:?}");

            let types: Vec<&str> = branches.iter().filter_map(|b| b["type"].as_str()).collect();
            assert!(
                types.contains(&"integer"),
                "missing integer branch: {types:?}"
            );
            assert!(
                types.contains(&"string"),
                "missing string branch: {types:?}"
            );
            assert!(types.contains(&"null"), "missing null branch: {types:?}");

            let string_branch = branches
                .iter()
                .find(|b| b["type"] == "string")
                .expect("string branch present");
            assert_eq!(string_branch["pattern"], "^[0-9]+$");

            found = true;
            break;
        }
    }
    assert!(found, "search tool not present in dump-tool-catalog output");
}
