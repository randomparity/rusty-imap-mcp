import { LATEST_PROTOCOL_VERSION, ToolSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";

import { dumpToolCatalog } from "./catalog-dump-harness.js";
import { spawnRaw, type RawHandles } from "./raw-harness.js";
import { spawnSdk, type SdkHandles } from "./sdk-harness.js";

const PINNED_PROTOCOL_VERSION = "2025-11-25";

describe("wire conformance (SDK harness)", () => {
  let harness: SdkHandles | undefined;

  afterEach(async () => {
    if (harness) {
      try {
        await harness.close();
      } finally {
        harness = undefined;
      }
    }
  });

  it("wire_smoke_initialize_returns_valid_envelope (SDK)", async () => {
    // Phase 1 parity: a successful connect() validates InitializeResult
    // through the SDK's Zod schema. If serverInfo or capabilities
    // were malformed, Zod would throw inside connect().
    harness = await spawnSdk();
    const info = harness.client.getServerVersion();
    expect(info?.name).toBeDefined();
    expect(info?.version).toBeDefined();
  });

  it("wire_initialize_advertises_tools_capability (SDK) — regression net for #261", async () => {
    harness = await spawnSdk();
    const caps = harness.client.getServerCapabilities();
    expect(caps, "capabilities must be present after initialize").toBeDefined();
    expect(
      caps?.tools,
      "capabilities.tools must be advertised — regression net for #261",
    ).toBeDefined();
  });

  it("wire_tools_list_returns_object_schemas (SDK) — regression net for fix/tool-input-schema-object-type", async () => {
    harness = await spawnSdk();
    const result = await harness.client.listTools();

    // Zod will have thrown inside listTools() if any tool's
    // inputSchema fails the SDK's Tool definition. Explicit asserts
    // below are belt-and-suspenders for if Zod ever relaxes.
    expect(
      result.tools.length,
      "tools/list must return at least the infrastructure tools",
    ).toBeGreaterThan(0);

    const names = result.tools.map((t) => t.name);
    expect(names, "list_accounts must be advertised").toContain("list_accounts");
    expect(names, "use_account must be advertised").toContain("use_account");

    for (const tool of result.tools) {
      const schema = tool.inputSchema as Record<string, unknown> | undefined;
      expect(schema, `tool ${tool.name}: inputSchema must be an object`).toBeDefined();
      expect(
        schema?.["type"],
        `tool ${tool.name}: inputSchema.type must be "object" (regression net)`,
      ).toBe("object");
    }
  });

  it("wire_resources_list_has_only_static_docs_for_no_accounts (SDK)", async () => {
    // The rimap://docs/... resources describe server semantics, not
    // account state, so they are advertised even with zero accounts
    // configured (#407). Only the per-account resources are absent.
    harness = await spawnSdk();
    const result = await harness.client.listResources();
    const uris = result.resources.map((r) => r.uri);
    expect(uris, "zero accounts must produce only the static doc resources").toEqual([
      "rimap://docs/postures",
      "rimap://docs/workflows",
    ]);
  });

  it("wire_tools_call_unknown_tool_returns_error_envelope (SDK)", async () => {
    harness = await spawnSdk();
    try {
      await harness.client.callTool({
        name: "this_tool_does_not_exist",
        arguments: {},
      });
      throw new Error("expected callTool to throw");
    } catch (err) {
      // rmcp 1.5 maps unknown tool names to INVALID_PARAMS (-32602)
      // with message "tool not found"; see Phase 1's
      // wire_tools_call_unknown_tool_returns_error_envelope test.
      // The SDK throws an McpError whose .code field is the JSON-RPC
      // error code.
      const error = err as { code?: number; message?: string };
      expect(error.code, "expected JSON-RPC error code -32602").toBe(-32602);
      expect(typeof error.message, "error.message must be a string").toBe("string");
    }
  });
});

describe("wire conformance (raw harness)", () => {
  let raw: RawHandles | undefined;

  afterEach(async () => {
    if (raw) {
      try {
        await raw.close();
      } finally {
        raw = undefined;
      }
    }
  });

  it("wire_protocol_version_negotiation_matches_vendored_schema (Raw)", async () => {
    // Four-way drift check (extends Phase 1's three-way):
    //   1. SDK's LATEST_PROTOCOL_VERSION constant
    //   2. PINNED_PROTOCOL_VERSION literal pinned in this test file
    //   3. negotiated value returned by the server on the wire
    //   4. Phase 1's PINNED_PROTOCOL_VERSION + fixture dir + rmcp::ProtocolVersion::LATEST
    // The wire read is direct — no optional/escape-hatch path. If the
    // server fails to echo the version, the test fails hard.
    expect(
      LATEST_PROTOCOL_VERSION,
      "SDK's LATEST drifted from this test's pinned literal — refresh both",
    ).toBe(PINNED_PROTOCOL_VERSION);

    raw = await spawnRaw();
    const response = await raw.request("initialize", {
      protocolVersion: PINNED_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "raw-self", version: "0.0.0" },
    });
    expect(response.result, "initialize must produce a result envelope").toBeDefined();
    const negotiated = response.result?.["protocolVersion"];
    expect(typeof negotiated, "result.protocolVersion must be a string on the wire").toBe("string");
    expect(negotiated, "server must echo the pinned protocol version on the wire").toBe(
      PINNED_PROTOCOL_VERSION,
    );
  });

  it("wire_initialized_notification_elicits_no_response (Raw)", async () => {
    raw = await spawnRaw();
    await raw.request("initialize", {
      protocolVersion: PINNED_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "raw-self", version: "0.0.0" },
    });
    await raw.notify("notifications/initialized", {});
    await raw.assertNoResponseWithin(200);
  });

  it("wire_unknown_method_returns_minus_32601 (Raw)", async () => {
    raw = await spawnRaw();
    await raw.request("initialize", {
      protocolVersion: PINNED_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "raw-self", version: "0.0.0" },
    });
    await raw.notify("notifications/initialized", {});

    // The raw harness now validates the full envelope inside
    // request() (jsonrpc==2.0, matching id, exactly-one-of, error
    // structural shape). The test below adds the JSON-RPC-specific
    // semantic check (the code value).
    const response = await raw.request("rimap/no_such_method", {});
    expect(response.error, "expected error envelope").toBeDefined();
    expect(response.error?.code, "JSON-RPC method-not-found code").toBe(-32601);
    expect(response.error?.message.length, "error.message must be non-empty").toBeGreaterThan(0);
  });

  it("wire_clean_eof_shutdown_exits_zero (Raw)", async () => {
    raw = await spawnRaw();
    await raw.request("initialize", {
      protocolVersion: PINNED_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "raw-self", version: "0.0.0" },
    });
    await raw.notify("notifications/initialized", {});
    const code = await raw.shutdownAndWait();
    expect(code, "server must exit 0 on clean stdin EOF").toBe(0);
    // shutdownAndWait already consumed the child; suppress afterEach.
    raw = undefined;
  });
});

describe("wire conformance (CLI catalog dump)", () => {
  it("wire_all_advertised_tools_pass_sdk_schema (CLI dump) — regression net for issue #264 strict-client gap", async () => {
    // The SDK harness only sees infrastructure tools when the server
    // is spawned with accounts=[]. This test invokes the test-support
    // `dump-tool-catalog` subcommand on the binary directly and
    // validates every TOOL_DEFS entry against the SDK's Zod Tool
    // schema. Catches malformed account-scoped tool schemas that the
    // wire-path SDK tests cannot reach without a live IMAP server.
    const entries = await dumpToolCatalog();
    expect(
      entries.length,
      "dump must contain 24 tool defs (27 ToolName variants - 3 sub-capabilities)",
    ).toBe(24);

    for (const entry of entries) {
      const result = ToolSchema.safeParse(entry);
      if (!result.success) {
        const name = (entry as { name?: string })?.name ?? "<unknown>";
        throw new Error(`SDK ToolSchema rejected tool ${name}: ${result.error.message}`);
      }
    }
  });
});
