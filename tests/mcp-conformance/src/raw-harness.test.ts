import { afterEach, describe, expect, it } from "vitest";
import {
  assertEnvelopeValid,
  spawnRaw,
  type JsonRpcResponse,
  type RawHandles,
} from "./raw-harness.js";

describe("assertEnvelopeValid", () => {
  it("accepts a well-formed result envelope", () => {
    const ok: JsonRpcResponse = {
      jsonrpc: "2.0",
      id: 1,
      result: { foo: "bar" },
    };
    expect(() => {
      assertEnvelopeValid(ok, 1);
    }).not.toThrow();
  });

  it("accepts a well-formed error envelope", () => {
    const err: JsonRpcResponse = {
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32601, message: "method not found" },
    };
    expect(() => {
      assertEnvelopeValid(err, 1);
    }).not.toThrow();
  });

  it("rejects a missing jsonrpc field", () => {
    const bad = { id: 1, result: {} } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/jsonrpc/);
  });

  it("rejects a wrong jsonrpc value", () => {
    const bad = { jsonrpc: "1.0", id: 1, result: {} } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/jsonrpc/);
  });

  it("rejects mismatched id", () => {
    const bad: JsonRpcResponse = { jsonrpc: "2.0", id: 99, result: {} };
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/id/);
  });

  it("rejects an envelope with both result and error", () => {
    const bad = {
      jsonrpc: "2.0",
      id: 1,
      result: {},
      error: { code: -1, message: "x" },
    } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/exactly one/);
  });

  it("rejects an envelope with neither result nor error", () => {
    const bad = { jsonrpc: "2.0", id: 1 } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/exactly one/);
  });

  it("rejects an error envelope with non-numeric code", () => {
    const bad = {
      jsonrpc: "2.0",
      id: 1,
      error: { code: "not-a-number", message: "x" },
    } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/error\.code/);
  });

  it("rejects an error envelope with missing message", () => {
    const bad = {
      jsonrpc: "2.0",
      id: 1,
      error: { code: -1 },
    } as unknown as JsonRpcResponse;
    expect(() => {
      assertEnvelopeValid(bad, 1);
    }).toThrow(/error\.message/);
  });
});

describe("raw-harness (live)", () => {
  let harness: RawHandles | undefined;

  afterEach(async () => {
    if (harness) {
      try {
        await harness.close();
      } finally {
        harness = undefined;
      }
    }
  });

  it("performs an initialize handshake and returns a parseable JSON-RPC response", async () => {
    harness = await spawnRaw();
    const response = await harness.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "raw-harness-self-test", version: "0.0.0" },
    });
    expect(response.jsonrpc).toBe("2.0");
    expect(response.id).toBe(1);
    expect(response.result).toBeDefined();
    expect(response.result?.["protocolVersion"]).toBe("2025-11-25");
  });

  it("reports no stdout response within a window after a notification", async () => {
    harness = await spawnRaw();
    await harness.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "raw-harness-self-test", version: "0.0.0" },
    });
    await harness.notify("notifications/initialized", {});
    await expect(harness.assertNoResponseWithin(200)).resolves.toBeUndefined();
  });

  it("tools/list honors cursor pagination and rejects a garbage cursor (#411)", async () => {
    harness = await spawnRaw();
    await harness.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "raw-harness-self-test", version: "0.0.0" },
    });
    await harness.notify("notifications/initialized", {});

    // No cursor: the zero-account catalog (infrastructure tools only) fits in
    // one page, so nextCursor is absent — no behavior change for small
    // catalogs.
    const first = await harness.request("tools/list", {});
    expect(first.error, JSON.stringify(first.error)).toBeUndefined();
    const tools = first.result?.["tools"] as unknown[];
    expect(Array.isArray(tools)).toBe(true);
    expect(tools.length).toBeGreaterThanOrEqual(2);
    expect(first.result?.["nextCursor"]).toBeUndefined();

    // A valid offset cursor ("0") returns the same first page.
    const zero = await harness.request("tools/list", { cursor: "0" });
    expect(zero.error).toBeUndefined();
    expect((zero.result?.["tools"] as unknown[]).length).toBe(tools.length);

    // A non-numeric cursor is a client error (JSON-RPC invalid params).
    const bad = await harness.request("tools/list", { cursor: "not-a-number" });
    expect(bad.result).toBeUndefined();
    expect(bad.error?.code).toBe(-32602);
  });
});
