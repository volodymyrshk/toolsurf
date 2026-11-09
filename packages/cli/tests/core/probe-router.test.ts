import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ProbeRouter,
  chamberNetworkSensors,
  makeCanary,
  type ProbeExpectedSensor,
  type ProbeIntent,
  type SsrfCanaryIntent,
  type StateMutationIntent,
  type ToolCaller,
} from "../../src/core/probe-router.js";

function setupChamberCaptures(): {
  rootDir: string;
  http: string;
  metadata: string;
  dns: string;
  cleanup: () => void;
} {
  const rootDir = mkdtempSync(join(tmpdir(), "probe-router-"));
  const captureDir = join(rootDir, "captures");
  mkdirSync(captureDir, { recursive: true });
  const http = join(captureDir, "http.jsonl");
  const metadata = join(captureDir, "metadata.jsonl");
  const dns = join(captureDir, "dns.jsonl");
  writeFileSync(http, "");
  writeFileSync(metadata, "");
  writeFileSync(dns, "");
  return {
    rootDir,
    http,
    metadata,
    dns,
    cleanup: () => rmSync(rootDir, { recursive: true, force: true }),
  };
}

function ssrfIntent(overrides: Partial<SsrfCanaryIntent> = {}): SsrfCanaryIntent {
  return {
    kind: "ssrf-canary",
    canary: overrides.canary ?? "test-canary-001",
    toolName: overrides.toolName ?? "fetch",
    paramName: overrides.paramName ?? "url",
    payload: overrides.payload ?? "http://chamber/path/test-canary-001",
    payloadVariant: overrides.payloadVariant ?? "plain",
    expectedSensors: overrides.expectedSensors ?? [],
  };
}

describe("ProbeRouter — canary enforcement", () => {
  test("rejects intents that bypass type checking with empty canary", async () => {
    const router = new ProbeRouter({ callTool: async () => ({}) });
    // Force an invalid intent through `as any` — the type system would
    // normally prevent this, but we still want the runtime guard to catch it.
    const bad = { ...ssrfIntent(), canary: "" } as unknown as ProbeIntent;
    await expect(router.fire(bad)).rejects.toThrow(/missing or empty canary/i);
  });

  test("rejects intents with non-string canary", async () => {
    const router = new ProbeRouter({ callTool: async () => ({}) });
    const bad = { ...ssrfIntent(), canary: undefined } as unknown as ProbeIntent;
    await expect(router.fire(bad)).rejects.toThrow(/missing or empty canary/i);
  });

  test("rejects canary collisions to keep attribution unambiguous", async () => {
    const router = new ProbeRouter({ callTool: async () => ({}) });
    const intent = ssrfIntent({ canary: "dup-canary" });
    await router.fire(intent);
    await expect(router.fire({ ...intent })).rejects.toThrow(/canary collision/i);
  });
});

describe("ProbeRouter — sensor attribution", () => {
  test("returns hits when an expected sensor capture file grows after firing", async () => {
    const sensors = setupChamberCaptures();
    try {
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];

      // Simulate the target making an outbound HTTP call by appending a row
      // to the chamber capture file as soon as the tool is called.
      const callTool: ToolCaller = async () => {
        appendFileSync(sensors.http, JSON.stringify({ method: "GET", path: "/x" }) + "\n");
        return { ok: true };
      };

      const router = new ProbeRouter({ callTool });
      const outcome = await router.fire(ssrfIntent({ expectedSensors }));

      expect(outcome.fired).toBe(true);
      expect(outcome.hits.length).toBe(1);
      expect(outcome.hits[0].sink).toBe("http");
      expect(outcome.hits[0].beforeCount).toBe(0);
      expect(outcome.hits[0].afterCount).toBe(1);
      expect(outcome.hits[0].delta).toBe(1);
    } finally {
      sensors.cleanup();
    }
  });

  test("returns no hits when sensor counts are unchanged", async () => {
    const sensors = setupChamberCaptures();
    try {
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const router = new ProbeRouter({ callTool: async () => ({}) });
      const outcome = await router.fire(ssrfIntent({ expectedSensors }));
      expect(outcome.hits).toEqual([]);
    } finally {
      sensors.cleanup();
    }
  });

  test("records error and still observes sensor hits when the tool throws after firing", async () => {
    const sensors = setupChamberCaptures();
    try {
      // Tool issues the outbound call THEN throws — the chamber capture is
      // valid evidence even though the tool itself errored.
      const callTool: ToolCaller = async () => {
        appendFileSync(sensors.http, JSON.stringify({ method: "GET" }) + "\n");
        throw new Error("upstream timeout");
      };
      const router = new ProbeRouter({ callTool });
      const outcome = await router.fire(
        ssrfIntent({ expectedSensors: [{ sink: "http", captureFile: sensors.http }] }),
      );
      expect(outcome.fired).toBe(false);
      expect(outcome.error).toMatch(/upstream timeout/);
      expect(outcome.hits[0].delta).toBe(1);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("ProbeRouter — registry", () => {
  test("looks up registered probes by canary", async () => {
    const router = new ProbeRouter({ callTool: async () => ({}) });
    const intent = ssrfIntent({ canary: "lookup-1" });
    await router.fire(intent);
    const found = router.lookupCanary("lookup-1");
    expect(found?.intent.canary).toBe("lookup-1");
    expect(found?.outcome?.fired).toBe(true);
  });

  test("counts registered, fired, and captured probes separately", async () => {
    const sensors = setupChamberCaptures();
    try {
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      let calls = 0;
      const callTool: ToolCaller = async () => {
        calls++;
        if (calls === 2) appendFileSync(sensors.http, "{}\n");
        if (calls === 3) throw new Error("bad");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      await router.fire(ssrfIntent({ canary: "p1", expectedSensors }));
      await router.fire(ssrfIntent({ canary: "p2", expectedSensors }));
      await router.fire(ssrfIntent({ canary: "p3", expectedSensors }));

      expect(router.registeredCount()).toBe(3);
      expect(router.firedCount()).toBe(2); // p3 threw
      expect(router.capturedCount()).toBe(1); // only p2 produced a hit
    } finally {
      sensors.cleanup();
    }
  });
});

describe("ProbeRouter — args dispatch", () => {
  test("ssrf-canary intent calls the tool with { [paramName]: payload }", async () => {
    const seen: Array<{ name: string; args: Record<string, unknown> }> = [];
    const callTool: ToolCaller = async (name, args) => {
      seen.push({ name, args });
      return {};
    };
    const router = new ProbeRouter({ callTool });
    await router.fire(
      ssrfIntent({ toolName: "fetch", paramName: "url", payload: "http://chamber/x" }),
    );
    expect(seen).toEqual([{ name: "fetch", args: { url: "http://chamber/x" } }]);
  });

  test("state-mutation intent passes args verbatim", async () => {
    const seen: Array<{ name: string; args: Record<string, unknown> }> = [];
    const callTool: ToolCaller = async (name, args) => {
      seen.push({ name, args });
      return {};
    };
    const router = new ProbeRouter({ callTool });
    const intent: StateMutationIntent = {
      kind: "state-mutation",
      canary: "state-1",
      toolName: "write_file",
      args: { path: "/tmp/test", content: "state-1" },
      expectedSensors: [],
    };
    await router.fire(intent);
    expect(seen).toEqual([
      { name: "write_file", args: { path: "/tmp/test", content: "state-1" } },
    ]);
  });
});

describe("ProbeRouter — tracing", () => {
  test("emits register, fire-start, fire-end events in order", async () => {
    const events: string[] = [];
    const router = new ProbeRouter({
      callTool: async () => ({}),
      onTrace: (e) => events.push(e.kind),
    });
    await router.fire(ssrfIntent());
    expect(events).toEqual(["register", "fire-start", "fire-end"]);
  });
});

describe("chamberNetworkSensors helper", () => {
  test("filters out missing capture files", () => {
    const sensors = chamberNetworkSensors({
      captures: { http: "/h.jsonl", dns: "/d.jsonl" }, // metadata + smtp absent
    });
    expect(sensors.map((s) => s.sink).sort()).toEqual(["dns", "http"]);
  });

  test("returns empty array when no captures are configured", () => {
    expect(chamberNetworkSensors({})).toEqual([]);
    expect(chamberNetworkSensors({ captures: {} })).toEqual([]);
  });
});

describe("makeCanary helper", () => {
  test("composes prefix, base36 counter, and random hex into a canary string", () => {
    expect(makeCanary("chamber-fuzz", 0, "abcd1234")).toBe("chamber-fuzz-0-abcd1234");
    expect(makeCanary("chamber-fuzz", 35, "abcd1234")).toBe("chamber-fuzz-z-abcd1234");
    expect(makeCanary("ipi", 36, "deadbeef")).toBe("ipi-10-deadbeef");
  });
});
