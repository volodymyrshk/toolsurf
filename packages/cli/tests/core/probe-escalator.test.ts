import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ProbeRouter,
  type ProbeExpectedSensor,
  type SsrfCanaryIntent,
  type ToolCaller,
} from "../../src/core/probe-router.js";
import {
  runEscalationCampaign,
  ssrfEscalationSteps,
  commandInjectionEscalationSteps,
  ipiAdversarialFixtureSteps,
  type EscalationContext,
  type EscalationStep,
  type EscalationTraceEvent,
} from "../../src/core/probe-escalator.js";

function setupChamber(): {
  rootDir: string;
  http: string;
  cleanup: () => void;
} {
  const rootDir = mkdtempSync(join(tmpdir(), "probe-escalator-"));
  const captureDir = join(rootDir, "captures");
  mkdirSync(captureDir, { recursive: true });
  const http = join(captureDir, "http.jsonl");
  writeFileSync(http, "");
  return {
    rootDir,
    http,
    cleanup: () => rmSync(rootDir, { recursive: true, force: true }),
  };
}

function defaultContext(): EscalationContext {
  return {
    fakeHttpUrl: "http://172.30.0.10:8080",
    fakeMetadataUrl: "http://172.30.0.12",
    toolName: "fetch",
    paramName: "url",
    intentKind: "ssrf-canary",
  };
}

function fakeStep(label: string): EscalationStep {
  return {
    variant: label,
    expectedSinks: ["http"],
    buildPayload: (_ctx, canary) => `http://172.30.0.10:8080/${label}/${canary}`,
  };
}

function mintCounter(): () => string {
  let n = 0;
  return () => `escalate-${(n++).toString(36)}`;
}

describe("runEscalationCampaign — short-circuit on miss", () => {
  test("does nothing when seed produced zero hits (Constraint 3)", async () => {
    const sensors = setupChamber();
    try {
      const router = new ProbeRouter({ callTool: async () => ({}) });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];

      const seedIntent: SsrfCanaryIntent = {
        kind: "ssrf-canary",
        canary: "seed-cold",
        toolName: "fetch",
        paramName: "url",
        payload: "http://172.30.0.10:8080/seed-cold",
        payloadVariant: "plain",
        expectedSensors,
      };
      const seed = await router.fire(seedIntent);
      expect(seed.hits).toEqual([]);

      const events: EscalationTraceEvent["kind"][] = [];
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b")],
        mintCanary: mintCounter(),
        onTrace: (e) => events.push(e.kind),
      });

      expect(result.seedHit).toBe(false);
      expect(result.steps).toEqual([]);
      expect(events).toEqual(["seed-miss-shortcircuit"]);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("runEscalationCampaign — stateful context", () => {
  test("reuses tool/param from context, never fans out (Constraint 2)", async () => {
    const sensors = setupChamber();
    try {
      const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
      const callTool: ToolCaller = async (name, args) => {
        calls.push({ name, args });
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];

      const seedIntent: SsrfCanaryIntent = {
        kind: "ssrf-canary",
        canary: "seed-hit",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/seed-hit",
        payloadVariant: "plain",
        expectedSensors,
      };
      const seed = await router.fire(seedIntent);
      expect(seed.hits.length).toBeGreaterThan(0);

      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("imds"), fakeStep("ssh"), fakeStep("rebind")],
        mintCanary: mintCounter(),
      });

      // 1 seed + 3 escalations; every call must target fetch.url
      expect(calls.length).toBe(4);
      for (const c of calls) {
        expect(c.name).toBe("fetch");
        expect(Object.keys(c.args)).toEqual(["url"]);
      }
      expect(result.steps.length).toBe(3);
      expect(result.steps.every((s) => s.outcome.intent.toolName === "fetch")).toBe(true);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("runEscalationCampaign — budget enforcement", () => {
  test("stops mid-campaign when wall-clock exceeds budgetMs (Constraint 1)", async () => {
    const sensors = setupChamber();
    try {
      // Each call sleeps 80ms — with budget 200ms we should fit ~2 steps.
      const callTool: ToolCaller = async () => {
        await new Promise((r) => setTimeout(r, 80));
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];

      const seedIntent: SsrfCanaryIntent = {
        kind: "ssrf-canary",
        canary: "seed-budget",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/seed-budget",
        payloadVariant: "plain",
        expectedSensors,
      };
      const seed = await router.fire(seedIntent);

      const events: EscalationTraceEvent[] = [];
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [
          fakeStep("a"),
          fakeStep("b"),
          fakeStep("c"),
          fakeStep("d"),
          fakeStep("e"),
        ],
        mintCanary: mintCounter(),
        budgetMs: 200,
        onTrace: (e) => events.push(e),
      });

      expect(result.budgetExhausted).toBe(true);
      expect(result.steps.length).toBeLessThan(5);
      expect(events.some((e) => e.kind === "budget-exhausted")).toBe(true);
    } finally {
      sensors.cleanup();
    }
  });

  test("default budget is 2000ms when not specified", async () => {
    const sensors = setupChamber();
    try {
      const callTool: ToolCaller = async () => {
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-budget-default",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a")],
        mintCanary: mintCounter(),
      });
      expect(result.budgetExhausted).toBe(false);
      expect(result.steps.length).toBe(1);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("runEscalationCampaign — abort signal", () => {
  test("stops when AbortSignal fires mid-campaign", async () => {
    const sensors = setupChamber();
    try {
      const callTool: ToolCaller = async () => {
        await new Promise((r) => setTimeout(r, 50));
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-abort",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });

      const controller = new AbortController();
      // Abort during the campaign — the loop checks signal at the top of
      // each iteration, so we need at least one step to happen before abort.
      setTimeout(() => controller.abort(), 75);

      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b"), fakeStep("c"), fakeStep("d")],
        mintCanary: mintCounter(),
        signal: controller.signal,
      });

      expect(result.aborted).toBe(true);
      expect(result.steps.length).toBeLessThan(4);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("runEscalationCampaign — canary uniqueness", () => {
  test("each step receives a fresh canary from the minter", async () => {
    const sensors = setupChamber();
    try {
      const callTool: ToolCaller = async () => {
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-canary",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b"), fakeStep("c")],
        mintCanary: mintCounter(),
      });

      const canaries = result.steps.map((s) => s.outcome.intent.canary);
      expect(new Set(canaries).size).toBe(canaries.length); // all unique
    } finally {
      sensors.cleanup();
    }
  });
});

describe("predefined escalation trees", () => {
  test("ssrfEscalationSteps covers IMDS, internal-port-scan, parser-strictness", () => {
    const steps = ssrfEscalationSteps();
    const variants = steps.map((s) => s.variant);
    expect(variants).toContain("imds-aws");
    expect(variants).toContain("imds-aws-v2-token");
    expect(variants).toContain("imds-gcp");
    expect(variants).toContain("imds-azure");
    expect(variants).toContain("internal-port-scan-localhost-ssh");
    expect(variants).toContain("internal-port-scan-localhost-redis");
    expect(variants).toContain("internal-port-scan-rfc1918");
    expect(variants).toContain("dns-rebind");
    expect(variants).toContain("userinfo-confusion");
    expect(variants).toContain("decimal-ip");
    expect(variants).toContain("file-scheme");
  });

  test("ssrf payload builders embed the canary verbatim", () => {
    const ctx = defaultContext();
    for (const step of ssrfEscalationSteps()) {
      const payload = step.buildPayload(ctx, "ABCDEF1234");
      expect(payload).toContain("ABCDEF1234");
    }
  });

  test("commandInjectionEscalationSteps covers shell injection variants", () => {
    const steps = commandInjectionEscalationSteps();
    expect(steps.length).toBeGreaterThan(0);
    for (const step of steps) {
      const payload = step.buildPayload(defaultContext(), "CMDX99");
      expect(payload).toContain("CMDX99");
    }
  });

  test("decimal-ip variant produces a 32-bit integer host", () => {
    const step = ssrfEscalationSteps().find((s) => s.variant === "decimal-ip")!;
    const payload = step.buildPayload(defaultContext(), "Z");
    // 172.30.0.10 → 2887647242
    expect(payload).toContain("2887647242");
  });
});

describe("budget mode override", () => {
  test("network mode uses 2000ms default when no budgetMs given", async () => {
    const sensors = setupChamber();
    try {
      // Each call sleeps 80ms — 5 steps = 400ms, well under 2000ms.
      const callTool: ToolCaller = async () => {
        await new Promise((r) => setTimeout(r, 80));
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-net",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b"), fakeStep("c"), fakeStep("d"), fakeStep("e")],
        mintCanary: mintCounter(),
        mode: "network",
      });
      expect(result.budgetExhausted).toBe(false);
      expect(result.steps.length).toBe(5);
    } finally {
      sensors.cleanup();
    }
  });

  test("cognitive mode allows long step durations under default 30000ms", async () => {
    const sensors = setupChamber();
    try {
      // Each step takes 600ms — 3 steps = 1800ms. With network default
      // (2000ms) this would just barely fit; we set explicit cognitive
      // mode and shorter manual budget to confirm the mode default applies
      // when budgetMs is omitted.
      const callTool: ToolCaller = async () => {
        await new Promise((r) => setTimeout(r, 600));
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-cog",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });
      // Don't pass budgetMs — let the cognitive default (30000ms) apply.
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b"), fakeStep("c")],
        mintCanary: mintCounter(),
        mode: "cognitive",
      });
      expect(result.budgetExhausted).toBe(false);
      expect(result.steps.length).toBe(3);
      expect(result.durationMs).toBeGreaterThan(1500);
    } finally {
      sensors.cleanup();
    }
  });

  test("explicit budgetMs always wins over mode default", async () => {
    const sensors = setupChamber();
    try {
      const callTool: ToolCaller = async () => {
        await new Promise((r) => setTimeout(r, 80));
        appendFileSync(sensors.http, "{}\n");
        return {};
      };
      const router = new ProbeRouter({ callTool });
      const expectedSensors: ProbeExpectedSensor[] = [
        { sink: "http", captureFile: sensors.http },
      ];
      const seed = await router.fire({
        kind: "ssrf-canary",
        canary: "seed-explicit",
        toolName: "fetch",
        paramName: "url",
        payload: "http://chamber/x",
        payloadVariant: "plain",
        expectedSensors,
      });
      // Cognitive mode would default to 30000ms, but we explicitly cap to
      // 150ms — only ~1 step should fit before exhaustion.
      const result = await runEscalationCampaign(seed, {
        router,
        expectedSensors,
        context: defaultContext(),
        steps: [fakeStep("a"), fakeStep("b"), fakeStep("c"), fakeStep("d")],
        mintCanary: mintCounter(),
        mode: "cognitive",
        budgetMs: 150,
      });
      expect(result.budgetExhausted).toBe(true);
      expect(result.steps.length).toBeLessThan(4);
    } finally {
      sensors.cleanup();
    }
  });
});

describe("IPI adversarial-fixture escalation tree", () => {
  test("provides the full second-order IPI vector set", () => {
    const variants = ipiAdversarialFixtureSteps().map((s) => s.variant);
    expect(variants).toContain("ipi-followup-fetch-self");
    expect(variants).toContain("ipi-followup-imds");
    expect(variants).toContain("ipi-followup-internal-port");
    expect(variants).toContain("ipi-followup-smtp-exfil");
    expect(variants).toContain("ipi-followup-dns-rebind");
  });

  test("every IPI step embeds the canary in its payload", () => {
    for (const step of ipiAdversarialFixtureSteps()) {
      const payload = step.buildPayload(defaultContext(), "IPI-9999");
      expect(payload).toContain("IPI-9999");
    }
  });

  test("smtp-exfil step uses mailto scheme with canary in subject and body", () => {
    const step = ipiAdversarialFixtureSteps().find(
      (s) => s.variant === "ipi-followup-smtp-exfil",
    )!;
    const payload = step.buildPayload(defaultContext(), "X42");
    expect(payload).toMatch(/^mailto:/);
    expect(payload).toContain("X42");
  });

  test("imds follow-up targets the AWS metadata IP", () => {
    const step = ipiAdversarialFixtureSteps().find(
      (s) => s.variant === "ipi-followup-imds",
    )!;
    const payload = step.buildPayload(defaultContext(), "Y");
    expect(payload).toContain("169.254.169.254");
  });
});
