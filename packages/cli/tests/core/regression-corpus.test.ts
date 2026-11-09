import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { A2aAdapter } from "../../src/adapters/a2a-adapter.js";
import { DangerousCapabilityModule } from "../../src/modules/dangerous-capability.js";
import { DescriptionInjectionDetectorModule } from "../../src/modules/description-injection-detector.js";
import { IpiSusceptibilityModule } from "../../src/modules/ipi-susceptibility.js";
import { RugPullDetectionModule } from "../../src/modules/rug-pull-detection.js";
import type { AuditModule, Finding, ModuleContext, ServerCapabilities } from "../../src/types/index.js";

interface RegressionCorpusCase {
  id: string;
  kind: "serverCapabilities" | "agentCard";
  description: string;
  expectedFindingPrefixes: string[];
  capabilities?: ServerCapabilities;
  agentCard?: Record<string, unknown>;
}

const FIXTURE_DIR = join(import.meta.dir, "..", "fixtures", "regression-corpus");
const TMP_DIR = join(import.meta.dir, ".tmp-regression-corpus");
const REQUIRED_FIXTURES = [
  "paypal-annotation-gap.json",
  "stripe-payment-tools.json",
  "filesystem-tools.json",
  "github-tools.json",
  "browser-agent-tools.json",
  "a2a-agent-card.json",
];

const MODULES: AuditModule[] = [
  new RugPullDetectionModule(),
  new DangerousCapabilityModule(),
  new IpiSusceptibilityModule(),
  new DescriptionInjectionDetectorModule(),
];

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function loadFixture(file: string): RegressionCorpusCase {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, file), "utf-8")) as RegressionCorpusCase;
}

async function capabilitiesForFixture(fixture: RegressionCorpusCase): Promise<ServerCapabilities> {
  if (fixture.kind === "serverCapabilities") {
    if (!fixture.capabilities) throw new Error(`${fixture.id} is missing capabilities`);
    return fixture.capabilities;
  }

  if (!fixture.agentCard) throw new Error(`${fixture.id} is missing agentCard`);
  mkdirSync(TMP_DIR, { recursive: true });
  const specFile = join(TMP_DIR, `${fixture.id}.agent-card.json`);
  writeFileSync(specFile, JSON.stringify(fixture.agentCard), "utf-8");

  const adapter = new A2aAdapter();
  return adapter.connect({ params: { specFile } });
}

async function runCorpusModules(capabilities: ServerCapabilities): Promise<Finding[]> {
  const context: ModuleContext = {
    capabilities,
    activeMode: false,
    verbose: false,
  };
  const findings: Finding[] = [];

  for (const mod of MODULES) {
    const results = await mod.run(context);
    for (const result of results) {
      if (result.finding) findings.push(result.finding);
    }
  }

  return findings;
}

describe("regression corpus", () => {
  test("contains every roadmap fixture family", () => {
    const loaded = REQUIRED_FIXTURES.map(loadFixture);

    expect(loaded.map((fixture) => fixture.id)).toEqual([
      "paypal-style-annotation-gap",
      "stripe-payment-tools",
      "filesystem-tools",
      "github-tools",
      "browser-agent-tools",
      "a2a-agent-card",
    ]);

    for (const fixture of loaded) {
      expect(fixture.description.length).toBeGreaterThan(20);
      expect(fixture.expectedFindingPrefixes.length).toBeGreaterThan(0);
    }
  });

  for (const file of REQUIRED_FIXTURES) {
    test(`${file} triggers its expected detector families`, async () => {
      const fixture = loadFixture(file);
      const capabilities = await capabilitiesForFixture(fixture);
      const findings = await runCorpusModules(capabilities);
      const findingIds = findings.map((finding) => finding.id);

      for (const prefix of fixture.expectedFindingPrefixes) {
        expect(findingIds.some((id) => id.startsWith(prefix))).toBe(true);
      }
    });
  }

  test("A2A Agent Card fixture preserves auth and push-notification metadata", async () => {
    const fixture = loadFixture("a2a-agent-card.json");
    const capabilities = await capabilitiesForFixture(fixture);

    expect(capabilities.protocol).toBe("a2a");
    expect(capabilities.capabilities.pushNotifications).toBe(true);
    expect(capabilities.capabilities.extendedAgentCard).toBe(true);
    expect(capabilities.capabilities.authenticationSchemes).toEqual(["bearerAuth", "serviceApiKey"]);
    expect(capabilities.capabilities.security).toEqual([{ bearerAuth: ["payments:write"] }]);
    expect(capabilities.tools.map((tool) => tool.name)).toEqual([
      "delegate_payment_task",
      "send_push_notification",
      "browse_web",
    ]);
  });
});
