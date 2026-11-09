import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { createActiveModules, createAllModules, createPassiveModules, MODULE_CATALOG_VERSION } from "../../src/core/module-catalog.js";

describe("module catalog", () => {
  test("is the single complete list of built-in modules", () => {
    const modules = createAllModules();
    const moduleFiles = readdirSync(join(import.meta.dir, "..", "..", "src", "modules"))
      .filter((file) => file.endsWith(".ts"));

    expect(modules).toHaveLength(moduleFiles.length);
    expect(MODULE_CATALOG_VERSION).toContain("agent-juice-shop");
  });

  test("has unique module ids", () => {
    const ids = createAllModules().map((module) => module.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("keeps passive and active module views consistent", () => {
    const all = createAllModules();
    const passive = createPassiveModules();
    const active = createActiveModules();

    expect(passive.every((module) => module.mode === "passive")).toBe(true);
    expect(active.every((module) => module.mode === "active")).toBe(true);
    expect(passive.length + active.length).toBe(all.length);
  });

  test("includes the newer high-signal modules in public listing", () => {
    const ids = new Set(createAllModules().map((module) => module.id));

    expect(ids.has("semantic-injection")).toBe(true);
    expect(ids.has("context-aware-fuzzer")).toBe(true);
    expect(ids.has("output-injection-detector")).toBe(true);
    expect(ids.has("timing-anomaly")).toBe(true);
    expect(ids.has("session-state-leakage")).toBe(true);
    expect(ids.has("agent-output-trust")).toBe(true);
    expect(ids.has("current-vulnerability-intel")).toBe(true);
  });
});
