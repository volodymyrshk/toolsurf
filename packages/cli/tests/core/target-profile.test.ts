import { describe, expect, test } from "bun:test";
import {
  parseTargetProfilePreset,
  presetToTargetProfile,
  getModuleRiskLevel,
} from "../../src/core/target-profile.js";
import { enforceScanMode } from "../../src/core/scan-modes.js";
import type { AuditModule } from "../../src/types/index.js";

function makeModule(id: string, mode: "passive" | "active"): AuditModule {
  return {
    id,
    name: id,
    description: id,
    version: "1.0.0",
    mode,
    async run() {
      return [];
    },
  };
}

describe("target-profile presets", () => {
  test("parses common aliases", () => {
    expect(parseTargetProfilePreset("production")).toBe("production");
    expect(parseTargetProfilePreset("prod")).toBe("production");
    expect(parseTargetProfilePreset("ci")).toBe("ci");
    expect(parseTargetProfilePreset("sandbox")).toBe("ci");
    expect(parseTargetProfilePreset("ide")).toBe("ide");
    expect(parseTargetProfilePreset("local")).toBe("ide");
  });

  test("maps presets to concrete environments", () => {
    const production = presetToTargetProfile("production");
    const ci = presetToTargetProfile("ci");
    const ide = presetToTargetProfile("ide");

    expect(production.environment).toBe("prod-external");
    expect(production.maxScanMode).toBe("safe-active");
    expect(ci.environment).toBe("test-sandbox");
    expect(ci.maxScanMode).toBe("full-active");
    expect(ide.environment).toBe("local-lab");
    expect(ide.maxScanMode).toBe("full-active");
  });
});

describe("scan-mode enforcement with target profiles", () => {
  test("production profile clamps full-active requests", () => {
    const modules = [
      makeModule("tool-permissions", "passive"),
      makeModule("active-fuzzer", "active"),
      makeModule("ssrf-detection", "active"),
    ];

    const result = enforceScanMode(
      modules,
      "full-active",
      presetToTargetProfile("production"),
    );

    expect(result.wasDowngraded).toBe(true);
    expect(result.effectiveMode).toBe("safe-active");
    expect(result.allowedModules.map((m) => m.id)).toEqual(["tool-permissions"]);
    expect(result.filteredModules.map((m) => m.module.id).sort()).toEqual([
      "active-fuzzer",
      "ssrf-detection",
    ]);
  });

  test("ci profile preserves full-active requests", () => {
    const modules = [
      makeModule("tool-permissions", "passive"),
      makeModule("active-fuzzer", "active"),
      makeModule("ssrf-detection", "active"),
    ];

    const result = enforceScanMode(
      modules,
      "full-active",
      presetToTargetProfile("ci"),
    );

    expect(result.wasDowngraded).toBe(false);
    expect(result.effectiveMode).toBe("full-active");
    expect(result.allowedModules.map((m) => m.id).sort()).toEqual([
      "active-fuzzer",
      "ssrf-detection",
      "tool-permissions",
    ]);
    expect(result.filteredModules.length).toBe(0);
  });

  test("unknown active modules default to high risk", () => {
    const modules = [
      makeModule("tool-permissions", "passive"),
      makeModule("new-active-module", "active"),
    ];

    const result = enforceScanMode(modules, "safe-active");

    expect(getModuleRiskLevel("new-active-module")).toBe("high");
    expect(result.allowedModules.map((m) => m.id)).toEqual(["tool-permissions"]);
    expect(result.filteredModules).toHaveLength(1);
    expect(result.filteredModules[0].riskLevel).toBe("high");
  });
});
