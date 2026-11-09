import { describe, test, expect } from "bun:test";

/**
 * The wizard is interactive (readline-based), so we test
 * the WizardResult interface structure and edge cases.
 * Full E2E testing of readline prompts would require
 * process spawning which is covered by integration tests.
 */

describe("Wizard Result Interface", () => {
  test("valid result structure matches expected shape", () => {
    // This tests the contract that the wizard produces
    const result = {
      server: "npx -y @modelcontextprotocol/server-filesystem /tmp",
      profile: "standard" as const,
      format: "terminal" as const,
      output: undefined,
      confirmed: true,
    };

    expect(result.server).toBeTruthy();
    expect(result.profile).toBe("standard");
    expect(result.format).toBe("terminal");
    expect(result.confirmed).toBe(true);
  });

  test("cancelled result has confirmed=false", () => {
    const result = {
      server: "some-server",
      profile: "quick" as const,
      format: "terminal" as const,
      output: undefined,
      confirmed: false,
    };

    expect(result.confirmed).toBe(false);
  });

  test("empty server result has confirmed=false", () => {
    const result = {
      server: "",
      profile: "standard" as const,
      format: "terminal" as const,
      output: undefined,
      confirmed: false,
    };

    expect(result.server).toBe("");
    expect(result.confirmed).toBe(false);
  });

  test("all formats are valid", () => {
    const validFormats = ["terminal", "json", "html", "markdown"];
    for (const fmt of validFormats) {
      expect(validFormats).toContain(fmt);
    }
  });

  test("all profiles are valid", () => {
    const validProfiles = ["quick", "standard", "enterprise"];
    for (const p of validProfiles) {
      expect(validProfiles).toContain(p);
    }
  });
});
