import { describe, test, expect } from "bun:test";
import {
  resolveProfile,
  isProfileName,
  PROFILES,
  type ProfileName,
} from "../../src/core/profiles.js";

describe("Scan Profiles", () => {
  describe("isProfileName", () => {
    test("recognizes valid profile names", () => {
      expect(isProfileName("quick")).toBe(true);
      expect(isProfileName("standard")).toBe(true);
      expect(isProfileName("enterprise")).toBe(true);
    });

    test("rejects invalid profile names", () => {
      expect(isProfileName("fast")).toBe(false);
      expect(isProfileName("pro")).toBe(false);
      expect(isProfileName("")).toBe(false);
      expect(isProfileName("QUICK")).toBe(false);
    });
  });

  describe("resolveProfile", () => {
    test("quick profile disables active and all extras", () => {
      const profile = resolveProfile("quick");
      expect(profile.active).toBe(false);
      expect(profile.tui).toBe(false);
      expect(profile.autofix).toBe(false);
      expect(profile.executiveSummary).toBe(false);
      expect(profile.compliance).toBeUndefined();
    });

    test("standard profile enables active only", () => {
      const profile = resolveProfile("standard");
      expect(profile.active).toBe(true);
      expect(profile.tui).toBe(false);
      expect(profile.autofix).toBe(false);
      expect(profile.executiveSummary).toBe(false);
    });

    test("enterprise profile enables everything", () => {
      const profile = resolveProfile("enterprise");
      expect(profile.active).toBe(true);
      expect(profile.tui).toBe(true);
      expect(profile.autofix).toBe(true);
      expect(profile.executiveSummary).toBe(true);
      expect(profile.compliance).toEqual(["all"]);
      expect(profile.minSeverity).toBe("LOW");
    });

    test("throws on invalid profile name", () => {
      expect(() => resolveProfile("invalid")).toThrow(
        'Unknown profile "invalid"'
      );
      expect(() => resolveProfile("")).toThrow('Unknown profile ""');
    });

    test("returns a copy (mutations do not affect original)", () => {
      const a = resolveProfile("enterprise");
      const b = resolveProfile("enterprise");
      a.active = false;
      expect(b.active).toBe(true);
      expect(PROFILES.enterprise.active).toBe(true);
    });
  });
});
