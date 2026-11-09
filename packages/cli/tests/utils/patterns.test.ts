import { describe, test, expect } from "bun:test";
import { URL_PARAM_PATTERNS, INJECTION_PARAM_PATTERNS } from "../../src/utils/patterns";

describe("URL Patterns", () => {
  test("matches url parameter names", () => {
    expect(URL_PARAM_PATTERNS.test("webhookUrl")).toBe(false); // Only matches exact
    expect(URL_PARAM_PATTERNS.test("url")).toBe(true);
    expect(URL_PARAM_PATTERNS.test("endpoint")).toBe(true);
    expect(URL_PARAM_PATTERNS.test("destination")).toBe(true);
  });
});

describe("Injection Patterns", () => {
  test("matches injection parameter names", () => {
    expect(INJECTION_PARAM_PATTERNS.test("query")).toBe(true);
    expect(INJECTION_PARAM_PATTERNS.test("sql")).toBe(true);
    expect(INJECTION_PARAM_PATTERNS.test("command")).toBe(true);
    expect(INJECTION_PARAM_PATTERNS.test("custom_query")).toBe(false);
  });
});
