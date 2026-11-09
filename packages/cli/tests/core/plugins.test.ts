import { describe, test, expect } from "bun:test";
import { loadPlugins, getPluginDir } from "../../src/core/plugins.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-plugin-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}

function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

describe("Plugin System", () => {
  test("getPluginDir returns ~/.toolsurf/plugins path", () => {
    const dir = getPluginDir();
    expect(dir).toContain(".toolsurf");
    expect(dir).toContain("plugins");
  });

  test("loads valid plugin from explicit path", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "my-plugin.js");
      writeFileSync(
        pluginPath,
        `export default {
          id: "test-plugin",
          name: "Test Plugin",
          description: "A test plugin",
          version: "1.0.0",
          mode: "passive",
          async run(context) { return []; }
        };`
      );

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(1);
      expect(result.modules[0].id).toBe("test-plugin");
      expect(result.modules[0].name).toBe("Test Plugin");
      expect(result.errors.length).toBe(0);
    } finally {
      teardown();
    }
  });

  test("rejects plugin with missing id", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "bad-plugin.js");
      writeFileSync(
        pluginPath,
        `export default {
          name: "Bad Plugin",
          description: "Missing id",
          version: "1.0.0",
          mode: "passive",
          async run() { return []; }
        };`
      );

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("id");
    } finally {
      teardown();
    }
  });

  test("rejects plugin with missing run function", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "no-run.js");
      writeFileSync(
        pluginPath,
        `export default {
          id: "no-run",
          name: "No Run",
          description: "No run function",
          version: "1.0.0",
          mode: "passive",
        };`
      );

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("run");
    } finally {
      teardown();
    }
  });

  test("rejects plugin with reserved built-in ID", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "conflict.js");
      writeFileSync(
        pluginPath,
        `export default {
          id: "tool-permissions",
          name: "Conflict Plugin",
          description: "Tries to override built-in",
          version: "1.0.0",
          mode: "passive",
          async run() { return []; }
        };`
      );

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("conflicts");
    } finally {
      teardown();
    }
  });

  test("reports error for non-existent file", async () => {
    const result = await loadPlugins(["/nonexistent/plugin.js"], false);
    expect(result.modules.length).toBe(0);
    expect(result.errors.length).toBe(1);
    expect(result.errors[0].error).toContain("not found");
  });

  test("reports error for unsupported extension", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "plugin.py");
      writeFileSync(pluginPath, "# python file");

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("extension");
    } finally {
      teardown();
    }
  });

  test("detects duplicate plugin IDs", async () => {
    setup();
    try {
      const p1 = join(TEST_DIR, "plugin1.js");
      const p2 = join(TEST_DIR, "plugin2.js");
      const content = `export default {
        id: "dupe-plugin",
        name: "Dupe Plugin",
        description: "Duplicate",
        version: "1.0.0",
        mode: "passive",
        async run() { return []; }
      };`;
      writeFileSync(p1, content);
      writeFileSync(p2, content);

      const result = await loadPlugins([p1, p2], false);
      expect(result.modules.length).toBe(1);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("Duplicate");
    } finally {
      teardown();
    }
  });

  test("rejects plugin with invalid mode", async () => {
    setup();
    try {
      const pluginPath = join(TEST_DIR, "bad-mode.js");
      writeFileSync(
        pluginPath,
        `export default {
          id: "bad-mode",
          name: "Bad Mode",
          description: "Invalid mode",
          version: "1.0.0",
          mode: "hybrid",
          async run() { return []; }
        };`
      );

      const result = await loadPlugins([pluginPath], false);
      expect(result.modules.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain("mode");
    } finally {
      teardown();
    }
  });

  test("returns empty results with no plugins", async () => {
    const result = await loadPlugins([], false);
    expect(result.modules.length).toBe(0);
    expect(result.errors.length).toBe(0);
  });
});
