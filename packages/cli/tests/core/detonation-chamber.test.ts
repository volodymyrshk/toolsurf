import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { createChamberRun, loadChamberManifest } from "../../src/core/detonation-chamber.js";

const TMP_DIR = join(import.meta.dir, "../.tmp-detonation-chamber");

describe("detonation chamber", () => {
  beforeEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  afterEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  test("generates compose, capture services, and a manifest", () => {
    const manifest = createChamberRun({
      name: "Vendor Target",
      outputDir: TMP_DIR,
      runId: "test-run",
      createdAt: "2026-05-01T00:00:00.000Z",
      target: {
        image: "example/target:1.0.0",
        command: "npm start",
        ports: ["127.0.0.1:3100:3100"],
      },
    });

    expect(manifest.name).toBe("vendor-target");
    expect(existsSync(manifest.composeFile)).toBe(true);
    expect(existsSync(join(manifest.runDir, "services", "fake-http.py"))).toBe(true);
    expect(existsSync(join(manifest.runDir, "services", "fake-smtp.py"))).toBe(true);
    expect(existsSync(join(manifest.runDir, "services", "fake-dns.py"))).toBe(true);
    expect(existsSync(join(manifest.runDir, "chamber.manifest.json"))).toBe(true);

    const compose = readFileSync(manifest.composeFile, "utf-8");
    const parsedCompose = parse(compose);
    expect(compose).toContain("internal: true");
    expect(compose).toContain("fake-metadata");
    expect(compose).toContain("172.30.0.53");
    expect(parsedCompose.services["fake-http"].volumes).toContain("./services:/services:ro");
    expect(parsedCompose.services["fake-http"].volumes).toContain("./captures:/captures");
    expect(compose).toContain("\"127.0.0.1:3100:3100\"");
    expect(compose).toContain("no-new-privileges:true");

    const loaded = loadChamberManifest(manifest.runDir);
    expect(loaded.services.fakeHttp.url).toBe("http://172.30.0.10:8080");
    expect(loaded.target?.image).toBe("example/target:1.0.0");
  });
});
