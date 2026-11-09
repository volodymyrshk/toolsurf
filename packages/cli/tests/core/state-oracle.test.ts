import { describe, expect, test } from "bun:test";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  unlinkSync,
  rmSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  diffSnapshots,
  findCanariesInDelta,
  takeSnapshot,
  writeDeltaArtifact,
  type StateDeltaArtifact,
} from "../../src/core/state-oracle.js";

function freshDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "state-oracle-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("state-oracle takeSnapshot", () => {
  test("hashes every regular file and sorts entries by path", () => {
    const { dir, cleanup } = freshDir();
    try {
      writeFileSync(join(dir, "b.txt"), "two");
      writeFileSync(join(dir, "a.txt"), "one");
      mkdirSync(join(dir, "nested"));
      writeFileSync(join(dir, "nested", "c.txt"), "three");

      const snap = takeSnapshot(dir);
      expect(snap.entries.map((e) => e.path)).toEqual([
        "a.txt",
        "b.txt",
        "nested/c.txt",
      ]);
      expect(snap.entries[0].sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(snap.entries.find((e) => e.path === "a.txt")?.size).toBe(3);
    } finally {
      cleanup();
    }
  });

  test("skips ignored directories", () => {
    const { dir, cleanup } = freshDir();
    try {
      writeFileSync(join(dir, "kept.txt"), "x");
      mkdirSync(join(dir, ".git"));
      writeFileSync(join(dir, ".git", "config"), "gitconfig");

      const snap = takeSnapshot(dir);
      expect(snap.entries.map((e) => e.path)).toEqual(["kept.txt"]);
    } finally {
      cleanup();
    }
  });

  test("custom ignore overrides defaults", () => {
    const { dir, cleanup } = freshDir();
    try {
      writeFileSync(join(dir, "a.txt"), "x");
      writeFileSync(join(dir, "b.log"), "y");
      const snap = takeSnapshot(dir, { ignore: [".log"] });
      expect(snap.entries.map((e) => e.path)).toEqual(["a.txt"]);
    } finally {
      cleanup();
    }
  });

  test("throws when root does not exist", () => {
    expect(() => takeSnapshot("/this/path/will/never/exist/abc123")).toThrow(
      /snapshot root does not exist/i,
    );
  });
});

describe("state-oracle diffSnapshots", () => {
  test("detects added, modified, and deleted files", () => {
    const { dir, cleanup } = freshDir();
    try {
      writeFileSync(join(dir, "kept.txt"), "same");
      writeFileSync(join(dir, "will-modify.txt"), "v1");
      writeFileSync(join(dir, "will-delete.txt"), "bye");
      const before = takeSnapshot(dir);

      writeFileSync(join(dir, "will-modify.txt"), "v2");
      unlinkSync(join(dir, "will-delete.txt"));
      writeFileSync(join(dir, "newly-added.txt"), "hello");
      const after = takeSnapshot(dir);

      const delta = diffSnapshots(before, after);
      const byKind = new Map(delta.changes.map((c) => [c.path, c.kind]));
      expect(byKind.get("newly-added.txt")).toBe("added");
      expect(byKind.get("will-modify.txt")).toBe("modified");
      expect(byKind.get("will-delete.txt")).toBe("deleted");
      expect(byKind.has("kept.txt")).toBe(false);
    } finally {
      cleanup();
    }
  });

  test("orders changes added → modified → deleted", () => {
    const { dir, cleanup } = freshDir();
    try {
      writeFileSync(join(dir, "x.txt"), "v1");
      writeFileSync(join(dir, "y.txt"), "delete-me");
      const before = takeSnapshot(dir);

      writeFileSync(join(dir, "x.txt"), "v2");
      unlinkSync(join(dir, "y.txt"));
      writeFileSync(join(dir, "z.txt"), "new");
      const after = takeSnapshot(dir);

      const delta = diffSnapshots(before, after);
      expect(delta.changes.map((c) => c.kind)).toEqual([
        "added",
        "modified",
        "deleted",
      ]);
    } finally {
      cleanup();
    }
  });

  test("rejects diffs with mismatched roots", () => {
    const a = freshDir();
    const b = freshDir();
    try {
      writeFileSync(join(a.dir, "a.txt"), "x");
      writeFileSync(join(b.dir, "b.txt"), "y");
      const sa = takeSnapshot(a.dir);
      const sb = takeSnapshot(b.dir);
      expect(() => diffSnapshots(sa, sb)).toThrow(/different roots/i);
    } finally {
      a.cleanup();
      b.cleanup();
    }
  });

  test("included content preview lets canary search find tokens", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      writeFileSync(join(dir, "owned.txt"), "before TOKEN-CANARY-12 after");
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);
      const change = delta.changes.find((c) => c.path === "owned.txt");
      expect(change).toBeDefined();
      expect("preview" in change! && change!.preview).toContain("TOKEN-CANARY-12");
    } finally {
      cleanup();
    }
  });
});

describe("state-oracle findCanariesInDelta", () => {
  test("matches canaries inside file content", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      writeFileSync(join(dir, "a.txt"), "garbage CHAMBER-FUZZ-001 trailing");
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);

      const hits = findCanariesInDelta(delta, ["CHAMBER-FUZZ-001"]);
      expect(hits.length).toBe(1);
      expect(hits[0].matchedIn).toContain("content");
      expect(hits[0].change.path).toBe("a.txt");
    } finally {
      cleanup();
    }
  });

  test("matches canaries embedded in file path", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      writeFileSync(join(dir, "out-CHAMBER-FUZZ-002.txt"), "");
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);

      const hits = findCanariesInDelta(delta, ["CHAMBER-FUZZ-002"]);
      expect(hits[0].matchedIn).toContain("path");
    } finally {
      cleanup();
    }
  });

  test("returns no hits when no canary appears", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      writeFileSync(join(dir, "neutral.txt"), "no canary here");
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);
      expect(findCanariesInDelta(delta, ["CHAMBER-FUZZ-X"])).toEqual([]);
    } finally {
      cleanup();
    }
  });

  test("empty canary list short-circuits to no hits", () => {
    expect(
      findCanariesInDelta(
        { rootDir: "/x", beforeAt: "", afterAt: "", changes: [] },
        [],
      ),
    ).toEqual([]);
  });

  test("does not match canaries inside oversized file content (preview skipped)", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      // 3 MiB of A's followed by the canary — exceeds default 2 MiB cap.
      const blob = "A".repeat(3 * 1024 * 1024) + "CHAMBER-FUZZ-OVERSIZE";
      writeFileSync(join(dir, "huge.txt"), blob);
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);
      // Canary should not match because preview was skipped for oversized.
      const hits = findCanariesInDelta(delta, ["CHAMBER-FUZZ-OVERSIZE"]);
      expect(hits).toEqual([]);
    } finally {
      cleanup();
    }
  });
});

describe("state-oracle writeDeltaArtifact", () => {
  test("writes a JSON artifact and returns its path", () => {
    const { dir, cleanup } = freshDir();
    try {
      const before = takeSnapshot(dir);
      writeFileSync(join(dir, "x.txt"), "hello");
      const after = takeSnapshot(dir);
      const delta = diffSnapshots(before, after);

      const outDir = join(dir, "_artifacts");
      const path = writeDeltaArtifact(outDir, delta, "oracle-1");
      const artifact = JSON.parse(readFileSync(path, "utf-8")) as StateDeltaArtifact;

      expect(artifact.version).toBe(1);
      expect(artifact.oracleId).toBe("oracle-1");
      expect(artifact.delta.changes.length).toBe(1);
      expect(artifact.delta.changes[0].path).toBe("x.txt");
    } finally {
      cleanup();
    }
  });

  test("sanitizes oracleId so weird characters cannot escape the artifact dir", () => {
    const { dir, cleanup } = freshDir();
    try {
      const snap = takeSnapshot(dir);
      const delta = diffSnapshots(snap, snap);
      const outDir = join(dir, "_artifacts");
      const path = writeDeltaArtifact(outDir, delta, "../../etc/passwd");
      // Sanitized — every non-alnum/_/- char becomes "_", so no path traversal.
      expect(path.endsWith("______etc_passwd.delta.json")).toBe(true);
      expect(path).not.toContain("..");
      expect(path).not.toContain("/etc/passwd");
    } finally {
      cleanup();
    }
  });
});
