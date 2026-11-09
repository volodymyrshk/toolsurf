import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";

/**
 * State oracle (Item 5 of the kill-chain architecture upgrade).
 *
 * Pure-logic primitive: walks a workdir, hashes every file, and produces
 * canary-aware before/after diffs. No chamber wiring lives here; the audit
 * module that uses this primitive owns the integration with ProbeRouter.
 *
 * Why: chamber sensors today only prove *network* side effects. Filesystem-,
 * git-, and notebook-MCPs don't necessarily phone home, but they DO mutate
 * disk state — that's the proof class state-oracle is designed to capture.
 *
 * The kill-chain assembler in `kill-chain.ts` already understands the proof
 * contract this module emits:
 *   - finding.id starting with `CHAMBER-FS` → `filesystem-diff` artifact
 *   - finding.id starting with `CHAMBER-STATE` → `state-diff` artifact
 *   - finding.evidence.fsDiffFile / stateDiffFile → path to the diff JSON
 * The state-oracle returns artifacts shaped exactly to feed those evidence
 * fields when callers persist them.
 */

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

export interface StateSnapshotEntry {
  /** Path relative to the snapshot root. Forward slashes. */
  path: string;
  size: number;
  /** SHA-256 hex hash of the file contents at snapshot time. */
  sha256: string;
  /** Last-modified time (ms since epoch) — informational only; never used for equality. */
  mtimeMs: number;
}

export interface StateSnapshot {
  rootDir: string;
  takenAt: string;
  entries: StateSnapshotEntry[];
}

export type StateDeltaChange =
  | {
      kind: "added";
      path: string;
      size: number;
      sha256: string;
      preview?: string;
    }
  | {
      kind: "modified";
      path: string;
      sizeBefore: number;
      sizeAfter: number;
      sha256Before: string;
      sha256After: string;
      preview?: string;
    }
  | {
      kind: "deleted";
      path: string;
      sha256: string;
    };

export interface StateDelta {
  rootDir: string;
  beforeAt: string;
  afterAt: string;
  changes: StateDeltaChange[];
}

export interface CanaryHit {
  canary: string;
  /** The change in which the canary appeared. */
  change: StateDeltaChange;
  /** Where in the change it landed: file content, file path, or both. */
  matchedIn: Array<"path" | "content">;
}

export interface SnapshotOptions {
  /**
   * Glob-ish path patterns to skip during the walk. Matched against the
   * path *relative to root*, with forward slashes. Substring match — keep
   * it simple; this is meant for things like `.git`, `node_modules`,
   * `.DS_Store`. Default: a small built-in list (see `DEFAULT_IGNORES`).
   */
  ignore?: string[];
  /**
   * Files larger than this many bytes are still hashed (so we know they
   * changed) but their content is NOT loaded into the canary search. This
   * keeps the oracle bounded against an MCP that tries to confuse it with
   * gigabyte writes. Default: 2 MiB.
   */
  maxContentBytesForCanary?: number;
}

export const DEFAULT_IGNORES = [".git/", "node_modules/", ".DS_Store"];

const DEFAULT_MAX_CONTENT_BYTES = 2 * 1024 * 1024;

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * Walk `rootDir` and produce a deterministic snapshot. Entries are sorted by
 * path so two snapshots over the same tree produce byte-identical JSON when
 * serialized — useful for replay-checking and for the test suite.
 *
 * Symlinks are followed only one level (we read the target's stat); if the
 * link points to a directory we descend into that directory. We never escape
 * the original root via `..`.
 *
 * Throws if `rootDir` does not exist — callers should usually
 * `mkdirSync(rootDir, { recursive: true })` first.
 */
export function takeSnapshot(rootDir: string, options: SnapshotOptions = {}): StateSnapshot {
  if (!existsSync(rootDir)) {
    throw new Error(`State oracle: snapshot root does not exist: ${rootDir}`);
  }
  const absRoot = resolve(rootDir);
  const ignore = options.ignore ?? DEFAULT_IGNORES;
  const entries: StateSnapshotEntry[] = [];

  walk(absRoot, absRoot, ignore, entries);

  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return {
    rootDir: absRoot,
    takenAt: new Date().toISOString(),
    entries,
  };
}

/**
 * Diff two snapshots and return the per-file changes. Snapshots must share
 * the same `rootDir` — diffing across different roots is a programmer error
 * (caller probably mixed up arguments) and throws.
 *
 * For "modified" changes we include a small content preview when the after-
 * file is below the canary-content size cap; the preview is what the oracle
 * later searches for canary tokens.
 */
export function diffSnapshots(
  before: StateSnapshot,
  after: StateSnapshot,
  options: SnapshotOptions = {},
): StateDelta {
  if (before.rootDir !== after.rootDir) {
    throw new Error(
      `State oracle: cannot diff snapshots from different roots ` +
        `(${before.rootDir} vs ${after.rootDir})`,
    );
  }
  const maxBytes = options.maxContentBytesForCanary ?? DEFAULT_MAX_CONTENT_BYTES;

  const beforeMap = new Map(before.entries.map((e) => [e.path, e]));
  const afterMap = new Map(after.entries.map((e) => [e.path, e]));

  const changes: StateDeltaChange[] = [];

  for (const [path, afterEntry] of afterMap) {
    const beforeEntry = beforeMap.get(path);
    if (!beforeEntry) {
      changes.push({
        kind: "added",
        path,
        size: afterEntry.size,
        sha256: afterEntry.sha256,
        preview: readPreview(join(after.rootDir, path), afterEntry.size, maxBytes),
      });
    } else if (beforeEntry.sha256 !== afterEntry.sha256) {
      changes.push({
        kind: "modified",
        path,
        sizeBefore: beforeEntry.size,
        sizeAfter: afterEntry.size,
        sha256Before: beforeEntry.sha256,
        sha256After: afterEntry.sha256,
        preview: readPreview(join(after.rootDir, path), afterEntry.size, maxBytes),
      });
    }
  }

  for (const [path, beforeEntry] of beforeMap) {
    if (!afterMap.has(path)) {
      changes.push({
        kind: "deleted",
        path,
        sha256: beforeEntry.sha256,
      });
    }
  }

  // Stable order — added → modified → deleted, then by path.
  const kindRank = { added: 0, modified: 1, deleted: 2 } as const;
  changes.sort((a, b) => {
    const k = kindRank[a.kind] - kindRank[b.kind];
    return k !== 0 ? k : a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });

  return {
    rootDir: before.rootDir,
    beforeAt: before.takenAt,
    afterAt: after.takenAt,
    changes,
  };
}

/**
 * Search a delta for canaries. A canary "lands" if it appears either:
 *   - inside a changed file's path, or
 *   - inside the loaded content preview of a changed file.
 *
 * The caller passes the canaries in (typically by enumerating
 * `router.allProbes().map(p => p.intent.canary)`). This is what flips a state
 * change from "something happened on disk" into "we caused this exact change
 * with this exact probe" — the same prospective attribution the ProbeRouter
 * provides for network sensors.
 */
export function findCanariesInDelta(
  delta: StateDelta,
  canaries: string[],
): CanaryHit[] {
  if (canaries.length === 0) return [];
  const hits: CanaryHit[] = [];

  for (const change of delta.changes) {
    const inPath = change.path;
    const inContent = "preview" in change ? change.preview ?? "" : "";
    for (const canary of canaries) {
      const matchedIn: Array<"path" | "content"> = [];
      if (inPath.includes(canary)) matchedIn.push("path");
      if (inContent.includes(canary)) matchedIn.push("content");
      if (matchedIn.length > 0) {
        hits.push({ canary, change, matchedIn });
      }
    }
  }

  return hits;
}

/**
 * Persist a delta to disk as a JSON artifact. Returns the absolute path of
 * the written file so the caller can stash it on `finding.evidence.fsDiffFile`
 * (or `stateDiffFile`) — that's what the kill-chain assembler reads to attach
 * a downloadable proof artifact.
 *
 * The file format is `StateDeltaArtifact` — a small wrapper around the delta
 * + a generated `oracleId` so multiple oracle runs against the same chamber
 * don't overwrite each other.
 */
export function writeDeltaArtifact(
  outputDir: string,
  delta: StateDelta,
  oracleId: string,
): string {
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });
  const artifactPath = join(outputDir, `${sanitize(oracleId)}.delta.json`);
  const artifact: StateDeltaArtifact = {
    version: 1,
    oracleId,
    writtenAt: new Date().toISOString(),
    delta,
  };
  writeFileSync(artifactPath, JSON.stringify(artifact, null, 2), "utf-8");
  return artifactPath;
}

export interface StateDeltaArtifact {
  version: 1;
  oracleId: string;
  writtenAt: string;
  delta: StateDelta;
}

// ────────────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────────────

function walk(
  root: string,
  current: string,
  ignore: string[],
  out: StateSnapshotEntry[],
): void {
  let names: string[];
  try {
    names = readdirSync(current);
  } catch {
    return;
  }

  for (const name of names) {
    const abs = join(current, name);
    const rel = toRel(root, abs);
    if (rel === "") continue;
    if (isIgnored(rel, ignore)) continue;

    let st;
    try {
      st = statSync(abs);
    } catch {
      continue;
    }

    if (st.isDirectory()) {
      walk(root, abs, ignore, out);
      continue;
    }
    if (!st.isFile()) continue;

    let sha256 = "";
    try {
      sha256 = createHash("sha256").update(readFileSync(abs)).digest("hex");
    } catch {
      // Permission denied / transient — skip this entry rather than failing
      // the whole snapshot.
      continue;
    }

    out.push({
      path: rel,
      size: st.size,
      sha256,
      mtimeMs: st.mtimeMs,
    });
  }
}

function toRel(root: string, abs: string): string {
  return relative(root, abs).split("\\").join("/");
}

function isIgnored(rel: string, ignore: string[]): boolean {
  for (const pat of ignore) {
    if (pat.endsWith("/")) {
      // directory pattern — match either as prefix or as a path segment
      const dir = pat.slice(0, -1);
      if (rel === dir) return true;
      if (rel.startsWith(`${dir}/`)) return true;
      if (rel.includes(`/${dir}/`)) return true;
    } else if (rel.includes(pat)) {
      return true;
    }
  }
  return false;
}

function readPreview(absPath: string, size: number, maxBytes: number): string | undefined {
  if (size > maxBytes) return undefined;
  try {
    const buf = readFileSync(absPath);
    // Heuristic: if the buffer has many NUL bytes treat it as binary and skip.
    let nulCount = 0;
    const sample = Math.min(buf.length, 512);
    for (let i = 0; i < sample; i++) {
      if (buf[i] === 0) nulCount++;
    }
    if (sample > 0 && nulCount / sample > 0.05) return undefined;
    return buf.toString("utf-8");
  } catch {
    return undefined;
  }
}

function sanitize(id: string): string {
  return id.replace(/[^A-Za-z0-9_-]/g, "_");
}
