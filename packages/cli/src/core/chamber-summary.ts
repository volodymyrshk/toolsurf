import { existsSync, readFileSync } from "node:fs";
import type { Finding, ScanReport } from "../types/index.js";
import type { ChamberManifest } from "./detonation-chamber.js";

type ChamberSummary = NonNullable<ScanReport["chamberSummary"]>;

/**
 * Build the structured `chamberSummary` block — JSON sibling of the terminal
 * 💥 Detonation Chamber panel. Consumed by:
 *   - CI dashboards
 *   - vendor-disclosure pipelines (`finding.yaml` exporter)
 *   - third-party reporters that don't parse terminal output
 *
 * Reads:
 *   - chamber manifest (paths, network, run-dir)
 *   - chamber capture files (HTTP/DNS/SMTP/metadata/netflow)
 *   - chamber-evidence and active-fuzzer findings
 *
 * Produces structured, JSON-safe data — no chalk strings, no hidden
 * dependencies. Safe to slim, safe to redact, safe to ship.
 */
export function buildChamberSummary(
  manifest: ChamberManifest,
  findings: Finding[],
): ChamberSummary {
  const captureRoot = manifest.runDir + "/captures";

  const httpCount = countLines(manifest.captures.http);
  const dnsCount = countLines(manifest.captures.dns);
  const smtpCount = countLines(manifest.captures.smtp);
  const metaCount = countLines(manifest.captures.metadata);
  const netflowCount = countLines(manifest.captures.netflow);

  const chamberFindings = findings.filter(
    (f) => f.id.startsWith("CHAMBER-") || f.id.startsWith("AF-CHAMBER"),
  );

  const confirmedExfil: ChamberSummary["confirmedExfil"] = [];
  const ipiRelays: ChamberSummary["ipiRelays"] = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const f of chamberFindings) {
    switch (f.severity) {
      case "CRITICAL": severityCounts.critical++; break;
      case "HIGH": severityCounts.high++; break;
      case "MEDIUM": severityCounts.medium++; break;
      case "LOW": severityCounts.low++; break;
    }

    const ev = (f.evidence ?? {}) as Record<string, unknown>;

    if (f.id === "CHAMBER-IPI-RELAY-001") {
      const hits = (ev.hits as Array<Record<string, unknown>>) ?? [];
      for (const h of hits) {
        ipiRelays.push({
          tool: String(h.tool ?? ""),
          paramName: h.paramName as string | undefined,
          probeUrl: String(h.probeUrl ?? ""),
          poisonToken: String(h.poisonToken ?? ""),
          preservedFullPrompt: Boolean(h.preservedFullPrompt),
          excerpt: String(h.excerpt ?? "").slice(0, 600),
        });
      }
    } else if (f.id.startsWith("AF-CHAMBER-")) {
      const captures = (ev.captures as Array<Record<string, unknown>>) ?? [];
      for (const c of captures) {
        const sink = c.sink as ChamberSummary["confirmedExfil"][number]["sink"];
        if (!["http", "dns", "smtp", "metadata"].includes(sink as string)) continue;
        confirmedExfil.push({
          findingId: f.id,
          tool: String(c.tool ?? ""),
          paramName: c.paramName as string | undefined,
          sink,
          payload: String(c.payload ?? ""),
          payloadVariant: c.payloadVariant as string | undefined,
          canary: String(c.canary ?? ""),
        });
      }
    }
  }

  return {
    runDir: manifest.runDir,
    networkName: manifest.network.name,
    captureRoot,
    captures: {
      http: { count: httpCount, capturePath: manifest.captures.http, sample: readFirst(manifest.captures.http) },
      dns: { count: dnsCount, capturePath: manifest.captures.dns, sample: readFirst(manifest.captures.dns) },
      smtp: { count: smtpCount, capturePath: manifest.captures.smtp, sample: readFirst(manifest.captures.smtp) },
      metadata: { count: metaCount, capturePath: manifest.captures.metadata, sample: readFirst(manifest.captures.metadata) },
      netflow: { count: netflowCount, capturePath: manifest.captures.netflow, sample: readFirst(manifest.captures.netflow) },
    },
    confirmedExfil,
    ipiRelays,
    severityCounts,
  };
}

function countLines(path: string | undefined): number {
  if (!path || !existsSync(path)) return 0;
  const txt = readFileSync(path, "utf-8").trim();
  return txt === "" ? 0 : txt.split("\n").length;
}

function readFirst(path: string | undefined): unknown {
  if (!path || !existsSync(path)) return undefined;
  const txt = readFileSync(path, "utf-8").trim();
  if (!txt) return undefined;
  const first = txt.split("\n", 1)[0];
  try { return JSON.parse(first); } catch { return first; }
}
