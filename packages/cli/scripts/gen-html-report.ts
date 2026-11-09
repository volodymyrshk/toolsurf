#!/usr/bin/env bun
/**
 * gen-html-report.ts
 *
 * Converts a toolsurf JSON scan output into a polished, self-contained
 * HTML report. UMRI v4.0 risk profile is the primary score, displayed as a
 * 5-axis radar with the umriScalar (100=safe, 0=max risk) as the hero number.
 *
 * Legacy securityScore is shown as a secondary comparison metric only —
 * UMRI is the defensible research-grade scoring system.
 *
 * Usage:
 *   bun run packages/cli/scripts/gen-html-report.ts <scan.json> > report.html
 */

import { readFileSync } from "node:fs";

const jsonPath = process.argv[2];
if (!jsonPath) {
  console.error("Usage: bun run gen-html-report.ts <scan.json>");
  process.exit(1);
}

const report = JSON.parse(readFileSync(jsonPath, "utf-8"));

// ── UMRI risk profile (primary) ────────────────────────────────────────────
const rp = report.riskProfile ?? {};
const umriScalar: number = typeof rp.umriScalar === "number" ? rp.umriScalar : 0;
const umriRounded = Math.round(umriScalar * 10) / 10;
const crs: number = typeof rp.compositeRiskScore === "number" ? rp.compositeRiskScore : 0;
const riskLevel: string = rp.riskLevel ?? "UNKNOWN";
const ssvcLabel: string = rp.ssvcLabel ?? "";
const formulaVersion: string = report.scoringFormulaVersion ?? "v4.0";

const axes = {
  exposure:          clamp01(rp.exposure),
  exploitChainDepth: clamp01(rp.exploitChainDepth),
  severityDensity:   clamp01(rp.severityDensity),
  capabilityRisk:    clamp01(rp.capabilityRisk),
  trustViolation:    clamp01(rp.trustViolation),
};

function clamp01(v: unknown): number {
  if (typeof v !== "number" || Number.isNaN(v)) return 0;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

// ── Legacy score (secondary, for comparison only) ──────────────────────────
const legacyScore: number = report.summary?.securityScore ?? 0;

// ── Severity counts + metadata ─────────────────────────────────────────────
const sev = report.summary?.findingsBySeverity ?? {};
const critCount: number = sev.CRITICAL ?? 0;
const highCount: number = sev.HIGH ?? 0;
const medCount: number = sev.MEDIUM ?? 0;
const lowCount: number = sev.LOW ?? 0;
const totalFindings: number = report.findings?.length ?? 0;

const serverName: string = report.server?.serverInfo?.name ?? "Unknown";
const serverVersion: string = report.server?.serverInfo?.version ?? "";
const protocolVersion: string = report.server?.protocolVersion ?? "";
const toolCount: number = report.server?.tools?.length ?? 0;
const moduleCount: number = report.modules?.length ?? 0;
const durationMs: number = report.durationMs ?? 0;
const totalChecks: number = report.summary?.totalChecks ?? 0;
const passed: number = report.summary?.passed ?? 0;
const scanDate = report.timestamp ? new Date(report.timestamp).toLocaleString() : new Date().toLocaleString();

// ── UMRI-driven colour palette (NOT legacy-score driven) ───────────────────
// umriScalar: 100=safe, 0=max risk. Same convention as legacy score for hue
// continuity, but the THRESHOLDS are tuned to the UMRI scale (which clusters
// real-world scans differently from the penalty model).
const umriColor =
  umriScalar <= 25 ? "#f85149" :   // CRITICAL band
  umriScalar <= 50 ? "#e3b341" :   // HIGH band
  umriScalar <= 75 ? "#58a6ff" :   // MEDIUM band
                     "#3fb950";    // LOW / MINIMAL band

const riskBg =
  riskLevel === "CRITICAL" ? "rgba(248,81,73,0.15)" :
  riskLevel === "HIGH"     ? "rgba(227,179,65,0.15)" :
  riskLevel === "MEDIUM"   ? "rgba(88,166,255,0.10)" :
                             "rgba(63,185,80,0.10)";

const riskBorder =
  riskLevel === "CRITICAL" ? "#f85149" :
  riskLevel === "HIGH"     ? "#e3b341" :
  riskLevel === "MEDIUM"   ? "#58a6ff" :
                             "#3fb950";

// ── Radar geometry (5-axis pentagon, UMRI axes) ────────────────────────────
const RADAR_CX = 145;
const RADAR_CY = 145;
const RADAR_R = 105;
const NUM_AXES = 5;

type AxisKey = keyof typeof axes;
const axisOrder: Array<[AxisKey, string]> = [
  ["exposure",          "Exposure"],
  ["exploitChainDepth", "Exploit Chain"],
  ["severityDensity",   "Severity Density"],
  ["capabilityRisk",    "Capability Risk"],
  ["trustViolation",    "Trust Violation"],
];

function polar(magnitude: number, axisIdx: number, r: number): [number, number] {
  const angle = -Math.PI / 2 + axisIdx * (2 * Math.PI / NUM_AXES);
  return [
    RADAR_CX + r * magnitude * Math.cos(angle),
    RADAR_CY + r * magnitude * Math.sin(angle),
  ];
}

const dataPoints = axisOrder
  .map(([key], i) => polar(axes[key], i, RADAR_R))
  .map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`)
  .join(" ");

const ringPolys = [0.25, 0.5, 0.75, 1.0].map((scale) =>
  Array.from({ length: NUM_AXES }, (_, i) => polar(scale, i, RADAR_R))
    .map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ")
);

const axisLines = axisOrder
  .map((_, i) => {
    const [ex, ey] = polar(1.0, i, RADAR_R);
    return `<line x1="${RADAR_CX}" y1="${RADAR_CY}" x2="${ex.toFixed(1)}" y2="${ey.toFixed(1)}" stroke="#30363d" stroke-width="0.6"/>`;
  })
  .join("");

const axisLabels = axisOrder
  .map(([key, label], i) => {
    const [lx, ly] = polar(1.22, i, RADAR_R);
    const val = axes[key];
    let anchor: string;
    if (Math.abs(lx - RADAR_CX) < 4) anchor = "middle";
    else if (lx > RADAR_CX) anchor = "start";
    else anchor = "end";
    return `
      <text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}" dominant-baseline="middle"
            fill="#7d8590" font-family="'SF Mono',monospace" font-size="10" font-weight="600">${label}</text>
      <text x="${lx.toFixed(1)}" y="${(ly + 13).toFixed(1)}" text-anchor="${anchor}" dominant-baseline="middle"
            fill="${umriColor}" font-family="'SF Mono',monospace" font-size="12" font-weight="700">${val.toFixed(2)}</text>`;
  })
  .join("");

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sevColor(s: string): string {
  if (s === "CRITICAL") return "#f85149";
  if (s === "HIGH")     return "#e3b341";
  if (s === "MEDIUM")   return "#58a6ff";
  if (s === "LOW")      return "#7d8590";
  return "#7d8590";
}

function sevBg(s: string): string {
  if (s === "CRITICAL") return "rgba(248,81,73,0.12)";
  if (s === "HIGH")     return "rgba(227,179,65,0.12)";
  if (s === "MEDIUM")   return "rgba(88,166,255,0.10)";
  return "rgba(125,133,144,0.08)";
}

// ── Findings (CRIT + HIGH + MEDIUM, top 10) ────────────────────────────────
const keyFindings = (report.findings ?? [])
  .filter((f: any) => ["CRITICAL", "HIGH", "MEDIUM"].includes(f.severity))
  .sort((a: any, b: any) => {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
  })
  .slice(0, 10);

const findingsHtml = keyFindings.map((f: any) => `
  <div class="finding-card" style="border-left-color:${sevColor(f.severity)};background:${sevBg(f.severity)}">
    <div class="finding-head">
      <span class="sev-badge" style="color:${sevColor(f.severity)};border-color:${sevColor(f.severity)}">${esc(f.severity)}</span>
      ${f.cweId ? `<span class="cwe-tag">${esc(f.cweId)}</span>` : ""}
      ${f.toolName ? `<span class="tool-tag">tool: ${esc(f.toolName)}</span>` : ""}
      ${typeof f.confidence === "number" ? `<span class="conf-tag">conf ${Math.round(f.confidence * 100)}%</span>` : ""}
    </div>
    <div class="finding-title">${esc(f.title)}</div>
    ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ""}
    ${f.remediation ? `<div class="finding-fix">▶ ${esc(f.remediation)}</div>` : ""}
  </div>`).join("\n");

// ── Kill chains ────────────────────────────────────────────────────────────
const kcs = report.killChainSummary?.chains ?? [];
const killChainHtml = kcs.length === 0 ? "" : `
<section>
  <h2 class="section-title">Kill Chains <span class="section-badge">${kcs.length}</span></h2>
  <div class="kc-grid">
    ${kcs.slice(0, 6).map((kc: any) => `
    <div class="kc-card">
      <div class="kc-head">
        <span class="kc-status kc-${(kc.status ?? "").toLowerCase()}">${esc(kc.status ?? "").toUpperCase()}</span>
        <span class="kc-id">${esc(kc.id ?? "")}</span>
        ${typeof kc.confidence === "number" ? `<span class="kc-conf">${Math.round(kc.confidence * 100)}%</span>` : ""}
      </div>
      <div class="kc-title">${esc(kc.title ?? "")}</div>
      <div class="kc-impact">${esc(kc.impact ?? "")}</div>
    </div>`).join("\n")}
  </div>
</section>`;

// ── Tool surface ───────────────────────────────────────────────────────────
const toolsHtml = toolCount === 0 ? "" : `
<section>
  <h2 class="section-title">Tool Surface <span class="section-badge">${toolCount} tools</span></h2>
  <div class="tool-grid">
    ${(report.server?.tools ?? []).map((t: any) => `
    <div class="tool-card">
      <div class="tool-name">${esc(t.name ?? "")}</div>
      <div class="tool-desc">${esc((t.description ?? "").slice(0, 90))}${(t.description ?? "").length > 90 ? "…" : ""}</div>
      ${t.annotations ? `<div class="tool-hints">
        ${t.annotations.readOnlyHint === true ? '<span class="hint hint-ok">readOnly</span>' : ""}
        ${t.annotations.readOnlyHint === false ? '<span class="hint hint-warn">mutates</span>' : ""}
        ${t.annotations.destructiveHint === true ? '<span class="hint hint-danger">destructive</span>' : ""}
      </div>` : ""}
    </div>`).join("\n")}
  </div>
</section>`;

// ── Modules with findings ──────────────────────────────────────────────────
const notableModules = (report.modules ?? [])
  .filter((m: any) => (m.findings?.length ?? 0) > 0 || m.error)
  .sort((a: any, b: any) => (b.findings?.length ?? 0) - (a.findings?.length ?? 0))
  .slice(0, 12);

const modulesHtml = notableModules.length === 0 ? "" : `
<section>
  <h2 class="section-title">Modules with Findings</h2>
  <div class="module-grid">
    ${notableModules.map((m: any) => {
      const findingCount = m.findings?.length ?? 0;
      const hasCrit = (m.findings ?? []).some((f: any) => f.severity === "CRITICAL");
      const color = m.error ? "#bc8cff" : hasCrit ? "#f85149" : "#e3b341";
      return `<div class="module-chip" style="border-color:${color}">
        <span class="module-name">${esc(m.moduleName ?? m.moduleId ?? "")}</span>
        <span class="module-count" style="color:${color}">${findingCount}</span>
      </div>`;
    }).join("\n")}
  </div>
</section>`;

// ── UMRI display ring (donut around umriScalar) ───────────────────────────
// More arc filled = more safe. Colour shifts toward red as arc shrinks.
const ringCirc = 2 * Math.PI * 56; // r=56
const ringArc = (umriScalar / 100) * ringCirc;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>toolsurf — ${esc(serverName)}</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #21262d;
    --text: #e6edf3;
    --muted: #7d8590;
    --mono: 'SF Mono','JetBrains Mono','Fira Code',Consolas,monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 60px;
  }

  /* ── HEADER ── */
  .page-header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 22px 40px;
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .logo {
    font-family: var(--mono);
    font-size: 16px;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: -0.02em;
  }
  .logo span { color: var(--muted); }
  .header-meta { display: flex; flex-direction: column; gap: 2px; }
  .header-server { font-size: 15px; font-weight: 600; color: var(--text); }
  .header-sub { font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .header-right { margin-left: auto; text-align: right; }
  .scan-date { font-size: 12px; color: var(--muted); }
  .formula-tag {
    font-size: 10px; color: var(--muted); font-family: var(--mono);
    background: var(--border); padding: 2px 8px; border-radius: 10px;
    letter-spacing: 0.05em; margin-top: 4px; display: inline-block;
  }

  /* ── UMRI HERO ── */
  .hero {
    display: grid;
    grid-template-columns: auto auto 1fr;
    gap: 36px;
    align-items: center;
    padding: 36px 40px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, var(--surface) 0%, var(--bg) 100%);
  }

  /* UMRI scalar ring */
  .umri-scalar { display: flex; flex-direction: column; align-items: center; gap: 8px; }
  .umri-ring { position: relative; width: 150px; height: 150px; }
  .umri-ring svg { transform: rotate(-90deg); }
  .umri-center {
    position: absolute; inset: 0;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }
  .umri-num {
    font-size: 40px;
    font-weight: 800;
    color: ${umriColor};
    line-height: 1;
    font-family: var(--mono);
  }
  .umri-label {
    font-size: 10px;
    color: var(--muted);
    margin-top: 4px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .umri-suffix {
    font-size: 11px;
    color: ${umriColor};
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.06em;
    margin-top: 2px;
  }

  /* UMRI radar */
  .umri-radar { position: relative; }
  .umri-radar svg { display: block; overflow: visible; }
  .radar-caption {
    text-align: center;
    font-size: 10px;
    color: var(--muted);
    font-family: var(--mono);
    margin-top: 6px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  /* Risk + meta column */
  .hero-meta { display: flex; flex-direction: column; gap: 16px; }
  .risk-banner {
    background: ${riskBg};
    border: 1px solid ${riskBorder};
    border-radius: 8px;
    padding: 12px 18px;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }
  .risk-level {
    font-size: 18px;
    font-weight: 800;
    color: ${riskBorder};
    letter-spacing: 0.06em;
    font-family: var(--mono);
  }
  .ssvc-pill {
    font-size: 10px;
    color: var(--text);
    background: var(--border);
    border: 1px solid ${riskBorder};
    padding: 2px 10px;
    border-radius: 10px;
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.08em;
  }
  .crs-line {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
    margin-left: auto;
  }
  .crs-line strong {
    color: var(--text);
    font-weight: 700;
  }

  .stats-row {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }
  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    min-width: 52px;
  }
  .stat-n {
    font-size: 22px;
    font-weight: 700;
    font-family: var(--mono);
    line-height: 1;
  }
  .stat-l {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .n-crit { color: #f85149; }
  .n-high { color: #e3b341; }
  .n-med  { color: #58a6ff; }
  .n-ok   { color: #3fb950; }
  .n-dim  { color: var(--muted); }

  .legacy-line {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
    padding-top: 8px;
    border-top: 1px dashed var(--border);
    margin-top: 4px;
  }
  .legacy-line strong { color: var(--text); font-weight: 700; }

  /* ── MAIN ── */
  .main { max-width: 1100px; margin: 0 auto; padding: 40px 40px 0; }
  section { margin-bottom: 48px; }

  .section-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }
  .section-badge {
    background: var(--border);
    color: var(--muted);
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 400;
    letter-spacing: 0;
  }

  /* ── FINDINGS ── */
  .finding-card {
    border-left: 3px solid;
    border-radius: 4px;
    padding: 14px 18px;
    margin-bottom: 10px;
  }
  .finding-head {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
    flex-wrap: wrap;
  }
  .sev-badge {
    font-size: 10px;
    font-weight: 700;
    padding: 1px 7px;
    border-radius: 3px;
    border: 1px solid;
    letter-spacing: 0.06em;
    font-family: var(--mono);
  }
  .cwe-tag, .conf-tag {
    font-size: 10px;
    color: var(--muted);
    background: var(--border);
    padding: 1px 7px;
    border-radius: 3px;
    font-family: var(--mono);
  }
  .tool-tag {
    font-size: 10px;
    color: #58a6ff;
    font-family: var(--mono);
  }
  .finding-title {
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 4px;
    line-height: 1.4;
  }
  .finding-desc {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 6px;
    line-height: 1.5;
  }
  .finding-fix {
    font-size: 11.5px;
    color: #3fb950;
    background: rgba(63,185,80,0.07);
    padding: 6px 10px;
    border-radius: 3px;
    line-height: 1.5;
  }

  /* ── KILL CHAINS ── */
  .kc-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
  }
  .kc-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 16px;
  }
  .kc-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .kc-status {
    font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 3px;
    letter-spacing: 0.08em; font-family: var(--mono);
  }
  .kc-complete { background: rgba(63,185,80,0.2); color: #3fb950; }
  .kc-partial  { background: rgba(227,179,65,0.2); color: #e3b341; }
  .kc-blocked  { background: rgba(88,166,255,0.2); color: #58a6ff; }
  .kc-id { font-size: 10px; color: var(--muted); font-family: var(--mono); }
  .kc-conf { margin-left: auto; font-size: 10px; color: var(--muted); }
  .kc-title { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
  .kc-impact { font-size: 11px; color: var(--muted); }

  /* ── MODULES ── */
  .module-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .module-chip {
    border: 1px solid;
    border-radius: 5px;
    padding: 6px 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--surface);
  }
  .module-name { font-size: 11px; color: var(--muted); font-family: var(--mono); }
  .module-count { font-size: 11px; font-weight: 700; font-family: var(--mono); }

  /* ── TOOLS ── */
  .tool-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 10px;
  }
  .tool-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
  }
  .tool-name {
    font-size: 12px;
    font-weight: 700;
    font-family: var(--mono);
    color: #58a6ff;
    margin-bottom: 4px;
  }
  .tool-desc { font-size: 11px; color: var(--muted); line-height: 1.4; margin-bottom: 6px; }
  .tool-hints { display: flex; gap: 4px; flex-wrap: wrap; }
  .hint {
    font-size: 9px; font-weight: 600; padding: 1px 5px; border-radius: 2px;
    letter-spacing: 0.04em; text-transform: uppercase; font-family: var(--mono);
  }
  .hint-ok     { background: rgba(63,185,80,0.15);  color: #3fb950; }
  .hint-warn   { background: rgba(227,179,65,0.15); color: #e3b341; }
  .hint-danger { background: rgba(248,81,73,0.15);  color: #f85149; }

  /* ── METHODOLOGY FOOTER ── */
  .methodology {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 18px 22px;
    margin: 40px 0;
    font-size: 11.5px;
    color: var(--muted);
    line-height: 1.7;
    font-family: var(--mono);
  }
  .methodology strong { color: var(--text); }
  .methodology .formula {
    background: var(--bg);
    padding: 8px 12px;
    border-radius: 4px;
    margin: 6px 0;
    display: inline-block;
  }

  .page-footer {
    text-align: center;
    padding: 28px 40px;
    font-size: 11px;
    color: var(--muted);
    border-top: 1px solid var(--border);
    font-family: var(--mono);
  }

  /* responsive */
  @media (max-width: 900px) {
    .hero { grid-template-columns: 1fr; gap: 24px; padding: 24px; }
    .main { padding: 24px; }
  }
</style>
</head>
<body>

<!-- HEADER -->
<header class="page-header">
  <div>
    <div class="logo">tool<span>surf</span></div>
  </div>
  <div class="header-meta">
    <div class="header-server">${esc(serverName)} ${serverVersion ? `<span style="color:var(--muted);font-size:12px">v${esc(serverVersion)}</span>` : ""}</div>
    <div class="header-sub">${toolCount} tools · ${moduleCount} modules · ${protocolVersion ? `MCP ${esc(protocolVersion)} · ` : ""}${durationMs >= 1000 ? (durationMs / 1000).toFixed(1) + "s" : durationMs + "ms"}</div>
  </div>
  <div class="header-right">
    <div class="scan-date">${esc(scanDate)}</div>
    <div class="formula-tag">UMRI ${esc(formulaVersion)}</div>
  </div>
</header>

<!-- UMRI HERO -->
<div class="hero">

  <!-- UMRI scalar ring -->
  <div class="umri-scalar">
    <div class="umri-ring">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r="56" fill="none" stroke="#21262d" stroke-width="10"/>
        <circle cx="75" cy="75" r="56" fill="none"
          stroke="${umriColor}" stroke-width="10"
          stroke-dasharray="${ringArc.toFixed(2)} ${ringCirc.toFixed(2)}"
          stroke-linecap="round"/>
      </svg>
      <div class="umri-center">
        <span class="umri-num">${umriRounded.toFixed(1)}</span>
        <span class="umri-label">UMRI Scalar</span>
        <span class="umri-suffix">100 = SAFE</span>
      </div>
    </div>
  </div>

  <!-- UMRI 5-axis radar -->
  <div class="umri-radar">
    <svg width="290" height="290" viewBox="0 0 290 290">
      <!-- reference rings -->
      ${ringPolys.map((pts, i) => `<polygon points="${pts}" fill="none" stroke="#21262d" stroke-width="${i === 3 ? 1 : 0.5}"/>`).join("")}
      <!-- axis lines -->
      ${axisLines}
      <!-- data polygon -->
      <polygon points="${dataPoints}" fill="${umriColor}" fill-opacity="0.25" stroke="${umriColor}" stroke-width="1.5"/>
      <!-- data vertices -->
      ${axisOrder.map(([key], i) => {
        const [px, py] = polar(axes[key], i, RADAR_R);
        return `<circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="3.5" fill="${umriColor}"/>`;
      }).join("")}
      <!-- axis labels -->
      ${axisLabels}
    </svg>
    <div class="radar-caption">5-Axis UMRI Risk Profile · values 0.00 – 1.00</div>
  </div>

  <!-- Risk + stats column -->
  <div class="hero-meta">
    <div class="risk-banner">
      <div class="risk-level">${esc(riskLevel)} RISK</div>
      ${ssvcLabel ? `<span class="ssvc-pill">SSVC · ${esc(ssvcLabel)}</span>` : ""}
      <span class="crs-line">CRS <strong>${crs.toFixed(3)}</strong> <span style="color:#525252">/ 0.926 ceiling</span></span>
    </div>

    <div class="stats-row">
      <div class="stat"><div class="stat-n n-crit">${critCount}</div><div class="stat-l">Critical</div></div>
      <div class="stat"><div class="stat-n n-high">${highCount}</div><div class="stat-l">High</div></div>
      <div class="stat"><div class="stat-n n-med">${medCount}</div><div class="stat-l">Medium</div></div>
      <div class="stat" style="border-left:1px solid var(--border);padding-left:24px;margin-left:4px">
        <div class="stat-n n-dim">${totalFindings}</div>
        <div class="stat-l">Total</div>
      </div>
      <div class="stat"><div class="stat-n n-ok">${passed}</div><div class="stat-l">Passed</div></div>
      <div class="stat"><div class="stat-n n-dim">${totalChecks}</div><div class="stat-l">Checks</div></div>
    </div>

    <div class="legacy-line">
      Legacy securityScore (penalty model, for comparison only): <strong>${legacyScore}/100</strong>.
      UMRI is the primary score — penalty model is shown for backwards compatibility.
    </div>
  </div>
</div>

<!-- MAIN -->
<main class="main">

  ${keyFindings.length > 0 ? `
  <section>
    <h2 class="section-title">Findings <span class="section-badge">${keyFindings.length} shown · ${totalFindings} total</span></h2>
    ${findingsHtml}
  </section>` : ""}

  ${killChainHtml}

  ${toolsHtml}

  ${modulesHtml}

  <div class="methodology">
    <strong>Scoring methodology — UMRI ${esc(formulaVersion)}.</strong>
    The Unified MCP Risk Index decomposes risk into five axes
    (Exposure, Exploit Chain Depth, Severity Density, Capability Risk, Trust Violation),
    each on an ordinal [0, 1] scale. The Composite Risk Score combines them via a
    weighted complement product with quadratic boost:
    <span class="formula">CRS = 1 − ∏ᵢ (1 − wᵢ · φ(Aᵢ)),  φ(x) = x(1+x)</span>.
    The UMRI scalar shown above is an affine rescaling:
    <span class="formula">S<sub>UMRI</sub> = 100 × ∏ᵢ (1 − wᵢ · φ(Aᵢ))</span>
    (100 = safest, 0 = maximum risk). Severity density uses log-sum-exp aggregation
    (β=1.5) normalised by capability-weighted attack surface (CWAS). Confidence is
    Bayes-updated by active probe outcomes before scoring. CRS scale type is ordinal
    — only rank-order comparisons are valid; do not compute means or arithmetic deltas.
    The legacy securityScore (penalty deduction model) is retained only for
    backwards compatibility with prior CLI output.
  </div>

</main>

<footer class="page-footer">
  toolsurf · ${esc(serverName)} · ${esc(scanDate)} · UMRI ${esc(formulaVersion)}
</footer>

</body>
</html>`;

process.stdout.write(html);
