/**
 * SVG Badge Generator.
 *
 * Generates a shields.io-compatible SVG badge showing
 * the security score from a scan report or SARIF file.
 *
 * Usage:
 *   toolsurf badge --score 85
 *   toolsurf badge -i report.json
 *   toolsurf badge -i report.json -o badge.svg
 */

import { readFileSync, writeFileSync } from "node:fs";

export interface BadgeOptions {
  /** Direct score (0-100) */
  score?: number;
  /** Input file (JSON report) to extract score from */
  input?: string;
  /** Output file path (defaults to stdout) */
  output?: string;
  /** Badge label (default: "MCP Audit") */
  label?: string;
}

function scoreToColor(score: number): string {
  if (score >= 90) return "#22c55e"; // green
  if (score >= 80) return "#4ade80"; // light green
  if (score >= 70) return "#eab308"; // yellow
  if (score >= 50) return "#f97316"; // orange
  return "#ef4444"; // red
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function generateBadgeSvg(score: number, label: string = "MCP Audit"): string {
  const color = scoreToColor(score);
  const grade = scoreToGrade(score);
  const rightText = `${score}/100 (${grade})`;

  // Calculate widths (approximate character width of 6.5px for 11px font)
  const leftWidth = Math.round(label.length * 6.5 + 12);
  const rightWidth = Math.round(rightText.length * 6.5 + 12);
  const totalWidth = leftWidth + rightWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${rightText}">
  <title>${label}: ${rightText}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftWidth}" height="20" fill="#555"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${leftWidth * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(leftWidth - 10) * 10}">${escXml(label)}</text>
    <text x="${leftWidth * 5}" y="140" transform="scale(.1)" fill="#fff" textLength="${(leftWidth - 10) * 10}">${escXml(label)}</text>
    <text aria-hidden="true" x="${(leftWidth + totalWidth) * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(rightWidth - 10) * 10}">${escXml(rightText)}</text>
    <text x="${(leftWidth + totalWidth) * 5}" y="140" transform="scale(.1)" fill="#fff" textLength="${(rightWidth - 10) * 10}">${escXml(rightText)}</text>
  </g>
</svg>`;
}

function escXml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function executeBadge(options: BadgeOptions): void {
  let score: number;

  if (options.score !== undefined) {
    score = Math.max(0, Math.min(100, options.score));
  } else if (options.input) {
    try {
      const content = readFileSync(options.input, "utf-8");
      const report = JSON.parse(content);

      // Support both ScanReport and SARIF formats
      if (report.summary?.securityScore !== undefined) {
        score = report.summary.securityScore;
      } else if (report.runs?.[0]?.properties?.securityScore !== undefined) {
        score = report.runs[0].properties.securityScore;
      } else {
        console.error("Error: Could not find security score in input file");
        process.exitCode = 1;
        return;
      }
    } catch (err) {
      console.error(
        `Error reading input file: ${err instanceof Error ? err.message : String(err)}`
      );
      process.exitCode = 1;
      return;
    }
  } else {
    console.error("Error: Provide --score <number> or --input <file>");
    process.exitCode = 1;
    return;
  }

  const svg = generateBadgeSvg(score, options.label);

  if (options.output) {
    writeFileSync(options.output, svg, "utf-8");
    console.log(`Badge saved to: ${options.output}`);
  } else {
    console.log(svg);
  }
}
