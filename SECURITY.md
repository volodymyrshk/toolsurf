# Security Policy

## Supported versions

ToolSurf is pre-1.0. Security fixes land on the latest release line.

| Version | Supported |
| --- | --- |
| `0.1.x` (alpha) | Yes |
| `< 0.1` | No |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting:

**https://github.com/volodymyrshk/toolsurf/security/advisories/new**

Include, where possible:

- A description of the issue and its impact.
- The ToolSurf version (`toolsurf --version`), OS, and runtime (Node/Bun).
- A minimal reproduction: the target type, the command you ran, and the
  relevant report excerpt.
- Whether the issue affects the scanner itself or a third-party target.

You can expect an acknowledgement on a best-effort basis within five business
days. Please give us a reasonable window to ship a fix before public
disclosure.

## Scope

In scope:

- The ToolSurf CLI, its modules, adapters, scoring, and report writers.
- The GitHub Action and container image.
- Supply-chain issues in the published package.

Out of scope:

- Vulnerabilities in third-party servers or APIs that ToolSurf audits. Report
  those to the vendor.
- Findings that require the operator to intentionally disable a safety control
  (for example, running `full-active` scanning against production without
  authorization).
- Denial-of-service caused by scanning a target you do not control.

## Safe harbor

We will not pursue legal action against researchers who act in good faith,
follow this policy, avoid privacy violations and data destruction, and give us
a reasonable opportunity to remediate before disclosure.
