# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM oven/bun:1 AS builder

WORKDIR /app

# Copy workspace root files
COPY package.json bun.lock tsconfig.json ./
COPY packages/cli/package.json packages/cli/

# Install dependencies
RUN bun install --frozen-lockfile

# Copy source
COPY packages/cli/src packages/cli/src
COPY packages/cli/tsconfig.json packages/cli/

# Build standalone binary
RUN cd packages/cli && bun build src/index.ts --compile --outfile /app/toolsurf

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM oven/bun:1-slim

# Install Node.js + npm for spawning MCP servers via npx
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scan

# Copy compiled binary
COPY --from=builder /app/toolsurf /usr/local/bin/toolsurf

# Pre-accept legal notice for non-interactive container use
ENV TOOLSURF_ACCEPT=true

ENTRYPOINT ["toolsurf"]
CMD ["--help"]
