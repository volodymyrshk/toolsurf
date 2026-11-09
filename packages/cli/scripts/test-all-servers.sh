#!/bin/bash
# 
# Helper script to test toolsurf against common community servers.
# Run this before cutting a release.

set -e

echo "Testing against filesystem..."
bun run src/index.ts scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --accept || true

echo "Testing against memory..."
bun run src/index.ts scan -s "npx -y @modelcontextprotocol/server-memory" --accept || true

echo "Testing against everything..."
bun run src/index.ts scan -s "npx -y @modelcontextprotocol/server-everything" --accept || true

echo "Testing against postgres..."
bun run src/index.ts scan -s "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/test" --accept || true

echo "All tests completed."
