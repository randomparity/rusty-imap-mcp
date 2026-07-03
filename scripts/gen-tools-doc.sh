#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_file="docs/tools.md"

# Emit the doc-oriented per-tool JSON from the live catalog and render it
# to Markdown. The renderer writes the output file only after building the
# whole document, so a mid-run failure never leaves a truncated doc.
cargo run --quiet -p rimap-server --features test-support \
    --bin rusty-imap-mcp --locked -- dump-tool-doc |
    python3 scripts/gen-tools-doc.py "$out_file"
