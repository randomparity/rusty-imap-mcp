#!/usr/bin/env bash
# Validate per-crate crates.io publish metadata for every workspace member.
#
# Checks, for each of the 8 rimap-* crates:
#   - a non-empty `description` (required by crates.io; the only per-crate
#     field — license/repository/authors/readme are workspace-inherited);
#   - every `categories` entry is a real crates.io category slug (crates.io
#     silently warns-and-ignores an unknown slug at upload, so a typo would
#     otherwise reach production undetected — `cargo publish --dry-run` is
#     offline and cannot catch it);
#   - `keywords` count <= 5 and each keyword <= 20 chars (crates.io limits).
#
# Exits non-zero listing every offending crate/field. Run from the repo root.
# Wired into the `publish-checks` CI job via `just check-metadata`.
set -euo pipefail

# cargo metadata --no-deps returns exactly the workspace members. Pass it to
# python3 (present on CI runners and used elsewhere in scripts/) via an env var
# so the heredoc can supply the validator on stdin.
RIMAP_METADATA="$(cargo metadata --no-deps --format-version 1)" \
    python3 - <<'PY'
import json
import os
import sys

# Valid crates.io category slugs used by this workspace. Source of truth:
# https://crates.io/category_slugs  (keep this set in sync when adding a
# category to a crate's manifest).
VALID_CATEGORIES = {
    "email",
    "config",
    "parser-implementations",
    "text-processing",
    "authentication",
    "network-programming",
    "command-line-utilities",
}

MAX_KEYWORDS = 5
MAX_KEYWORD_LEN = 20

meta = json.loads(os.environ["RIMAP_METADATA"])
errors = []

for pkg in sorted(meta["packages"], key=lambda p: p["name"]):
    name = pkg["name"]

    description = (pkg.get("description") or "").strip()
    if not description:
        errors.append(f"{name}: missing non-empty `description`")

    categories = pkg.get("categories") or []
    for slug in categories:
        if slug not in VALID_CATEGORIES:
            errors.append(
                f"{name}: invalid category slug {slug!r} "
                f"(not in {sorted(VALID_CATEGORIES)})"
            )

    keywords = pkg.get("keywords") or []
    if len(keywords) > MAX_KEYWORDS:
        errors.append(
            f"{name}: {len(keywords)} keywords exceeds the crates.io max "
            f"of {MAX_KEYWORDS}"
        )
    for kw in keywords:
        if len(kw) > MAX_KEYWORD_LEN:
            errors.append(
                f"{name}: keyword {kw!r} exceeds {MAX_KEYWORD_LEN} chars"
            )

if errors:
    print("::error::publishable-metadata check failed:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

print(f"ok: publish metadata valid for {len(meta['packages'])} crates")
PY
