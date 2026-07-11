# Corpus wave-1 ingestion — implementation plan (issue #551)

**Design (source of truth):**
`docs/superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md`
(Components 4 & 5, Wave 1). Depends on #549 (corpus repo, CLOSED) and #550
(`--corpus-root` + pinned checkout, CLOSED).

## Durable resume facts

- **Main-repo branch:** `feat/corpus-wave1-ingestion-551`
- **BASE_BRANCH:** `main`
- **Main-repo guardrails:** `just ci` (umbrella). CI hard-gates individually:
  `rustfmt` (`just fmt-check`), `clippy` (`just lint`), `check (macOS)`,
  `test (stable)` (`just test`), `test (MSRV 1.88.0)` (`just test-msrv`),
  `cargo-deny` (`just deny`), `zizmor self-check`. The oracle crate is
  **workspace-excluded**; run its checks explicitly:
  `cargo test --manifest-path html-oracle/Cargo.toml` and
  `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`.
- **Corpus repo:** `randomparity/rusty-imap-mcp-corpus` (PRIVATE). Guardrail =
  `validate.yml` (`python tools/validate/validate.py --corpus-root .` +
  `python -m unittest discover -s tools/validate/tests`). Local python ≥3.11
  required (system is 3.9; use `python3.13`).
- **Current pinned corpus SHA (main-repo nightly):**
  `69d31655e51ade38dd7ed6ee8209336d80516562` (empty-plumbing proof from #550).
- **Nightly workflow:** `.github/workflows/nightly-html-oracle.yml` already runs
  `--repo-root . --corpus-root corpus` with **no** `--corpus-min-compared`.

## Cross-repo sequence (data-dependency ordered)

The main-repo baseline PR **cannot** be finalized until the wave-1 corpus commit
is merged: the nightly pins that SHA, and the allowlist / `--corpus-min-compared`
floor / baseline-note numbers are all outputs of running the oracle over the
merged corpus. Operator decision (this session): **author + merge the corpus PR,
then open the main-repo PR for review.**

1. **Corpus repo** — author `wave1/` inputs, pass `validate.yml`, merge → SHA.
2. **Main repo** — pin that SHA, run oracle locally, triage, populate
   `corpus-allowlist.toml` + set `N`, write baseline note, PR for review.

## Component design decisions (this wave)

- **Sourcing (comprehensive, ~300–800 structurally-distinct inputs):**
  - **html5lib-tests tree-construction** (`.dat`) — the structural workhorse;
    rich nested HTML yields hundreds of distinct skeletons. MIT.
  - **html5lib-tests tokenizer** (`.test`) — mostly structurally-trivial
    (char-level); only survivors of structural-fingerprint dedup are kept. MIT.
  - **Open email templates** — Cerberus, MJML samples, Foundation for Emails.
    MIT/permissive; large distinct skeletons (tables, inline CSS, VML CC, pixel
    `<img>`).
  - **Deterministic synthetic mutations** — enumerated (no RNG): charset
    relabels (UTF-8↔windows-1252 label mismatch), CTE swaps
    (base64 ⇄ quoted-printable ⇄ 7bit), entity corruption (semicolon-less legacy
    entities, overlong numeric refs).
- **Reproducibility / provenance:** the wave-1 builder lives in the **corpus
  repo** under `tools/ingest/` and regenerates `wave1/` byte-identically and
  offline from vendored, pinned upstream source files under
  `tools/ingest/vendor/<source>/` (each with its upstream `LICENSE`) plus the
  enumerated synthetic generator. No `.eml`/`.meta.toml` are written outside
  `wave1/` (so the validator never walks tooling). This satisfies the synthetic
  determinism requirement and keeps provenance first-class.
- **Canaries (validator criterion 8 + nightly assertion):** ≥1 input per family.
  - `stray-tag-boundary` / `entity-href`: authored normal comparable HTML
    (healthy = ≥1 live `ComparedNonempty`).
  - `binary-part`: base64 CTE over invalid-UTF-8 bytes under `charset=utf-8`,
    decoding to ≥30 % U+FFFD (healthy = skipped by `is_mostly_binary`).

## Hard constraints (from validator + oracle, verified by reading source)

- Stem = lowercase hex SHA-256 of the `.eml` bytes; one sibling
  `<stem>.meta.toml`.
- **CRLF only:** `count("\r\n") == count("\n") == count("\r")` — no bare LF/CR.
- Each `.eml` must parse (Python `email` / Rust `mail-parser`) and yield ≥1
  `text/html` part.
- **Structural-fingerprint uniqueness** (criterion 6): tag/attr-*name* sequence
  hash must be unique tree-wide. Every tag-less input (pure text, comment-only,
  DOCTYPE-only, entity-only) collapses to one skeleton → **at most one**
  structurally-trivial input in the whole corpus. Dedup at generation time by
  importing `validate.py`'s `structural_fingerprint`/`html_part_texts` so the
  gate and the generator agree byte-for-byte.
- `meta.toml`: exactly one provenance basis. Wave 1 = SPDX `license` +
  `license_url`. Required strings: `source`, `source_url`, `notes`. `wave=1`,
  ISO `added`, non-empty allowlisted `scrub` (`["none"]` for pristine),
  allowlisted `probes`.

## Baseline procedure (Component 5, all figures are `corpus/`-prefixed)

1. Check out corpus at merged SHA into `corpus/`; run
   `cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root . --corpus-root corpus`.
2. Read `report.json` `corpus` block: `total`, `skipped`, `ref_error`,
   `compared_nonempty`.
3. Triage every HARD (`hard_inputs`): real sanitizer silent-drop → file an issue
   (never allowlist); systemic comparison-layer noise → fix the layer (out of
   wave-1 scope — flag it); benign per-input quirk → one `corpus-allowlist.toml`
   entry keyed `corpus/<stem>` with required `reason`. Re-run until 0 HARD.
4. `N = floor(0.9 × corpus_compared_nonempty)`; wire it into the nightly via
   `CORPUS_MIN_COMPARED`.
5. Baseline note under `docs/security/` records: allowlist size,
   `corpus_compared_nonempty`, comparable denominator
   (`corpus_total − corpus_skipped − corpus_ref_error`), non-allowlisted HARD
   (0), coverage % (`compared_nonempty / comparable`). KEEP bar: allowlist ≤
   `max(5, 0.5 % of compared_nonempty)`, not growing, zero non-allowlisted HARD,
   coverage ≥ 60 % (below-60 % → recorded exemption, not auto-KILL).

## Acceptance criteria (issue #551)

- [x] Wave-1 inputs ingested + passing `validate.yml`, all three canary families
      present. (454 inputs; corpus PR merged at SHA
      `8387292061098d1299aa504cffb7be0a5bcb4dde`.)
- [x] First nightly over the pinned wave-1 corpus green (0 HARD, 83.0 % coverage);
      `corpus-allowlist.toml` (0 entries, triaged) + `--corpus-min-compared 338`
      populated from it.
- [x] Restated baseline note committed under `docs/security/`
      (`html-oracle-corpus-wave1-baseline.md`).

## Outcome (as merged)

- Corpus repo PR #1 merged → pinned SHA `8387292061098d1299aa504cffb7be0a5bcb4dde`.
- Curated to comparable inputs (operator decision): empty-reference and
  non-comparable (foster-parenting/frameset/plaintext/NUL) html5lib cases
  excluded at ingestion; all exclusions are benign reference-limitation
  divergences, none a real sanitizer silent-drop.
- Baseline: 454 inputs, 376 compared_nonempty, 453 comparable, **83.0 % coverage,
  0 HARD, 0 allowlist entries** (bar 5), N=338. KEEP.
