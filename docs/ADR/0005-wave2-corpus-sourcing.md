# ADR-0005: Wave-2 corpus sourcing — download-at-build pinned-by-hash + text-node scrub

- **Status:** Accepted
- **Date:** 2026-07-11
- **Issue:** [#554](https://github.com/randomparity/rusty-imap-mcp/issues/554)
- **Spec:** [docs/superpowers/specs/2026-07-11-oracle-corpus-wave2-ingestion-design.md](../superpowers/specs/2026-07-11-oracle-corpus-wave2-ingestion-design.md)
- **Parent design:** [docs/superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md](../superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md)
  (staged-wave model; Component 4 reserved the `redistribution_basis` / `scrub`
  schema slots this ADR now fills for Wave 2)

## Context

Wave 2 grows the differential HTML-oracle corpus with **real public email
corpora** (Enron, SpamAssassin, Nazario phishing). This crosses two trust
boundaries that Wave 1 (synthetic + license-clean templates, vendored as small
pinned files) never touched:

1. **Data volume + provenance.** The sources are far too large to vendor
   (Enron alone is ~423 MB) and carry **no code license** — so Wave 1's
   "vendor small pinned upstreams + stamp an SPDX `license`" model does not
   apply.
2. **PII.** Real mail contains real personal data (Enron especially), and the
   validator's advisory PII scan **skips any input marked `scrub = ["none"]`**
   (`validate.py::scan_pii`), so an unscrubbed real-mail input rides in
   unchecked. The corpus repo is private today but the parent design preserves a
   path to public.

Both decisions have viable alternatives a future reader would otherwise
re-litigate.

## Decision

**1. Download-at-build, pinned by SHA-256.** The Wave-2 generator
(`tools/ingest/build_wave2.py` + `sources.py`) fetches each upstream archive from
a pinned URL at *local build time*, verifies a recorded SHA-256 **before use**
(hard-fail on mismatch), caches under a gitignored `tools/ingest/.cache/`, then
filters → scrubs → dedups → caps → writes `wave2/`. The committed `wave2/` tree —
not the megacorpus — is what ships and what `validate.yml` gates; **CI never
downloads**. `sources.toml` records each `url` + `sha256` + `redistribution_basis`
+ attribution + selection caps. Provenance uses the `redistribution_basis =
"research-corpus"` branch of `meta.toml`, not an SPDX `license`.

**2. Structure-preserving text-node scrub for all Wave-2 real mail.** Every
Wave-2 input is redacted with a deterministic text-node-only redactor
(`scrub.py`: email / phone / long-digit → fixed placeholder tokens), recorded as
`scrub = ["text-nodes-redacted"]`. Markup bytes (tags, attribute names *and*
values, comments) pass through verbatim, so the `structural_fingerprint` is
invariant and the oracle still probes the true tokenizer shape. Because both
sanitizers see the same scrubbed text, text-drop detection is unaffected. The
`scrub` marker activates the validator's advisory PII scan as a backstop.

**3. Nazario sourced from an immutable git-mirror commit, not `monkey.org`.**
The canonical `monkey.org` host is flaky; a GitHub-raw URL at a pinned commit
SHA is immutable and highly available. Nazario is **CC-BY-4.0** (per its
`README.txt`), so it is cleanly redistributable with **attribution**, which
`meta.toml` records. Any source that cannot be fetched from a stable pinned URL,
hashed, or cleared for redistribution is **dropped**, not force-added.

## Consequences

- Regeneration is reproducible and offline-after-cache; `build_wave2.py --check`
  fails on any byte drift. A changed upstream archive surfaces as a SHA-256
  mismatch and must be re-pinned in a reviewed change — it cannot silently alter
  the corpus.
- Scrubbing costs a small, low-stakes slice of what the parent design framed as
  "Wave-3 scrub tooling," delivered early. It is intentionally *light* (three
  patterns, text nodes only) — the general scrub framework remains a Wave-3
  concern.
- The advisory PII scan now actually runs on Wave-2 inputs (it was inert while
  everything was `["none"]`), giving a machine backstop behind human PR review.
- A future public-repo flip re-scrutinizes these inputs but starts from
  already-scrubbed bodies rather than raw PII.
- The `.cache/` download directory must be gitignored so a megacorpus is never
  accidentally committed.

## Considered & rejected

- **Vendor the raw corpora (Wave-1 model).** Rejected: Enron/SpamAssassin/Nazario
  are hundreds of MB to GB; committing them bloats the repo, and they carry no
  code license to stamp. Download-at-build + pinned hash gives the same
  reproducibility without storing the megacorpus.
- **A Zenodo DOI or HuggingFace/Parquet dataset for the phishing slice.**
  Rejected: the available Zenodo ("MeAJOR") and HuggingFace phishing datasets are
  **preprocessed** (feature-engineered CSV/Parquet with a normalized `body`
  column) — they have already stripped the raw HTML the oracle needs. Only a raw
  `.mbox`/`.eml` source preserves the tokenizer shape.
- **PhishTank (and URL-feed phishing intelligence generally).** Rejected: it is a
  feed of phishing **URLs**, not email messages — no HTML bodies. Extracting HTML
  would require crawling live phishing sites (unsafe, non-reproducible, and yields
  *web-page* not *email* HTML). Ephemeral hourly feeds also cannot be pinned by
  hash.
- **No scrub — commit filtered public-corpus bodies as-is (`scrub=["none"]`).**
  Rejected: the validator's PII scan is bypassed for `["none"]`, so real PII would
  ride in unchecked, and a public flip would republish real people's mail. The
  text-node scrub is oracle-neutral, so there is no fidelity cost to justify the
  risk.
- **Scrub attribute values too (`attr-values-redacted`).** Deferred (not adopted
  for Wave 2): redacting attribute values risks altering an `href`/`src` token the
  oracle compares, needing extra care to stay structure-preserving. Text-node
  scrub covers rendered-text PII, which is what the advisory scan checks; attr
  scrubbing can be added if a concrete need appears.
- **Run the generator (with its downloads) in the corpus repo's CI.** Rejected:
  CI would then depend on external hosts and hit rate limits; validating the
  already-committed `wave2/` bytes at a pinned SHA is hermetic and matches the
  Wave-1 model.
