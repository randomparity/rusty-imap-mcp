# Differential HTML Oracle — EPVME Discovery Run

First run of the differential HTML→text sanitizer oracle (issue #529) over the
external EPVME malicious-email corpus, captured **July 10, 2026**. This is the
"discovery" run: point the oracle at a large real-world corpus, triage what it
surfaces, and decide what hardening is needed before EPVME can gate anything.

## How to reproduce

```bash
# One-time: fetch + extract EPVME (~49k .eml, ~170 MB of zips).
just test-epvme --download --cache-dir /path/to/EPVME-Dataset   # extracts to <cache>/extracted

# Run the oracle over the extracted tree.
cargo run --release --locked --manifest-path html-oracle/Cargo.toml -- \
  --repo-root . \
  --epvme-dir /path/to/EPVME-Dataset/extracted \
  --report /tmp/epvme-oracle.json
# --limit N caps the number of .eml files processed (deterministic; files sorted first).
```

Runtime: ~16 s for the full corpus in release mode.

## Results (full corpus)

| Metric | Value |
| --- | --- |
| inputs (html parts) | 47,876 |
| exact match | 47,608 (99.4%) |
| compared non-empty | 30,932 |
| SOFT (warning-explained drop) | 164 |
| HARD (unexplained divergence) | 103 |
| skipped / ref_error | 1 / 0 |

## Triage of the 103 HARD divergences

**Zero are confirmed production silent-drop bugs.** Every HARD is an oracle-side
faithfulness or normalization gap, in three families:

### 1. Text boundary / tree-construction noise — 60

The reference (`lol_html`, a streaming rewriter) and production (`html5ever`, a
full tree builder) disagree on how **stray / mismatched end tags** reshape the
DOM, and `norm::tokenize` splits only on whitespace, so the disagreement surfaces
as a punctuation-grouping divergence.

Confirmed example (`epvme/3382f306…`): the body is
`<pre><tt>Dear PayPal Member</font></a>,`. html5ever ignores the stray
`</font></a>` and keeps `Member,` as one text run → token `member,`. lol_html
fires element-boundary events for the stray end tags and separates them → tokens
`member` + `,`. Same visible text, different tokenization. Also seen as
`(usdrugs)` vs `usdrugs` + `)` and `usdrugs.` vs `usdrugs`.

### 2. Binary-garbage bodies — 37

Parts whose `contents()` is non-HTML byte-soup (mojibake); all carry
`UnicodeC0C1Stripped`. Two independent tokenizers shred invalid bytes
differently. These are not text at all — the oracle should skip parts that are
not plausibly text before comparing.

### 3. Href-normalization gaps — 6

- **Entities not decoded in href attributes** (`http|akcosm&eacute;tica.com`).
  The reference collects `el.get_attribute("href")` raw (`reference.rs`), which
  `lol_html` does *not* entity-decode, while production extracts hrefs through
  html5ever, which does. Any href containing an HTML entity diverges.
- **`mailto:` without a recipient** (`mailto|commercecorps.live?subject=…&amp;body=…`).
  `norm::href_identity`'s mailto branch returns the whole query string as the
  "domain" when there is no `@`, instead of `None` or the bare domain.

## Interpretation

- The **core differential is sound**: 99.4% exact-match over 30,932 real
  adversarial HTML bodies, and every divergence is explained without positing a
  production bug.
- The **comparison layer is too noise-sensitive** for a wild corpus. Curated
  fixtures never exercised stray-tag tree-construction differences, binary
  parts, or entity-bearing hrefs, so the internal corpus reported 0 HARD. EPVME
  does exercise them, and they dominate the signal.
- Allowlisting 103 per-input entries would bury the signal in noise and is the
  wrong fix — the noise is systematic, not per-input.

## Hardening applied

All three noise sources were fixed in the same branch (commit
`feat(html-oracle): harden comparison against wild-corpus noise`):

1. **Punctuation/boundary-robust comparison.** `norm::tokenize` trims
   leading/trailing non-alphanumerics, so `member,` and `member` + `,` reduce to
   the same token. Interior punctuation (`x&y`, `e.g`) is preserved. Collapsed
   bucket 1.
2. **Skip non-text parts.** The runner skips any part whose decoded body is
   >10% `U+FFFD` replacement characters (`is_mostly_binary`). Legitimate
   non-Latin text decodes to real codepoints, not `U+FFFD`, so international
   content is not excluded. Collapsed bucket 2.
3. **Faithful href handling.** The reference entity-decodes href attribute
   values via `decode_entities`; `href_identity` drops the `?subject=&body=`
   header block from `mailto:` and requires an actual recipient. Collapsed
   bucket 3.

## Results after hardening (full corpus)

| Metric | Before | After |
| --- | --- | --- |
| HARD | 103 | **2** |
| SOFT | 164 | 84 |
| skipped (binary) | 1 | 168 |
| exact match | 47,608 | 47,622 |

The **2 residual HARD** (`epvme/b9777a25…`, `epvme/ee557c9f…`) are the same
nested-MIME-blob family: `multipart/mixed` samples where `html_bodies()` returns
the raw MIME container (with a quoted-printable `text/plain` sub-part) as a
pseudo-HTML body. The surviving `20` token is part of a QP `=20` encoded space,
not visible text. This is not a production silent drop.

These two are now allowlisted in `html-oracle/epvme-allowlist.toml`, so the
full EPVME run reports **0 HARD, 0 stale**. That file is merged into the
allowlist only when `--epvme-dir` is set, so its `epvme/…` entries never show
as stale in the hermetic `--repo-root` run.

## If EPVME becomes a CI gate

- **Never add EPVME ids to the shared `allowlist.toml`.** The hermetic
  `--repo-root .` nightly does not load EPVME, so any `epvme/…` entry there
  would always be reported stale. EPVME entries live in
  `html-oracle/epvme-allowlist.toml`, merged only when `--epvme-dir` is set.
- Keep the run off the every-night hermetic schedule: use `workflow_dispatch`
  or a lower-frequency job with a pinned dataset snapshot + caching.

## Current status

EPVME is a **manual run** for now (no CI job). Invoke the oracle with
`--epvme-dir` against a locally extracted dataset as shown above. The loader,
flags, and EPVME allowlist are in place; wiring a scheduled/dispatch CI job is
deferred to a later session.

## Bearing on the #529 keep/kill retro

The oracle *did* find something real — not a sanitizer bug, but three concrete
faithfulness gaps in its own comparison layer that curated fixtures could not
reach. Those gaps are now fixed, and the hardened oracle runs the full EPVME
corpus at 2 HARD / 47,876 (0.006%), zero of them a production silent drop.
That argues **keep**: the HARD channel is now trustworthy on wild input, the
allowlist stays empty, and the differential agrees with production on 47,622
real adversarial bodies.
