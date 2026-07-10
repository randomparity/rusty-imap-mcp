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

## Required hardening before EPVME can gate

1. **Punctuation/boundary-robust comparison.** Strip leading/trailing
   punctuation from tokens (or compare on substantial words) so `member,` and
   `member` + `,` do not diverge. This collapses bucket 1 (~60).
2. **Skip non-text parts.** When a part decodes to a high proportion of
   replacement/control characters (the `UnicodeC0C1Stripped` signal), exclude it
   from the differential rather than comparing tokenized noise. This collapses
   bucket 2 (~37).
3. **Faithful href handling.** Entity-decode href attribute values in the
   reference (reuse `decode_entities`), and return `None` (or bare domain) from
   `href_identity` for a `mailto:` with no recipient. This collapses bucket 3 (6).

With those three in place, re-run over EPVME and re-triage; only then is a
recurring EPVME regression gate worth building. The hermetic `--repo-root .`
nightly stays unchanged in the meantime.

## Bearing on the #529 keep/kill retro

The oracle *did* find something real — not a sanitizer bug, but three concrete
faithfulness gaps in its own comparison layer that curated fixtures could not
reach. That argues **keep**, conditional on the hardening above landing so the
allowlist stays small and the HARD channel is trustworthy.
