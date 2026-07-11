# Differential HTML Oracle — Corpus Wave-2 Baseline

Restated keep/kill baseline for the differential HTML→text sanitizer oracle
(issue #529) over the **combined wave-1 + wave-2** external corpus (issue #554,
design
[`2026-07-11-oracle-corpus-wave2-ingestion-design.md`](../superpowers/specs/2026-07-11-oracle-corpus-wave2-ingestion-design.md)),
captured **July 11, 2026**. It supersedes the
[wave-1 baseline](html-oracle-corpus-wave1-baseline.md): the pinned SHA now
includes `wave2/`, and the `--corpus-min-compared` floor is recomputed over the
combined corpus.

All figures below are the **`corpus/`-prefixed** counts (never the global
totals). The in-repo fuzz/injection seeds are excluded so the baseline cannot be
propped up by the tame in-repo corpus — the whole point of the per-prefix count
(design Component 2).

## Pinned corpus

- Repo: `randomparity/rusty-imap-mcp-corpus` (private)
- Pinned SHA: `d90cafe938a2c1e2d5d99b9d37893c1ab1d0fb09` (wave-2 ingestion + PII
  hardening, PRs #3 + #4)
- Inputs: **654** — 454 wave-1 (unchanged) + **200 wave-2**:
  - 120 SpamAssassin public corpus, 80 Nazario phishing corpus (CC-BY-4.0).
  - All PII-scrubbed (node-scoped, text + attribute values + comments) behind a
    **fail-closed residual-PII drop gate** — the generator drops any input whose
    address/phone/SSN survives to a conformant-parser renderer-visible or
    fully-decoded projection (the validator's regex `9-pii` scan is not treated as
    proof of PII-freeness). `redistribution_basis = "research-corpus"`. Generated
    deterministically; see that repo's `tools/ingest/README.md`.
  - **Enron was evaluated and dropped** — the full ~517k-message corpus is 100%
    `text/plain` (0 HTML-bearing messages), so it contributes nothing to an
    HTML-sanitizer oracle.

## How to reproduce

```bash
# Check out the corpus at the pinned SHA (nightly does this into corpus/).
git clone git@github.com:randomparity/rusty-imap-mcp-corpus.git corpus
git -C corpus checkout d90cafe938a2c1e2d5d99b9d37893c1ab1d0fb09

cargo run --locked --manifest-path html-oracle/Cargo.toml -- \
  --repo-root . --corpus-root corpus --corpus-min-compared 517 \
  --report /tmp/wave2.json
```

## Results (corpus/-prefixed)

| Metric | Value |
| --- | --- |
| corpus_total | 654 |
| corpus_skipped | 1 (the `binary-part` canary, via `is_mostly_binary`) |
| corpus_ref_error | 0 |
| corpus_compared_nonempty | 575 |
| comparable denominator (`total − skipped − ref_error`) | 653 |
| coverage (`compared_nonempty / comparable`) | **88.1 %** |
| non-allowlisted HARD | **0** |
| allowlist entries | **0** |
| canary families healthy | 3/3 (stray-tag-boundary, entity-href, binary-part) |

## Keep/kill evaluation (restated per-wave rule)

The #529 absolute "< 10 allowlist entries" bar is restated as a corpus-relative
rule with an absolute floor (design Component 5). Every figure is the
`corpus/`-prefixed count above.

| KEEP criterion | Bar | This wave | Verdict |
| --- | --- | --- | --- |
| allowlist entries | ≤ `max(5, 0.5 % × 575)` = **5** | 0 | ✅ |
| allowlist growing week-over-week | no | 0 (was 0 at wave 1) | ✅ |
| non-allowlisted HARD | 0 | 0 | ✅ |
| coverage | ≥ 60 % | 88.1 % | ✅ |

**Verdict: KEEP.** No exemption needed — coverage clears the fixed 60 % floor and
the allowlist is empty.

## Triage

The wave-2 nightly produces **0 HARD** and needs **0 allowlist entries**. Adding
200 real-mail inputs (SpamAssassin spam + Nazario phishing) introduced **no**
sanitizer silent-drops and raised coverage from the wave-1 baseline's 83.0 % to
88.1 %.

This confirms the wave-1 keep/kill note's prediction: **real mail compares far
better than html5lib tree-construction.** Where wave-1's html5lib inputs were
dominated by cases the *streaming* `lol_html` reference could not compare (empty
reference or foster-parenting/frameset/NUL over-reporting — curated out at
ingestion), real spam and phishing HTML is exactly the comparable shape the
oracle wants: `compared_nonempty` rose from 376 to 575 (≈ +199, i.e. nearly all
200 new inputs became live comparisons), with zero benign or real divergences to
triage.

Had any wave-2 divergence been a real silent drop of browser-visible text it
would have been filed as a bug and its input removed, never allowlisted; the
runtime `corpus-allowlist.toml` stays empty, which is the healthy state.

## Floor

`--corpus-min-compared N = floor(0.9 × 575) = 517`, wired into
`.github/workflows/nightly-html-oracle.yml`. The 10 % headroom absorbs a routine
single prune/promotion; a pinned-SHA bump that silently drops a large fraction of
corpus comparisons still trips the floor. Recompute `N` in the same reviewed
SHA-bump PR whenever a wave or a batch of promotions/prunes materially shifts the
comparison count.
