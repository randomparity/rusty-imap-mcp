# Differential HTML Oracle — Corpus Wave-1 Baseline

Restated keep/kill baseline for the differential HTML→text sanitizer oracle
(issue #529) over the **wave-1** external corpus (issue #551, design
[`2026-07-10-oracle-corpus-expansion-design.md`](../superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md)),
captured **July 11, 2026**. This is the first nightly over the pinned wave-1
corpus; it sets the `--corpus-min-compared` floor and the per-wave keep/kill
numbers that the nightly enforces from here on.

All figures below are the **`corpus/`-prefixed** counts (never the global
totals). The in-repo fuzz/injection seeds are excluded so the baseline cannot be
propped up by the tame in-repo corpus — the whole point of the per-prefix count
(design Component 2).

## Pinned corpus

- Repo: `randomparity/rusty-imap-mcp-corpus` (private)
- Pinned SHA: `8387292061098d1299aa504cffb7be0a5bcb4dde` (wave-1 ingestion)
- Inputs: **454** — 402 html5lib-tests, 14 email templates, 38 synthetic
  (all MIT/permissive, PII-free). Generated deterministically; see that repo's
  `tools/ingest/README.md`.

## How to reproduce

```bash
# Check out the corpus at the pinned SHA (nightly does this into corpus/).
git clone git@github.com:randomparity/rusty-imap-mcp-corpus.git corpus
git -C corpus checkout 8387292061098d1299aa504cffb7be0a5bcb4dde

cargo run --locked --manifest-path html-oracle/Cargo.toml -- \
  --repo-root . --corpus-root corpus --corpus-min-compared 338 \
  --report /tmp/wave1.json
```

## Results (corpus/-prefixed)

| Metric | Value |
| --- | --- |
| corpus_total | 454 |
| corpus_skipped | 1 (the `binary-part` canary, via `is_mostly_binary`) |
| corpus_ref_error | 0 |
| corpus_compared_nonempty | 376 |
| comparable denominator (`total − skipped − ref_error`) | 453 |
| coverage (`compared_nonempty / comparable`) | **83.0 %** |
| non-allowlisted HARD | **0** |
| allowlist entries | **0** |
| canary families healthy | 3/3 (stray-tag-boundary, entity-href, binary-part) |

## Keep/kill evaluation (restated per-wave rule)

The #529 absolute "< 10 allowlist entries" bar is restated as a corpus-relative
rule with an absolute floor (design Component 5). Every figure is the
`corpus/`-prefixed count above.

| KEEP criterion | Bar | This wave | Verdict |
| --- | --- | --- | --- |
| allowlist entries | ≤ `max(5, 0.5 % × 376)` = **5** | 0 | ✅ |
| allowlist growing week-over-week | no | n/a (first wave) | ✅ |
| non-allowlisted HARD | 0 | 0 | ✅ |
| coverage | ≥ 60 % | 83.0 % | ✅ |

**Verdict: KEEP.** No exemption needed — coverage clears the fixed 60 % floor and
the allowlist is empty.

## Triage

The wave-1 nightly produces **0 HARD** and needs **0 allowlist entries**. During
ingestion the html5lib corpus surfaced a class of *benign* divergences where the
streaming `lol_html` reference cannot match production's full html5ever tree
construction — foster-parenting / adoption-agency text merges, `<frameset>`
character-data discarding, NUL→U+FFFD replacement, and `<plaintext>` streaming
errors. In every case production loses **no** visible text (it merges or
replaces-with-U+FFFD, never silently drops), so none is a sanitizer bug. These
are curated out at corpus-repo ingestion (documented, reproducible, keyed by
reason) rather than suppressed per-input here — the runtime `corpus-allowlist.toml`
stays empty, which is the healthy state. Had any divergence been a real silent
drop it would have been filed as a bug and its input removed, never allowlisted.

## Floor

`--corpus-min-compared N = floor(0.9 × 376) = 338`, wired into
`.github/workflows/nightly-html-oracle.yml`. The 10 % headroom absorbs a routine
single prune/promotion; a pinned-SHA bump that silently drops a large fraction of
corpus comparisons still trips the floor. Recompute `N` in the same reviewed
SHA-bump PR whenever a wave or a batch of promotions/prunes materially shifts the
comparison count.
