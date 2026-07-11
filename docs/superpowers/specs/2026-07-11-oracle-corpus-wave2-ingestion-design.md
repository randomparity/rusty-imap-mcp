# Oracle corpus — Wave 2 ingestion (filtered public corpora)

- **Issue:** [#554](https://github.com/randomparity/rusty-imap-mcp/issues/554)
- **Parent design (source of truth for the staged-wave model):**
  [2026-07-10-oracle-corpus-expansion-design.md](2026-07-10-oracle-corpus-expansion-design.md)
  — Component 4 "Wave 2 — filtered public corpora" and Component 5 "per-wave
  allowlist re-baselining".
- **ADR:** [ADR-0005](../../ADR/0005-wave2-corpus-sourcing.md) (download-at-build
  pinned-by-hash sourcing + text-node scrub for real mail).
- **Depends on (all merged):** #549 (corpus repo + validator + `validate.yml`),
  #550 (`--corpus-root` + `corpus-allowlist.toml` + pinned-SHA nightly checkout),
  #551 (Wave 1: 454 inputs, `--corpus-min-compared 338`, pinned SHA `c9e9217`).

## Summary

Grow the differential HTML-oracle corpus with a second wave drawn from **real
public email corpora** (Enron, SpamAssassin, Nazario phishing), so the oracle
diffs production's `test_support::sanitize_html` against real-world adversarial
and messy email HTML rather than only synthetic and spec-derived inputs. The
Wave-2 generator lives in the **private corpus repo** under `tools/ingest/`; it
**downloads each upstream archive at build time, verifies a pinned SHA-256**,
filters to HTML-bearing messages, applies a structure-preserving text-node PII
scrub, deduplicates by the existing tree-wide structural fingerprint, caps the
result, and writes `wave2/`. The main repo then bumps the pinned corpus SHA,
triages every HARD to zero non-allowlisted, recomputes the
`--corpus-min-compared` floor over the combined corpus, and commits a restated
per-wave baseline note.

## Goals

- Ingest a bounded (~200–300) set of **structurally distinct** real-mail HTML
  inputs, each reproducibly derived from a hash-pinned upstream archive.
- Every input carries first-class provenance (`redistribution_basis`,
  attribution where the source license requires it) and a recorded PII scrub.
- The generator is deterministic (`--check` byte-identical, offline-after-cache).
- The combined nightly stays green: 0 non-allowlisted HARD, recomputed floor,
  restated baseline.

## Non-goals

- **Wave 3** (scrubbed personal mail) — its own issue; gated on the full scrub
  tooling and a repo-visibility decision. Wave 2 introduces only a *light*
  text-node redactor, not the general scrub framework.
- **Promotion** of any Wave-2 divergence into the curated
  `tests/injection-corpus/` assertion tier — that path is per-divergence.
- **Changing the oracle or validator contracts.** Wave 2 uses the existing
  `redistribution_basis` / `scrub` / `probes` schema slots as-is and adds **no**
  validator change — comment redaction is folded under the existing `SCRUB_STEPS`
  labels rather than adding a `comments-redacted` value (see "meta.toml contract"
  and "Validator facts confirmed").

## Sources

All three are download-at-build, each pinned by a recorded SHA-256, each
`redistribution_basis = "research-corpus"`. Exact URLs + hashes are recorded in
`tools/ingest/sources.toml` at build time; the table names the intended artifact.

| Source | Pinned artifact | Redistribution | Notes |
|---|---|---|---|
| **Enron** | `enron_mail_20150507.tar.gz` (~423 MB), `https://www.cs.cmu.edu/~enron/` | public (FERC release) → `research-corpus` | Mostly plaintext; HTML-bearing messages are the minority we filter to. |
| **SpamAssassin** | `https://spamassassin.apache.org/old/publiccorpus/*.tar.bz2` (spam / spam_2 / hard_ham as needed) | public research corpus → `research-corpus` | Spam sets are HTML-rich with evasion markup. |
| **Nazario** | raw `.mbox`, pinned **git-mirror commit URL** (GitHub-raw at an immutable commit) + SHA-256 | **CC-BY-4.0** → `research-corpus`, **attribution required** | Canonical `monkey.org` is flaky; an immutable commit URL is more reproducible. Attribution (Jose Nazario, CC-BY-4.0) recorded in `meta.toml`. |

**Drop rule.** If a source cannot be fetched from a stable pinned URL, cannot
have its SHA-256 recorded, or cannot be cleared for (private-repo) redistribution,
that source is **dropped, logged, and the wave ships without it** — never
force-added or silently substituted. Nazario's CC-BY-4.0 removes the expected
blocker, but the rule stands for all three.

## Architecture (corpus repo, `tools/ingest/`)

Mirrors Wave 1: the generator runs **locally** to produce `wave2/`; the committed
tree is what `validate.yml` gates. **No network runs in CI** — CI only validates
already-committed bytes. New modules:

- **`build_wave2.py`** — entry point. Orchestrates
  fetch → iterate → filter → scrub → wrap → fingerprint-dedup → cap → write,
  with a `--check` mode that regenerates `wave2/` and fails on any byte drift.
  Reuses **only** the small, stable pieces of `build_wave1`/`validate` by import
  (`build_wave1._encode_body` for CRLF-clean **base64** payloads — the CTE Wave 1
  uses; `validate.html_part_texts` + `validate.structural_fingerprint` so the
  generator's dedup scope is byte-identical to the validator's criterion-6 check).
  It writes its **own** `.eml` assembly, `meta.toml`, `wave2/` tree writer, and
  `--check` diff — it does **not** reuse `build_wave1.build_eml` (takes a
  wave-1 `Candidate`) or `build_wave1.write_tree` (hardcoded to `wave1/`), and
  makes **no** change to `build_wave1.py`.
- **`sources.py`** — per-source fetch: download the pinned URL to a gitignored
  `tools/ingest/.cache/`, **verify the recorded SHA-256 before any use**
  (hard-fail on mismatch), then iterate the archive/mbox **in memory in archive
  order** (`tarfile`/`mailbox`; never extract-then-`os.walk`) and yield messages
  carrying ≥1 `text/html` part. Sources are processed in a fixed order (see
  §"Selection").
- **`scrub.py`** — deterministic, structure-preserving text-node redactor
  (see below).
- **`sources.toml`** — reproducibility manifest: per source `url`, `sha256`,
  human description, `redistribution_basis`, attribution, and the selection
  parameters (per-source cap).

## Pipeline (per candidate message)

1. **Extract** the message's `text/html` part(s), decoded to text via the
   declared charset (as Wave 1 did for templates).
2. **Scrub** PII patterns across the whole decoded HTML source (below); markup
   structure is preserved (only text/value/comment content is rewritten).
3. **Wrap** the scrubbed HTML as a fresh CRLF `.eml` (`text/html; charset=utf-8`,
   **base64** CTE via `build_wave1._encode_body`, as Wave 1 does), then compute the
   **content-hash stem** over the final `.eml` bytes.
4. **Fingerprint** exactly as the validator's criterion 6 does —
   `structural_fingerprint("\x1e".join(html_part_texts(eml_bytes)))` over the
   **built** `.eml` (not the raw scrubbed html), so the generator's dedup scope
   matches the validator byte-for-byte; **drop** if the fingerprint already exists
   **tree-wide** — the seen-set is preloaded from all 454 Wave-1 inputs (their
   `.eml` fingerprinted the same way) and grows across the Wave-2 run. This enforces validator
   criterion 6 (tree-wide structural uniqueness) at generation time and prevents
   a real newsletter skeleton from colliding with a Wave-1 template. Dedup is
   **keep-first** over a fully-deterministic traversal (see §"Determinism").
5. **Select** per §"Selection".

### Scrub design (`scrub.py`)

**Scope: the whole decoded HTML source, not text nodes only.** The validator's
`scan_pii` scans `html_part_texts`, which is `raw.decode(charset)` of each
`text/html` part — i.e. the **entire HTML source** including attribute values,
`mailto:`/`tel:` hrefs, tracking-URL query strings, and comments (validate.py
`html_part_texts` / `scan_pii`). Real Enron/SpamAssassin/Nazario mail carries
real addresses and phone numbers in exactly those markup positions — a genuine
PII leak, not merely a validator-WARN. So the redactor operates over the full
decoded HTML string, redacting three PII patterns to fixed placeholder tokens
**wherever they occur** (text, attribute values, comments):

- email → `[redacted-email]`, North-American phone → `[redacted-phone]`, long
  digit run (≥7) → `[redacted-number]`. The tokens do not match the validator's
  `_EMAIL_RE` / `_PHONE_RE`, so a complete redaction of *literal-form* PII yields
  **zero** `9-pii` WARN.

- **Node-scoped, structure-preserving by construction.** The redactor does **not**
  regex over the raw source string — a phone/long-digit class includes `\s` and
  `-`, which are themselves HTML structural delimiters (unquoted-attribute
  whitespace, the comment terminator `-->`), so a raw-source match could span a
  boundary and silently delete an attribute name or eat a `-->` on exactly the
  messy adversarial markup Wave 2 ingests. Instead it redacts **within each parsed
  content span in isolation** — text runs, individual quoted attribute *values*,
  and comment inner content — via a structure-aware tokenization that tiles the
  source exactly into markup vs content, so a match is confined to one span and
  can never consume a markup delimiter, tag name, or attribute name. Exact tiling
  is proven by a byte-identity test (a PII-free input round-trips unchanged).
  Because `structural_fingerprint` hashes the tag/attr-**name** sequence and
  **ignores attribute values** (validate.py `structural_fingerprint` /
  `_StructureCollector`), the fingerprint is invariant under this node-scoped
  scrub. (This is *not* the ADR-0005-rejected text-node-only scrub: attribute
  values and comments are in scope; only the *span* a regex may consume is
  node-local.)

- **Oracle-neutral.** Both production and the reference sanitizer see the same
  redacted input, so a dropped `[redacted-email]` (in text *or* an `href`) is as
  detectable as a dropped address; redacting a PII *substring* of an attribute
  value leaves the `href`/`src` token itself intact and comparable.

- **Deterministic + edge cases.** Fixed regexes, fixed tokens, no RNG → the
  content-hash stem is stable and `--check` is byte-identical. Node-scoping plus a
  guard against corrupting numeric character references (a digit run preceded by
  `&#`/`&#x` is left intact) covers the known hazards; the fixtures in "Testing"
  assert `structural_fingerprint` invariance for a digit run adjacent to `-->`,
  inside a comment, and separating two unquoted attributes.

Recorded as `scrub = ["text-nodes-redacted", "attr-values-redacted"]` — the two
`SCRUB_STEPS` labels validate.py defines for redacted content. Comment content is
also redacted, but `SCRUB_STEPS` has no `comments-redacted` value, so it is folded
under these two labels (over-scrubbed relative to the label, never under); `notes`
records that redaction spans text, attribute values, **and** comments so a future
auditor is not misled by the label. This activates the validator's advisory
PII scan (`scan_pii` skips `["none"]` inputs). Because the redaction and the scan
share the whole decoded-source scope, a residual `9-pii` WARN is a real
**literal-form** redactor miss (not expected markup noise) — but see the
entity-obfuscation blind spot below: **zero `9-pii` WARN does not prove zero
committed PII.**

**Entity-obfuscation blind spot.** `scan_pii` runs `_EMAIL_RE` over the raw
decoded source *without* char-ref conversion, so an entity-obfuscated address
(`joe&#64;x.com`, where `&#64;` is `@`) — a standard spam/phishing evasion,
present in the very Nazario/SpamAssassin sources here — matches neither the
scanner nor a literal-form redactor. The redactor therefore **detects on a
char-ref-decoded view of each node** (redacting the raw entity span when its
decoded form matches PII) as a first line, but this cannot be assumed complete.
**Human PR review of every Wave-2 ingestion is the backstop for entity-encoded
PII, and any future public-repo flip must re-scrutinize these inputs rather than
trust the machine scan.**

## Selection

Structural-fingerprint dedup already guarantees every kept input is a distinct
skeleton, so selection among survivors is secondary to the dedup. Rule:

- Within each source, sort unique-skeleton candidates by content-hash stem
  (stable, unbiased) and take up to a **per-source cap**.
- Caps: **Enron ≤ 100, SpamAssassin ≤ 120, Nazario ≤ 80**, global **≤ 300**.
  Spam/phishing HTML stresses a sanitizer harder than benign corporate mail, so
  they get the larger share; if a source yields fewer unique skeletons, take what
  exists. The caps are a **ceiling, not a target**: because the fingerprint is
  tag/attr-name-only, template-heavy real mail dedups hard, so **structural
  diversity — not the cap — is the binding limit** and the actual yield may be
  well below 300. The generator logs per-source kept/dropped counts; a genuinely
  small yield is recorded in the baseline note (with a lower `N`), not forced up.
- Fully deterministic (no RNG). Caps live in `sources.toml`, so a re-baseline can
  adjust them in a reviewed change.

**Source-processing order (adversarial-first).** The tree-wide seen-set is shared
across sources, so whichever source is processed first claims any skeleton common
to several (e.g. a marketing-table layout in both Enron and spam). To make the
cap-weighting intent (§ above) an outcome rather than an accident of order,
sources are processed in a **fixed, documented order that favors the
higher-signal sources: SpamAssassin → Nazario → Enron.** A cross-source skeleton
collision therefore resolves toward the adversarial source, and Enron (benign,
largest) fills only the residual. The order is recorded in `sources.toml`.

Inputs are written under `wave2/{enron,spamassassin,nazario}/<stem>.eml` +
`<stem>.meta.toml`. Wave subdirectories are cosmetic to the oracle (it walks the
whole tree); they organize provenance and per-source review.

## Determinism

`--check` byte-identity rests on the *entire* traversal being a pure function of
the pinned archive bytes. Determinism comes from a **fully-ordered traversal**,
not from an order-independent tie-break:

- **In-archive iteration only.** `sources.py` iterates each source **in memory in
  archive order** — `tarfile`/`mailbox` member order — and **never** extracts to
  disk and `os.walk`s it (a filesystem walk yields platform-dependent order).
- **One total candidate order:** fixed source order (SpamAssassin → Nazario →
  Enron) then in-archive order within each source. Keep-first over this total
  order picks a deterministic winner for **every** fingerprint collision — both
  cross-source (resolves to the earlier source) and within-source structural
  duplicates, which are *common* in spam blasts (many messages share a skeleton
  with differing text → same fingerprint, different content-hash stems). The
  first in traversal order wins; the final per-source stem sort orders the written
  set.
- **`--check` is a plain regeneration byte-identity check** — regenerate `wave2/`
  from the cached pinned archives and assert zero diff. (No shuffle-invariance
  claim: keep-first is order-*dependent* by design, so the guarantee is "same
  pinned bytes + same traversal ⇒ same tree," not "any candidate order ⇒ same
  tree.")

## `meta.toml` contract (Wave 2)

Per input: `redistribution_basis = "research-corpus"` (not an SPDX `license`);
**`redistribution_note`** (non-empty — the validator's `redistribution_basis`
branch requires it; records the per-source basis, e.g. the CC-BY-4.0 attribution
for Nazario or the public-release basis for Enron/SpamAssassin); `source`,
`source_url`, `notes` (non-empty; `notes` records the filter and the scrub scope
text+attr+comments); `wave = 2`; ISO `added`;
`scrub = ["text-nodes-redacted", "attr-values-redacted"]` (the two `SCRUB_STEPS`
labels available; comment redaction is folded under them and spelled out in
`notes`); `probes = []` (Wave-2 inputs are not canaries).

**Canaries.** Criterion 8 is tree-wide and already satisfied by Wave 1's three
families; Wave 2 adds none. Validation must still show all three families present
tree-wide after `wave2/` lands.

## Main-repo re-baseline (Component 5)

1. Bump the pinned SHA in `.github/workflows/nightly-html-oracle.yml` to the
   merged Wave-2 corpus commit; run the oracle over the **combined** corpus
   locally.
2. Triage **every** HARD: real sanitizer silent-drop → file a bug + drop the
   input (never allowlist); systemic comparison-layer noise → flag it; benign
   per-input quirk → one `corpus-allowlist.toml` entry with a required `reason`.
   Re-run until 0 non-allowlisted HARD.
3. Recompute `N = floor(0.9 × corpus_compared_nonempty)` over the combined
   corpus; update `CORPUS_MIN_COMPARED`.
4. Write `docs/security/html-oracle-corpus-wave2-baseline.md` recording allowlist
   size, `compared_nonempty`, comparable denominator, non-allowlisted HARD (0),
   coverage %, restated KEEP bar (`max(5, 0.5% × compared_nonempty)`; coverage
   ≥ 60% floor; below-60% → recorded exemption, not auto-KILL).

**Coverage expectation (from Wave 1's key learning).** Wave 1's streaming
`lol_html` reference could not compare most html5lib tree-construction cases,
forcing heavy curation. Real mail is expected to hit far less of that pathology,
so coverage should *rise* — but the **actual oracle run is the gate**, not this
expectation. If coverage instead drops below 60%, the baseline note records
whether that is a legitimate reference-limitation or a real defect.

## Error handling & failure modes

- **Archive SHA-256 mismatch → hard fail.** Never build from unverified bytes; a
  changed upstream must be re-pinned in a reviewed change.
- **Source URL dead / archive unfetchable → drop that source** (logged), don't
  substitute.
- **PII scan WARN** on a Wave-2 input → a real redactor miss (the scan and the
  redaction share whole-source scope) → **extend `scrub.py`** until the WARN
  clears; never suppress it and never allowlist the input.
- **Structural collision with Wave 1** → the input is dropped at generation, so
  the combined tree never violates criterion 6.
- **Malformed / unparsable source message** → skipped (a corpus of hundreds
  need not ingest every message); the count of skipped-unparsable is logged so a
  silent mass-skip is visible.
- **`--check` drift** → non-zero exit; the generator is not reproducible and the
  change is rejected.

## Testing

Corpus repo (pure-stdlib Python ≥3.11, `unittest`, mirroring the validator's
tests):

- `scrub.py`: redaction is complete (all three patterns in text, attribute
  values, and comments), **structure-preserving** (tag/attr-name bytes unchanged;
  `structural_fingerprint` invariant), **idempotent**, and deterministic; a
  scrubbed body produces no `9-pii` WARN. Fixtures asserting `structural_finger`
  `print` invariance (the node-scoping guarantee): a ≥7-digit run **adjacent to a
  comment terminator** (`<!--1234567-->`), **inside** a comment, and **separating
  two unquoted attributes** (`<td width=123 4567>`); plus `mailto:`/`tel:` href, a
  literal `<` in text, a `<style>` block, and a numeric character reference
  (`&#1234567;`) left intact. One fixture asserts an **entity-obfuscated** address
  (`joe&#64;x.com`) is detected via the decoded view.
- `sources.py`: SHA-256 verification accepts a matching archive and **hard-fails**
  a mismatch (mocked bytes — no network in tests); HTML-bearing filter selects
  only messages with a `text/html` part; iteration follows in-archive order.
- Tree-wide dedup: a candidate whose fingerprint matches a Wave-1 input is
  dropped; a cross-source collision resolves to the fixed-order winner.
- `build_wave2.py --check` determinism: a **regeneration byte-identity** test
  (re-run from the cached pinned archives, assert zero diff) and an
  order-*dependent* survivor assertion (two within-source messages sharing a
  `structural_fingerprint` but differing in content-hash stem → the
  archive-order-first one is the one written).

Main repo: the oracle run over the combined corpus is the integration gate; the
baseline note records the numbers. No Rust code changes are expected (workflow +
docs + `corpus-allowlist.toml`/floor only).

## Security considerations

- **Malware-inert.** The corpus is HTML text the oracle sanitizes but never
  renders or executes; worst case from a hostile input is a false HARD (noisy,
  self-announcing), never RCE/exfiltration (parent design threat model).
- **PII.** Real mail carries PII in both rendered text and markup (`mailto:`
  hrefs, tracking URLs, comments); the node-scoped whole-scope scrub + the
  activated advisory scan + human review of the ingestion PR are the layered
  mitigation. The machine scan catches **literal-form** PII; **entity-obfuscated**
  PII (`&#64;` for `@`) is a known blind spot the redactor mitigates via a
  char-ref-decoded detection view but human review must backstop. The repo stays
  **private**; a future public flip is its own reviewed decision that must
  re-scrutinize these inputs, not trust the scan.
- **Download trust.** Build-time downloads are pinned by SHA-256; a compromised
  mirror cannot change the committed bytes without a hash mismatch that hard-fails
  the build. CI never downloads — it validates committed bytes at a pinned SHA.
- **License contamination.** `redistribution_basis` provenance is validated per
  input; Nazario's CC-BY-4.0 attribution is recorded. Anything unclearable is
  dropped, not force-added.

## Validator facts confirmed (design-time, against current `validate.py`)

Confirmed by reading the current `validate.py` so no schema surprise surfaces
after generating 300 files:

- **`scan_pii` scope:** scans `html_part_texts` = `raw.decode(charset)` of each
  `text/html` part — the **whole HTML source**, not rendered text nodes. This is
  what forces the whole-source scrub scope above.
- **`structural_fingerprint`:** hashes the tag/attr-**name** sequence and
  **ignores attribute values** (`for name, _value in attrs`), so PII-substring
  redaction of values/text/comments leaves the fingerprint invariant.
- **`SCRUB_STEPS`** includes `text-nodes-redacted` and `attr-values-redacted`;
  **`REDISTRIBUTION_BASES`** includes `research-corpus`.
- **Provenance branch requires `redistribution_note`.** `_validate_provenance_basis`
  takes the `redistribution_basis` branch whenever that key is present and then
  **hard-requires a non-empty `redistribution_note`** (Wave 1 never hit this — it
  used the `license` branch). Every Wave-2 `meta.toml` must carry it. The plan's
  first task re-confirms the full Wave-2 meta (incl. `redistribution_note`,
  `probes = []`) validates clean before authoring.

## Acceptance criteria

- [ ] Wave-2 inputs under `wave2/` pass `validate.yml` (content-hash stems,
      CRLF-exact, ≥1 `text/html` part, `redistribution_basis` provenance,
      `scrub = ["text-nodes-redacted", "attr-values-redacted"]` with **zero**
      residual `9-pii` WARN, tree-wide structural + stem uniqueness); all three
      canary families still present tree-wide.
- [ ] Generator deterministic (`--check` byte-identical) and sources each archive
      by pinned SHA-256; `sources.toml` records url+hash+basis+attribution;
      un-clearable/unfetchable sources dropped.
- [ ] First nightly over the combined pinned corpus green: HARDs triaged to 0
      non-allowlisted; `corpus-allowlist.toml` + recomputed `--corpus-min-compared`
      populated from it.
- [ ] Restated baseline note committed under `docs/security/`
      (`html-oracle-corpus-wave2-baseline.md`).
