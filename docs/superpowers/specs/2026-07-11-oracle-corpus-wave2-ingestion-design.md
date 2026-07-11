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
  `redistribution_basis` / `scrub` / `probes` schema slots as-is. (One optional
  validator touch is called out under "Open validator question".)

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
  fetch → iterate → filter → scrub → wrap → fingerprint-dedup → cap → `write_tree`,
  with a `--check` mode that regenerates `wave2/` and fails on any byte drift.
  Reuses Wave 1's `build_eml`, `_encode_body` (CRLF-exact CTE selection),
  content-hash stem, and `write_tree` by **importing** them from `build_wave1`
  (no behavior-changing refactor of `build_wave1.py`; a post-change
  `build_wave1.py --check` guards Wave-1 byte-identity).
- **`sources.py`** — per-source fetch: download the pinned URL to a gitignored
  `tools/ingest/.cache/`, **verify the recorded SHA-256 before any use**
  (hard-fail on mismatch), then iterate the archive/mbox and yield messages
  carrying ≥1 `text/html` part.
- **`scrub.py`** — deterministic, structure-preserving text-node redactor
  (see below).
- **`sources.toml`** — reproducibility manifest: per source `url`, `sha256`,
  human description, `redistribution_basis`, attribution, and the selection
  parameters (per-source cap).

## Pipeline (per candidate message)

1. **Extract** the message's `text/html` part(s), decoded to text via the
   declared charset (as Wave 1 did for templates).
2. **Scrub** text-node content (below); markup is byte-preserved.
3. **Wrap** the scrubbed HTML as a fresh CRLF `.eml` with a chosen charset
   (UTF-8) and CTE (7bit if ASCII-clean, else quoted-printable or base64 — the
   Wave-1 `_encode_body` rule), then compute the **content-hash stem** over the
   final `.eml` bytes.
4. **Fingerprint** with the validator's `structural_fingerprint`; **drop** if the
   fingerprint already exists **tree-wide** — the seen-set is preloaded from all
   454 Wave-1 inputs and grows across the Wave-2 run. This enforces validator
   criterion 6 (tree-wide structural uniqueness) at generation time and prevents
   a real newsletter skeleton from colliding with a Wave-1 template.
5. **Select** per §"Selection".

### Scrub design (`scrub.py`)

- Redacts, **within text nodes only**, three PII patterns to fixed placeholder
  tokens: email address → `[redacted-email]`, North-American phone →
  `[redacted-phone]`, long digit run (≥7 digits) → `[redacted-number]`. Tokens
  are the same strings the validator's `_EMAIL_RE` / `_PHONE_RE` will *not*
  match, so a clean scrub yields no advisory `9-pii` WARN.
- **Structure-preserving:** all markup bytes (tags, attribute names *and values*,
  comments, doctype) pass through **verbatim**; only rendered text-node content is
  rewritten. The `structural_fingerprint` (tag/attr-name sequence) is therefore
  invariant under scrub, and the oracle still probes the true tokenizer shape.
- **Deterministic:** fixed regexes, fixed replacement tokens, no RNG — so the
  content-hash stem is stable and `--check` is byte-identical.
- **Oracle-neutral:** because both production and the reference sanitizer see the
  same scrubbed text, text-drop detection is unaffected (a dropped
  `[redacted-email]` is as detectable as a dropped address).

Recorded as `scrub = ["text-nodes-redacted"]`, which activates the validator's
advisory PII scan (`scan_pii` skips `["none"]` inputs) as a backstop against a
missed pattern.

## Selection

Structural-fingerprint dedup already guarantees every kept input is a distinct
skeleton, so selection among survivors is secondary to the dedup. Rule:

- Within each source, sort unique-skeleton candidates by content-hash stem
  (stable, unbiased) and take up to a **per-source cap**.
- Caps: **Enron ≤ 100, SpamAssassin ≤ 120, Nazario ≤ 80**, global **≤ 300**.
  Spam/phishing HTML stresses a sanitizer harder than benign corporate mail, so
  they get the larger share; if a source yields fewer unique skeletons, take what
  exists.
- Fully deterministic (no RNG). Caps live in `sources.toml`, so a re-baseline can
  adjust them in a reviewed change.

Inputs are written under `wave2/{enron,spamassassin,nazario}/<stem>.eml` +
`<stem>.meta.toml`. Wave subdirectories are cosmetic to the oracle (it walks the
whole tree); they organize provenance and per-source review.

## `meta.toml` contract (Wave 2)

Per input: `redistribution_basis = "research-corpus"` (not an SPDX `license`);
`source`, `source_url`, `notes` (non-empty; `notes` records the filter, the
scrub, and — for Nazario — the CC-BY-4.0 attribution); `wave = 2`; ISO `added`;
`scrub = ["text-nodes-redacted"]`; `probes = []` (Wave-2 inputs are not canaries).

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
- **PII scan WARN** on a Wave-2 input → the redactor missed a pattern → fix
  `scrub.py`, never suppress the warning.
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

- `scrub.py`: redaction is complete (all three patterns), structure-preserving
  (markup bytes unchanged; fingerprint invariant), idempotent, and deterministic;
  a scrubbed body produces no `9-pii` WARN.
- `sources.py`: SHA-256 verification accepts a matching archive and **hard-fails**
  a mismatch (mocked bytes — no network in tests); HTML-bearing filter selects
  only messages with a `text/html` part.
- Tree-wide dedup: a candidate whose fingerprint matches a Wave-1 input is
  dropped.
- `build_wave2.py --check` determinism over a small fixture archive.

Main repo: the oracle run over the combined corpus is the integration gate; the
baseline note records the numbers. No Rust code changes are expected (workflow +
docs + `corpus-allowlist.toml`/floor only).

## Security considerations

- **Malware-inert.** The corpus is HTML text the oracle sanitizes but never
  renders or executes; worst case from a hostile input is a false HARD (noisy,
  self-announcing), never RCE/exfiltration (parent design threat model).
- **PII.** Real mail carries PII; the text-node scrub + the activated advisory
  scan + human review of the ingestion PR are the layered mitigation. The repo
  stays **private**; a future public flip is its own reviewed decision and would
  re-scrutinize these inputs.
- **Download trust.** Build-time downloads are pinned by SHA-256; a compromised
  mirror cannot change the committed bytes without a hash mismatch that hard-fails
  the build. CI never downloads — it validates committed bytes at a pinned SHA.
- **License contamination.** `redistribution_basis` provenance is validated per
  input; Nazario's CC-BY-4.0 attribution is recorded. Anything unclearable is
  dropped, not force-added.

## Open validator question (resolve in the plan)

Wave 1 asserted the validator accepts `probes = []` and
`redistribution_basis = "research-corpus"` for a non-canary input. The plan's
first task **confirms both against the current `validate.py`** (reading
`_validate_scrub`, the provenance check, and the `probes` shape check) before any
input is authored, so a schema surprise is caught at design time, not after
generating 300 files.

## Acceptance criteria

- [ ] Wave-2 inputs under `wave2/` pass `validate.yml` (content-hash stems,
      CRLF-exact, ≥1 `text/html` part, `redistribution_basis` provenance,
      `scrub = ["text-nodes-redacted"]` with no `9-pii` WARN, tree-wide
      structural + stem uniqueness); all three canary families still present
      tree-wide.
- [ ] Generator deterministic (`--check` byte-identical) and sources each archive
      by pinned SHA-256; `sources.toml` records url+hash+basis+attribution;
      un-clearable/unfetchable sources dropped.
- [ ] First nightly over the combined pinned corpus green: HARDs triaged to 0
      non-allowlisted; `corpus-allowlist.toml` + recomputed `--corpus-min-compared`
      populated from it.
- [ ] Restated baseline note committed under `docs/security/`
      (`html-oracle-corpus-wave2-baseline.md`).
