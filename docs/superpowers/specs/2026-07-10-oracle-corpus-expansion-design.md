# HTML oracle corpus expansion — design

**Issue:** follow-up to [#529](https://github.com/randomparity/rusty-imap-mcp/issues/529)
(differential HTML→text sanitizer oracle)
· **Priority:** P3 · **Effort:** M · **Theme:** C (oracles, invariants,
meta-testing)

**Extends:**
`docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`
(the oracle itself) and its EPVME discovery run
(`docs/security/html-oracle-epvme-discovery.md`).

## Problem

The differential HTML oracle (#529) compares production's
`test_support::sanitize_html` against an independent `lol_html` reference and
red-flags **silent drops** — attacker-controlled text the sanitizer removes with
no explaining `SecurityWarning`. Its keep/kill retro criteria were calibrated
against a **33-input** in-repo corpus (`fuzz/corpus/content_html/` seeds +
`tests/injection-corpus/*/input.eml` HTML parts).

Two facts make that corpus too small to trust the nightly signal long-term:

1. **The in-repo corpus reports 0 HARD by construction.** The EPVME discovery
   run showed the curated fixtures never exercised stray-tag tree-construction
   differences, binary parts, or entity-bearing hrefs — the noise classes that
   dominate real mail. Those were surfaced only by pointing the oracle at ~48k
   external messages. The oracle's comparison layer is now hardened against them
   (`norm::tokenize` punctuation-trim, `is_mostly_binary` skip, faithful href
   entity-decode), but the *committed* corpus still can't reach those paths, so a
   regression in that hardening would pass the nightly unnoticed.

2. **EPVME cannot gate CI.** EPVME is a ~49k-message, ~170 MB external download
   that lives only on a developer's machine. It carries no committable license,
   contains unscrubbed real mail, and is a **manual run** (no CI job). The
   nightly hermetic `--repo-root .` job never sees it. So the only corpus CI
   *can* reproduce deterministically is the 33 tame in-repo inputs.

The gap: we need a **larger, license-clean, PII-scrubbed, version-pinned**
corpus that CI can check out and replay deterministically — big and varied
enough that the hardened HARD channel is exercised on every nightly, without
inheriting EPVME's licensing/PII/size problems.

## Goal

Stand up a dedicated, provenance-tracked corpus that the nightly oracle consumes
at a pinned commit, grown in three risk-ordered waves, with a curated promotion
path back into `tests/injection-corpus/` when a divergence proves interesting.

## Acceptance criteria

- [ ] A separate `rusty-imap-mcp-corpus` repository exists with: a README
  defining layout and contribution rules, a per-input `meta.toml` provenance
  format, and a self-validation CI that fails on a missing/invalid `meta.toml`,
  a non-allowlisted license, an unparsable `.eml`, an `.eml` with no
  `text/html` part, or a structural-fingerprint duplicate.
- [ ] The main-repo oracle runner accepts a `--corpus-root <dir>` flag that loads
  every `.eml` under a checked-out corpus tree via the existing
  `corpus::load_eml_tree` path, keyed under a `corpus/…` id prefix.
- [ ] The nightly workflow checks out `rusty-imap-mcp-corpus` at a **pinned
  commit SHA** and runs the oracle with `--corpus-root` against it.
- [ ] Wave 1 is ingested (html5lib-tests + open email templates + synthetic
  mutations) and the first nightly over it establishes a restated keep/kill
  baseline.
- [ ] The corpus contains at least one **canary input per hardening family**
  (stray-tag boundary, entity-bearing href, binary/mojibake part), tagged in
  `meta.toml`, and the nightly asserts each canary is in its **healthy state**
  (text-token families: ≥1 live comparison; binary-part: skipped by the
  `is_mostly_binary` guard) — so a regression in the comparison-layer hardening
  flips a canary and fails the nightly instead of passing unnoticed.
- [ ] The nightly report emits a **`corpus/`-prefixed comparison count**, and
  the run fails (or loudly warns) if it falls below an expected floor for the
  pinned SHA — the global inert tripwire is masked by the in-repo baseline and
  cannot detect an all-skipped corpus on its own.
- [ ] The #529 retro thresholds are restated as a corpus-size-relative rule with
  an absolute floor (the absolute "< 10 allowlist entries" bar was calibrated for
  33 inputs and degenerates at both small and large N).

## Grounding survey — reality this design binds to

- **The loader already supports external `.eml` trees.**
  `html-oracle/src/corpus.rs::load_eml_tree(dir, id_prefix, limit)` walks a
  directory tree (symlink-cycle-safe, sorted, deterministically `--limit`-capped),
  extracts each message's `text/html` parts exactly the way the injection corpus
  does (`extract_html_parts`), and keys ids as `<id_prefix>/<file-stem>`. It
  assumes stems are unique across the tree (content-hash filenames satisfy this).
  `--corpus-root` reuses this verbatim with `id_prefix = "corpus"`.
- **The runner already has the arg-plumbing and per-source allowlist pattern.**
  `main.rs::parse_args` handles `--repo-root`, `--report`, `--epvme-dir`,
  `--limit`. `assemble_inputs` appends an external tree when `--epvme-dir` is
  set. `assemble_allowlist(with_epvme)` merges `epvme-allowlist.toml` **only**
  when the EPVME tree is loaded, so its `epvme/…` entries never show stale in the
  hermetic run. `--corpus-root` follows this exact pattern with a
  `corpus-allowlist.toml`.
- **`--corpus-root` and `--epvme-dir` are distinct, coexisting inputs.** They are
  not the same dataset: EPVME is the giant local-only external download (manual
  triage, `docs/security/html-oracle-epvme-discovery.md`); the corpus repo is the
  committed, license-clean, CI-checkout-able tree. Both call `load_eml_tree` with
  different prefixes and different companion allowlists. This is **not** a
  replace-don't-deprecate violation: they are two different data sources with
  different provenance and CI availability, not two implementations of one thing.
- **Naming hazard:** `--repo-root` (the main checkout, source of in-repo seeds)
  and `--corpus-root` (the external corpus checkout) differ by one word and are
  both load-bearing. `--help`/usage text and the workflow step must name each
  explicitly; a swap silently loads the wrong tree.
- **The comparison layer is wild-corpus-hardened.** The EPVME discovery run
  (2 HARD / 47,876; 0 production silent-drop bugs) fixed the three systemic
  noise families. A curated corpus is therefore about **reproducible nightly
  signal on committed inputs**, not about discovering new noise classes — those
  are already handled.
- **The oracle only *reads* corpus bytes.** It decodes, tokenizes with `lol_html`
  and `scraper` (isolated-text decode only), and set-diffs tokens. It never
  executes, renders, or network-fetches an input. A hostile corpus input can at
  worst produce a false HARD (a nightly-red annoyance), never code execution —
  which bounds the blast radius of trusting an external corpus repo (see Threat
  model).
- **CRLF convention.** `tests/injection-corpus/README.md` requires `input.eml`
  to use CRLF terminators (header parsing depends on it) and excludes the corpus
  from EOL/whitespace/typo hooks. The corpus repo inherits the same rule and
  enforces it in self-validation.

## Non-goals

- **No change to the oracle's diff/reference/normalization logic.** This is
  corpus + plumbing only. Any divergence the bigger corpus surfaces is triaged
  under the existing #529 rules; a real sanitizer bug is fixed under its own
  issue.
- **No replacement of EPVME.** The manual `--epvme-dir` path and its docs stay.
  The corpus repo is additive.
- **No corpus content in the main repo.** The `.eml` bodies live in
  `rusty-imap-mcp-corpus`, consumed by checkout. Only the pinned SHA, the
  `--corpus-root` plumbing, and `corpus-allowlist.toml` live in the main repo.
- **No floating-ref checkout.** CI never tracks the corpus repo's default branch;
  it pins a SHA that a human bumps via a reviewed PR (supply-chain integrity).
- **No expected-output assertions in the corpus tier.** The corpus repo is
  inputs-only (no `expected.json`). Exact assertions live exclusively in the
  promoted `tests/injection-corpus/` tier.

## Design

### Two tiers, one promotion path

| Tier | Location | Contains | Grows by | Assertion |
| --- | --- | --- | --- | --- |
| **Oracle corpus** | `rusty-imap-mcp-corpus` (external repo) | inputs-only `.eml` + `meta.toml` | staged waves | differential (token set-diff vs reference) |
| **Curated fixtures** | `tests/injection-corpus/` (main repo) | `input.eml` + `expected.json` | **promotion** from a proven divergence | exact required/forbidden output + warning codes |

**Promotion trigger:** when a nightly HARD (or a notable SOFT) maps to a real,
reproducible sanitizer behaviour worth locking — either a fixed bug's regression
guard or a benign-but-load-bearing case — that single input is copied into a new
`tests/injection-corpus/<name>/` directory with a hand-authored `expected.json`
and registered in the snapshot suite. **The corpus-repo input is then removed**
(the assertion now lives in the durable tier). Removal is mandatory, not
optional: leaving it would compare the same content under two ids
(`corpus/<stem>` and `injection/<name>`), and any `corpus-allowlist.toml` entry
that suppressed a benign divergence is keyed by `corpus/<stem>` — so the
`injection/<name>` copy, with no matching key, would re-fire the very divergence
that was correctly allowlisted. The promotion checklist therefore includes,
in one reviewed SHA-bump PR: deleting the corpus `.eml`/`.meta.toml`, deleting
any now-orphaned `corpus-allowlist.toml` entry, and **recomputing
`--corpus-min-compared N`** from the post-removal baseline (a promotion removes
a live-comparing input, lowering the corpus comparison count — the floor's 10%
headroom covers a single removal, but a batch of promotions/prunes must
re-baseline `N` so the drop is not read as a floor breach).

**Retention asymmetry** (restating #529's "corpus only grows"): the **curated
tier only grows** — removing a fixture needs an explicit rationale, per
`tests/injection-corpus/README.md`. The **oracle tier may prune**
never-diverging inputs that add runtime but no signal; provenance in `meta.toml`
makes such pruning auditable.

### Component 1 — `rusty-imap-mcp-corpus` repository (follow-up issue A)

Layout:

```
rusty-imap-mcp-corpus/
├── README.md                    # layout, contribution + scrub rules, license policy
├── LICENSE                      # repo license; per-input licenses in meta.toml
├── .github/workflows/validate.yml   # self-validation CI
├── tools/validate/              # the validator (Python; see below)
├── wave1/
│   ├── html5lib/
│   │   ├── <stem>.eml
│   │   └── <stem>.meta.toml
│   ├── templates/
│   └── synthetic/
└── wave2/                       # added later (wave3 investigated + dropped — see Component 4)
```

- **One `.eml` + one sibling `<stem>.meta.toml` per input.** The `.eml` is a
  full RFC 822 message carrying ≥1 `text/html` part (so `load_eml_tree` yields
  at least one input). **Stems are the content hash of the `.eml`** (e.g. the
  hex SHA-256), which makes tree-wide stem uniqueness automatic (identical stem
  ⇒ identical bytes ⇒ a benign exact duplicate) — a `wave-source-NNN` scheme is
  *not* used, because a human could reuse `NNN` across waves and silently alias
  two different inputs to one oracle id.
- **CRLF terminators in every `.eml`** (same rule as the injection corpus).
- Wave subdirectories are cosmetic to the oracle (`load_eml_tree` walks the whole
  tree); they exist for human/provenance organization and per-wave validation.

#### `meta.toml` provenance format

```toml
# One per .eml. Every field below is REQUIRED; validation fails closed on any
# missing field (mirrors the oracle allowlist's "reason is required" rule).
source          = "html5lib-tests"        # dataset / template project / "synthetic"
source_url      = "https://github.com/html5lib/html5lib-tests"
wave            = 1                        # 1 | 2 | 3
added           = "2026-07-10"            # ISO date, provenance timeline
scrub           = ["none"]                # PII-redaction provenance; see below
probes          = ["stray-tag-boundary"]  # hardening families exercised; see below
notes           = "tokenizer test: adoption-agency stray </font></a>"

# Provenance basis — exactly ONE of these two is required, never both:
license         = "MIT"                    # SPDX id, for code-licensed sources
license_url     = "https://github.com/html5lib/html5lib-tests/blob/master/LICENSE"
# ...OR, for third-party real mail that carries no grantable code license
# (research corpora — wave 2; the `consent` basis went unused after wave 3 was dropped):
# redistribution_basis = "research-corpus"  # research-corpus | consent | synthetic
# redistribution_note  = "SpamAssassin public corpus, redistributable per its terms"

# `scrub` documents what was rewritten to remove PII, as an ordered list of
# applied steps. Allowed values:
#   "none"                 — pristine upstream sample, nothing rewritten
#   "text-nodes-redacted"  — visible text nodes replaced with placeholders
#   "attr-values-redacted" — attribute VALUES (href targets, addresses) replaced
# Structure (tag names, attribute NAMES, nesting) is NEVER rewritten — a scrub
# that changed structure would invalidate the sample as a tokenizer probe.
#
# `probes` (may be empty) tags which comparison-layer hardening families this
# input exercises, so the nightly can assert each family still gets ≥1 live
# comparison. Allowed values:
#   "stray-tag-boundary"   — stray/mismatched end tags (norm::tokenize trim path)
#   "entity-href"          — an href attribute value containing an HTML entity
#   "binary-part"          — a >10% U+FFFD part (is_mostly_binary skip path)
# An input may probe more than one family. A canary-asserting wave MUST include
# ≥1 input per family (enforced by validation criterion 8). Healthy state is
# family-specific: the text-token families produce a live comparison, while a
# binary-part canary is *skipped* by is_mostly_binary (its guard firing). A
# hardening regression flips the canary and reddens the nightly.
```

**Provenance-basis scope.** Wave 1 sources (html5lib-tests, MIT templates,
synthetic) all carry a real SPDX `license`. The `redistribution_basis` branch
exists for waves 2/3 (research corpora / consented mail have no code license),
but its allowed values and the redistribution vetting for each wave-2/3 source
are settled in those waves' own issues — this spec only reserves the schema slot
so wave 1's `meta.toml` does not wall later waves off. `"public-domain"` is
**not** used (it is not a valid SPDX identifier); genuinely public-domain
sources use `license = "CC0-1.0"`.

#### Self-validation CI (`validate.yml`)

This is the corpus repo's **only** workflow. The repo is data-only (no shipped
binary, no library consumers), and the expensive work — actually running the
`lol_html` differential over the corpus — lives in the *main* repo's nightly,
which checks this repo out at a pinned SHA. So the corpus repo needs no build,
test-matrix, release, code-scanning, or scheduled job; adding any of those would
burn Actions minutes (which a **private** repo draws from the account quota —
Linux 1×; public repos get free standard runners) for zero benefit. Concretely,
`validate.yml` is:

- a **single Ubuntu job** (no matrix, no macOS/Windows), pinned-SHA actions,
  `permissions: contents: read`;
- triggered on `pull_request` and `push` to the default branch **only**, with
  `paths:` filters so it fires solely when `.eml` / `.meta.toml` / validator code
  change (a README edit spends nothing);
- guarded by a `concurrency` group with `cancel-in-progress: true`, so rapid
  re-pushes to an ingestion PR supersede rather than stack.

The validator fails on:

1. any `.eml` without a sibling `.meta.toml` (or vice-versa);
2. a `.meta.toml` that doesn't parse or is missing any required field, or that
   sets **both** `license` and `redistribution_basis` or **neither** (exactly
   one provenance basis is required);
3. a `license` value not in the SPDX allowlist (`MIT`, `Apache-2.0`,
   `BSD-3-Clause`, `CC0-1.0`, `Unlicense` — extended per wave by a reviewed
   change), when the `license` branch is used;
4. an `.eml` that `mail-parser` cannot parse **or** that yields zero
   `text/html` parts (it would be silently inert in the oracle);
5. an `.eml` not using CRLF terminators;
6. a **structural-fingerprint duplicate** — two inputs whose tag-name /
   attribute-name sequence hash collides add cost without new tokenizer signal;
7. a **tree-wide file-stem collision** — two `.eml` sharing a stem alias their
   oracle ids and one masks the other. Content-hash stems make this automatic,
   but the validator asserts it directly (independent of the fingerprint check,
   which only catches *structural* dupes) so a naming mistake fails loud;
8. a **missing or invalid canary** — for a wave that asserts canary coverage
   (wave 1 onward), the tree must contain ≥1 input tagging each required
   `probes` family (`stray-tag-boundary`, `entity-href`, `binary-part`). Without
   this static gate a forgotten canary is not "claimed" by any `meta.toml`, so
   the nightly's per-family check would pass *vacuously* — the requirement must
   fail closed at corpus-repo CI, not rely on the nightly noticing an absence.
   **Additionally, each `binary-part`-tagged input must decode to a comfortable
   margin above the guard threshold — ≥ 30 % `U+FFFD`** by the same ratio the
   runtime uses (`replacement × 10 > total` with `total` counting *non-whitespace*
   chars only, matching `is_mostly_binary` in `main.rs`). The margin — not exact
   parity — is deliberate: `is_mostly_binary` runs on the *decoded* string
   (`rimap_content::decode` after `mail-parser` extraction), which the corpus
   repo's "no main-repo dependency" constraint forbids the validator from
   reproducing byte-for-byte. A canary at ≥ 30 % `U+FFFD` is robustly binary
   under any reasonable decode, so a small validator/runtime decode difference
   cannot flip it across the 10 % line — whereas a bare `>10 %` re-check leaves a
   10.01 % canary exactly as fragile as the drift it is meant to prevent. This
   keeps a binary-part canary from silently dropping below the guard threshold
   (which would redden the nightly as a *phantom* `is_mostly_binary` regression)
   without requiring the validator to replicate the full decode chain;
9. (advisory, non-blocking) a PII heuristic scan (email-address / phone regex)
   over inputs whose `scrub` is not `["none"]`, warning if a raw address
   survives redaction.

**Validation certifies "loads," not "compared."** Criterion 4 guarantees an
input yields a `CorpusInput`, but the oracle *runtime* additionally skips inputs
that return `ContentError::LimitExceeded`, decode to >10 % `U+FFFD`
(`is_mostly_binary`), or hit a `ReferenceError` — none of which a static
validator replicates. So "validates in the corpus repo" ⇒ "loads in the oracle,"
**not** ⇒ "produces a live comparison." The per-`corpus/` comparison floor
(Component 2) is what guards the stronger property at runtime.

**Validator language — Python, for cost.** Because the "validates ⇒ loads"
guarantee is already *approximate* (criterion 8 uses a ≥30 % margin precisely
because a validator cannot replicate `rimap_content::decode` byte-for-byte), the
validator does not need to be a Rust program reusing `mail-parser`. On a private
repo a Rust validator pays a `cargo build` on every run — the single largest
minute sink here (~30–90 s cold, ~10 s cached). A **Python** validator (walk the
tree, `tomllib` for `meta.toml`, an `email`/MIME parser for the `text/html`
parts, `hashlib` for stem/fingerprint hashes) is compile-free and near-instant,
and its different MIME parser is well within the margin the design already
tolerates. The corpus repo therefore **depends on nothing from the main repo**;
the `text/html`-extraction and ~20-line structural-fingerprint logic are
**re-implemented** (not shared as a crate), and that duplication is called out in
both READMEs so a change to one is mirrored.

**CI cost & visibility.** The frugality above matters only while the repo is
**private** (Actions minutes billed against the account quota); the day it goes
**public**, standard runners are free and none of it is load-bearing. The single
code change on that flip is auth in the *main* repo's nightly (Component 3):
while private the corpus checkout needs a read-scoped token (fine-grained PAT or
a GitHub App / deploy key) as a secret; going public drops the token for a plain
`actions/checkout`. Flipping visibility still raises the stakes on the corpus's
PII surface (publishing a curated phishing/malware sample set) — see Threat model.
(This was originally framed around Wave 3's personal mail, now dropped.)

### Component 2 — `--corpus-root` runner flag (follow-up issue B, main repo)

In `html-oracle/src/main.rs`:

- Add `corpus_root: Option<PathBuf>` to `Args`; parse `--corpus-root <dir>`
  (and honor a `CORPUS_ROOT` env var, mirroring `EPVME_DIR`).
- In `assemble_inputs`: when `corpus_root` is set, append
  `corpus::load_eml_tree(corpus_root, "corpus", limit)` (same call shape as the
  EPVME branch). `--limit` applies to whichever external tree is loaded; if both
  `--epvme-dir` and `--corpus-root` are somehow set, each is capped independently
  — documented, though the nightly sets only one.
- In `assemble_allowlist`: gain a `with_corpus: bool` and merge a new
  `html-oracle/corpus-allowlist.toml` **only** when `--corpus-root` is set, so
  `corpus/…` entries never show stale in the hermetic run (exact mirror of the
  EPVME allowlist handling). `corpus-allowlist.toml` ships empty with the
  required-`reason` header comment; the first wave-1 nightly populates it.
- Usage/`--help` text names `--repo-root` (in-repo seeds) and `--corpus-root`
  (external corpus checkout) distinctly to defuse the naming hazard.
- **Per-source comparison floor.** The runner reports, *attributable to the
  `corpus/` id prefix* and separately from the global totals, four counts:
  `corpus_total`, `corpus_skipped`, `corpus_ref_error`, and
  `corpus_compared_nonempty`. The coverage denominator Component 5's 60% floor
  needs is `corpus`-comparable = `corpus_total − corpus_skipped −
  corpus_ref_error`: `ref_error` inputs (a `lol_html` reference failure, tallied
  separately from `skipped` in `main.rs`) can never produce a live comparison, so
  they are excluded from the denominator rather than deflating coverage for a
  non-corpus reason. The denominator is *not* reconstructable from
  `compared_nonempty` alone, since non-skipped-but-empty inputs sit between the
  two. When `--corpus-root` is set with an expected floor
  (`--corpus-min-compared <N>`, wired in the nightly), the run fails if the
  `corpus/`-prefixed comparison count is below `N`. The existing global inert
  tripwire (`total > 0 && compared_nonempty == 0`) is masked by the 33 in-repo
  inputs and cannot detect an all-skipped corpus; this per-prefix floor is what
  catches "the pinned SHA changed and now every corpus input is skipped."
- **Canary-family coverage (direction-aware).** The runner reads each corpus
  input's `probes` tag (sibling `.meta.toml`) and records that input's outcome,
  including whether `is_mostly_binary` fired. The healthy signal is
  family-specific because the guards act at different points:
  - `stray-tag-boundary`, `entity-href` (text-token families): healthy = a live
    comparison (that Matches). The nightly fails if the family drops to **zero
    live comparisons** — a hardening regression turned its guard inputs inert,
    or the canary was lost.
  - `binary-part`: healthy = the input is **skipped by `is_mostly_binary`** (the
    guard fired). That skip returns before `compared_nonempty` increments, so a
    *working* binary-part canary produces zero live comparisons by construction —
    its assertion is therefore inverted: the nightly fails if a binary-part
    canary instead produces a **live comparison or HARD** or **disappears
    entirely** (canary lost). A uniform "≥1 live comparison" rule cannot express
    this family; the per-input skip-reason record is what makes it observable.
    The failure message names **both** hypotheses — "`is_mostly_binary` guard
    regressed **or** this canary no longer decodes to >10 % `U+FFFD`" — so triage
    is not biased toward a false security-regression conclusion; the corpus-CI
    gate (validation criterion 8) makes the "no longer binary" branch a
    should-not-happen, but the nightly still names it.

This adds a `meta.toml` read in the corpus-loading path (`corpus.rs` gains an
optional sibling-metadata read for `--corpus-root` inputs only; the in-repo and
`--epvme-dir` paths are unchanged and carry no `probes`). `reference.rs`,
`diff.rs`, and `norm.rs` are untouched — the comparison itself is already
general.

### Component 3 — nightly workflow checkout (follow-up issue B, main repo)

Extend `.github/workflows/nightly-html-oracle.yml` with a second checkout of the
corpus repo at a **pinned SHA** into a sibling path, then run with
`--corpus-root`:

```yaml
- name: Checkout corpus (pinned SHA)
  uses: actions/checkout@<pinned-sha>  # v7.x
  with:
    repository: randomparity/rusty-imap-mcp-corpus
    ref: <corpus-commit-sha>           # PINNED — bumped via reviewed PR only
    path: corpus
    persist-credentials: false

- name: Assert corpus checkout is non-empty
  run: test -n "$(find corpus -name '*.eml' -print -quit)"

- name: Run differential oracle
  # --corpus-min-compared is added only once a baseline exists (see below).
  run: >
    cargo run --locked --manifest-path html-oracle/Cargo.toml --
    --repo-root . --corpus-root corpus ${CORPUS_MIN_COMPARED:+--corpus-min-compared $CORPUS_MIN_COMPARED}
```

**The floor is bootstrapped, not circular.** `--corpus-min-compared` is
*absent* (no floor check — the runner treats a missing flag as "no floor") on
the two runs that necessarily precede a baseline: the rollout step-2 empty-corpus
plumbing proof (where the `corpus/`-prefixed count is 0, so any positive floor
would spuriously fail) and the wave's *first* nightly (which exists to establish
the baseline). Only after that first nightly reports a `corpus/`-prefixed
baseline is `N = floor(0.9 × baseline)` set — in the **follow-up reviewed
SHA-bump PR**, never in the baselining run itself. The 10% headroom absorbs the
routine expected removals (a mandatory prune on promotion, oracle-tier pruning of
never-diverging inputs) so a legitimate single removal is not read as a floor
breach, while a pinned-SHA bump that silently drops a large fraction of corpus
comparisons still fails. When a removal batch or a new wave shifts the baseline
materially, `N` is recomputed in the same reviewed SHA-bump PR that makes the
change (see the promotion checklist and failure modes).

- The `ref` is a 40-char commit SHA, never a branch/tag. Bumping it (to pull in
  a new wave) is a reviewed main-repo PR — the corpus can't change what CI runs
  without a human in the loop.
- **The corpus repo starts private** (decided), so the checkout uses a
  read-scoped token — a fine-grained PAT or a GitHub App / deploy key — added as
  a main-repo secret. The design keeps the **option to go public later**: on that
  flip the token is dropped for a plain `actions/checkout` (the sole auth change),
  and the corpus repo's own Actions minutes stop counting (see Threat model).
- `zizmor`/`actionlint` clean (repo policy): every `uses:` a full SHA + version
  comment, minimal `permissions: contents: read`, `persist-credentials: false`.

### Component 4 — staged ingestion (Approach C: cheapest-risk first)

**Wave 1 — synthetic + license-clean templates (follow-up issue C).** No PII, no
third-party-corpus licensing questions; the safe first cut.
- **html5lib-tests** tokenizer/tree-construction cases wrapped as minimal
  `.eml` (`Content-Type: text/html`, CRLF). These are the canonical
  tokenizer-divergence probes — exactly the class the differential exists to
  catch — and are MIT-licensed.
- **Open email templates** — Cerberus, MJML samples, Foundation for Emails
  (all MIT/permissive, PII-free, realistic responsive-email HTML): tables,
  inline CSS, VML conditional comments, tracking-pixel-shaped `<img>`.
- **Deterministic synthetic mutations** — a small generator producing charset
  relabels (UTF-8 bytes under a `windows-1252` label and vice-versa), CTE swaps
  (base64 ⇄ quoted-printable ⇄ 7bit for the same body), and entity corruption
  (semicolon-less legacy entities, overlong numeric refs). Deterministic (fixed
  seed / enumerated, no RNG) so regenerating yields byte-identical output.

**Wave 2 — filtered public corpora.** Enron, SpamAssassin, Nazario phishing —
filtered to HTML-bearing messages, deduped by the same structural fingerprint,
capped at ~200–300 representatives to bound nightly runtime. These sources carry
no code license, so each input's provenance uses the `redistribution_basis`
branch of `meta.toml` (research-corpus terms), not an SPDX `license`; the
allowed bases and per-source redistribution vetting are settled in this wave's
own issue, and anything that can't be cleared is dropped, not force-added.
**Deferred to its own issue after wave 1's baseline is stable.**

**Wave 3 — scrubbed personal mail. Investigated 2026-07-11 and dropped.** The
premise was that real Gmail would add structural diversity worth the PII risk. A
read-only probe of a 2.5 GB personal mbox (15,082 messages) tested that premise
before building any scrub tooling: it deduped by the same criterion-6 structural
fingerprint (9,469 unique skeletons, only 4 already in the 654-input corpus),
then ran each representative through the **actual html-oracle**. Result: **0
HARD**, 3,824 SOFT (5,842 match), at 97.5% comparability. The SOFT set is ~100%
the systematic marketing-mail trio — `HtmlHiddenContentDetected` (99.9%),
`HtmlRemoteImageStripped` (99%), `HtmlStyleStripped` (96%) — all *explained*
drops already covered by Waves 1+2, not new signal. The apparent skeleton
diversity was document-permutation noise (whole-document tag/attr-name sequences
vary per message); under the real engines it collapses to no new divergence.
Benign personal correspondence is structurally the wrong source for HARD
divergences — those come from adversarial tokenizer-confusion tricks, which is
why Wave 2 targeted spam/phishing. **Maximal PII risk, ~zero marginal oracle
signal → closed; not reopened as personal mail.** If a Wave 3 is ever wanted,
the data points to improving the reference sanitizer's html5lib
tree-construction coverage or a fresh *adversarial* source, not real mail. (No
GitHub issue was opened for this wave.)

Each wave is a separate ingestion PR to the corpus repo, followed by a main-repo
PR bumping the pinned SHA.

### Component 5 — per-wave allowlist re-baselining

The #529 keep/kill retro used an **absolute** bar (`allowlist < 10 entries`)
calibrated for 33 inputs. As the corpus grows to hundreds/thousands, restate it
as a **rate**, recomputed and recorded after each wave's first nightly:

- After a wave's first nightly, triage every new HARD: real sanitizer bug →
  file an issue (never allowlist a real bug); systemic oracle-noise class →
  fix the comparison layer (as the EPVME run did), not a per-input allowlist;
  genuinely benign per-input quirk → one `corpus-allowlist.toml` entry with a
  required `reason`.
- **Restated KEEP bar (per wave).** Every figure below is the
  **`corpus/`-prefixed** count, never the global one — Component 2 introduced the
  per-prefix count precisely so the in-repo baseline cannot prop up a broken
  corpus, and the keep/kill decision must inherit that isolation (a global
  reading would let the 33 tame in-repo inputs clear the health floor on a corpus
  that is itself all-skipping). The allowlist entry count stays at or below
  **`max(5, 0.5% of the corpus/-prefixed compared_nonempty)`** for that wave
  *and* is not growing week-over-week *and* there are zero non-allowlisted HARD
  on the latest run *and* `corpus_compared_nonempty` is **≥ 60% of the
  `corpus`-comparable inputs** (`corpus_total − corpus_skipped −
  corpus_ref_error`) — a concrete floor replacing the vague "covers the bulk";
  the EPVME run was 65%. The `max(5, …)` form is
  deliberate: a bare `0.5% × compared_nonempty` collapses to ~0 at small N (0.5%
  of a wave-1 corpus of a few hundred comparisons is 1–2), which would hold
  wave 1 to a near-zero-entry bar it cannot meet after honest triage; the
  absolute floor of 5 preserves the old "< 10" intent at small N, and the 0.5%
  rate lets the ceiling scale (≈ 5 at 1,000 comparisons, more beyond) as later
  waves grow the corpus.
  - *The 60% coverage floor is a fixed cross-wave bar* (EPVME-calibrated; that
    broad real-mail run was 65%), evaluated on the `corpus/`-prefixed counts. It
    is **not** re-derived from the run it gates — deriving a floor from the same
    nightly's coverage and then checking that nightly against it is circular (a
    run can never fall below a floor computed from itself). A wave measuring
    below 60% is **not an automatic KILL**: it triggers a documented review in
    the per-wave note recording whether the low coverage is legitimate or a real
    defect. Because the denominator already excludes skips and `ref_error`,
    binary/mojibake-heaviness *cannot* lower this ratio (an `is_mostly_binary`
    skip drops the input from numerator and denominator alike). The only thing
    that lowers skip-excluding coverage is a high proportion of
    **non-skipped-but-empty-reference** inputs — all-non-content-tag, empty, or
    near-empty HTML bodies that pass the `is_mostly_binary` guard yet yield no
    reference tokens. A wave legitimately rich in such bodies (bare structural
    templates, say) is the exemptable case; a broken pin or an otherwise-inert
    corpus is the real-defect case — the per-wave note names which, with the
    numbers (a spike in non-skipped-but-empty inputs or in `corpus_ref_error`,
    not binary skips, is what to investigate when coverage dips). The bar stays
    concrete and falsifiable; the exemption is explicit and recorded, not a
    silent per-run recalculation.
- **KILL** if holding the gate green needs an allowlist above that rate or one
  that keeps growing, and no HARD ever mapped to a real bug.
- Record the `corpus/`-prefixed numbers (allowlist size,
  `corpus_compared_nonempty`, the coverage denominator `corpus`-comparable =
  `corpus_total − corpus_skipped − corpus_ref_error`, and the non-allowlisted
  HARD count) plus any filed bugs in a short per-wave note under `docs/security/`,
  so keep/kill stays mechanical — the comparable denominator is what makes the
  60% coverage floor computable.

## Threat model

- **Malicious corpus input.** The oracle only reads/tokenizes/diffs bytes; it
  never executes or renders them. Worst case from a hostile input is a false
  HARD (nightly red — noise, self-announcing), never RCE or exfiltration. Blast
  radius is bounded to CI signal quality.
- **Corpus-repo compromise / tampering.** Mitigated by the **pinned SHA**: CI
  runs a fixed commit, so a push to the corpus repo (even a malicious one)
  cannot change what the main repo's CI executes until a human bumps the SHA in
  a reviewed PR. The corpus repo's own self-validation CI is a second gate on
  what lands there.
- **PII leakage (wave-2 real mail; wave 3 dropped).** With personal-mail Wave 3
  closed (Component 4), the residual PII surface is Wave 2's public corpora.
  Mitigated by: node-scoped scrubbing recorded in `meta.toml.scrub`, the advisory
  PII-heuristic scan in self-validation, and human review of each ingestion PR.
  The residual risk is a scrub miss; the heuristic scan and that review are the
  backstop.
- **Repo visibility — start private, option to open later (decided).** The
  corpus aggregates adversarial / phishing HTML (Wave 3's scrubbed personal mail
  was dropped). Public hosting would publish a curated malware/phishing sample set
  (AV/abuse/GitHub-TOS considerations) and raise the stakes on any scrub miss, so
  the repo **starts private**: it contains those samples and costs a read-scoped
  token in the nightly (Component 3), and its Actions minutes draw from the
  account quota (which is why `validate.yml` is kept to a single lean job). The
  path to public is preserved and cheap — dropping the checkout token is the only
  auth change — but any public flip is its own reviewed decision (now weighing
  only the adversarial/phishing samples, since Wave 3's personal mail was
  dropped), not an afterthought.
- **License contamination.** `cargo-deny` covers Rust dependencies, not data
  files. The corpus repo's SPDX-allowlist validation is the sole license gate;
  anything unclearable is dropped at ingestion, not force-added.

## Failure modes & edge cases

- **Corpus checkout empty / path wrong in CI:** `load_eml_tree` treats an
  absent/unreadable dir as "contributes nothing, not an error," so a wrong
  `--corpus-root` path yields a silently smaller run. Guard: the workflow asserts the
  checkout produced files (fail the step if `corpus/` is empty) so a broken pin
  doesn't masquerade as a clean nightly. `compared_nonempty` in the report is a
  second tripwire (the runner already treats total>0 with compared_nonempty==0
  as inert → HARD).
- **`.eml` with no `text/html` part slips past validation:** self-validation
  rejects it at ingestion (criterion 4), so it can't reach the oracle silently.
- **Stem collision across waves:** two inputs sharing a file stem alias their
  oracle ids and one masks the other. Prevented by content-hash stems (identical
  stem ⇒ identical bytes) **and** the explicit tree-wide stem-uniqueness
  validation criterion (7), which is independent of the structural-fingerprint
  check (6) — two structurally-different files sharing a stem pass (6) but fail
  (7).
- **Structural-fingerprint false-merge:** two genuinely different inputs hashing
  alike are dropped as dupes, losing signal. Accepted: the fingerprint is
  tag/attr-name sequence, so a collision means near-identical structure — low
  signal loss, and the alternative (no dedup) bloats runtime. Tunable if a wave
  shows over-merging.
- **Pinned SHA drift vs. corpus-allowlist:** if the corpus repo advances but the
  main-repo SHA isn't bumped, new inputs simply aren't tested yet (safe). If the
  SHA is bumped but `corpus-allowlist.toml` isn't updated for a new benign
  divergence, the nightly goes red and is triaged — the intended fail-loud path,
  not a silent gap.
- **SHA bumped to prune/promote, `N` not re-baselined:** removing live-comparing
  inputs drops the `corpus/`-prefixed count; the floor's 10% headroom covers a
  single removal, but a batch without recomputing `--corpus-min-compared N`
  trips the floor with a *false* failure. Guard: `N` recompute is a mandatory
  item in the SHA-bump PR checklist (Component 1 promotion, Component 3). A false
  floor breach is fail-loud (nightly red), not silent, so it self-announces for
  triage.
- **`--limit` interaction:** with both external trees set, `--limit` caps each
  independently; the nightly sets only `--corpus-root`, so this is a
  local-invocation-only corner, documented in `--help`.

## Rollout / rollback

- **Rollout:** (1) create the corpus repo with README + `meta.toml` format +
  self-validation CI (issue A). (2) Land `--corpus-root` + the pinned-SHA
  checkout in the main repo, initially pointing at an empty-but-valid corpus
  commit (issue B) — proves the plumbing with zero inputs. (3) Ingest wave 1 to
  the corpus repo, bump the pinned SHA, run the first nightly, populate
  `corpus-allowlist.toml` from its output, record the restated baseline (issue
  C). Waves 2 and 3 follow as their own issues.
- **Rollback:** revert the main-repo `--corpus-root` + checkout change; the
  nightly falls back to the hermetic `--repo-root .` run (the current behaviour).
  The corpus repo can be archived independently. Nothing in the shipped supply
  chain or PR gates depends on any of it (the oracle crate is workspace-excluded
  and nightly-only).

## Follow-up issues (filed after this spec is approved)

- **A ([#549](https://github.com/randomparity/rusty-imap-mcp/issues/549)) —**
  create `rusty-imap-mcp-corpus` (README, `meta.toml` format, self-validation
  CI).
- **B ([#550](https://github.com/randomparity/rusty-imap-mcp/issues/550)) —**
  main-repo: `--corpus-root` flag on the oracle runner + `corpus-allowlist.toml`
  + pinned-SHA corpus checkout in `nightly-html-oracle.yml`.
- **C ([#551](https://github.com/randomparity/rusty-imap-mcp/issues/551)) —**
  wave-1 ingestion (html5lib-tests + Cerberus/MJML/Foundation templates +
  deterministic synthetic mutations) + restated keep/kill baseline.

Implementation of each happens under its issue via `/work-issue`; this spec is
the shared design they reference. Waves 2 and 3 get their own issues once wave
1's baseline is stable.

## Considered & rejected

- **Grow the in-repo corpus directly** (commit hundreds of `.eml` under
  `fuzz/corpus/` or `tests/`). Rejected: bloats the main repo and its clone/CI
  with adversarial payloads, mixes inputs-only oracle fodder with the curated
  assertion tier, and offers no place for provenance/license metadata. A
  separate repo keeps the main tree lean and the provenance first-class.
- **Git submodule instead of pinned-SHA checkout.** Rejected: submodules pin a
  SHA too but add working-tree friction (recursive clone, detached-HEAD
  confusion, `.gitmodules` churn) for every contributor, when only the nightly
  needs the corpus. A CI-only `actions/checkout` at a pinned ref gives the same
  integrity with none of the local-dev cost.
- **Point the nightly at EPVME.** Rejected: EPVME is unlicensed for
  redistribution, contains unscrubbed real mail, is ~170 MB, and can't be
  committed or checked out in CI. It stays a manual `--epvme-dir` discovery
  tool.
- **Rename/replace `--epvme-dir` with `--corpus-root`.** Rejected: they are
  different data sources (local giant download vs. committed curated repo) with
  different provenance and CI availability, not two implementations of one
  concept — so replace-don't-deprecate doesn't apply. Both coexist.
- **Reuse `expected.json` assertions in the corpus tier.** Rejected: authoring
  exact expectations for hundreds of inputs is the cost the differential oracle
  exists to avoid. The corpus stays inputs-only; exact assertions live only in
  the promoted `tests/injection-corpus/` fixtures.
- **Floating-branch corpus checkout.** Rejected: lets the corpus repo change
  what the main repo's CI runs without review — a supply-chain hole. Pinned SHA,
  bumped by reviewed PR, closes it.
- **Keep the absolute "< 10 allowlist" keep/kill bar.** Rejected: calibrated for
  33 inputs, it becomes either trivially satisfied or meaningless at 1,000+
  inputs. A per-`compared_nonempty` rate scales the intent honestly.
