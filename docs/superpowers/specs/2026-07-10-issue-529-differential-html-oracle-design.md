# Differential HTML→text sanitizer oracle — design

**Issue:** [#529](https://github.com/randomparity/rusty-imap-mcp/issues/529)
· **Priority:** P3 · **Effort:** M–L · **Theme:** C (oracles, invariants,
meta-testing)

**Extends:** `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`
§8.1 (explicit deferral: "Differential HTML oracle. Comparing `ammonia`/`scraper`
output against a second sanitizer … a sprint of its own.")

## Problem

The HTML→text sanitizer in `rimap-content` is the #1 prompt-injection defense:
it decides which bytes of an adversarial email body reach the agent. Its only
oracles today are its own snapshots (`insta`) and crash-only fuzz targets, plus
the feature-gated `fuzz_oracle.rs`. Snapshots assert *what the sanitizer does*;
they cannot catch a bug where the sanitizer **silently drops attacker-controlled
text** — because nobody wrote the missing case.

A *differential oracle* runs a second, independently-implemented extraction
engine over the same input and flags where the two disagree. Because the two
engines have uncorrelated bugs, a divergence is a signal that at least one is
wrong. The highest-value signal is text the reference engine surfaces that the
production sanitizer dropped **without emitting any warning** — an unannounced
silent drop, the exact injection-defense gap snapshots miss.

The hard part — and why §8.1 called this "a sprint of its own" — is defining
"equivalent sanitization" between two engines. The production sanitizer
*intentionally* drops content (CSS-hidden elements, `<script>`/`<style>`, remote
images). A naive text-equality diff would flag every intended drop as a
divergence — pure noise. The equivalence relation must be defined against the
sanitizer's `SecurityWarning` output, not against raw text equality.

## Acceptance criteria (from the issue)

- [ ] Nightly job with an allowlist file for known-benign divergences.
- [ ] ≥1 sprint retro on whether the oracle found anything (kill it if pure
  noise — oracles must earn their maintenance).

Container-gating convention (from the parent spec): keep nightly suites out of
the PR-blocking check set.

## Grounding survey — reality the assertions bind to

- **Production entry point:** `rimap_content::html::sanitize(raw: &[u8],
  charset: Option<&str>) -> Result<HtmlResult, ContentError>` (in
  `crates/rimap-content/src/html/pipeline.rs`). Reachable from out-of-tree code
  via the `test-support` feature (the module is `pub` for `test_support`
  re-export). `HtmlResult` carries `body_text: String`, `anchor_hrefs:
  Vec<String>`, `body_html: String`, `warnings: Vec<SecurityWarning>`.
- **Production parser:** `scraper` (wraps `html5ever`) + `ammonia`. Both share
  the html5ever tokenizer, so a genuinely independent oracle engine must NOT be
  html5ever-based.
- **Non-content tags production skips** during text extraction
  (`crates/rimap-content/src/html/extract.rs`, `NON_CONTENT_TAGS`): `script`,
  `style`, `noscript`, `template`, `head`, `title`.
- **Drop-explaining warning codes** (`rimap_core::warning::WarningCode`, emitted
  by `pipeline.rs`): `HtmlHiddenContentDetected`, `HtmlScriptStripped`,
  `HtmlStyleStripped`, `HtmlRemoteImageStripped`, `HtmlLinkTextHrefMismatch`,
  `HtmlAnchorUnparsableHref`.
- **`anchor_hrefs`** are collected from the *ammonia-sanitized* HTML, so only
  ammonia-surviving schemes appear (http, https, mailto; `javascript:`/`data:`
  are dropped, and that drop is NOT announced by a warning).
- **Corpus available today:** `fuzz/corpus/content_html/` (20 raw-HTML seeds)
  and `tests/injection-corpus/*/input.eml` (11 fixtures carry a `text/html`
  part, detected by grepping `text/html`). Injection fixtures are full `.eml`
  messages; the HTML part must be extracted with `mail-parser` (the production
  MIME parser, already a workspace dependency).
- **Isolation precedent:** `fuzz/` is a separate workspace (root `Cargo.toml`
  `exclude = ["fuzz"]`, own `Cargo.lock`, own `rust-version = "1.94.0"`). It is
  invisible to `just lint` (`clippy --workspace --all-targets --all-features`),
  `just test-msrv` (`cargo +1.88.0 check --workspace --all-targets
  --all-features`), and `just deny` (`cargo deny --all-features check`) because
  those use `--workspace`, which does not descend into excluded members.
- **`lol_html`** (Cloudflare streaming HTML rewriter) is version 3.0.0,
  BSD-3-Clause — already on `deny.toml`'s license allowlist (line 25). It has
  its own WHATWG-conformant tokenizer, independent of html5ever.

## Non-goals

- **No change to the production sanitizer.** The oracle is pure observation. Any
  bug it surfaces is fixed under a separate issue/PR.
- **No PR-gating.** The oracle runs nightly only. It never joins the 8 gating
  checks (`rustfmt`, `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV
  1.88.0)`, `cargo-deny`, `zizmor`, `SonarQube`).
- **No `lol_html` in the shipped supply chain.** It lives only in the excluded
  oracle crate; the server binary and all workspace crates never link it.
- **No non-safe-scheme href comparison.** `javascript:`/`data:`/`vbscript:`
  hrefs are dropped by policy (an allowlist decision, not a silent-drop bug), so
  the oracle compares only http/https/mailto hrefs.
- **No CSS-hidden re-implementation in the reference engine.** Detecting
  `display:none` et al. is production's job; the reference engine deliberately
  does not replicate it, which is *why* hidden content shows up as a divergence
  the warning must explain.
- **No self-hosted corpus persistence.** The corpus is the in-repo fuzz +
  injection fixtures already under version control.

## Design

### Component 1 — excluded oracle crate `html-oracle/`

A new crate at repo root, added to root `Cargo.toml` `exclude`, with its own
`Cargo.lock`. Mirrors `fuzz/` exactly. Layout:

```
html-oracle/
├── Cargo.toml          # package rust-version = "1.94.0"; NOT MSRV-bound
├── Cargo.lock
├── allowlist.toml      # known-benign divergence signatures
├── src/
│   ├── main.rs         # CLI runner: load corpus, diff, report, exit code
│   ├── reference.rs    # lol_html-based reference extractor
│   ├── diff.rs         # two-tier equivalence rule
│   └── allowlist.rs    # allowlist load + lookup
└── tests/
    └── oracle_logic.rs # unit tests for diff/allowlist with hand-built inputs
```

Dependencies: `rimap-content` (path, `features = ["test-support"]`),
`rimap-core` (path, for `WarningCode`), `lol_html = "3"`, `mail-parser`
(workspace-pinned version echoed literally), `serde`/`serde_json`, `toml`.

Because the crate is excluded from the main workspace, none of its dependencies
(`lol_html` and transitives) enter `clippy --all-features`, `test-msrv`, or
`cargo-deny`. Its own toolchain is stable (pinned via `rust-toolchain.toml`
inheritance from the repo root, which selects stable 1.94.0), so `lol_html`'s
own MSRV is irrelevant.

### Component 2 — reference extractor (`reference.rs`)

`fn extract_reference(html: &str) -> ReferenceExtract` where

```rust
struct ReferenceExtract {
    text_tokens: BTreeSet<String>,   // normalized visible-text tokens
    hrefs: BTreeSet<String>,         // normalized safe-scheme anchor hrefs
}
```

Uses `lol_html::rewrite_str` (or the low-level `HtmlRewriter`) with:

- **Text handler:** accumulate text nodes, but suppress accumulation while
  inside any tag in the *same* `NON_CONTENT_TAGS` set production skips
  (`script`, `style`, `noscript`, `template`, `head`, `title`). This keeps the
  two engines agreeing on the spec-uncontroversial exclusions, so those never
  register as divergences. Depth-tracked element handlers on those tags flip a
  "suppress" counter on start and off on end.
- **Anchor handler:** on `<a href>`, parse the scheme; retain only
  `http`/`https`/`mailto`. Normalize (trim, lowercase scheme + host).
- **Normalization** (shared with production tokens): Unicode NFC, lowercase,
  split on Unicode whitespace (`char::is_whitespace`), drop empty tokens. Result
  is a `BTreeSet<String>` (order-independent, dedup'd).

The reference engine does **not** implement CSS-hidden detection, href-mismatch
detection, or ammonia's tag allowlist — only the non-content-tag skip. That is
the deliberate independence: everything else production does is what the diff
scrutinizes.

### Component 3 — two-tier equivalence rule (`diff.rs`)

For each corpus input, given production `HtmlResult` and `ReferenceExtract`:

```
prod_text_tokens = normalize(result.body_text)
prod_hrefs       = normalize_safe_scheme(result.anchor_hrefs)

text_reference_only = ref.text_tokens - prod_text_tokens - allowlist_text[input]
href_reference_only = ref.hrefs       - prod_hrefs       - allowlist_href[input]
reference_only      = text_reference_only ∪ href_reference_only

if reference_only is empty:
    verdict = Match
else if result.warnings contains any DROP_EXPLAINING code:
    verdict = Soft(reference_only)   # explained drop — triage, nightly stays green
else:
    verdict = Hard(reference_only)   # silent drop — nightly RED
```

`DROP_EXPLAINING = { HtmlHiddenContentDetected, HtmlScriptStripped,
HtmlStyleStripped, HtmlRemoteImageStripped, HtmlLinkTextHrefMismatch,
HtmlAnchorUnparsableHref }`.

The rule is intentionally *coarse on the soft side* (any explaining warning
downgrades a drop to soft) and *sharp on the hard side* (a drop with zero
explaining warnings is unambiguous). This keeps day-one noise low while still
red-flagging the true silent-drop bug class. The allowlist absorbs the residual.

Also compute `production_only = prod_text_tokens - ref.text_tokens` and record
it in the report (informational): production surfacing text the reference
dropped is rare but indicates a real disagreement worth a human glance. It never
fails the job (production is the source of truth for *what ships*; the reference
is not authoritative).

### Component 4 — corpus loader + runner (`main.rs`)

1. **Raw-HTML seeds:** read every file under `fuzz/corpus/content_html/` as
   `raw: &[u8]`, `charset = None`. Input id = `content_html/<filename>`.
2. **Injection fixtures:** for each `tests/injection-corpus/*/input.eml`, parse
   with `mail-parser`; for each `text/html` part, take its decoded bytes +
   declared charset. Input id = `injection/<dir>[/part<n>]`. Fixtures with no
   `text/html` part are skipped (logged at info).
3. For each input: `sanitize()` (skip inputs that return
   `ContentError::LimitExceeded` — over-cap inputs are a separate concern, logged
   as skipped), `extract_reference()`, apply the diff.
4. Write `html-oracle/report.json`: per-input verdict, the divergent tokens,
   which warnings fired, and totals (`hard`, `soft`, `match`, `skipped`).
5. Exit code: non-zero iff `hard > 0`. Print a compact human summary to stderr
   (stdout stays clean for potential piping).

Corpus paths are resolved relative to a `--repo-root` CLI arg (default: the
crate's `CARGO_MANIFEST_DIR/..`), so the runner works both locally and in CI.

### Component 5 — allowlist (`allowlist.toml`)

```toml
# Each entry suppresses one known-benign divergence. `reason` is REQUIRED;
# an entry without a reason is a load-bearing error (fail closed).
[[allow]]
input = "content_html/some-seed"
tokens = ["benignword"]          # text tokens and/or hrefs to subtract
reason = "lol_html emits U+00A0 as a separate token; benign formatting diff."
```

Loaded into `HashMap<String, BTreeSet<String>>` keyed by input id. An entry
whose `input` matches no corpus input is a warning in the report (stale
allowlist rot detector) but not a hard failure. Ships empty (`# no entries yet`)
so the first nightly run establishes the real baseline.

### Component 6 — nightly workflow `.github/workflows/nightly-html-oracle.yml`

- Trigger: `schedule` (nightly cron) + `workflow_dispatch`.
- `permissions: contents: read` (minimal).
- Single Ubuntu job, stable toolchain via the repo `rust-toolchain.toml`.
- Steps: checkout (SHA-pinned action) → `cargo run --manifest-path
  html-oracle/Cargo.toml -- --repo-root .` → `actions/upload-artifact`
  (SHA-pinned) uploads `html-oracle/report.json` with `if: always()`.
- Job is red iff the runner exits non-zero (a HARD divergence). SOFT and
  informational divergences leave it green; the artifact carries them for the
  retro.
- Every `uses:` is a full 40-char SHA with a version comment (repo policy;
  `zizmor` and `actionlint` must pass — though `zizmor self-check` gates only
  the workflows it is pointed at, this one follows the same rules).

## Failure modes & edge cases

- **Empty / whitespace-only body:** both engines yield empty token sets →
  `Match`. Covered by unit test.
- **Over-cap input (> `MAX_HTML_BYTES`):** production returns `LimitExceeded`;
  runner logs `skipped` and moves on (no verdict). A reference extraction of a
  1 MiB+ body would compare against nothing meaningful.
- **Input with `<script>alert(1)</script>` and nothing else:** both engines skip
  `<script>` → empty token sets → `Match`. No false positive.
- **CSS-hidden secret, no other warning:** production drops it AND emits
  `HtmlHiddenContentDetected` → `Soft`. Correct: the drop is announced.
- **Silent drop (hypothetical bug):** production drops visible `<p>` text with
  *no* warning → reference surfaces it → `Hard`. This is the target signal.
- **`javascript:` href:** reference restricts to safe schemes, so it never
  appears in `ref.hrefs` → no divergence. No false positive from policy drops.
- **U+00A0 / zero-width / bidi tokens:** NFC + whitespace-split normalization
  may still leave engine-specific artifacts; these are the expected first-run
  SOFT/allowlist churn. The retro decides whether normalization needs
  tightening.
- **Malformed `.eml` with no `text/html`:** skipped with an info log, not an
  error.
- **`mail-parser` and production disagree on charset for a part:** the runner
  passes the part's declared charset to `sanitize()`, matching production's own
  call path, so decoding is apples-to-apples.

## Testing

Unit tests in `html-oracle/tests/oracle_logic.rs` (and `src` unit mods) with
hand-built HTML strings, not the live corpus (deterministic, no fixture
coupling):

- `silent_drop_is_hard`: HTML where a naive extractor sees text production drops
  with no warning → `Hard`. (Constructed by feeding the reference a token the
  fake production result omits with empty warnings.)
- `explained_drop_is_soft`: same divergence but production result carries
  `HtmlHiddenContentDetected` → `Soft`.
- `allowlisted_token_suppressed`: the divergent token is in the allowlist →
  `Match`.
- `non_content_tags_never_diverge`: `<script>`/`<style>`/`<title>` content is
  skipped by both → `Match`.
- `safe_scheme_href_only`: `javascript:` href absent from reference; `https:`
  href present and compared.
- `normalization_nfc_and_whitespace`: `"  Héllo\tWORLD "` and `"héllo world"`
  normalize to the same token set.
- `missing_reason_is_error`: an allowlist entry without `reason` fails to load.
- `stale_allowlist_entry_is_reported_not_fatal`: an entry for a non-existent
  input surfaces as a report warning, exit code unaffected.

The oracle crate is compiled and unit-tested by its own `cargo test`; it is NOT
run by `just test` (excluded workspace). A one-line note in `AGENTS.md` documents
how to run it locally.

## Considered & rejected

- **Same-tokenizer naive extractor (no new dependency).** Build the reference on
  the same `scraper` parse, extracting all text with none of production's
  skipping. Rejected as the *sole* approach: it is blind to html5ever
  tokenizer-confusion bugs, which are a real injection vector. The chosen design
  still borrows its best idea — the warning-explained-drop rule.
- **`html2text` / `select` / raw `html5ever` as the reference.** All html5ever-
  based; they share the production tokenizer and cannot catch tokenizer-level
  divergence. Rejected — defeats the purpose of a *differential* oracle.
- **In-workspace feature-gated `[[test]]` + optional `lol_html`.** Rejected:
  `just lint`, `just test-msrv`, and `just deny` all pass `--all-features`, which
  would enable the feature and drag `lol_html` (and its MSRV) onto the PR/MSRV
  critical path — the opposite of the isolation goal. The excluded-crate pattern
  (proven by `fuzz/`) is the only clean isolation.
- **Strict "any divergence fails" gate.** Two independent tokenizers disagree on
  many benign edge cases; a strict gate red-flags constantly on day one and
  demands a large allowlist before it stabilizes. Rejected in favor of the
  two-tier rule.
- **Report-only (never fails).** Loses the automated red/green signal; relies on
  a human reading an artifact that will rot — the exact failure mode the
  acceptance criteria warn against. Rejected.
- **Per-token warning attribution** (map each dropped token to the specific
  warning that explains it). Rejected as over-engineering for a P3 oracle: we
  cannot cleanly attribute which dropped token came from which hidden element
  without re-implementing production. The coarse soft/hard split plus allowlist
  is the tractable MVP; the retro can tighten it if warranted.

## Rollout / rollback

- **Rollout:** land the crate + workflow; the first nightly establishes the
  baseline. Populate `allowlist.toml` from that first run's SOFT/HARD output.
  Any first-run HARD divergence is triaged before the allowlist is committed —
  if it is a real sanitizer bug, file a separate issue (do not allowlist a real
  bug).
- **Retro (acceptance criterion):** after ≥1 sprint, review whether the oracle
  surfaced anything actionable. If it is pure noise, delete the crate + workflow
  (they are fully isolated, so removal is a clean revert with zero blast radius
  on the shipped code).
- **Rollback:** delete `html-oracle/`, the workflow, and the `exclude` entry.
  Nothing in the shipped supply chain or PR gates depends on it.
