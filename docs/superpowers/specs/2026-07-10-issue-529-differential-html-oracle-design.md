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

- **Production entry point:** `mod html` is **private** (`lib.rs` declares `mod
  html;`, not `pub mod`). The reachable-from-out-of-tree path, under the
  `test-support` feature, is `rimap_content::test_support::sanitize_html(raw:
  &[u8], charset: Option<&str>) -> Result<rimap_content::test_support::HtmlResult,
  ContentError>` (an alias for `crate::html::sanitize`). **Name collision
  warning:** `rimap_content::sanitize` (re-exported at the crate root from
  `unicode`) is the *Unicode scrubber*, a different function — the oracle must
  call `test_support::sanitize_html` for production HTML processing and reserve
  bare `sanitize` for the Unicode step. `HtmlResult` carries `body_text: String`,
  `anchor_hrefs: Vec<String>`, `body_html: String`, `warnings:
  Vec<SecurityWarning>`.
- **`body_text` is already Unicode-scrubbed.** Production's `extract_text` routes
  the extracted text through `unicode::sanitize` (NFKC-fold via `normalize_nfkc`
  → `normalize_line_endings` → `filter_codepoints`, which strips zero-width,
  bidi-override, and C0/C1 controls → grapheme truncate). So `body_text` is
  **NFKC-normalized with invisible codepoints removed**, and those strips are
  announced only by `Unicode*` warning codes (NOT members of `DROP_EXPLAINING`).
  The reference must apply the *same* scrub before tokenizing, or benign
  NFKC/codepoint transforms become spurious HARD divergences.
- **Crate-root re-exports available to the oracle** (from `pub use unicode::{…}`):
  `rimap_content::decode(bytes, charset)`, `normalize_nfkc`, `filter_codepoints`,
  and `sanitize` (the Unicode scrubber). The oracle reuses `decode` and
  `sanitize` so its normalization is byte-identical to production's.
- **Production parser:** `scraper` (wraps `html5ever`, a full tree-construction
  parser) + `ammonia`. Both share the html5ever tokenizer, so a genuinely
  independent oracle engine must NOT be html5ever-based. `lol_html` is a
  *streaming* rewriter with no tree construction, so it will legitimately diverge
  from html5ever on malformed HTML (foster-parenting, implicit close, head/body
  hoisting) — see Failure modes; that structural divergence is a first-class
  reason the equivalence rule and body-scope gate exist.
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
  BSD-3-Clause, with its own WHATWG-conformant tokenizer independent of
  html5ever. Because the oracle crate is **excluded** from the main workspace,
  `cargo deny --all-features check` (which scans the workspace lockfile) never
  sees `lol_html` or its transitives — the `deny.toml` license allowlist is
  irrelevant to it. Since the oracle *executes* `lol_html` over adversarial email
  in CI, the nightly workflow runs its own `cargo deny check` scoped to
  `html-oracle/Cargo.lock` (Component 6) rather than relying on the main gate.

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
(workspace-pinned version echoed literally), `url` (href scheme+host parsing —
the same crate `rimap-content` already uses transitively), `serde`/`serde_json`,
`toml`. The crate ships its own `html-oracle/deny.toml` (or reuses the root one)
so the nightly `cargo deny` step has a config; its allowed-licenses list must
include `lol_html`'s BSD-3-Clause and its transitives' licenses.

Because the crate is excluded from the main workspace, none of its dependencies
(`lol_html` and transitives) enter `clippy --all-features`, `test-msrv`, or
`cargo-deny`. Its own toolchain is stable (pinned via `rust-toolchain.toml`
inheritance from the repo root, which selects stable 1.94.0), so `lol_html`'s
own MSRV is irrelevant.

### Component 2 — reference extractor (`reference.rs`)

`fn extract_reference(decoded_html: &str) -> Result<ReferenceExtract, ReferenceError>`
where

```rust
struct ReferenceExtract {
    text_tokens: BTreeSet<String>,   // normalized visible-text tokens
    href_ids:    BTreeSet<String>,   // safe-scheme (scheme, host/domain) identities
}
```

**Input is already-decoded UTF-8.** The runner decodes each corpus input exactly
once with `rimap_content::decode(raw, charset)` (Component 4) and hands the *same*
string to both engines, so byte→str decoding can never be a divergence source
(finding: charset asymmetry). The reference takes `&str`, not bytes.

Uses `lol_html::HtmlRewriter` (low-level, so text/element handlers and errors are
observable) with:

- **Implicit-body model + non-content suppression:** accumulate text by
  **default** (as if inside body), suppressing only while inside a tag in the
  *same* `NON_CONTENT_TAGS` set production skips (`script`, `style`, `noscript`,
  `template`, `head`, `title`). **Do NOT require a literal `<body>` start tag.**
  Production runs on html5ever, which *synthesizes* an `<html><head><body>`
  skeleton for every document — `extract_text` selects that synthesized `<body>`
  (`extract.rs:43`), so a bare fragment like `<p>hi</p>` still yields text.
  `lol_html` does no tree construction, so a body-presence gate would make the
  reference accumulate **nothing** on the 10-of-20 `content_html` seeds (and the
  many bare `div`/`p` email fragments) that lack a literal `<body>` — silently
  inert, always `Match`. Suppressing the explicit `<head>`/`<title>` region
  (already in the set) plus defaulting-in-body reproduces html5ever's "text not
  in head goes to body" placement without tree construction. A suppression depth
  counter gates accumulation.
  - *Unclosed-tag note:* `script`/`style`/`title`/`noscript`/`textarea` are
    raw-/escapable-raw-text elements — **both** tokenizers consume to EOF when
    they are unclosed, so an unclosed one suppresses the tail consistently in
    both engines (no masking). `head`/`template` unclosed cases are neutralized
    by the body-scope gate. Unit tests pin unclosed `<title>`/`<script>`/
    `<noscript>` behavior so a lol_html version bump cannot silently regress it.
- **Anchor handler:** on `<a href>`, parse with `url`/scheme inspection; retain
  only `http`/`https`/`mailto`. Reduce each to a **scheme+host identity** —
  `(scheme, lowercased host)` for http(s), `(mailto, lowercased domain)` for
  mailto — and **discard path/query/fragment**. This is deliberate: production's
  hrefs come from the *ammonia-rewritten* HTML (percent-encoding, entity
  resolution, and canonicalization applied), so a full-URL-string comparison
  would flag benign encoding differences as HARD. The mismatch defense the
  oracle backstops cares about the target host, not path encoding, so scheme+host
  is the right comparison altitude. The *same* reduction runs on production's
  `anchor_hrefs`.
- **Boundary separators — match `push_text`:** production's `push_text`
  (`extract.rs:136`) inserts a separating space between adjacent text nodes (when
  the buffer does not already end in whitespace) *before* the scrub, so
  `<p>a</p><p>b</p>` yields body_text `"a b"` → tokens `{a, b}`, not `{ab}`. The
  reference MUST insert an equivalent separator between distinct text chunks — the
  robust rule is to push a single space at **every element start and end tag** and
  between separate `lol_html` text chunks. Over-separating is harmless (the later
  whitespace-split + drop-empty collapses it); *under*-separating merges
  adjacent-element text into one spurious token that has no explaining warning →
  false HARD on nearly every multi-paragraph email. This boundary parity is as
  load-bearing as the Unicode-scrub parity.
- **Text normalization — byte-identical to production:** apply
  `rimap_content::sanitize` (the Unicode scrubber: NFKC + line-ending +
  `filter_codepoints` + grapheme truncate) to the separator-joined accumulated
  text, exactly as production's `extract_text` does, THEN lowercase and split on
  Unicode whitespace (`char::is_whitespace`), dropping empty tokens. Reusing
  production's scrubber guarantees NFKC folding and invisible-codepoint stripping
  are identical on both sides, so `Unicode*`-class transforms (which are NOT
  `DROP_EXPLAINING`) can never produce a HARD divergence. Production's `body_text`
  is tokenized with the same lowercase + whitespace split (it is already scrubbed
  and separator-joined). Result is a `BTreeSet<String>`.

`ReferenceError` wraps a `lol_html` rewrite/handler error. The reference engine
does **not** implement CSS-hidden detection, href-mismatch detection, or
ammonia's tag allowlist — only the body-scope + non-content-tag skip and the
shared Unicode scrub. That is the deliberate independence: the tokenizer and the
tree/streaming shape differ, and everything else production does (hidden
detection, allowlisting) is what the diff scrutinizes.

### Component 3 — two-tier equivalence rule (`diff.rs`)

For each corpus input, given production `HtmlResult` and `ReferenceExtract`:

```
# body_text is already Unicode-scrubbed; tokenize with the same
# lowercase + Unicode-whitespace split the reference uses.
prod_text_tokens = tokenize(result.body_text)
# reduce production hrefs to the SAME scheme+host identity as the reference.
prod_href_ids    = safe_scheme_ids(result.anchor_hrefs)

text_reference_only = ref.text_tokens - prod_text_tokens - allowlist_text[input]
href_reference_only = ref.href_ids    - prod_href_ids    - allowlist_href[input]
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
   with `mail-parser`; for each `text/html` part, take its raw bytes + declared
   charset. Input id = `injection/<dir>[/part<n>]`. Fixtures with no `text/html`
   part are skipped (logged at info).
3. For each input, **decode once**: `decoded = rimap_content::decode(raw,
   charset)`. Run production `test_support::sanitize_html(raw, charset)` (skip
   inputs returning `ContentError::LimitExceeded` — over-cap inputs are a separate
   concern, counted `skipped`). Run `extract_reference(&decoded)`; on
   `ReferenceError`, log-and-skip that input, counted `ref_error` (a single
   hostile input must not abort the whole run). When both succeed, apply the diff.
4. Write `html-oracle/report.json`: per-input verdict, the divergent tokens,
   which warnings fired, `production_only` (informational), and totals (`hard`,
   `soft`, `match`, `skipped`, `ref_error`, `stale_allowlist_entries`,
   `compared_nonempty`). `compared_nonempty` counts inputs where the reference
   produced a non-empty token-or-href set — a **coverage floor** that proves the
   oracle is actually comparing content, not silently inert (see finding: a
   body-gate bug could make the reference empty on half the corpus and still show
   all-`Match`). If `compared_nonempty` is 0 while inputs were processed, the run
   is treated as a HARD failure (the oracle is broken, not clean).
5. Exit code: non-zero iff `hard > 0` (`ref_error`/`skipped`/`soft` never fail
   the job). Print a compact human summary to stderr (stdout stays clean for
   potential piping).

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
- Steps: checkout (SHA-pinned action) → `cargo deny --manifest-path
  html-oracle/Cargo.toml check advisories bans licenses sources` (supply-chain
  coverage for the oracle's own dependency graph, which the main workspace gate
  never sees) → `cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root
  .` → `actions/upload-artifact` (SHA-pinned) uploads `html-oracle/report.json`
  with `if: always()`. The oracle crate carries its own `deny.toml` (or reuses
  the root one via `--config`) so `lol_html` + transitives get advisory/license/
  ban checks despite being out of the main workspace.
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
  appears in `ref.href_ids` → no divergence. No false positive from policy drops.
- **U+00A0 / zero-width / bidi / NFKC-foldable tokens:** because the reference
  runs the *same* `rimap_content::sanitize` Unicode scrub as production
  (NFKC + `filter_codepoints`), both sides fold and strip identically → `Match`.
  This is the fix for the otherwise-fatal flaw where these benign, already-
  announced Unicode transforms (whose only warnings are `Unicode*`, not
  `DROP_EXPLAINING`) would have been classified HARD and red-flooded the first
  nightly over the injection corpus. Covered by a normalization unit test.
- **Streaming-vs-tree structural divergence (foster-parenting, implicit close,
  head/body hoisting):** `lol_html` (streaming, no tree construction) and
  html5ever (full tree construction) can place a text run differently on
  malformed HTML. The body-scope gate removes the common head-hoist case. Any
  residual divergence with no explaining warning is a *genuine* tokenizer/
  structural disagreement — exactly the tokenizer-confusion class the oracle
  exists to surface — so it is correctly HARD and triaged (real bug → filed;
  benign → allowlisted). A foster-parenting unit case pins the behavior.
- **Unclosed suppression tag** (`<title>foo`, `<script>…`EOF): raw-text elements
  are consumed to EOF by both tokenizers, so suppression is consistent (no
  masking of later divergences); `head`/`template` are neutralized by body-scope.
  Unit tests pin this against a `lol_html` regression.
- **Reference extraction error** (`lol_html` handler/limit error): the runner
  logs-and-skips that single input (`ref_error` count), never aborting the run.
- **Malformed `.eml` with no `text/html`:** skipped with an info log, not an
  error.
- **Charset (both engines):** `mail-parser` charset-decodes text parts to UTF-8
  before storage, and production's `bodies.rs` passes those decoded bytes plus the
  *declared* charset to `html::sanitize`. The oracle carries the identical
  `(bytes, charset)` pair: the runner decodes once via `rimap_content::decode(raw,
  charset)` for the reference, and production re-decodes the same `raw`+`charset`
  internally. Both engines therefore decode identically — even in the pathological
  UTF-8-bytes-under-a-legacy-label double-decode case — so charset can never be a
  false divergence source. A Windows-1252 unit test pins that `part.contents()` is
  pre-decoded and the declared charset is carried faithfully.

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
- `href_identity_ignores_path_and_encoding`: `https://e.com/a%20b?x=%41` and
  `https://e.com/other` both reduce to the same `(https, e.com)` identity, so a
  path/query/encoding-only difference is not a divergence.
- `shared_unicode_scrub_no_false_hard`: a token containing a zero-width joiner
  and an NFKC-foldable ligature normalizes identically on both sides (production
  `body_text` vs reference) → `Match`, proving `Unicode*` transforms never HARD.
- `windows_1252_input_decodes_consistently`: an ISO-8859-1/Windows-1252 seed
  (byte `0xE9`) yields the same `é` token on both sides via `decode`.
- `bodyless_fragment_is_not_inert`: a bare `<p>visible</p>` (no `<html>`/`<body>`)
  surfaces the token `visible` from the reference — proving the implicit-body
  model, so the reference is not silently empty on body-less corpus seeds.
- `element_boundary_separator_parity`: `<p>a</p><p>b</p>` (and `<b>foo</b><b>bar</b>`)
  tokenize to `{a, b}` (`{foo, bar}`) on **both** sides → `Match`, pinning the
  `push_text`-equivalent boundary separator so adjacent-element text never merges
  into a spurious HARD.
- `structural_divergence_is_hard`: a foster-parented / body-hoisted text run that
  the reference surfaces with no explaining warning → `Hard` (the intended
  tokenizer-confusion signal), confirming the class is not silently dropped.
- `unclosed_suppression_tag_no_masking`: an unclosed `<script>`/`<title>`/
  `<noscript>` suppresses only its own raw-text tail consistently and does not
  mask a later divergence.
- `reference_error_is_skipped_not_fatal`: a synthesized `ReferenceError` for one
  input increments `ref_error` and leaves the exit code driven only by `hard`.
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
- **Retro (acceptance criterion) — operational keep/kill bar:** after ≥1 sprint
  of nightly runs, apply this falsifiable rule:
  - **KEEP** if *either* (a) at least one HARD divergence led to a filed and
    confirmed sanitizer bug (the oracle earned its keep by catching a real
    defect), *or* (b) the gate is stable and low-maintenance — the allowlist has
    **< 10** entries, is **not growing** week-over-week, there are **zero
    unexplained (non-allowlisted) HARD** divergences on the latest run, **and**
    `compared_nonempty` covers the bulk of processed inputs (the oracle is
    demonstrably comparing content — an all-`Match` run with near-zero
    `compared_nonempty` is a broken/inert oracle, counting as KILL evidence, not
    KEEP).
  - **KILL** otherwise — specifically if the allowlist must exceed 10 entries or
    keep growing just to hold the gate green, and no HARD has ever mapped to a
    real bug. Delete the crate + workflow (fully isolated, so removal is a clean
    revert with zero blast radius on shipped code).
  These thresholds are the decision rule, not aspirations; record the three
  numbers (allowlist size, growth, unexplained-HARD count) plus any filed bugs in
  the retro so keep/kill is mechanical, not a judgment call.
- **Rollback:** delete `html-oracle/`, the workflow, and the `exclude` entry.
  Nothing in the shipped supply chain or PR gates depends on it.
