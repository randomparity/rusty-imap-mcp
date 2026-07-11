# `--corpus-root` oracle flag + pinned-SHA corpus checkout — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Issue:** [#550](https://github.com/randomparity/rusty-imap-mcp/issues/550)
(follow-up B to [#529](https://github.com/randomparity/rusty-imap-mcp/issues/529))

**Spec:** `docs/superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md`
(Components 2 & 3). Component 1 (the corpus repo) shipped under #549; wave-1
ingestion (#551) is separate.

**Goal:** Wire the main-repo oracle runner to consume an external corpus tree
deterministically — a `--corpus-root` flag mirroring the existing `--epvme-dir`
pattern, a per-`corpus/`-prefix comparison floor, direction-aware canary
assertions driven by each input's `meta.toml` `probes` tag, a
`corpus-allowlist.toml`, and a second pinned-SHA corpus checkout in the nightly
workflow — **without touching the oracle's diff/reference/normalization logic**
(`diff.rs`, `reference.rs`, `norm.rs` stay byte-for-byte unchanged).

## Base branch & guardrails

- **Base branch:** `main`. Work on `feat/corpus-root-oracle-550`.
- **Oracle-crate guardrails** (the crate is workspace-**excluded** — its own
  `Cargo.lock`, only `unwrap_used = "warn"` in `[lints.clippy]`; the workspace
  `-D warnings` / `print_stderr` denies do **not** apply, so `eprintln!` on
  stderr is the established diagnostic idiom here):
  - `cargo test --manifest-path html-oracle/Cargo.toml`
  - `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
  - `cargo fmt --manifest-path html-oracle/Cargo.toml -- --check`
  - `cargo deny --locked --manifest-path html-oracle/Cargo.toml check`
- **Main workspace unaffected:** `just check && just lint` (the excluded crate
  must not enter the workspace graph).
- **Workflow guardrails:** `actionlint .github/workflows/nightly-html-oracle.yml`
  and `zizmor .github/workflows/nightly-html-oracle.yml` must be clean. Every
  `uses:` is a full 40-char SHA + version comment; `permissions: contents: read`.

## Global constraints

- **No new runtime dependencies.** `toml`, `serde`, `mail-parser` are already in
  the oracle's `Cargo.toml`. The `meta.toml` `probes` read reuses `toml`.
- **`--corpus-root` and `--epvme-dir` coexist** — distinct data sources, not a
  replacement (spec "Considered & rejected"). The EPVME path
  (`load_eml_tree`, `epvme-allowlist.toml`) stays **behaviorally unchanged**.
- **Prefix isolation:** corpus inputs are keyed `corpus/<stem>` by
  `load_eml_tree`/`load_corpus_tree`. Every corpus count and canary decision is
  computed over the `corpus/` prefix only, never the global totals — the 33
  in-repo inputs must never prop up a broken corpus.
- **Empty-corpus plumbing proof stays green.** The nightly first points at the
  empty-but-valid corpus commit
  `69d31655e51ade38dd7ed6ee8209336d80516562` with **no** `--corpus-min-compared`.
  With zero corpus inputs: zero corpus counts, no floor check (flag absent), no
  `probes` present ⇒ no canary assertion fires. The run must exit 0 on the
  in-repo corpus alone.
- **Corpus checkout auth:** the corpus repo is **private**. The nightly's second
  `actions/checkout` authenticates with a fine-grained PAT read secret
  `secrets.CORPUS_READ_TOKEN` (operator-provisioned; `contents: read` on
  `randomparity/rusty-imap-mcp-corpus`). Going public later drops only the
  `token:` line.

## Files touched

```
html-oracle/
├── src/main.rs         # Args (+corpus_root,+corpus_min_compared), --help, ParsedArgs,
│                       #   Kind, per-prefix CorpusReport, check_floor, check_canaries,
│                       #   assemble_inputs/assemble_allowlist corpus branches, exit wiring
├── src/corpus.rs       # CorpusInput.probes; load_corpus_tree (sibling meta read)
└── corpus-allowlist.toml   # NEW — ships empty, required-reason header
.github/workflows/nightly-html-oracle.yml   # second pinned-SHA checkout + --corpus-root run
AGENTS.md               # "--corpus-root" note in the oracle section
```

`diff.rs`, `reference.rs`, `norm.rs`, `allowlist.rs`, `epvme-allowlist.toml` are
**not** modified.

---

## Task 1 — `--corpus-root` / `--corpus-min-compared` args + `--help`

**Files:** `html-oracle/src/main.rs`.

**Why:** the runner must accept the new external tree and an optional floor, and
`--help` must name `--repo-root` (in-repo seeds) and `--corpus-root` (external
checkout) distinctly to defuse the one-word naming hazard. Today `parse_args`
returns `Args` directly and silently ignores unknown args; refactor it into a
pure, testable scanner so the acceptance criterion "unit tests cover the arg" is
met without spawning the binary.

**Interfaces produced:**
- `Args` gains `corpus_root: Option<PathBuf>` and
  `corpus_min_compared: Option<usize>`.
- `enum ParsedArgs { Run(Box<Args>), Help, Error(String) }` (box to keep the
  `Run` variant small; `Error` carries a diagnostic for a present-but-invalid
  flag value — fail fast rather than silently degrade).
- `fn parse_args_from<I: Iterator<Item = String>>(iter: I, epvme_env:
  Option<PathBuf>, corpus_env: Option<PathBuf>) -> ParsedArgs` — pure; env
  defaults injected. `parse_args()` reads `EPVME_DIR` / `CORPUS_ROOT` from the
  environment and delegates.
- `const USAGE: &str` naming every flag.

- [ ] **Step 1 — failing tests** in `main.rs` `#[cfg(test)] mod tests`:

```rust
fn run_args(argv: &[&str]) -> Args {
    match parse_args_from(argv.iter().map(|s| s.to_string()), None, None) {
        ParsedArgs::Run(a) => *a,
        ParsedArgs::Help => panic!("expected Run"),
    }
}

#[test]
fn parses_corpus_root_and_min_compared() {
    let a = run_args(&["--corpus-root", "/c", "--corpus-min-compared", "42"]);
    assert_eq!(a.corpus_root.as_deref(), Some(Path::new("/c")));
    assert_eq!(a.corpus_min_compared, Some(42));
}

#[test]
fn corpus_root_defaults_from_env() {
    let p = PathBuf::from("/from-env");
    let parsed = parse_args_from(std::iter::empty(), None, Some(p.clone()));
    let ParsedArgs::Run(a) = parsed else { panic!("expected Run") };
    assert_eq!(a.corpus_root, Some(p));
}

#[test]
fn explicit_corpus_root_overrides_env() {
    let parsed = parse_args_from(
        ["--corpus-root", "/cli"].iter().map(|s| s.to_string()),
        None,
        Some(PathBuf::from("/env")),
    );
    let ParsedArgs::Run(a) = parsed else { panic!("expected Run") };
    assert_eq!(a.corpus_root.as_deref(), Some(Path::new("/cli")));
}

#[test]
fn help_flag_yields_help_and_names_both_roots() {
    for flag in ["--help", "-h"] {
        let parsed = parse_args_from([flag].iter().map(|s| s.to_string()), None, None);
        assert!(matches!(parsed, ParsedArgs::Help), "{flag}");
    }
    assert!(USAGE.contains("--repo-root"));
    assert!(USAGE.contains("--corpus-root"));
    assert!(USAGE.contains("--corpus-min-compared"));
}

#[test]
fn unparseable_min_compared_is_an_error_not_a_silent_disable() {
    // A typo must NOT collapse to "no floor" — that would silently remove the
    // very guard the flag exists to provide.
    let parsed = parse_args_from(
        ["--corpus-min-compared", "notanumber"].iter().map(|s| s.to_string()),
        None,
        None,
    );
    assert!(matches!(parsed, ParsedArgs::Error(_)));
}
```

- [ ] **Step 2 — run, verify fail:**
  `cargo test --manifest-path html-oracle/Cargo.toml --lib parses_ help_ corpus_`
  Expected: FAIL (symbols undefined).

- [ ] **Step 3 — implement.** Replace `Args`, `parse_args`, and add
  `ParsedArgs`/`parse_args_from`/`USAGE`:

```rust
struct Args {
    repo_root: PathBuf,
    report: PathBuf,
    epvme_dir: Option<PathBuf>,
    corpus_root: Option<PathBuf>,
    corpus_min_compared: Option<usize>,
    limit: Option<usize>,
}

enum ParsedArgs {
    Run(Box<Args>),
    Help,
    Error(String),
}

const USAGE: &str = "\
html-oracle — differential HTML→text sanitizer oracle

USAGE:
    html-oracle [OPTIONS]

OPTIONS:
    --repo-root <DIR>            Main-repo checkout: in-repo fuzz + injection seeds
    --corpus-root <DIR>          External corpus checkout (rusty-imap-mcp-corpus);
                                 loaded under `corpus/…` ids. Env: CORPUS_ROOT
    --epvme-dir <DIR>            Local EPVME dataset tree. Env: EPVME_DIR
    --corpus-min-compared <N>    Fail if fewer than N corpus/ inputs compare nonempty
    --limit <N>                  Cap source .eml files per external tree
    --report <FILE>              JSON report path (default: html-oracle/report.json)
    -h, --help                   Print this help
";

fn parse_args() -> ParsedArgs {
    parse_args_from(
        std::env::args().skip(1),
        std::env::var_os("EPVME_DIR").map(PathBuf::from),
        std::env::var_os("CORPUS_ROOT").map(PathBuf::from),
    )
}

fn parse_args_from<I: Iterator<Item = String>>(
    iter: I,
    epvme_env: Option<PathBuf>,
    corpus_env: Option<PathBuf>,
) -> ParsedArgs {
    let mut repo_root: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut epvme_dir = epvme_env;
    let mut corpus_root = corpus_env;
    let mut corpus_min_compared: Option<usize> = None;
    let mut limit: Option<usize> = None;
    let mut it = iter;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => return ParsedArgs::Help,
            "--repo-root" => repo_root = it.next().map(PathBuf::from),
            "--report" => report = it.next().map(PathBuf::from),
            "--epvme-dir" => epvme_dir = it.next().map(PathBuf::from),
            "--corpus-root" => corpus_root = it.next().map(PathBuf::from),
            "--corpus-min-compared" => match it.next() {
                Some(v) => match v.parse() {
                    Ok(n) => corpus_min_compared = Some(n),
                    Err(_) => {
                        return ParsedArgs::Error(format!(
                            "--corpus-min-compared expects a non-negative integer, got {v:?}"
                        ));
                    }
                },
                None => {
                    return ParsedArgs::Error(
                        "--corpus-min-compared requires a value".to_string(),
                    );
                }
            },
            "--limit" => limit = it.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let repo_root = repo_root.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let report =
        report.unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("report.json"));
    ParsedArgs::Run(Box::new(Args {
        repo_root,
        report,
        epvme_dir,
        corpus_root,
        corpus_min_compared,
        limit,
    }))
}
```

In `main()`, handle the new enum at the top:

```rust
fn main() -> ExitCode {
    let args = match parse_args() {
        ParsedArgs::Run(a) => *a,
        ParsedArgs::Help => {
            eprint!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ParsedArgs::Error(msg) => {
            eprintln!("html-oracle: {msg}");
            return ExitCode::FAILURE;
        }
    };
    // …rest unchanged for now…
}
```

> `matches!` is used only in **test** code (the existing `diff.rs`/oracle tests
> already do this); keep non-test control flow on explicit `match`/`let-else`
> per house style.

- [ ] **Step 4 — run, verify pass:** the four tests from Step 1.
- [ ] **Step 5 — commit:**
  `git commit -m "feat(oracle): --corpus-root/--corpus-min-compared args + --help (#550)"`

---

## Task 2 — corpus loader: sibling `meta.toml` `probes` read

**Files:** `html-oracle/src/corpus.rs`, `html-oracle/src/main.rs` (call site in a
later task).

**Why:** the canary check needs each corpus input's `probes` families. Only the
`--corpus-root` path reads sibling metadata; the in-repo and `--epvme-dir` paths
carry none (spec Component 2). Keep `load_eml_tree` byte-for-byte unchanged so
the EPVME path and its existing tests are untouched; add a sibling
`load_corpus_tree` that reuses `collect_eml_files` + `extract_html_parts`.

**Interfaces produced:**
- `CorpusInput` gains `pub probes: Vec<String>` (empty for all non-corpus
  inputs). `CorpusInput` does **not** derive `Default`, and it is constructed at
  **two** sites — both must set `probes: Vec::new()` or the crate won't compile
  (`missing field probes`): `load_fuzz_seeds` (`corpus.rs:~109`) and
  `extract_html_parts` (`corpus.rs:~167`). `load_corpus_tree` then overwrites the
  field on the corpus inputs it produces.
- `pub fn load_corpus_tree(dir: &Path, limit: Option<usize>) ->
  Result<Vec<CorpusInput>, CorpusError>` — same walk/sort/limit as
  `load_eml_tree` with a hardcoded `"corpus"` prefix, plus a sibling
  `<stem>.meta.toml` `probes` read applied to every part of that `.eml`.

- [ ] **Step 1 — failing tests** in `corpus.rs` `mod tests`:

```rust
#[test]
fn load_corpus_tree_reads_probes_and_prefixes_ids() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("corpus");
    std::fs::create_dir_all(root.join("wave1")).unwrap();
    let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n";
    std::fs::write(root.join("wave1/aa11.eml"), eml).unwrap();
    std::fs::write(
        root.join("wave1/aa11.meta.toml"),
        "probes = [\"stray-tag-boundary\", \"entity-href\"]\n",
    )
    .unwrap();

    let inputs = load_corpus_tree(&root, None).unwrap();
    let got = inputs.iter().find(|i| i.id == "corpus/aa11").expect("loaded");
    assert_eq!(got.probes, vec!["stray-tag-boundary", "entity-href"]);
}

#[test]
fn load_corpus_tree_tolerates_missing_meta() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("corpus");
    std::fs::create_dir_all(&root).unwrap();
    let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n";
    std::fs::write(root.join("bb22.eml"), eml).unwrap();
    // No sibling meta.toml.
    let inputs = load_corpus_tree(&root, None).unwrap();
    let got = inputs.iter().find(|i| i.id == "corpus/bb22").expect("loaded");
    assert!(got.probes.is_empty());
}
```

- [ ] **Step 2 — run, verify fail:**
  `cargo test --manifest-path html-oracle/Cargo.toml --lib corpus::tests::load_corpus_tree`

- [ ] **Step 3 — implement.** Add the `probes` field to `CorpusInput`, set
  `probes: Vec::new()` at **both** construction sites (`load_fuzz_seeds` and
  `extract_html_parts` — grep `CorpusInput {` to confirm you caught them all),
  and add:

```rust
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    probes: Vec<String>,
}

/// Load an external corpus tree the same way [`load_eml_tree`] does (walk, sort,
/// deterministic `limit`), keyed under `corpus/…`, additionally attaching each
/// input's sibling `<stem>.meta.toml` `probes` families. A missing/unparseable
/// meta yields empty `probes` (the input still loads) and logs a warning — the
/// corpus repo's self-validation (issue #549, criterion 8) is the gate that
/// guarantees valid metadata at the pinned SHA.
pub fn load_corpus_tree(
    dir: &Path,
    limit: Option<usize>,
) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut files = Vec::new();
    collect_eml_files(dir, &mut files);
    files.sort();
    if let Some(limit) = limit {
        files.truncate(limit);
    }
    let mut out = Vec::new();
    for eml in &files {
        let stem = eml
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let first = out.len();
        extract_html_parts(eml, &format!("corpus/{stem}"), &mut out)?;
        let probes = read_probes(eml);
        for input in &mut out[first..] {
            input.probes = probes.clone();
        }
    }
    Ok(out)
}

fn read_probes(eml: &Path) -> Vec<String> {
    let meta_path = eml.with_extension("meta.toml");
    let Ok(text) = std::fs::read_to_string(&meta_path) else {
        return Vec::new();
    };
    match toml::from_str::<Meta>(&text) {
        Ok(meta) => meta.probes,
        Err(e) => {
            eprintln!("html-oracle: unparseable {}: {e}", meta_path.display());
            Vec::new()
        }
    }
}
```

> `Path::with_extension("meta.toml")` turns `aa11.eml` into `aa11.meta.toml`
> (it replaces the final extension). Verify the stem/sibling convention matches
> the corpus repo (`<stem>.eml` + `<stem>.meta.toml`, content-hash stems).

- [ ] **Step 4 — run, verify pass** (both new tests) and confirm the untouched
  EPVME tests still pass:
  `cargo test --manifest-path html-oracle/Cargo.toml --lib corpus::`
- [ ] **Step 5 — commit:**
  `git commit -m "feat(oracle): load_corpus_tree reads sibling meta.toml probes (#550)"`

---

## Task 3 — wire corpus loading + `corpus-allowlist.toml`

**Files:** `html-oracle/src/main.rs`, `html-oracle/corpus-allowlist.toml` (new).

**Why:** `assemble_inputs` must append the corpus tree when `--corpus-root` is
set (mirroring the EPVME branch), and `assemble_allowlist` must merge
`corpus-allowlist.toml` **only** then, so `corpus/…` entries never show stale in
a hermetic `--repo-root` run.

- [ ] **Step 1 — create `html-oracle/corpus-allowlist.toml`** (ships empty,
  mirrors `epvme-allowlist.toml`):

```toml
# Known-benign divergences specific to the external corpus tree (issue #550).
#
# This file is merged into the allowlist ONLY when --corpus-root is set, so its
# `corpus/…` entries never appear stale in the hermetic --repo-root nightly run
# (which does not load the corpus). Populate from the wave-1 baseline; never
# allowlist a real sanitizer silent-drop — file an issue instead. Each entry
# REQUIRES a `reason` (fail closed).
#
# [[allow]]
# input = "corpus/<content-hash-stem>"
# tokens = ["benignword"]
# reason = "why this divergence is benign"
```

- [ ] **Step 2 — `assemble_allowlist` gains `with_corpus`:**

```rust
fn assemble_allowlist(with_epvme: bool, with_corpus: bool) -> Result<allowlist::Allowlist, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut text = std::fs::read_to_string(manifest.join("allowlist.toml")).unwrap_or_default();
    if with_epvme && let Ok(extra) = std::fs::read_to_string(manifest.join("epvme-allowlist.toml"))
    {
        text.push('\n');
        text.push_str(&extra);
    }
    if with_corpus
        && let Ok(extra) = std::fs::read_to_string(manifest.join("corpus-allowlist.toml"))
    {
        text.push('\n');
        text.push_str(&extra);
    }
    allowlist::load(&text).map_err(|e| e.to_string())
}
```

- [ ] **Step 3 — `assemble_inputs` gains the corpus branch** (after the EPVME
  branch, before `Ok(inputs)`):

```rust
    if let Some(corpus_root) = &args.corpus_root {
        let mut extra =
            corpus::load_corpus_tree(corpus_root, args.limit).map_err(|e| e.to_string())?;
        eprintln!(
            "html-oracle: corpus {} html part(s) from {}",
            extra.len(),
            corpus_root.display()
        );
        inputs.append(&mut extra);
    }
```

- [ ] **Step 4 — update the `assemble_allowlist` call in `main()`:**

```rust
    let allow = match assemble_allowlist(args.epvme_dir.is_some(), args.corpus_root.is_some()) {
```

- [ ] **Step 5 — verify** it compiles and the whole suite is still green:
  `cargo test --manifest-path html-oracle/Cargo.toml`
  `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
- [ ] **Step 6 — commit:**
  `git commit -m "feat(oracle): load corpus tree + corpus-allowlist under --corpus-root (#550)"`

---

## Task 4 — per-`corpus/`-prefix counts (`Kind` refactor + `CorpusReport`)

**Files:** `html-oracle/src/main.rs`.

**Why:** the global inert tripwire (`total>0 && compared_nonempty==0`) is masked
by the 33 in-repo inputs and cannot detect an all-skipped corpus. The runner must
report, attributable to the `corpus/` prefix and separate from global totals:
`total`, `skipped`, `ref_error`, `compared_nonempty`. Refactor `process_one` to
**return** a per-input `Kind` (it keeps its existing global-total and
hard/soft-vec side effects unchanged) so both the corpus counts and the Task-5
canary check derive from one classification.

**Interfaces produced:**
- `enum Kind { SanitizeSkip, BinarySkip, RefError, ComparedEmpty, ComparedNonempty }`
  (`#[derive(Clone, Copy, PartialEq, Eq, Debug)]`).
- `struct CorpusRecord { probes: Vec<String>, kind: Kind }` collected per
  `corpus/`-prefixed input.
- `#[derive(Default, Serialize)] struct CorpusReport { total, skipped,
  ref_error, compared_nonempty: usize }` (+ Task-5 fields).
- `Report` gains `corpus: Option<CorpusReport>` (`skip_serializing_if =
  "Option::is_none"`), `Some` iff `--corpus-root` set.

- [ ] **Step 1 — failing test** (drive the count wiring through the runner in
  `tests/oracle_logic.rs`; see Task 5 for canary/floor integration tests):

```rust
#[test]
fn reports_corpus_prefixed_counts() {
    let tmp = tempfile::tempdir().unwrap();
    // In-repo seed so the global run is not inert.
    let seed = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("hello"), b"<p>hello world</p>").unwrap();
    // One corpus input.
    let corpus = tmp.path().join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(
        corpus.join("c1.eml"),
        "Content-Type: text/html; charset=utf-8\r\n\r\n<p>alpha beta</p>\r\n",
    )
    .unwrap();
    std::fs::write(corpus.join("c1.meta.toml"), "probes = []\n").unwrap();

    let report = tmp.path().join("report.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"]).arg(tmp.path())
        .args(["--corpus-root"]).arg(&corpus)
        .args(["--report"]).arg(&report)
        .status().unwrap();
    assert!(status.success());

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(json["corpus"]["total"], 1);
    assert_eq!(json["corpus"]["compared_nonempty"], 1);
    assert_eq!(json["corpus"]["skipped"], 0);
}
```

- [ ] **Step 2 — run, verify fail** (`json["corpus"]` is null today).

- [ ] **Step 3 — implement.**
  - Add `Kind`, `CorpusRecord`, `CorpusReport`; add `corpus_records:
    Vec<CorpusRecord>` to `Outcome`.
  - Change `process_one` to `-> Kind`, returning the matching variant at each
    exit while keeping every existing `out.totals.*` increment and
    hard/soft-vec push:
    - sanitize error → `Kind::SanitizeSkip` (after `out.totals.skipped += 1`)
    - `is_mostly_binary` → `Kind::BinarySkip` (after `skipped += 1`)
    - reference error → `Kind::RefError`
    - reached `classify`: return `Kind::ComparedNonempty` when
      `!refx.text_tokens.is_empty() || !refx.href_ids.is_empty()` (the same
      predicate that increments `compared_nonempty`), else `Kind::ComparedEmpty`.
      Compute this **before** `record_verdict` so the verdict path is unchanged.
  - In `run_inputs`, capture the returned `Kind` and, for `corpus/`-prefixed
    ids, push a `CorpusRecord { probes: input.probes.clone(), kind }`.
  - After `run_inputs`, when `args.corpus_root.is_some()`, fold
    `corpus_records` into a `CorpusReport`:

```rust
fn corpus_report(records: &[CorpusRecord]) -> CorpusReport {
    let mut r = CorpusReport { total: records.len(), ..CorpusReport::default() };
    for rec in records {
        match rec.kind {
            Kind::SanitizeSkip | Kind::BinarySkip => r.skipped += 1,
            Kind::RefError => r.ref_error += 1,
            Kind::ComparedNonempty => r.compared_nonempty += 1,
            Kind::ComparedEmpty => {}
        }
    }
    r
}
```

  - Set `Report.corpus = args.corpus_root.is_some().then(|| corpus_report(&outcome.corpus_records))`.

> The coverage denominator the spec's floor uses is
> `total − skipped − ref_error`; expose the raw counts and let the reader derive
> it. Do not pre-compute a ratio here.

- [ ] **Step 4 — run, verify pass** (the count test) and full suite green.
- [ ] **Step 5 — commit:**
  `git commit -m "feat(oracle): per-corpus-prefix comparison counts in report (#550)"`

---

## Task 5 — floor check + direction-aware canary check + exit wiring

**Files:** `html-oracle/src/main.rs`.

**Why:** `--corpus-min-compared <N>` fails the run if the corpus comparison count
falls below `N` (the real guard against a pinned-SHA bump that silently skips the
whole corpus). The canary check asserts, per `probes` family, direction-aware
health: text-token families (`stray-tag-boundary`, `entity-href`) must produce
≥1 live comparison; `binary-part` must be **skipped by `is_mostly_binary`** — its
assertion is **inverted** (a live comparison/HARD means the guard regressed).
Both checks are pure functions so unit tests cover them without the binary.

**Interfaces produced:**
- `const TEXT_TOKEN_FAMILIES: &[&str] = &["stray-tag-boundary", "entity-href"];`
- `const BINARY_FAMILY: &str = "binary-part";`
- `fn check_floor(compared_nonempty: usize, min: Option<usize>) -> Option<String>`
- `fn check_canaries(records: &[CorpusRecord]) -> Vec<String>`
- `CorpusReport` gains `#[serde] min_compared: Option<usize>`,
  `floor_breach: Option<String>`, `canary_failures: Vec<String>`.

- [ ] **Step 1 — failing unit tests** in `main.rs` `mod tests`:

```rust
fn rec(probes: &[&str], kind: Kind) -> CorpusRecord {
    CorpusRecord { probes: probes.iter().map(|s| s.to_string()).collect(), kind }
}

#[test]
fn floor_fails_only_below_min() {
    assert!(check_floor(5, Some(10)).is_some());
    assert!(check_floor(10, Some(10)).is_none());
    assert!(check_floor(0, None).is_none()); // flag absent (plumbing proof)
}

#[test]
fn canaries_empty_corpus_is_silent() {
    // Empty-but-valid corpus: no probes present, no assertion fires.
    assert!(check_canaries(&[]).is_empty());
}

#[test]
fn text_family_needs_a_live_comparison() {
    // Healthy: a stray-tag-boundary input that produced a live comparison.
    assert!(check_canaries(&[rec(&["stray-tag-boundary"], Kind::ComparedNonempty)]).is_empty());
    // Regressed: tagged but inert (guard turned it into an empty/skip outcome).
    let fails = check_canaries(&[rec(&["entity-href"], Kind::ComparedEmpty)]);
    assert_eq!(fails.len(), 1);
    assert!(fails[0].contains("entity-href"));
}

#[test]
fn binary_part_canary_is_inverted() {
    // Healthy: skipped by is_mostly_binary.
    assert!(check_canaries(&[rec(&["binary-part"], Kind::BinarySkip)]).is_empty());
    // Regressed: it produced a live comparison instead of being skipped.
    let fails = check_canaries(&[rec(&["binary-part"], Kind::ComparedNonempty)]);
    assert_eq!(fails.len(), 1);
    assert!(fails[0].contains("is_mostly_binary"));
    assert!(fails[0].contains("no longer decodes")); // names the decode hypothesis
}

#[test]
fn binary_part_canary_flags_non_guard_skip_without_misattribution() {
    // A binary-part input that errored in sanitize (never reached the guard) is
    // still unhealthy, but the message must name the "different stage" path too,
    // not assert a false is_mostly_binary regression.
    let fails = check_canaries(&[rec(&["binary-part"], Kind::SanitizeSkip)]);
    assert_eq!(fails.len(), 1);
    assert!(fails[0].contains("different stage"));
}
```

- [ ] **Step 2 — run, verify fail.**

- [ ] **Step 3 — implement the pure checks:**

```rust
fn check_floor(compared_nonempty: usize, min: Option<usize>) -> Option<String> {
    let min = min?;
    if compared_nonempty < min {
        Some(format!(
            "corpus comparison floor breached: {compared_nonempty} < --corpus-min-compared {min}"
        ))
    } else {
        None
    }
}

fn check_canaries(records: &[CorpusRecord]) -> Vec<String> {
    let mut fails = Vec::new();
    for family in TEXT_TOKEN_FAMILIES {
        let tagged: Vec<&CorpusRecord> =
            records.iter().filter(|r| r.probes.iter().any(|p| p == family)).collect();
        if tagged.is_empty() {
            continue; // family not present (e.g. empty corpus) — nothing to assert
        }
        let live = tagged.iter().filter(|r| r.kind == Kind::ComparedNonempty).count();
        if live == 0 {
            fails.push(format!(
                "canary family '{family}' produced 0 live comparisons — comparison-layer \
                 hardening regressed (its guard inputs went inert) or the canary was lost"
            ));
        }
    }
    let bin: Vec<&CorpusRecord> =
        records.iter().filter(|r| r.probes.iter().any(|p| p == BINARY_FAMILY)).collect();
    if !bin.is_empty() {
        // Healthy iff the is_mostly_binary guard fired (BinarySkip). Any other
        // outcome means the guard did NOT fire — either it regressed (input
        // reached the comparison stage: ComparedEmpty/ComparedNonempty/RefError)
        // or the input errored earlier in sanitize (SanitizeSkip). The message
        // names all three hypotheses so triage is not biased toward a false
        // security-regression conclusion.
        let via_guard = bin.iter().filter(|r| r.kind == Kind::BinarySkip).count();
        if via_guard != bin.len() {
            let off = bin.len() - via_guard;
            fails.push(format!(
                "binary-part canary unhealthy ({via_guard}/{} skipped via is_mostly_binary, \
                 {off} did not): the is_mostly_binary guard regressed, this canary no longer \
                 decodes to >10% U+FFFD, or it was skipped/errored by a different stage",
                bin.len()
            ));
        }
    }
    fails
}
```

- [ ] **Step 4 — wire into `main()` and the exit code.** After building
  `CorpusReport`, when `args.corpus_root.is_some()`:
  - `corpus.min_compared = args.corpus_min_compared;`
  - `corpus.floor_breach = check_floor(corpus.compared_nonempty, args.corpus_min_compared);`
  - `corpus.canary_failures = check_canaries(&outcome.corpus_records);`
  Extend the exit decision (fold into `exit_code`, or compute a
  `Vec<String>` of fatal reasons): fail when `hard > 0` **or** `inert` **or**
  the corpus `floor_breach` is `Some` **or** `canary_failures` is non-empty. Emit
  each reason via `eprintln!` before returning `ExitCode::FAILURE`. Update
  `print_summary` to echo the corpus counts when present.

- [ ] **Step 5 — integration tests** in `tests/oracle_logic.rs`:

```rust
#[test]
fn corpus_min_compared_above_actual_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("hello"), b"<p>hello world</p>").unwrap();
    let corpus = tmp.path().join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(
        corpus.join("c1.eml"),
        "Content-Type: text/html; charset=utf-8\r\n\r\n<p>alpha</p>\r\n",
    ).unwrap();
    std::fs::write(corpus.join("c1.meta.toml"), "probes = []\n").unwrap();

    let report = tmp.path().join("report.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"]).arg(tmp.path())
        .args(["--corpus-root"]).arg(&corpus)
        .args(["--corpus-min-compared", "99"])
        .args(["--report"]).arg(&report)
        .status().unwrap();
    assert!(!status.success(), "floor breach must fail the run");
}

#[test]
fn empty_corpus_plumbing_proof_greens() {
    // Mirrors the nightly's step-2 empty-but-valid corpus, floor flag absent.
    let tmp = tempfile::tempdir().unwrap();
    let seed = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("hello"), b"<p>hello world</p>").unwrap();
    let corpus = tmp.path().join("corpus"); // empty tree
    std::fs::create_dir_all(&corpus).unwrap();

    let report = tmp.path().join("report.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"]).arg(tmp.path())
        .args(["--corpus-root"]).arg(&corpus)
        .args(["--report"]).arg(&report)
        .status().unwrap();
    assert!(status.success(), "empty corpus + no floor must green");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(json["corpus"]["total"], 0);
}
```

  Add a binary-part canary integration test only if a compact >10%-`U+FFFD`
  fixture is easy to synthesize inline; the unit test on `check_canaries` already
  covers the inversion, so this is optional coverage, not required.

- [ ] **Step 6 — run, verify all pass; full crate guardrails:**
  `cargo test --manifest-path html-oracle/Cargo.toml`
  `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
  `cargo fmt --manifest-path html-oracle/Cargo.toml -- --check`
- [ ] **Step 7 — commit:**
  `git commit -m "feat(oracle): corpus floor + direction-aware canary gate (#550)"`

---

## Task 6 — nightly workflow + docs

**Files:** `.github/workflows/nightly-html-oracle.yml`, `AGENTS.md`.

**Why:** the nightly must check out the private corpus repo at a pinned SHA and
run the oracle with `--corpus-root`. The floor flag is **absent** for now (no
baseline; it lands in the wave-1 SHA-bump PR under #551).

- [ ] **Step 1 — add the corpus checkout + `--corpus-root` run** to
  `nightly-html-oracle.yml`. Insert **only** the checkout step after the existing
  main `Checkout` step and before `Install Rust toolchain`:

```yaml
      - name: Checkout corpus (pinned SHA)
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          repository: randomparity/rusty-imap-mcp-corpus
          ref: 69d31655e51ade38dd7ed6ee8209336d80516562  # PINNED — bump via reviewed PR only
          path: corpus
          token: ${{ secrets.CORPUS_READ_TOKEN }}
          persist-credentials: false
```

  > **Do NOT add a "non-empty corpus" assertion in this PR.** The pinned commit
  > `69d3165…` is the empty-but-valid corpus (zero `.eml`, verified: it is the
  > only commit on the repo and #549's scaffold), so a
  > `find corpus -name '*.eml'` guard would exit 1 and turn the plumbing-proof
  > nightly red — the opposite of the acceptance criterion. The non-empty
  > assertion belongs in the **#551 wave-1 SHA-bump PR**, where the pin points at
  > a populated tree. Here, checkout-only is correct; the oracle loading zero
  > corpus inputs and still greening on the in-repo seeds *is* the proof.

  Change the run step to:

```yaml
      - name: Run differential oracle
        run: cargo run --locked --manifest-path html-oracle/Cargo.toml -- --repo-root . --corpus-root corpus
```

- [ ] **Step 2 — lint the workflow:**
  `actionlint .github/workflows/nightly-html-oracle.yml`
  `zizmor .github/workflows/nightly-html-oracle.yml`
  Expected clean: SHA-pinned `uses:`, `contents: read`, `persist-credentials:
  false`. If zizmor flags the `token:` on the second checkout, confirm it is the
  read secret (not `GITHUB_TOKEN`) and add a scoped `# zizmor: ignore[...]` only
  if a genuine false positive, with a justification comment.

- [ ] **Step 3 — update `AGENTS.md`** "Differential HTML oracle" section: add one
  line that the nightly also runs `--corpus-root corpus` against the pinned
  `rusty-imap-mcp-corpus` checkout, and that `--corpus-root <dir>` +
  `--corpus-min-compared <N>` exist for local runs. Reference the corpus-expansion
  spec.

- [ ] **Step 4 — commit:**
  `git commit -m "ci(oracle): pinned-SHA corpus checkout + --corpus-root in nightly (#550)"`

---

## Task 7 — full guardrails + local empty-corpus proof

**Files:** none (verification).

- [ ] **Step 1 — oracle crate green:**
  `cargo test --manifest-path html-oracle/Cargo.toml`
  `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
  `cargo fmt --manifest-path html-oracle/Cargo.toml -- --check`
  `cargo deny --locked --manifest-path html-oracle/Cargo.toml check`
- [ ] **Step 2 — main workspace unaffected:** `just check && just lint`.
- [ ] **Step 3 — local plumbing proof** against an empty corpus dir:
  `mkdir -p /tmp/empty-corpus && cargo run --locked --manifest-path html-oracle/Cargo.toml -- --repo-root . --corpus-root /tmp/empty-corpus`
  Expected: exit 0; `report.json` has `corpus.total == 0` and no
  `floor_breach`/`canary_failures`. Also run the hermetic
  `--repo-root .` (no `--corpus-root`) and confirm it still greens with no
  `corpus` section and no stale `corpus/…` allowlist entries.
- [ ] **Step 4 — Cargo.lock parity:** if `html-oracle/Cargo.lock` changed, it is
  committed (the crate has its own lock; see the fuzz-lockfile-parity convention).
  No new deps were added, so the lock should be unchanged.
- [ ] **Step 5 — exercise the real nightly path before merge.** Nothing in PR CI
  runs `nightly-html-oracle.yml` (it is `schedule` / `workflow_dispatch` only), so
  the private-repo checkout, `CORPUS_READ_TOKEN`, and pinned SHA are otherwise
  first exercised only at the first post-merge nightly. Gate the PR on a manual
  run against the pushed feature branch:
  - Confirm the prerequisites exist: corpus repo `randomparity/rusty-imap-mcp-corpus`
    is readable, commit `69d31655e51ade38dd7ed6ee8209336d80516562` resolves
    (`gh api repos/randomparity/rusty-imap-mcp-corpus/commits/69d3165 --jq .sha`),
    and the `CORPUS_READ_TOKEN` secret is set
    (`gh secret list --json name -q '.[].name' | grep -qx CORPUS_READ_TOKEN`).
  - After pushing the branch (Task-6 workflow present on it), trigger:
    `gh workflow run nightly-html-oracle.yml --ref feat/corpus-root-oracle-550`
    then poll the run to completion (`gh run list --workflow nightly-html-oracle.yml
    --branch feat/corpus-root-oracle-550 --limit 1 --json databaseId,status,conclusion`)
    and confirm `conclusion == success` — the corpus checkout resolved, the oracle
    loaded zero corpus inputs, and it exited 0 on the in-repo seeds.
  - If the token secret is not yet provisioned, this step is **blocked on the
    operator** — surface it in the PR body as a pre-merge checklist item rather
    than merging an unexercised auth path.

---

## Self-review notes (author)

- **Spec coverage:** Component 2 (`--corpus-root`, env, allowlist, per-prefix
  counts, floor, canaries) → Tasks 1–5. Component 3 (nightly checkout) → Task 6.
- **Untouched by design:** `diff.rs`, `reference.rs`, `norm.rs`, `allowlist.rs`,
  the EPVME `load_eml_tree` and its tests, `epvme-allowlist.toml` — the spec's
  "no change to diff/reference/normalization logic" non-goal.
- **Empty-corpus greenness** is asserted three ways: no `--corpus-min-compared`
  ⇒ `check_floor` returns `None`; no probes present ⇒ `check_canaries` returns
  empty; global inert tripwire satisfied by the in-repo seeds. Task 5's
  `empty_corpus_plumbing_proof_greens` locks it.
- **Canary direction:** text families assert ≥1 `ComparedNonempty`; `binary-part`
  asserts *all tagged are `BinarySkip`* (inverted) — the one genuinely new
  mechanism, unit-tested in `binary_part_canary_is_inverted`.
- **Non-empty assert deferred:** the pinned SHA `69d3165…` is the empty-but-valid
  corpus, so Task 6 ships the corpus **checkout only** — the non-empty guard lands
  in the #551 wave-1 SHA-bump PR against a populated pin. Shipping it now would
  red the plumbing proof.
- **Pre-merge auth exercise:** PR CI never runs the schedule-only nightly, so
  Task 7 Step 5 manually `workflow_dispatch`-runs it on the feature branch to
  exercise the real private checkout + `CORPUS_READ_TOKEN` + pin before merge;
  blocked-on-operator if the secret is unprovisioned.
- **Verify-at-build points** (flagged inline, not placeholders):
  `Path::with_extension("meta.toml")` sibling convention; both `CorpusInput`
  construction sites take the new `probes` field; zizmor's stance on the second
  checkout `token:`.
