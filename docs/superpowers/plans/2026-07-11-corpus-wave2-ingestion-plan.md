# Corpus Wave-2 Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest ~200–300 structurally-distinct, PII-scrubbed HTML inputs from
Enron + SpamAssassin + Nazario into the private corpus repo's `wave2/`, then
restate the oracle keep/kill baseline in the main repo.

**Architecture:** A deterministic, offline-after-cache generator in the corpus
repo (`tools/ingest/`) downloads each upstream archive (pinned by SHA-256),
iterates messages in archive order, node-scoped-scrubs PII, wraps each as a CRLF
`.eml`, dedups by tree-wide structural fingerprint, caps per source, and writes
`wave2/`. The main repo bumps the pinned corpus SHA, triages HARDs, recomputes the
`--corpus-min-compared` floor, and commits a baseline note.

**Tech Stack:** Python ≥3.11 stdlib only (`email`, `html.parser`, `tarfile`,
`mailbox`, `hashlib`, `urllib`, `tomllib`); `unittest`. No third-party deps.

**Spec (source of truth):**
`docs/superpowers/specs/2026-07-11-oracle-corpus-wave2-ingestion-design.md`.
**ADR:** `docs/ADR/0005-wave2-corpus-sourcing.md`.

## Global Constraints

- **Two repos.** Generator + `wave2/` live in `randomparity/rusty-imap-mcp-corpus`
  (checked out at sibling `/Volumes/Source Code Volume/src/rusty-imap-mcp-corpus`).
  Baseline/floor/allowlist/nightly-SHA live in the **main** repo on branch
  `feat/corpus-wave2-ingestion-554`.
- **Corpus guardrail:** `python tools/validate/validate.py --corpus-root .` +
  `python -m unittest discover -s tools/validate -p 'test_*.py'` +
  `python -m unittest discover -s tools/ingest/tests -p 'test_*.py'`. Local Python must
  be ≥3.11 (system is 3.9 → use `python3.13`).
- **Main-repo guardrails:** `just ci` umbrella; individually gated: `rustfmt`,
  `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`,
  `zizmor`. The `html-oracle` crate is workspace-excluded; run it explicitly:
  `cargo run --manifest-path html-oracle/Cargo.toml -- ...`.
- **Pure stdlib, no RNG, deterministic.** `build_wave2.py --check` must regenerate
  `wave2/` byte-identically.
- **Provenance:** `redistribution_basis = "research-corpus"`; **non-empty
  `redistribution_note`** (REQUIRED by the validator's redistribution branch);
  `scrub = ["text-nodes-redacted", "attr-values-redacted"]`; `wave = 2`;
  `probes = []`; `notes` records filter + scrub scope (text+attr+comments).
- **Fixed source order (adversarial-first):** SpamAssassin → Nazario → Enron.
- **Per-source caps:** Enron ≤100, SpamAssassin ≤120, Nazario ≤80; global ≤300.
- **Reuse only stable pieces by import** — `from build_wave1 import _encode_body`
  (CRLF-clean base64) and `from validate import html_part_texts,
  structural_fingerprint`. Wave 2 writes its **own** `.eml` assembly, `meta.toml`,
  `wave2/` writer, and `--check` diff. Do **NOT** reuse `build_wave1.build_eml`
  (takes a wave-1 `Candidate`), `build_wave1.write_tree` (hardcoded to `wave1/`),
  or `meta_toml` (emits the `license` branch); make **no** edit to `build_wave1.py`.
- **CTE is base64** (as Wave 1) — `_encode_body` does not auto-select; there is no
  7bit/QP selection to reuse.
- **Fingerprint scope = criterion 6:** dedup on
  `structural_fingerprint("\x1e".join(html_part_texts(eml_bytes)))` over the
  **built** `.eml`, matching the validator exactly.

---

## File Structure

Corpus repo, `tools/ingest/`:

- `scrub.py` — node-scoped PII redactor. `scrub_html(html: str) -> str`,
  `_redact(text: str) -> str`.
- `sources.py` — `fetch_verified(url, sha256, cache_dir) -> bytes`;
  `iter_html_messages(archive: bytes, kind: str) -> Iterator[str]`
  (yields each message's decoded HTML, in archive order).
- `sources.toml` — per-source `url`, `sha256`, `redistribution_basis`,
  `attribution`, `cap`, `kind` (`"tar.gz"|"tar.bz2"|"mbox"`), processing order.
- `build_wave2.py` — orchestrator + `--check`.
- `tests/test_scrub.py`, `tests/test_sources.py`, `tests/test_build_wave2.py`.
- `.gitignore` += `tools/ingest/.cache/`.

Main repo:

- `.github/workflows/nightly-html-oracle.yml` — bump `ref:` + `CORPUS_MIN_COMPARED`.
- `html-oracle/corpus-allowlist.toml` — triage result (likely still empty).
- `docs/security/html-oracle-corpus-wave2-baseline.md` — restated baseline.

---

## Task 0: Sync the corpus repo and pin the Wave-2 branch base (precondition)

**Files:** none (git state). Corpus repo.

Wave 1 (`build_wave1.py`, `wave1/`, and `validate.py`) lives on corpus
`origin/main` at the **merged** commit `c9e9217`. The local checkout may be stale
(e.g. at scaffold `69d3165`); `import build_wave1` and the tree-wide dedup both
fail silently if the branch is based on the scaffold.

- [ ] **Step 1: Sync + base the branch**

```bash
cd "/Volumes/Source Code Volume/src/rusty-imap-mcp-corpus"
git fetch origin
git checkout -B feat/wave2-ingestion origin/main   # origin/main == merged wave-1 (c9e9217)
```

- [ ] **Step 2: Assert the wave-1 base is present** (fail loud if not)

```bash
test -f tools/ingest/build_wave1.py || { echo "MISSING build_wave1.py"; exit 1; }
python3.13 -c "import sys; sys.path.insert(0,'tools/ingest'); import build_wave1"  # imports clean
N=$(find wave1 -name '*.eml' | wc -l | tr -d ' '); echo "wave1 inputs: $N"
test "$N" = "454" || echo "WARN: expected 454 wave-1 inputs, found $N"
```

Expected: `build_wave1.py` present, imports clean, 454 wave-1 `.eml`. If not,
stop — the base is wrong.

---

## Task 1: Confirm the validator accepts a Wave-2-shaped meta

**Files:**
- Test: `tools/ingest/tests/test_meta_shape.py` (corpus repo)

**Interfaces:**
- Consumes: `validate.validate_meta(meta_path: Path, root: Path) -> tuple[dict|None, list[Finding]]`
  (the REAL signature — reads a file, returns a `(meta, findings)` tuple).
- Produces: proof that a full Wave-2 meta (incl. **`redistribution_note`**,
  `probes=[]`) validates with 0 ERROR, so 300 files are not generated against a
  wrong schema.

- [ ] **Step 1: Write the failing test** — serialize a Wave-2 meta to a temp
  `.meta.toml`, call the real `validate_meta(path, root)`, unpack the tuple,
  assert `meta is not None` and no `ERROR` findings.

```python
import unittest, importlib.util, pathlib, tempfile
V = pathlib.Path(__file__).resolve().parents[2] / "validate" / "validate.py"
spec = importlib.util.spec_from_file_location("validate", V)
validate = importlib.util.module_from_spec(spec); spec.loader.exec_module(validate)

WAVE2_META_TOML = '''\
source = "SpamAssassin public corpus"
source_url = "https://spamassassin.apache.org/old/publiccorpus/"
notes = "HTML-bearing spam; node-scoped PII scrub over text+attr+comments."
redistribution_basis = "research-corpus"
redistribution_note = "Apache SpamAssassin public corpus, redistributable per its terms"
wave = 2
added = "2026-07-11"
scrub = ["text-nodes-redacted", "attr-values-redacted"]
probes = []
'''

class TestWave2MetaShape(unittest.TestCase):
    def test_meta_validates_clean(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            mp = root / "wave2" / "spamassassin" / "x.meta.toml"
            mp.parent.mkdir(parents=True)
            mp.write_text(WAVE2_META_TOML)
            meta, findings = validate.validate_meta(mp, root)
            errors = [f for f in findings if f.level == "ERROR"]
            self.assertIsNotNone(meta)
            self.assertEqual(errors, [], msg=str(errors))
```

- [ ] **Step 2: Run it** — `cd rusty-imap-mcp-corpus && python3.13 -m unittest tools.ingest.tests.test_meta_shape -v`. **Read `validate.py` first** and match the exact `validate_meta` signature/return. Expected: PASS. If it FAILS on a required field (e.g. `redistribution_note`) or `probes=[]`, the meta template is wrong — fix `WAVE2_META_TOML` to satisfy the real validator, or if `probes=[]` is genuinely rejected, stop and surface it (out-of-scope validator change).

- [ ] **Step 3: Commit**

```bash
git add tools/ingest/tests/test_meta_shape.py
git commit -m "test(ingest): confirm validator accepts wave-2 meta shape"
```

---

## Task 2: `scrub.py` — the `_redact` primitive (PII patterns)

**Files:**
- Create: `tools/ingest/scrub.py`
- Test: `tools/ingest/tests/test_scrub.py`

**Interfaces:**
- Produces: `_redact(text: str) -> str` — redacts email / phone / long-digit and
  entity-obfuscated `@`, leaving a numeric character reference intact.

- [ ] **Step 1: Write failing tests**

```python
from tools.ingest.scrub import _redact

def test_email_redacted():            assert _redact("ping joe@x.com now") == "ping [redacted-email] now"
def test_entity_obfuscated_email():   assert _redact("joe&#64;x.com") == "[redacted-email]"
def test_phone_redacted():            assert _redact("call 415-555-1234") == "call [redacted-phone]"
def test_long_digit_run():            assert _redact("id 12345678 end") == "id [redacted-number] end"
def test_numeric_charref_7_preserved(): assert _redact("&#1234567;") == "&#1234567;"
def test_numeric_charref_8_preserved(): assert _redact("&#12345678;") == "&#12345678;"  # F7 regression
def test_hex_charref_preserved():     assert _redact("&#x1234567;") == "&#x1234567;"
def test_short_digits_kept():         assert _redact("year 2026") == "year 2026"
def test_idempotent():                assert _redact(_redact("joe@x.com")) == _redact("joe@x.com")
```

- [ ] **Step 2: Run to verify fail** — `python3.13 -m unittest tools.ingest.tests.test_scrub -v` → FAIL (module missing).

- [ ] **Step 3: Implement `_redact`**

```python
"""Deterministic PII redaction primitives (node-scoped; see scrub_html)."""
import re

_AT_ENTITY_RE = re.compile(r"&#0*64;|&#x0*40;|&commat;", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)
_LONGDIGIT_RE = re.compile(r"\d{7,}")
# A digit run belongs to a numeric character reference if what precedes it is
# `&#` (decimal) or `&#x`/`&#X` (hex) followed by only ref digits — anchored to
# the whole reference, so an 8+-digit &#…; is protected too (F7).
_CHARREF_PREFIX_RE = re.compile(r"&#x?[0-9a-fA-F]*$")

def _redact(text: str) -> str:
    """Redact literal- and entity-obfuscated PII in a single content span.

    Applied only to text/comment/attribute-value spans (never raw markup), so a
    match cannot cross a tag boundary. Deterministic and idempotent.
    """
    text = _AT_ENTITY_RE.sub("@", text)          # de-obfuscate &#64; -> @
    text = _EMAIL_RE.sub("[redacted-email]", text)
    text = _PHONE_RE.sub("[redacted-phone]", text)

    def _num(m: "re.Match") -> str:
        if _CHARREF_PREFIX_RE.search(text[: m.start()]):
            return m.group()                     # digits of a numeric charref
        return "[redacted-number]"

    return _LONGDIGIT_RE.sub(_num, text)
```

- [ ] **Step 4: Run to verify pass.** Adjust the phone regex if a fixture reveals a
  gap (keep it identical to the validator's `_PHONE_RE` so the two agree).

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/scrub.py tools/ingest/tests/test_scrub.py
git commit -m "feat(ingest): node-scoped PII redaction primitive"
```

---

## Task 3: `scrub.py` — `scrub_html` (structure-aware tokenizer)

**Files:**
- Modify: `tools/ingest/scrub.py`
- Test: `tools/ingest/tests/test_scrub.py`

**Interfaces:**
- Consumes: `_redact`; `validate.structural_fingerprint` (for the invariance test).
- Produces: `scrub_html(html: str) -> str` — a single regex alternation tiles the
  source **exactly** into `comment | tag | text | stray-'<'`; redaction is applied
  only inside text tokens, comment inner content, and quoted attribute values.
  Because the alternation consumes every byte, a PII-free input round-trips
  byte-for-byte (the strong gate); redaction can never touch a tag/attr name or a
  markup delimiter.

- [ ] **Step 1: Write failing tests** — the strong gate is **byte-identity on
  PII-free input**; fingerprint-invariance alone is too weak (it ignores text and
  attribute-value bytes).

```python
import importlib.util, pathlib
from tools.ingest.scrub import scrub_html
_V = pathlib.Path(__file__).resolve().parents[2] / "validate" / "validate.py"
_s = importlib.util.spec_from_file_location("validate", _V)
validate = importlib.util.module_from_spec(_s); _s.loader.exec_module(validate)
fp = validate.structural_fingerprint

# Strong gate: redaction is a no-op on PII-free HTML -> exact byte round-trip.
PII_FREE = [
    "<p>hello <b>world</b></p>",
    "<td width=12 34>y</td>",                       # unquoted attrs, short digits
    "<p>if a < b then c &amp; d</p>",               # literal '<' + entity in text
    "<!-- a benign comment --><div class='x'>ok</div>",
    "<style>.a{margin:12px}</style><a href='http://e/x'>t</a>",
    "<img src=\"http://e/p.gif?w=12&h=34\">",
]
def test_pii_free_roundtrip():
    for h in PII_FREE:
        assert scrub_html(h) == h, h

# Redaction happens, and structure is preserved even on adversarial markup.
def _same_structure(html): assert fp(scrub_html(html)) == fp(html)
def test_mailto_href_value_redacted():
    out = scrub_html('<a href="mailto:joe@x.com">hi</a>')
    assert out == '<a href="mailto:[redacted-email]">hi</a>'
def test_digit_run_adjacent_to_comment_end():   _same_structure("<p><!--1234567--></p><b>x</b>")
def test_digit_between_unquoted_attrs():         _same_structure("<td width=1234567 x=1>y</td>")
def test_literal_lt_in_text():                   _same_structure("<p>if a < b then c</p>")
def test_style_block_preserved_structurally():   _same_structure("<style>.a{width:1234567px}</style><p>x</p>")
def test_comment_pii_redacted():
    assert scrub_html("<!-- reply joe@x.com --><p>x</p>") == "<!-- reply [redacted-email] --><p>x</p>"
def test_idempotent():
    h = '<a href="mailto:joe@x.com">call 415-555-1234</a>'
    assert scrub_html(scrub_html(h)) == scrub_html(h)
```

- [ ] **Step 2: Run to verify fail** → FAIL (`scrub_html` missing).

- [ ] **Step 3: Implement `scrub_html`** with a whole-string regex alternation that
  tiles the source exactly (every byte consumed by exactly one token), so the
  round-trip is exact by construction — no offset arithmetic, no event-merge
  gaps.

```python
# Exact-tiling tokenizer: comment | real tag | text run | a stray '<'.
# A "real tag" starts with a letter, '/', '!', or '?'; a bare '<' not followed by
# one of those is HTML text (e.g. "a < b") and is left verbatim. `.` (DOTALL)
# over the alternation guarantees every byte is consumed exactly once.
_TOKEN_RE = re.compile(
    r"<!--.*?-->"           # comment (non-greedy)
    r"|<[a-zA-Z!/?][^>]*>"  # a tag, up to the first '>'
    r"|[^<]+"               # a text run
    r"|<",                  # a stray '<' (literal text)
    re.DOTALL,
)
_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')

def _redact_tag(tag: str) -> str:
    # Redact only inside quoted attribute values; tag/attr names untouched.
    return _QUOTED.sub(lambda m: m.group()[0] + _redact(m.group()[1:-1]) + m.group()[0], tag)

def scrub_html(html: str) -> str:
    out = []
    for m in _TOKEN_RE.finditer(html):
        tok = m.group()
        if tok.startswith("<!--") and tok.endswith("-->"):
            out.append("<!--" + _redact(tok[4:-3]) + "-->")   # comment inner
        elif tok.startswith("<") and len(tok) > 1 and tok[1] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!/?":
            out.append(_redact_tag(tok))                       # a tag
        else:
            out.append(_redact(tok))                           # text run or stray '<'
    return "".join(out)
```

- [ ] **Step 4: Run to verify pass.** The `test_pii_free_roundtrip` gate must pass
  for every fixture — if it fails, the tokenizer is not tiling exactly; fix
  `scrub_html`, not the test. Confirm idempotence and the redaction assertions.
  (Known limitation: a literal `>` inside a quoted attribute value ends the tag
  token early; this cannot break the byte round-trip and only means such an
  attribute's PII is redacted as text rather than as a value — still redacted,
  still structure-preserving. Add a fixture if a real source exhibits it.)

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/scrub.py tools/ingest/tests/test_scrub.py
git commit -m "feat(ingest): structure-preserving node-scoped html scrub"
```

---

## Task 4: `sources.py` — `fetch_verified` (download + SHA-256)

**Files:**
- Create: `tools/ingest/sources.py`
- Test: `tools/ingest/tests/test_sources.py`

**Interfaces:**
- Produces: `fetch_verified(url: str, sha256: str, cache_dir: Path) -> bytes` —
  returns cached bytes if the cached file's SHA-256 matches; else downloads,
  verifies, caches; **raises `SystemExit`** on hash mismatch. No network in tests
  (inject a `_opener` seam or monkeypatch `urlopen`).

- [ ] **Step 1: Write failing tests** (mock the downloader; assert accept + hard-fail)

```python
import hashlib, pathlib, unittest
from tools.ingest import sources

class TestFetch(unittest.TestCase):
    def test_matching_hash_accepts(self):
        data = b"hello-corpus"
        h = hashlib.sha256(data).hexdigest()
        sources._download = lambda url: data  # seam
        out = sources.fetch_verified("http://x/y", h, self.tmp())
        self.assertEqual(out, data)
    def test_mismatch_hard_fails(self):
        sources._download = lambda url: b"tampered"
        with self.assertRaises(SystemExit):
            sources.fetch_verified("http://x/y", "0"*64, self.tmp())
    def tmp(self):
        d = pathlib.Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        return d
```

- [ ] **Step 2: Run to verify fail** → FAIL (module missing).

- [ ] **Step 3: Implement**

```python
"""Download-at-build source fetch (pinned by SHA-256) + in-archive iteration."""
import hashlib, tarfile, io, mailbox, email, tempfile, os
from email import policy
from pathlib import Path
from urllib.request import urlopen, Request

def _download(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "rusty-imap-mcp-corpus/ingest"})
    with urlopen(req, timeout=120) as r:  # nosec - pinned by sha256 below
        return r.read()

def fetch_verified(url: str, sha256: str, cache_dir: Path) -> bytes:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / sha256
    if cached.exists():
        data = cached.read_bytes()
        if hashlib.sha256(data).hexdigest() == sha256:
            return data
    data = _download(url)
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        raise SystemExit(f"sha256 mismatch for {url}: got {got} != pinned {sha256}")
    cached.write_bytes(data)
    return data
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/sources.py tools/ingest/tests/test_sources.py
git commit -m "feat(ingest): sha256-verified source fetch with cache"
```

---

## Task 5: `sources.py` — `iter_html_messages` (in-archive-order HTML filter)

**Files:**
- Modify: `tools/ingest/sources.py`
- Test: `tools/ingest/tests/test_sources.py`

**Interfaces:**
- Produces: `iter_html_messages(archive: bytes, kind: str) -> Iterator[str]` —
  yields each message's first `text/html` part decoded to text, **in archive
  order**, skipping messages with no HTML part or that fail to parse. `kind` ∈
  `{"tar.gz","tar.bz2","mbox"}`. Iterates **in memory** (`tarfile`/`mailbox`),
  never extract-then-walk.

- [ ] **Step 1: Write failing tests** — build a tiny in-memory tar of two `.eml`
  (one HTML, one plaintext-only) and assert only the HTML one yields, and order
  is archive order.

```python
def _tar(members):  # [(name, bytes)]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members:
            ti = tarfile.TarInfo(name); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()

HTML_EML = b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>\r\n"
TXT_EML  = b"Content-Type: text/plain\r\n\r\nplain\r\n"

def test_only_html_yielded_in_order():
    from tools.ingest.sources import iter_html_messages
    arc = _tar([("a.eml", TXT_EML), ("b.eml", HTML_EML)])
    got = list(iter_html_messages(arc, "tar.gz"))
    assert got == ["<p>hi</p>\r\n"]
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement** — one HTML text per message (first `text/html` part),
  decoded via declared charset with `errors="replace"` (matches the validator).

```python
def _html_of(raw: bytes) -> str | None:
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except (ValueError, UnicodeError):
        return None
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except LookupError:
                return payload.decode("utf-8", errors="replace")
    return None

def iter_html_messages(archive: bytes, kind: str):
    if kind in ("tar.gz", "tar.bz2"):
        mode = "r:gz" if kind == "tar.gz" else "r:bz2"
        with tarfile.open(fileobj=io.BytesIO(archive), mode=mode) as t:
            for member in t:                      # archive order
                if not member.isfile():
                    continue
                f = t.extractfile(member)
                if f is None:
                    continue
                html = _html_of(f.read())
                if html is not None:
                    yield html
    elif kind == "mbox":
        with tempfile.NamedTemporaryFile(suffix=".mbox", delete=False) as tf:
            tf.write(archive); path = tf.name
        try:
            for msg in mailbox.mbox(path):        # file order
                html = _html_of(msg.as_bytes())
                if html is not None:
                    yield html
        finally:
            os.unlink(path)
    else:
        raise SystemExit(f"unknown source kind: {kind}")
```

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/sources.py tools/ingest/tests/test_sources.py
git commit -m "feat(ingest): in-archive-order html-bearing message iterator"
```

---

## Task 6: `build_wave2.py` + `sources.toml` (orchestrate, dedup, cap, --check)

**Files:**
- Create: `tools/ingest/build_wave2.py`, `tools/ingest/sources.toml`
- Modify: `.gitignore` (+`tools/ingest/.cache/`)
- Test: `tools/ingest/tests/test_build_wave2.py`

**Interfaces:**
- Consumes: `sources.fetch_verified`, `sources.iter_html_messages`,
  `scrub.scrub_html`; `from build_wave1 import _encode_body`;
  `from validate import html_part_texts, structural_fingerprint`. Wave 2 writes
  its **own** `.eml` builder, `meta.toml`, tree writer, and `--check` diff — it
  does **not** call `build_wave1.build_eml`/`write_tree`/`meta_toml` and does not
  modify `build_wave1.py`.
- Produces: `main(argv) -> int` (0 ok / 1 drift); writing
  `wave2/{spamassassin,nazario,enron}/<stem>.eml` + `<stem>.meta.toml`; `--check`
  regenerates and diffs.

- [ ] **Step 1: Write `sources.toml`** — one `[[source]]` per corpus in fixed
  order, `sha256 = ""` placeholders filled in Task 7 after vetting.

```toml
# Fixed processing order: adversarial-first (spamassassin, nazario, enron).
[[source]]
name = "spamassassin"
kind = "tar.bz2"
url = "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
sha256 = ""            # filled after vetting (Task 7)
cap = 120
redistribution_basis = "research-corpus"
redistribution_note = "Apache SpamAssassin public corpus, redistributable per its terms"
attribution = "Apache SpamAssassin public corpus"
[[source]]
name = "nazario"
kind = "mbox"
url = ""               # pinned GitHub-raw immutable-commit URL, filled in Task 7
sha256 = ""
cap = 80
redistribution_basis = "research-corpus"
redistribution_note = "Nazario phishing corpus (c) Jose Nazario, CC-BY-4.0 (attribution required)"
attribution = "Nazario phishing corpus, (c) Jose Nazario, CC-BY-4.0"
[[source]]
name = "enron"
kind = "tar.gz"
url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
sha256 = ""
cap = 100
redistribution_basis = "research-corpus"
redistribution_note = "Enron email dataset, FERC public release"
attribution = "Enron email dataset (FERC public release)"
```

- [ ] **Step 2: Write the failing test.** **Critical: criterion-6 dedup is
  tag/attr-NAME only** — `_StructureCollector` has no `handle_data`, so text and
  attribute *values* are ignored. Fixtures that must survive as distinct inputs
  MUST differ in tag/attr **names**, not text. Drive `_build` with stubbed fetch +
  iterator (no network), a temp corpus root, and check the real properties.

```python
import importlib, pathlib, tempfile, unittest, base64, email
from email import policy

class TestBuildWave2(unittest.TestCase):
    def setUp(self):
        self.bw2 = importlib.import_module("tools.ingest.build_wave2")
    def _html_of(self, eml_bytes):  # decode the built .eml back to HTML text
        msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return part.get_payload(decode=True).decode("utf-8")
        return ""
    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d); (root / "wave1").mkdir()
            # wave-1 seed with the <p> skeleton -> any wave-2 <p>-only msg dedups out
            (root / "wave1" / "a.eml").write_bytes(self.bw2.build_eml("<p>seed</p>"))
            msgs = {"spamassassin": [
                "<div><a href='mailto:joe@x.com'>x</a></div>",           # distinct skeleton, has PII
                "<p>collides with wave-1 skeleton</p>",                    # dropped (== <p> seed)
                "<table><tr><td>one</td></tr></table>",                   # distinct skeleton
                "<table><tr><td>two</td></tr></table>",                   # within-source dup of prev -> dropped
            ]}
            self.bw2.iter_html_messages = lambda archive, kind: iter(msgs.get(kind, []))
            self.bw2.fetch_verified = lambda url, sha, cache: b"stub"
            self.bw2._load_sources = lambda: [{
                "name": "spamassassin", "kind": "tar.bz2", "url": "u", "sha256": "s",
                "cap": 10, "redistribution_basis": "research-corpus",
                "redistribution_note": "n", "attribution": "att"}]
            self.bw2.ROOT = root
            self.assertEqual(self.bw2._build(check=False), 0)
            written = list((root / "wave2" / "spamassassin").glob("*.eml"))
            self.assertEqual(len(written), 2)                      # div-skeleton + table-skeleton
            texts = [self._html_of(p.read_bytes()) for p in written]
            joined = "\n".join(texts)
            self.assertIn("[redacted-email]", joined)              # real PII gate (decoded)
            self.assertNotIn("joe@x.com", joined)
            self.assertEqual(self.bw2._build(check=True), 0)       # regeneration byte-identical
```

- [ ] **Step 3: Implement `build_wave2.py`** against the REAL API (own eml/meta/
  writer/diff; criterion-6 fingerprint over the built `.eml`).

```python
"""Deterministic wave-2 generator: fetch -> iterate -> scrub -> dedup -> cap -> write."""
import sys, tomllib, hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent                   # tools/ingest
ROOT = HERE.parents[1]                                   # corpus repo root
# Bootstrap sys.path exactly as build_wave1.py does, so bare imports resolve under
# direct-script, `-m unittest tools.ingest.tests.<mod>`, and discover alike.
sys.path.insert(0, str(HERE))                            # build_wave1, sources, scrub
sys.path.insert(0, str(ROOT / "tools" / "validate"))    # validate
from build_wave1 import _encode_body                     # noqa: E402  CRLF-clean base64
from validate import html_part_texts, structural_fingerprint  # noqa: E402
from sources import fetch_verified, iter_html_messages   # noqa: E402
from scrub import scrub_html                             # noqa: E402

CACHE = HERE / ".cache"
_ADDED = "2026-07-11"

def build_eml(html: str) -> bytes:
    """Wrap scrubbed HTML as a CRLF .eml matching Wave 1's header shape
    (MIME-Version + text/html; charset=utf-8; base64 CTE)."""
    headers = b"\r\n".join((
        b"MIME-Version: 1.0",
        b"Content-Type: text/html; charset=utf-8",
        b"Content-Transfer-Encoding: base64",
    ))
    return headers + b"\r\n\r\n" + _encode_body(html.encode("utf-8"), "base64")

def _fingerprint(eml: bytes) -> str:
    return structural_fingerprint("\x1e".join(html_part_texts(eml)))  # criterion 6

def _load_sources() -> list[dict]:
    with (HERE / "sources.toml").open("rb") as f:
        return tomllib.load(f)["source"]                 # fixed adversarial-first order

def _wave1_fingerprints() -> set[str]:
    return {_fingerprint(e.read_bytes()) for e in (ROOT / "wave1").rglob("*.eml")}

def _meta(src: dict) -> bytes:
    note = src["redistribution_note"].replace('"', "'")
    return (
        f'source = "{src["attribution"]}"\n'
        f'source_url = "{src["url"]}"\n'
        f'notes = "HTML-bearing {src["name"]} message; node-scoped PII scrub over '
        f'text, attribute values, and comments."\n'
        f'redistribution_basis = "{src["redistribution_basis"]}"\n'
        f'redistribution_note = "{note}"\n'
        f'wave = 2\nadded = "{_ADDED}"\n'
        f'scrub = ["text-nodes-redacted", "attr-values-redacted"]\nprobes = []\n'
    ).encode("utf-8")

def _generate() -> dict[str, bytes]:
    seen = _wave1_fingerprints()
    files: dict[str, bytes] = {}
    for src in _load_sources():
        if not src["url"] or not src["sha256"]:
            print(f"skip {src['name']}: unpinned", file=sys.stderr); continue
        archive = fetch_verified(src["url"], src["sha256"], CACHE)
        kept = dropped = seen_msgs = 0
        for html in iter_html_messages(archive, src["kind"]):
            if kept >= src["cap"]:
                break
            seen_msgs += 1
            eml = build_eml(scrub_html(html))
            fp = _fingerprint(eml)
            if fp in seen:                               # tree-wide keep-first dedup
                dropped += 1
                continue
            seen.add(fp)
            stem = hashlib.sha256(eml).hexdigest()
            base = f"wave2/{src['name']}/{stem}"
            files[base + ".eml"] = eml
            files[base + ".meta.toml"] = _meta(src)
            kept += 1
        # Observability: structure-only dedup can collapse template-heavy real mail
        # HARD, so surface the drop rate — low kept vs high dropped means low
        # structural diversity, which the operator must weigh against the floor.
        print(f"{src['name']}: kept {kept}, dropped-as-dup {dropped} "
              f"(scanned {seen_msgs})", file=sys.stderr)
    return files

def _write(files: dict[str, bytes]) -> int:
    wave2 = ROOT / "wave2"
    if wave2.exists():
        for p in sorted(wave2.rglob("*")):
            if p.is_file():
                p.unlink()
    for rel, data in files.items():
        p = ROOT / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return 0

def _check(files: dict[str, bytes]) -> int:
    drift = []
    on_disk = {str(p.relative_to(ROOT)) for p in (ROOT / "wave2").rglob("*") if p.is_file()}
    for rel, data in files.items():
        p = ROOT / rel
        if not p.exists() or p.read_bytes() != data:
            drift.append(f"changed {rel}")
    for rel in sorted(on_disk - set(files)):
        drift.append(f"unexpected {rel}")
    for d in drift:
        print(d, file=sys.stderr)
    return 1 if drift else 0

def _build(check: bool) -> int:
    files = _generate()
    return _check(files) if check else _write(files)

def main(argv: list[str]) -> int:
    return _build(check="--check" in argv)

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run tests to verify pass.** Before running, **open the real
  `build_wave1.py`** and confirm `_encode_body(body: bytes, cte: str) -> bytes`
  and the `from validate import html_part_texts, structural_fingerprint` line
  still hold (they do at `c9e9217`). No edit to `build_wave1.py` is made. If a
  fixture reveals the base64 header must match Wave 1's byte-for-byte for a shared
  input, compare against a `build_wave1.build_eml(candidate)` output and align the
  header bytes.

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/build_wave2.py tools/ingest/sources.toml \
        tools/ingest/tests/test_build_wave2.py .gitignore
git commit -m "feat(ingest): deterministic wave-2 generator (fetch/scrub/dedup/cap)"
```

---

## Task 7: Vet sources, generate `wave2/`, validate, open corpus PR

**Files:** `tools/ingest/sources.toml` (real SHAs), `wave2/**` (generated),
`tools/ingest/README.md` (append wave-2 section).

This task is **operational** (network + judgement), not TDD. Corpus repo, on a
branch `feat/wave2-ingestion`.

- [ ] **Step 1: Vet + pin each source.** For SpamAssassin and Enron: download the
  archive, record its real `sha256` into `sources.toml`. For Nazario: locate a raw
  `.mbox` at an **immutable GitHub-raw commit URL** (e.g. a pinned commit of a
  mirror such as `diegoocampoh/MachineLearningPhishing`), confirm it is the
  CC-BY-4.0 corpus, record URL + `sha256`. **Drop-rule:** if any source cannot be
  fetched from a stable pinned URL or cleared for redistribution, remove its
  `[[source]]` entry, note it in the PR, and proceed with the rest.
- [ ] **Step 2: Generate** — `python3.13 tools/ingest/build_wave2.py`. Inspect the
  per-source `kept` / `dropped-as-dup` / `scanned` counts. **Reality check:**
  criterion-6 dedup is on the tag/attr-**name** skeleton only, and real
  marketing/phishing mail is template-heavy, so structural diversity — not the
  caps — is the binding limit. Expect kept ≪ cap with high drop rates.
  **Expected floor:** aim for a combined `compared_nonempty` that keeps
  `N = floor(0.9 × compared_nonempty)` meaningful and clears the spec's 60%
  coverage bar. **Contingency if the total surviving skeletons are too few**
  (e.g. < ~60 combined): add more SpamAssassin subsets (`spam_2`, `hard_ham` —
  more distinct skeletons) to `sources.toml`; do **not** raise caps (dedup, not
  the cap, is the limiter). If diversity is genuinely low, record the smaller
  wave and a lower `N` in the Task 8 baseline note as a legitimate outcome — the
  oracle run is the gate, not a target count.
- [ ] **Step 3: Determinism** — `python3.13 tools/ingest/build_wave2.py --check`
  → zero diff. Re-run `build_wave1.py --check` → still byte-identical.
- [ ] **Step 4: Validate** — `python3.13 tools/validate/validate.py --corpus-root .`
  → 0 `ERROR`. **Zero `9-pii` WARN**; if any WARN fires, extend `scrub.py`
  (Task 2/3), regenerate, re-validate — never suppress. Confirm all three canary
  families still report present tree-wide.
- [ ] **Step 5: Run the ingest + validator unit suites** —
  `python3.13 -m unittest discover -s tools/ingest -p 'test_*.py'` and the
  validator suite → all pass.
- [ ] **Step 6: Append `tools/ingest/README.md`** — document the wave-2 pipeline,
  sources, pinned hashes, scrub scope, and determinism (`--check`).
- [ ] **Step 7: Commit + push + open corpus PR**, let `validate.yml` run green,
  merge (operator-authorized for corpus PRs), record the **merged SHA**.

---

## Task 8: Main-repo re-baseline (bump SHA, triage, floor, note)

**Files (main repo, branch `feat/corpus-wave2-ingestion-554`):**
- Modify: `.github/workflows/nightly-html-oracle.yml`
- Modify: `html-oracle/corpus-allowlist.toml` (only if a benign HARD appears)
- Create: `docs/security/html-oracle-corpus-wave2-baseline.md`

Operational task; the oracle run is the gate.

- [ ] **Step 1: Check out the merged corpus at the new SHA** into `corpus/` and run
  `cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root . --corpus-root corpus --report /tmp/wave2.json`.
- [ ] **Step 2: Read `report.json`** `corpus` block: `total`, `skipped`,
  `ref_error`, `compared_nonempty`, `hard_inputs`.
- [ ] **Step 3: Triage every HARD** — real sanitizer silent-drop → file a bug +
  drop the input from the corpus (re-run); systemic comparison-layer noise → flag
  it; benign per-input quirk → one `corpus-allowlist.toml` entry keyed
  `corpus/<stem>` with a required `reason`. Re-run until **0 non-allowlisted HARD**.
- [ ] **Step 4: Recompute the floor** — `N = floor(0.9 × corpus_compared_nonempty)`
  over the **combined** corpus; set `CORPUS_MIN_COMPARED: "<N>"` in the nightly and
  bump `ref:` to the merged SHA.
- [ ] **Step 5: Write `docs/security/html-oracle-corpus-wave2-baseline.md`** —
  same table as the wave-1 note: pinned SHA, per-`corpus/`-prefix counts, coverage
  %, non-allowlisted HARD (0), allowlist size, KEEP-bar evaluation
  (`max(5, 0.5% × compared_nonempty)`; coverage ≥60% floor), canary health.
- [ ] **Step 6: Guardrails + commit** — `zizmor .github/workflows/nightly-html-oracle.yml`;
  `just fmt-check lint` (no Rust changed, but run the umbrella if quick). Stage
  explicit paths; commit
  `feat(oracle): re-baseline over wave-2 corpus (#554)`.

---

## Self-Review (completed)

- **Spec coverage:** corpus base precondition (T0), validator meta-shape incl.
  `redistribution_note` (T1), node-scoped scrub `_redact` + entity-obfuscation +
  charref guard (T2), exact-tiling `scrub_html` + PII-free byte-identity gate (T3),
  download+SHA-256 (T4), HTML filter + in-archive order (T5), criterion-6 dedup +
  fixed order + caps + own eml/meta/writer + determinism (T6), vet/generate/
  validate/PR (T7), re-baseline + floor + note (T8) — all mapped.
- **Real-API alignment (plan-review iter 1):** `redistribution_note` is REQUIRED
  and now in every meta path (T1, T6); `validate_meta(path, root) -> tuple` called
  correctly (T1); Wave 2 reuses only `_encode_body` + `html_part_texts` +
  `structural_fingerprint` and writes its own eml/meta/writer/diff (T6, no
  `build_wave1` edit); CTE is base64 (no auto-select); dedup fingerprint scope
  matches the validator's criterion 6 over the built `.eml`.
- **No placeholders:** the only intentionally-deferred values are the real
  `sha256`/Nazario `url` (Task 7 — vetting outputs by design).
- **Type consistency:** `_redact`/`scrub_html`/`build_eml`/`_fingerprint`/
  `fetch_verified`/`iter_html_messages` signatures are consistent across T2–T6.
