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
  `python -m unittest discover -s tools/ingest -p 'test_*.py'`. Local Python must
  be ≥3.11 (system is 3.9 → use `python3.13`).
- **Main-repo guardrails:** `just ci` umbrella; individually gated: `rustfmt`,
  `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`,
  `zizmor`. The `html-oracle` crate is workspace-excluded; run it explicitly:
  `cargo run --manifest-path html-oracle/Cargo.toml -- ...`.
- **Pure stdlib, no RNG, deterministic.** `build_wave2.py --check` must regenerate
  `wave2/` byte-identically.
- **Provenance:** `redistribution_basis = "research-corpus"`;
  `scrub = ["text-nodes-redacted", "attr-values-redacted"]`; `wave = 2`;
  `probes = []`; `notes` records filter + scrub scope (text+attr+comments) +
  Nazario CC-BY-4.0 attribution.
- **Fixed source order (adversarial-first):** SpamAssassin → Nazario → Enron.
- **Per-source caps:** Enron ≤100, SpamAssassin ≤120, Nazario ≤80; global ≤300.
- **Reuse Wave-1 helpers by import** (`build_wave1.build_eml`, `_encode_body`,
  content-hash stem, `write_tree`); do **not** refactor `build_wave1.py` in a way
  that changes its output — guard with `python3.13 build_wave1.py --check`.

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

## Task 1: Confirm the validator accepts a Wave-2-shaped meta

**Files:**
- Test: `tools/ingest/tests/test_meta_shape.py` (corpus repo)

**Interfaces:**
- Consumes: `tools/validate/validate.py` (`validate_meta` / `_validate_scrub` /
  provenance + `probes` checks).
- Produces: proof that `redistribution_basis="research-corpus"`,
  `scrub=["text-nodes-redacted","attr-values-redacted"]`, `probes=[]` validate
  clean, so 300 files are not generated against a wrong schema.

- [ ] **Step 1: Write the failing test** — build an in-memory Wave-2 meta dict and
  a minimal valid `.eml`, run the validator's per-input meta checks, assert no
  `ERROR`-level findings.

```python
import unittest, importlib.util, pathlib
V = pathlib.Path(__file__).resolve().parents[2] / "validate" / "validate.py"
spec = importlib.util.spec_from_file_location("validate", V)
validate = importlib.util.module_from_spec(spec); spec.loader.exec_module(validate)

WAVE2_META = {
    "source": "SpamAssassin public corpus",
    "source_url": "https://spamassassin.apache.org/old/publiccorpus/",
    "notes": "HTML-bearing spam; node-scoped PII scrub over text+attr+comments.",
    "redistribution_basis": "research-corpus",
    "wave": 2, "added": "2026-07-11",
    "scrub": ["text-nodes-redacted", "attr-values-redacted"],
    "probes": [],
}

class TestWave2MetaShape(unittest.TestCase):
    def test_meta_validates_clean(self):
        findings = validate.validate_meta(WAVE2_META, "wave2/spamassassin/x.meta.toml")
        errors = [f for f in findings if f.level == "ERROR"]
        self.assertEqual(errors, [], msg=str(errors))
```

- [ ] **Step 2: Run it** — `cd rusty-imap-mcp-corpus && python3.13 -m unittest tools.ingest.tests.test_meta_shape -v`. If `validate_meta`'s real signature differs (e.g. it takes a parsed `Input`), adapt the call to the actual public function — **read `validate.py` first** and match it. Expected once matched: PASS. If it FAILS on `probes=[]`, stop: the schema needs a validator change not in scope — surface it.

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

def test_email_redacted():           assert _redact("ping joe@x.com now") == "ping [redacted-email] now"
def test_entity_obfuscated_email():   assert _redact("joe&#64;x.com") == "[redacted-email]"
def test_phone_redacted():            assert _redact("call 415-555-1234") == "call [redacted-phone]"
def test_long_digit_run():            assert _redact("id 12345678 end") == "id [redacted-number] end"
def test_numeric_charref_preserved(): assert _redact("&#1234567;") == "&#1234567;"
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
# 7+ digit run, but NOT the digits of a numeric character reference (&#…; / &#x…;).
_LONGDIGIT_RE = re.compile(r"(?<!&#)(?<!&#x)\d{7,}")

def _redact(text: str) -> str:
    """Redact literal- and entity-obfuscated PII in a single content span.

    Applied only to text/comment/attribute-value spans (never raw markup), so a
    match cannot cross a tag boundary. Deterministic and idempotent.
    """
    text = _AT_ENTITY_RE.sub("@", text)          # de-obfuscate &#64; -> @
    text = _EMAIL_RE.sub("[redacted-email]", text)
    text = _PHONE_RE.sub("[redacted-phone]", text)
    text = _LONGDIGIT_RE.sub("[redacted-number]", text)
    return text
```

- [ ] **Step 4: Run to verify pass.** Adjust the phone regex if a fixture reveals a
  gap (keep it identical to the validator's `_PHONE_RE` so the two agree).

- [ ] **Step 5: Commit**

```bash
git add tools/ingest/scrub.py tools/ingest/tests/test_scrub.py
git commit -m "feat(ingest): node-scoped PII redaction primitive"
```

---

## Task 3: `scrub.py` — `scrub_html` (node-scoped span walk)

**Files:**
- Modify: `tools/ingest/scrub.py`
- Test: `tools/ingest/tests/test_scrub.py`

**Interfaces:**
- Consumes: `_redact`; `validate.structural_fingerprint` (for the invariance test).
- Produces: `scrub_html(html: str) -> str` — redacts only within content spans
  (text runs incl. entities, comment inner, quoted attribute values); every tag
  name, attribute name, and markup delimiter is byte-preserved.

- [ ] **Step 1: Write failing tests** (structure-preservation is the gate)

```python
import importlib.util, pathlib
from tools.ingest.scrub import scrub_html
_V = pathlib.Path(__file__).resolve().parents[2] / "validate" / "validate.py"
_s = importlib.util.spec_from_file_location("validate", _V)
validate = importlib.util.module_from_spec(_s); _s.loader.exec_module(validate)
fp = validate.structural_fingerprint

def _same_structure(html): assert fp(scrub_html(html)) == fp(html)

def test_mailto_href_value_redacted():
    out = scrub_html('<a href="mailto:joe@x.com">hi</a>')
    assert "joe@x.com" not in out and out.startswith('<a href="mailto:[redacted-email]"')
def test_digit_run_adjacent_to_comment_end():   _same_structure("<p><!--1234567--></p><b>x</b>")
def test_digit_between_unquoted_attrs():         _same_structure("<td width=123 4567>y</td>")
def test_literal_lt_in_text():                   _same_structure("<p>if a < b then c</p>")
def test_style_block_preserved_structurally():   _same_structure("<style>.a{width:1234567px}</style><p>x</p>")
def test_comment_pii_redacted():
    assert "joe@x.com" not in scrub_html("<!-- reply joe@x.com --><p>x</p>")
def test_idempotent():
    h = '<a href="mailto:joe@x.com">call 415-555-1234</a>'
    assert scrub_html(scrub_html(h)) == scrub_html(h)
```

- [ ] **Step 2: Run to verify fail** → FAIL (`scrub_html` missing).

- [ ] **Step 3: Implement `scrub_html`** using `HTMLParser` source offsets. Group
  maximal runs of content events (`data`/`entityref`/`charref`) into one span so
  an address split by an entity (`joe&#64;x.com`) is redacted as a unit; redact
  comment inner; within a start/startend tag redact only quoted attribute values;
  emit every structural byte verbatim.

```python
from html.parser import HTMLParser

class _Spans(HTMLParser):
    """Record (abs_offset, kind) for every construct; kind in
    {content, comment, tag, struct}. convert_charrefs=False so entity refs stay
    as source and fold into the surrounding content span."""
    def __init__(self, src: str):
        super().__init__(convert_charrefs=False)
        self._starts = [0]
        for ch in src:
            self._starts.append(self._starts[-1] + 1 if ch != "\n" else self._starts[-1] + 1)
        # line-start table for getpos() -> absolute index
        self._line_off = [0]
        for i, ch in enumerate(src):
            if ch == "\n":
                self._line_off.append(i + 1)
        self.events = []
    def _abs(self):
        line, col = self.getpos()
        return self._line_off[line - 1] + col
    def _mark(self, kind): self.events.append((self._abs(), kind))
    def handle_starttag(self, t, a): self._mark("tag")
    def handle_startendtag(self, t, a): self._mark("tag")
    def handle_endtag(self, t): self._mark("struct")
    def handle_data(self, d): self._mark("content")
    def handle_entityref(self, n): self._mark("content")
    def handle_charref(self, n): self._mark("content")
    def handle_comment(self, d): self._mark("comment")
    def handle_decl(self, d): self._mark("struct")
    def handle_pi(self, d): self._mark("struct")
    def unknown_decl(self, d): self._mark("struct")

_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')

def _redact_tag(tag: str) -> str:
    return _QUOTED.sub(lambda m: m.group()[0] + _redact(m.group()[1:-1]) + m.group()[0], tag)

def scrub_html(html: str) -> str:
    p = _Spans(html); p.feed(html); p.close()
    ev = p.events + [(len(html), "end")]
    out, i = [], 0
    while i < len(ev) - 1:
        start, kind = ev[i]
        # merge consecutive content spans into one so entities don't split PII
        j = i
        if kind == "content":
            while ev[j + 1][1] == "content":
                j += 1
        end = ev[j + 1][0]
        span = html[start:end]
        if kind == "content":
            out.append(_redact(span))
        elif kind == "comment":
            out.append(span[:4] + _redact(span[4:-3]) + span[-3:])  # <!-- inner -->
        elif kind == "tag":
            out.append(_redact_tag(span))
        else:
            out.append(span)  # struct: verbatim
        i = j + 1
    return "".join(out)
```

- [ ] **Step 4: Run to verify pass.** If a fixture trips the offset math or a
  content-merge boundary, fix `scrub_html` (not the test); the fingerprint-
  invariance assertions are the contract. Confirm idempotence holds.

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
  `scrub.scrub_html`, and from `build_wave1`: `build_eml(html)->bytes` (CRLF
  `.eml` with CTE chosen by `_encode_body`), the content-hash stem helper, and
  `write_tree(dir, files)`. **Read `build_wave1.py` first** and match the real
  helper names/signatures.
- Produces: `main(argv)`; writing `wave2/{spamassassin,nazario,enron}/<stem>.eml`
  + `<stem>.meta.toml`; `--check` regenerates and diffs.

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
attribution = "Apache SpamAssassin public corpus"
[[source]]
name = "nazario"
kind = "mbox"
url = ""               # pinned GitHub-raw immutable-commit URL, filled in Task 7
sha256 = ""
cap = 80
redistribution_basis = "research-corpus"
attribution = "Nazario phishing corpus, (c) Jose Nazario, CC-BY-4.0"
[[source]]
name = "enron"
kind = "tar.gz"
url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
sha256 = ""
cap = 100
redistribution_basis = "research-corpus"
attribution = "Enron email dataset (FERC public release)"
```

- [ ] **Step 2: Write failing test** — a fixture-archive end-to-end run + a
  regeneration byte-identity check + an order-dependent survivor assertion.

```python
# Feed two in-memory archives via a monkeypatched fetch; assert:
#  (1) HTML-bearing, structurally-unique messages are written under the right dir;
#  (2) a message whose fingerprint matches a wave-1 input is dropped;
#  (3) --check after a run produces zero diff;
#  (4) two same-fingerprint/different-content messages -> the archive-order-first
#      one is written (order-dependent keep-first).
```

- [ ] **Step 3: Implement `build_wave2.py`**

```python
"""Deterministic wave-2 generator: fetch -> iterate -> scrub -> dedup -> cap -> write."""
import sys, tomllib, hashlib
from pathlib import Path
import build_wave1                       # reuse helpers (same dir)
from sources import fetch_verified, iter_html_messages
from scrub import scrub_html

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]                   # corpus repo root
CACHE = HERE / ".cache"

def _load_sources():
    with (HERE / "sources.toml").open("rb") as f:
        return tomllib.load(f)["source"]  # already in fixed order

def _wave1_fingerprints() -> set[str]:
    seen = set()
    for eml in (ROOT / "wave1").rglob("*.eml"):
        html = build_wave1.first_html(eml.read_bytes())     # match real helper
        if html is not None:
            seen.add(build_wave1.structural_fp(html))       # match real helper
    return seen

def _build(check: bool) -> int:
    seen = _wave1_fingerprints()
    files = {}                            # rel path -> bytes
    for src in _load_sources():
        if not src["url"] or not src["sha256"]:
            print(f"skip {src['name']}: unpinned", file=sys.stderr); continue
        archive = fetch_verified(src["url"], src["sha256"], CACHE)
        kept = 0
        for html in iter_html_messages(archive, src["kind"]):
            if kept >= src["cap"]:
                break
            scrubbed = scrub_html(html)
            fp = build_wave1.structural_fp(scrubbed)
            if fp in seen:
                continue                  # tree-wide dedup, keep-first
            seen.add(fp)
            eml = build_wave1.build_eml(scrubbed)
            stem = hashlib.sha256(eml).hexdigest()
            base = f"wave2/{src['name']}/{stem}"
            files[base + ".eml"] = eml
            files[base + ".meta.toml"] = _meta(src, stem).encode()
            kept += 1
        print(f"{src['name']}: kept {kept}", file=sys.stderr)
    return build_wave1.write_tree(ROOT, files, check=check)  # match real signature

def _meta(src, stem) -> str:
    return (
        f'source = "{src["attribution"]}"\n'
        f'source_url = "{src["url"]}"\n'
        f'notes = "HTML-bearing {src["name"]} message; node-scoped PII scrub over '
        f'text, attribute values, and comments. {src["attribution"]}"\n'
        f'redistribution_basis = "{src["redistribution_basis"]}"\n'
        f'wave = 2\nadded = "2026-07-11"\n'
        f'scrub = ["text-nodes-redacted", "attr-values-redacted"]\nprobes = []\n'
    )

def main(argv):
    return _build(check="--check" in argv)

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run tests to verify pass.** Reconcile every `build_wave1.*` call
  with the real helper names (the placeholders `first_html`, `structural_fp`,
  `build_eml`, `write_tree` must be replaced with what `build_wave1.py` actually
  exports; if a helper is private, import it explicitly or add a thin public
  wrapper in `build_wave1.py` **without changing its output** — verify with
  `python3.13 build_wave1.py --check`).

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
  per-source `kept` counts (expect up to the caps; real mail should dedup less
  than Wave 1's tree-construction pathology).
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

- **Spec coverage:** sourcing/download-hash (T4), HTML filter + in-archive order
  (T5), node-scoped whole-scope scrub incl. entity-obfuscation + numeric-charref
  guard (T2/T3), tree-wide dedup + fixed order + caps + determinism (T6),
  provenance/meta (T6/T7), validation + canaries + zero-9-pii (T7), re-baseline +
  floor + note (T8) — all mapped.
- **No placeholders:** the only intentionally-deferred values are the real
  `sha256`/Nazario `url` (Task 7, by design — they are vetting outputs) and the
  `build_wave1.*` helper names (Task 6 Step 4 reconciles them against the real
  module).
- **Type consistency:** `_redact`/`scrub_html`/`fetch_verified`/
  `iter_html_messages` signatures are used consistently across T2–T6.
