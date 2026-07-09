//! Adversarial corpus test harness.
//!
//! Iterates every fixture under `tests/injection-corpus/` (repo-root)
//! and runs assertions derived from the fixture's `expected.json`
//! against the output of `rimap_content::parse_message`. A single
//! `#[test]` drives all fixtures so a failure in one fixture does
//! not short-circuit the rest — instead, all failures are reported
//! in a single panic at the end.

#![expect(clippy::unwrap_used, reason = "test code may unwrap on fixture I/O")]
#![expect(clippy::expect_used, reason = "test code may expect on fixture I/O")]
#![expect(clippy::panic, reason = "test failures are reported via panic")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "corpus harness panics on unclassified variants inside Result-returning helpers; \
              this is intentional — an unknown variant is a harness gap, not a recoverable error"
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rimap_content::{Content, ContentError, parse_message};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    #[expect(dead_code, reason = "deserialized for schema compatibility, not read")]
    description: String,
    #[serde(default = "default_expect_ok")]
    expect: ExpectKind,
    #[serde(default)]
    must_contain: Vec<String>,
    #[serde(default)]
    must_not_contain: Vec<String>,
    #[serde(default)]
    body_html_must_contain: Vec<String>,
    #[serde(default)]
    body_html_must_not_contain: Vec<String>,
    #[serde(default)]
    alternate_parts_must_contain: Vec<String>,
    #[serde(default)]
    warning_codes: Vec<String>,
    #[serde(default)]
    forbidden_warning_codes: Vec<String>,
    #[serde(default)]
    meta: Option<ExpectedMeta>,
    #[serde(default)]
    error_kind: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ExpectKind {
    Ok,
    Error,
}

fn default_expect_ok() -> ExpectKind {
    ExpectKind::Ok
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedMeta {
    #[serde(default)]
    mailing_list_present: Option<bool>,
    #[serde(default)]
    attachment_count: Option<usize>,
    #[serde(default)]
    body_truncated: Option<bool>,
}

fn corpus_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/rimap-content/.
    // Corpus lives at repo-root/tests/injection-corpus/.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(Path::parent) // repo-root
        .map(|root| root.join("tests").join("injection-corpus"))
        .expect("could not resolve repo-root from CARGO_MANIFEST_DIR")
}

fn load_fixtures() -> BTreeMap<String, (PathBuf, Expected)> {
    let root = corpus_root();
    let mut out = BTreeMap::new();
    let entries = match fs::read_dir(&root) {
        Ok(e) => e,
        Err(err) => panic!("could not read {}: {err}", root.display()),
    };
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let expected_path = dir.join("expected.json");
        if !expected_path.exists() {
            continue;
        }
        let json = fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", expected_path.display()));
        let expected: Expected = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("parse {}: {e}", expected_path.display()));
        out.insert(name, (dir, expected));
    }
    out
}

fn assert_fixture(name: &str, dir: &Path, expected: &Expected) -> Result<(), String> {
    let input_path = dir.join("input.eml");
    let raw = fs::read(&input_path).map_err(|e| format!("read {}: {e}", input_path.display()))?;

    let result = parse_message(&raw);

    match (&expected.expect, result) {
        (ExpectKind::Ok, Ok(content)) => assert_ok_body(name, &content, expected),
        (ExpectKind::Ok, Err(err)) => Err(format!("{name}: expected Ok but got Err({err})")),
        (ExpectKind::Error, Ok(_)) => Err(format!("{name}: expected Err but got Ok")),
        (ExpectKind::Error, Err(err)) => assert_err_kind(name, &err, expected),
    }
}

fn assert_ok_body(name: &str, content: &Content, expected: &Expected) -> Result<(), String> {
    assert_body_substrings(name, &content.untrusted.body_text, expected)?;
    assert_body_html_substrings(name, content.untrusted.body_html.as_deref(), expected)?;
    assert_alternate_parts_substrings(name, &content.untrusted.alternate_parts, expected)?;
    assert_warning_codes(name, &content.security_warnings, expected)?;
    assert_meta_fields(name, &content.meta, expected)
}

/// Assert every `alternate_parts_must_contain` needle appears in at
/// least one entry of `content.untrusted.alternate_parts`. This lets a
/// fixture prove that content which is surfaced but *segregated* out of
/// the primary body — e.g. an unsigned sibling under `multipart/signed`
/// — still lands in the untrusted namespace rather than being dropped or
/// promoted into `meta`. A fixture declaring needles when no alternate
/// part carries them is a failure.
fn assert_alternate_parts_substrings(
    name: &str,
    alternate_parts: &[String],
    expected: &Expected,
) -> Result<(), String> {
    for needle in &expected.alternate_parts_must_contain {
        if !alternate_parts.iter().any(|part| part.contains(needle)) {
            return Err(format!(
                "{name}: no alternate part contains required substring {needle:?} \
                 (alternate_parts={alternate_parts:?})"
            ));
        }
    }
    Ok(())
}

/// Assert `body_html_must_contain` / `body_html_must_not_contain`
/// against `content.untrusted.body_html`, so a fixture can prove the
/// surfaced HTML is sanitized (e.g. `<script>` stripped) independently
/// of the plain-text `body_text` checks. A fixture requiring HTML
/// substrings when no `body_html` was surfaced is a failure.
fn assert_body_html_substrings(
    name: &str,
    body_html: Option<&str>,
    expected: &Expected,
) -> Result<(), String> {
    if expected.body_html_must_contain.is_empty() && expected.body_html_must_not_contain.is_empty()
    {
        return Ok(());
    }
    let Some(html) = body_html else {
        return Err(format!(
            "{name}: body_html assertions declared but no body_html was surfaced"
        ));
    };
    for needle in &expected.body_html_must_contain {
        if !html.contains(needle) {
            return Err(format!(
                "{name}: body_html missing required substring {needle:?} (body_html={html:?})"
            ));
        }
    }
    for needle in &expected.body_html_must_not_contain {
        if html.contains(needle) {
            return Err(format!(
                "{name}: body_html contains forbidden substring {needle:?} (body_html={html:?})"
            ));
        }
    }
    Ok(())
}

fn assert_body_substrings(name: &str, body: &str, expected: &Expected) -> Result<(), String> {
    for needle in &expected.must_contain {
        if !body.contains(needle) {
            return Err(format!(
                "{name}: body missing required substring {needle:?} (body={body:?})"
            ));
        }
    }
    for needle in &expected.must_not_contain {
        if body.contains(needle) {
            return Err(format!(
                "{name}: body contains forbidden substring {needle:?} (body={body:?})"
            ));
        }
    }
    Ok(())
}

fn assert_warning_codes(
    name: &str,
    warnings: &[rimap_content::SecurityWarning],
    expected: &Expected,
) -> Result<(), String> {
    let observed: Vec<&'static str> = warnings
        .iter()
        .map(|w| {
            rimap_content::test_support::warning_code_label(w.code).unwrap_or_else(|| {
                panic!(
                    "corpus harness encountered unclassified WarningCode variant {:?}",
                    w.code
                )
            })
        })
        .collect();
    for required in &expected.warning_codes {
        if !observed.contains(&required.as_str()) {
            return Err(format!(
                "{name}: missing required warning_code {required:?} (observed={observed:?})"
            ));
        }
    }
    for forbidden in &expected.forbidden_warning_codes {
        if observed.contains(&forbidden.as_str()) {
            return Err(format!(
                "{name}: forbidden warning_code {forbidden:?} was emitted"
            ));
        }
    }
    Ok(())
}

fn assert_meta_fields(
    name: &str,
    meta: &rimap_content::ContentMeta,
    expected: &Expected,
) -> Result<(), String> {
    let Some(want_meta) = &expected.meta else {
        return Ok(());
    };
    if let Some(want) = want_meta.mailing_list_present {
        let got = meta.mailing_list.is_some();
        if got != want {
            return Err(format!(
                "{name}: meta.mailing_list_present want={want} got={got}"
            ));
        }
    }
    if let Some(want) = want_meta.attachment_count {
        let got = meta.attachments.len();
        if got != want {
            return Err(format!(
                "{name}: meta.attachment_count want={want} got={got}"
            ));
        }
    }
    if let Some(want) = want_meta.body_truncated
        && meta.body_truncated != want
    {
        return Err(format!(
            "{name}: meta.body_truncated want={want} got={}",
            meta.body_truncated
        ));
    }
    Ok(())
}

fn assert_err_kind(name: &str, err: &ContentError, expected: &Expected) -> Result<(), String> {
    let Some(want) = expected.error_kind.as_deref() else {
        return Err(format!("{name}: expect=error requires error_kind field"));
    };
    let got = rimap_content::test_support::error_kind_label(err).unwrap_or_else(|| {
        panic!("corpus harness encountered unclassified ContentError variant {err:?}")
    });
    if got == want {
        Ok(())
    } else {
        Err(format!("{name}: error_kind want={want:?} got={got:?}"))
    }
}

#[test]
fn alternate_parts_must_contain_detects_presence_and_absence() {
    let json = r#"{"description":"t","alternate_parts_must_contain":["payload"]}"#;
    let expected: Expected = serde_json::from_str(json).unwrap();

    let present = vec![
        "harmless".to_string(),
        "carries the payload here".to_string(),
    ];
    assert!(assert_alternate_parts_substrings("t", &present, &expected).is_ok());

    let absent = vec!["harmless".to_string()];
    let err = assert_alternate_parts_substrings("t", &absent, &expected)
        .expect_err("missing needle must fail");
    assert!(err.contains("payload"), "err={err}");

    let empty: Vec<String> = Vec::new();
    assert!(assert_alternate_parts_substrings("t", &empty, &expected).is_err());
}

#[test]
fn all_corpus_fixtures_pass() {
    let fixtures = load_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no fixtures found under {}",
        corpus_root().display()
    );

    let mut failures: Vec<String> = Vec::new();
    for (name, (dir, expected)) in &fixtures {
        if let Err(msg) = assert_fixture(name, dir, expected) {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n  - {}",
        failures.join("\n  - ")
    );
}
