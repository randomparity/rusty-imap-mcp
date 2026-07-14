//! Unit tests for the transcript `normalize` helper. A dedicated binary so the
//! pure-function tests run without needing a full wire session. Includes the
//! wire support tree because `transcript.rs` lives under it.
//!
//! The tests use `assert!`/`assert_eq!` only (no `expect`/`panic`/`unwrap`), so
//! this root file carries no blanket `#![expect(...)]` — the included support
//! modules keep their own module-scoped attributes.

#[path = "support/wire/mod.rs"]
mod wire;

use wire::transcript::normalize;

#[test]
fn masks_server_version() {
    let raw = r#""version": "0.1.1-dev""#;
    let out = normalize(raw);
    assert!(out.contains(r#""version": "<VERSION>""#), "got: {out}");
    assert!(!out.contains("0.1.1-dev"), "version leaked: {out}");
}

#[test]
fn leaves_envelope_clock_time_untouched() {
    // The greediest risk: a naive `:<digits>` mask would eat this.
    let raw = "Date: Wed, 01 Jan 2020 10:30:00 +0000";
    assert_eq!(normalize(raw), raw, "clock time must survive normalize");
}

#[test]
fn leaves_small_scripted_numbers_untouched() {
    let raw = r#""uid": 2, "size": 42, "total_matched": 3"#;
    assert_eq!(normalize(raw), raw, "scripted numerics must survive");
}

#[test]
fn leaves_security_warning_text_untouched() {
    let raw = r#""security_warnings": ["hidden-instructions detected"]"#;
    assert_eq!(normalize(raw), raw, "warning text is the guarded payload");
}

#[test]
fn version_value_with_escaped_quote_is_fully_replaced() {
    // Guards the escaped-quote scan: the close-quote search must skip \" so the
    // whole value is masked, not truncated at the inner escaped quote.
    let raw = r#""version": "1.0\"weird""#;
    let out = normalize(raw);
    assert!(out.contains(r#""version": "<VERSION>""#), "got: {out}");
    assert!(
        !out.contains("weird"),
        "value tail leaked past escaped quote: {out}"
    );
}
