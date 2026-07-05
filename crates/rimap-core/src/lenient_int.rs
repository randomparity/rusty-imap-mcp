//! Lenient integer deserializers + schema helpers (issue #292).
//!
//! Some MCP hosts (notably Claude Code, see
//! [anthropics/claude-code#24599]) stringify integer-typed tool
//! arguments before sending them. Strict JSON Schema validators in
//! those hosts then reject the call before it reaches us. This module
//! widens each integer input field's published schema to accept either
//! the integer form or a digit-string form, and decodes the string
//! form back to the canonical Rust type.
//!
//! Lives in `rimap-core` so tool-input types in both `rimap-core`
//! (e.g. [`crate::uid_selector::UidSelector`]) and `rimap-server` can
//! share one implementation; `rimap-server` re-exports it as
//! `crate::tools::lenient_int`.
//!
//! # Exported pairs
//!
//! Apply each pair to a struct field via (path shown for `rimap-server`
//! consumers; within `rimap-core` use `crate::lenient_int::`):
//!
//! ```ignore
//! #[serde(default, deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize")]
//! #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
//! pub limit: Option<usize>,
//! ```
//!
//! | Field type           | Deserializer                  | Schema                  |
//! |----------------------|-------------------------------|-------------------------|
//! | `Option<usize>`      | `deserialize_opt_usize`       | `schema_opt_usize`      |
//! | `Option<u32>`        | `deserialize_opt_u32`         | `schema_opt_u32`        |
//! | `Option<u64>`        | `deserialize_opt_u64`         | `schema_opt_u64`        |
//! | `NonZeroU32`         | `deserialize_nonzero_u32`     | `schema_nonzero_u32`    |
//! | `Option<NonZeroU32>` | `deserialize_opt_nonzero_u32` | `schema_opt_nonzero_u32`|
//!
//! Booleans and string fields are intentionally NOT covered — see the
//! design doc at
//! `docs/superpowers/specs/2026-05-18-issue-292-lenient-int-coercion-design.md`
//! "Out of scope" section.
//!
//! [anthropics/claude-code#24599]: https://github.com/anthropics/claude-code/issues/24599

use core::num::NonZeroU32;
use core::str::FromStr;

use serde::Deserialize;
use serde::de::{self, Deserializer};

/// Internal wire shape: either a JSON integer or a JSON string. The
/// per-type deserializers below convert this into the canonical Rust
/// integer type.
///
/// Uses `i64` rather than `i128` because serde's untagged-enum path
/// does not reliably dispatch `i128` through every data format; `i64`
/// covers every integer type we widen (`usize` on 64-bit is bounded by
/// the values we actually accept, `u32` and `NonZeroU32` fit easily).
///
/// Uses owned `String` rather than `&'a str` so the same deserializer
/// works whether the caller calls `serde_json::from_str` (which can
/// borrow from the original buffer) or `serde_json::from_value` (which
/// goes through `serde_json::Value` and cannot borrow). The MCP
/// dispatch layer in `mcp/tool_catalog.rs` uses `from_value`, so the
/// borrow path is not viable in production.
#[derive(Deserialize)]
#[serde(untagged)]
enum IntOrStr {
    Int(i64),
    Str(String),
}

/// Parse a digit-only string into any integer type that implements
/// [`FromStr`]. Empty strings and any non-ASCII-digit byte are rejected
/// up front so the error message identifies the wire-shape problem
/// instead of forwarding an opaque `FromStr` failure.
fn parse_int_str<T, E>(s: &str, label: &str) -> Result<T, E>
where
    T: FromStr,
    E: de::Error,
{
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::invalid_value(
            de::Unexpected::Str(s),
            &"integer in string form (digits only)",
        ));
    }
    s.parse::<T>().map_err(|_| {
        let exp = format!("integer in {label} range");
        E::invalid_value(de::Unexpected::Str(s), &exp.as_str())
    })
}

/// Convert a wire-decoded `i64` into any integer type that implements
/// [`TryFrom<i64>`]. Rejects negatives explicitly so the error message
/// distinguishes a sign error from a magnitude error.
fn i64_to_int<T, E>(n: i64, label: &str) -> Result<T, E>
where
    T: TryFrom<i64>,
    E: de::Error,
{
    if n < 0 {
        return Err(E::invalid_value(
            de::Unexpected::Signed(n),
            &"non-negative integer",
        ));
    }
    T::try_from(n).map_err(|_| {
        let exp = format!("integer in {label} range");
        E::invalid_value(de::Unexpected::Other("integer"), &exp.as_str())
    })
}

/// Convert an [`IntOrStr`] into any integer type that implements both
/// [`FromStr`] and [`TryFrom<i64>`]. Used by both the `Option<T>` and
/// `NonZero` deserializers below.
fn intorstr_to_int<T, E>(v: IntOrStr, label: &str) -> Result<T, E>
where
    T: FromStr + TryFrom<i64>,
    E: de::Error,
{
    match v {
        IntOrStr::Int(n) => i64_to_int::<T, E>(n, label),
        IntOrStr::Str(s) => parse_int_str::<T, E>(&s, label),
    }
}

/// Shared body for every `deserialize_opt_<integer>` shim below.
fn deserialize_opt_int<'de, T, D>(d: D, label: &'static str) -> Result<Option<T>, D::Error>
where
    T: FromStr + TryFrom<i64>,
    D: Deserializer<'de>,
{
    let Some(v) = Option::<IntOrStr>::deserialize(d)? else {
        return Ok(None);
    };
    intorstr_to_int::<T, D::Error>(v, label).map(Some)
}

/// Deserialize `Option<usize>` from either a JSON integer, a JSON
/// digit-string, or `null`/absent.
///
/// # Errors
///
/// Returns a serde error when the input is the wrong JSON type, a
/// negative integer, an empty/non-digit string, or numerically out of
/// range for `usize`.
pub fn deserialize_opt_usize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error> {
    deserialize_opt_int::<usize, D>(d, "usize")
}

/// Deserialize `Option<u32>` from integer, digit-string, or null/absent.
///
/// # Errors
///
/// Same semantics as [`deserialize_opt_usize`], scoped to `u32` range.
pub fn deserialize_opt_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    deserialize_opt_int::<u32, D>(d, "u32")
}

/// Deserialize `Option<u64>` from integer, digit-string, or null/absent.
///
/// # Errors
///
/// Same semantics as [`deserialize_opt_usize`], scoped to `u64` range.
/// Note that the integer form is bounded by `i64::MAX` because the
/// internal `IntOrStr` enum uses `i64`; values above that ceiling must
/// be supplied as a digit string.
pub fn deserialize_opt_u64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    deserialize_opt_int::<u64, D>(d, "u64")
}

/// Deserialize `NonZeroU32` from integer or digit-string. Rejects 0
/// and overflow.
///
/// # Errors
///
/// In addition to the integer-range errors from [`intorstr_to_int`]
/// scoped to `u32`, returns an error when the parsed value is `0`.
pub fn deserialize_nonzero_u32<'de, D: Deserializer<'de>>(d: D) -> Result<NonZeroU32, D::Error> {
    let v = IntOrStr::deserialize(d)?;
    let n: u32 = intorstr_to_int::<u32, D::Error>(v, "u32")?;
    NonZeroU32::new(n)
        .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Unsigned(0), &"nonzero u32"))
}

/// Deserialize `Option<NonZeroU32>` from integer, digit-string, or null/absent.
/// Rejects 0 and overflow with a clear error.
///
/// # Errors
///
/// Same semantics as [`deserialize_nonzero_u32`], plus accepts `null`/absent
/// as `None`.
pub fn deserialize_opt_nonzero_u32<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<NonZeroU32>, D::Error> {
    let Some(v) = Option::<IntOrStr>::deserialize(d)? else {
        return Ok(None);
    };
    let n: u32 = intorstr_to_int::<u32, D::Error>(v, "u32")?;
    let nz = NonZeroU32::new(n)
        .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Unsigned(0), &"nonzero u32"))?;
    Ok(Some(nz))
}

/// Maximum representable in the integer-branch of a `oneOf` schema for
/// any `usize`/`u64` lenient field — capped at `i64::MAX` because the
/// internal [`IntOrStr::Int`] arm uses `i64`. Values above this ceiling
/// must come in through the digit-string branch.
const I64_MAX_AS_U64: u64 = i64::MAX as u64;

/// Maximum representable in the integer-branch of a `oneOf` schema for
/// any `u32`/`NonZeroU32` lenient field.
const U32_MAX_AS_U64: u64 = u32::MAX as u64;

/// Build a lenient `oneOf` schema accepting an integer in
/// `[minimum, maximum]`, a digit-string matching `pattern`, and (when
/// `nullable`) JSON null. Single source for the `schema_*` entry points
/// below, which differ only in these four parameters.
fn lenient_schema(minimum: u64, maximum: u64, pattern: &str, nullable: bool) -> schemars::Schema {
    let mut variants = vec![
        serde_json::json!({ "type": "integer", "minimum": minimum, "maximum": maximum }),
        serde_json::json!({ "type": "string", "pattern": pattern }),
    ];
    if nullable {
        variants.push(serde_json::json!({ "type": "null" }));
    }
    schemars::json_schema!({ "oneOf": variants })
}

/// Schema for `Option<usize>` accepted as integer, digit-string, or null.
///
/// Emitted via `#[schemars(schema_with = "lenient_int::schema_opt_usize")]`.
///
/// # Bounds
///
/// The integer branch caps `maximum` at `i64::MAX` (`9_223_372_036_854_775_807`)
/// because [`deserialize_opt_usize`] decodes through `IntOrStr::Int(i64)`.
/// Callers needing larger values must use the digit-string branch; pinning
/// the schema ceiling keeps host-side pre-flight validation aligned with
/// what the deserializer will actually accept (issue #292).
pub fn schema_opt_usize(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    lenient_schema(0, I64_MAX_AS_U64, "^[0-9]+$", true)
}

/// Schema for `Option<u32>` accepted as integer, digit-string, or null.
pub fn schema_opt_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    lenient_schema(0, U32_MAX_AS_U64, "^[0-9]+$", true)
}

/// Schema for `Option<u64>` accepted as integer, digit-string, or null.
///
/// # Bounds
///
/// The integer branch caps `maximum` at `i64::MAX` (`9_223_372_036_854_775_807`)
/// because [`deserialize_opt_u64`] decodes through `IntOrStr::Int(i64)`.
/// `u64` values above that ceiling must be supplied via the digit-string
/// branch; the deserializer's rustdoc says the same thing. Keeping schema
/// and runtime in sync is the whole point of issue #292.
pub fn schema_opt_u64(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    lenient_schema(0, I64_MAX_AS_U64, "^[0-9]+$", true)
}

/// Schema for `NonZeroU32` accepted as positive integer or
/// positive-integer-string. No null branch — the field is required.
pub fn schema_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    lenient_schema(1, U32_MAX_AS_U64, "^[1-9][0-9]*$", false)
}

/// Schema for `Option<NonZeroU32>` accepted as positive integer,
/// positive-integer-string, or null.
pub fn schema_opt_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    lenient_schema(1, U32_MAX_AS_U64, "^[1-9][0-9]*$", true)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Wrap {
        #[serde(default, deserialize_with = "super::deserialize_opt_usize")]
        n: Option<usize>,
    }

    #[test]
    fn accepts_integer_form() {
        let w: Wrap = serde_json::from_str(r#"{"n": 100}"#).unwrap();
        assert_eq!(w.n, Some(100));
    }

    #[test]
    fn accepts_string_form() {
        let w: Wrap = serde_json::from_str(r#"{"n": "100"}"#).unwrap();
        assert_eq!(w.n, Some(100));
    }

    #[test]
    fn accepts_null() {
        let w: Wrap = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn accepts_absent() {
        let w: Wrap = serde_json::from_str(r"{}").unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn rejects_non_numeric_string() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": "abc"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn rejects_negative_string() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": "-1"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn rejects_overflow_string() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": "99999999999999999999"}"#).unwrap_err();
        assert!(
            err.to_string().contains("integer") || err.to_string().contains("overflow"),
            "got: {err}",
        );
    }

    #[test]
    fn rejects_float() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": 1.5}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn rejects_boolean() {
        let err = serde_json::from_str::<Wrap>(r#"{"n": true}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[derive(Debug, Deserialize)]
    struct WrapOptU32 {
        #[serde(default, deserialize_with = "super::deserialize_opt_u32")]
        n: Option<u32>,
    }

    #[test]
    fn opt_u32_int_form() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": 4294967295}"#).unwrap();
        assert_eq!(w.n, Some(u32::MAX));
    }

    #[test]
    fn opt_u32_string_form() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": "12345"}"#).unwrap();
        assert_eq!(w.n, Some(12345));
    }

    #[test]
    fn opt_u32_rejects_overflow() {
        let err = serde_json::from_str::<WrapOptU32>(r#"{"n": 4294967296}"#).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn opt_u32_rejects_negative_int() {
        let err = serde_json::from_str::<WrapOptU32>(r#"{"n": -1}"#).unwrap_err();
        assert!(err.to_string().contains("non-negative"), "got: {err}");
    }

    #[test]
    fn opt_u32_null_is_none() {
        let w: WrapOptU32 = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[derive(Debug, Deserialize)]
    struct WrapOptU64 {
        #[serde(default, deserialize_with = "super::deserialize_opt_u64")]
        n: Option<u64>,
    }

    #[test]
    fn opt_u64_int_form() {
        let w: WrapOptU64 = serde_json::from_str(r#"{"n": 9223372036854775807}"#).unwrap();
        assert_eq!(w.n, Some(9_223_372_036_854_775_807));
    }

    #[test]
    fn opt_u64_string_form() {
        let w: WrapOptU64 = serde_json::from_str(r#"{"n": "12345"}"#).unwrap();
        assert_eq!(w.n, Some(12345));
    }

    #[test]
    fn opt_u64_string_form_above_i64_max() {
        let w: WrapOptU64 = serde_json::from_str(r#"{"n": "18446744073709551615"}"#).unwrap();
        assert_eq!(w.n, Some(u64::MAX));
    }

    #[test]
    fn opt_u64_rejects_overflow_string() {
        let err =
            serde_json::from_str::<WrapOptU64>(r#"{"n": "18446744073709551616"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn opt_u64_rejects_negative_int() {
        let err = serde_json::from_str::<WrapOptU64>(r#"{"n": -1}"#).unwrap_err();
        assert!(err.to_string().contains("non-negative"), "got: {err}");
    }

    #[test]
    fn opt_u64_rejects_negative_string() {
        let err = serde_json::from_str::<WrapOptU64>(r#"{"n": "-1"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn opt_u64_rejects_non_digit_string() {
        let err = serde_json::from_str::<WrapOptU64>(r#"{"n": "abc"}"#).unwrap_err();
        assert!(err.to_string().contains("integer"), "got: {err}");
    }

    #[test]
    fn opt_u64_null_is_none() {
        let w: WrapOptU64 = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn opt_u64_absent_is_none() {
        let w: WrapOptU64 = serde_json::from_str(r"{}").unwrap();
        assert_eq!(w.n, None);
    }

    use core::num::NonZeroU32;

    #[derive(Debug, Deserialize)]
    struct WrapNz {
        #[serde(deserialize_with = "super::deserialize_nonzero_u32")]
        n: NonZeroU32,
    }

    #[test]
    fn nonzero_u32_int_form() {
        let w: WrapNz = serde_json::from_str(r#"{"n": 42}"#).unwrap();
        assert_eq!(w.n.get(), 42);
    }

    #[test]
    fn nonzero_u32_string_form() {
        let w: WrapNz = serde_json::from_str(r#"{"n": "42"}"#).unwrap();
        assert_eq!(w.n.get(), 42);
    }

    #[test]
    fn nonzero_u32_rejects_zero_int() {
        let err = serde_json::from_str::<WrapNz>(r#"{"n": 0}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}",
        );
    }

    #[test]
    fn nonzero_u32_rejects_zero_string() {
        let err = serde_json::from_str::<WrapNz>(r#"{"n": "0"}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}",
        );
    }

    #[derive(Debug, Deserialize)]
    struct WrapOptNz {
        #[serde(default, deserialize_with = "super::deserialize_opt_nonzero_u32")]
        n: Option<NonZeroU32>,
    }

    #[test]
    fn opt_nonzero_u32_int_form() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": 42}"#).unwrap();
        assert_eq!(w.n.map(NonZeroU32::get), Some(42));
    }

    #[test]
    fn opt_nonzero_u32_string_form() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": "42"}"#).unwrap();
        assert_eq!(w.n.map(NonZeroU32::get), Some(42));
    }

    #[test]
    fn opt_nonzero_u32_null_is_none() {
        let w: WrapOptNz = serde_json::from_str(r#"{"n": null}"#).unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn opt_nonzero_u32_absent_is_none() {
        let w: WrapOptNz = serde_json::from_str(r"{}").unwrap();
        assert_eq!(w.n, None);
    }

    #[test]
    fn opt_nonzero_u32_rejects_zero_int() {
        let err = serde_json::from_str::<WrapOptNz>(r#"{"n": 0}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}",
        );
    }

    #[test]
    fn opt_nonzero_u32_rejects_zero_string() {
        let err = serde_json::from_str::<WrapOptNz>(r#"{"n": "0"}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}",
        );
    }

    #[test]
    fn schema_opt_usize_has_oneof_with_three_branches() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_usize(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v
            .get("oneOf")
            .and_then(|x| x.as_array())
            .expect("oneOf array");
        assert_eq!(one_of.len(), 3, "expected 3 branches, got {one_of:?}");
        let types: Vec<_> = one_of
            .iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(types.contains(&"null"));
    }

    #[test]
    fn schema_nonzero_u32_has_no_null_branch() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_nonzero_u32(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v
            .get("oneOf")
            .and_then(|x| x.as_array())
            .expect("oneOf array");
        assert_eq!(one_of.len(), 2);
        let types: Vec<_> = one_of
            .iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(!types.contains(&"null"));
    }

    #[test]
    fn schema_opt_usize_integer_branch_capped_at_i64_max() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_usize(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v
            .get("oneOf")
            .and_then(|x| x.as_array())
            .expect("oneOf array");
        let integer_branch = one_of
            .iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("integer"))
            .expect("integer branch present");
        assert_eq!(
            integer_branch
                .get("maximum")
                .and_then(serde_json::Value::as_u64),
            Some(9_223_372_036_854_775_807),
            "integer branch must cap at i64::MAX to match IntOrStr::Int(i64); got {integer_branch:?}",
        );
    }

    #[test]
    fn schema_opt_u64_integer_branch_capped_at_i64_max() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_u64(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v
            .get("oneOf")
            .and_then(|x| x.as_array())
            .expect("oneOf array");
        let integer_branch = one_of
            .iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("integer"))
            .expect("integer branch present");
        assert_eq!(
            integer_branch
                .get("maximum")
                .and_then(serde_json::Value::as_u64),
            Some(9_223_372_036_854_775_807),
            "integer branch must cap at i64::MAX to match IntOrStr::Int(i64); got {integer_branch:?}",
        );
    }

    #[test]
    fn schema_opt_nonzero_u32_has_oneof_with_three_branches() {
        let mut g = schemars::SchemaGenerator::default();
        let s = super::schema_opt_nonzero_u32(&mut g);
        let v = serde_json::to_value(s).unwrap();
        let one_of = v
            .get("oneOf")
            .and_then(|x| x.as_array())
            .expect("oneOf array");
        assert_eq!(one_of.len(), 3, "expected 3 branches, got {one_of:?}");
        let types: Vec<_> = one_of
            .iter()
            .filter_map(|b| b.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(types.contains(&"integer"));
        assert!(types.contains(&"string"));
        assert!(types.contains(&"null"));
        let string_branch = one_of
            .iter()
            .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("string"))
            .expect("string branch present");
        assert_eq!(
            string_branch.get("pattern").and_then(|p| p.as_str()),
            Some("^[1-9][0-9]*$"),
        );
    }
}
