//! Lenient integer deserializers + schema helpers.
//!
//! Some MCP hosts (notably Claude Code, see issue #292) stringify
//! integer-typed tool arguments before sending them. Strict JSON
//! Schema validators in those hosts then reject the call before it
//! reaches us. This module widens each integer input field's published
//! schema to accept either the integer or a digit-string, and decodes
//! the string form back to the canonical Rust type.

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

fn parse_usize_str<E: de::Error>(s: &str) -> Result<usize, E> {
    if s.is_empty() {
        return Err(E::invalid_value(
            de::Unexpected::Str(s),
            &"non-empty digit string",
        ));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::invalid_value(
            de::Unexpected::Str(s),
            &"integer in string form (digits only)",
        ));
    }
    s.parse::<usize>()
        .map_err(|_| E::invalid_value(de::Unexpected::Str(s), &"integer in usize range"))
}

fn i64_to_usize<E: de::Error>(n: i64) -> Result<usize, E> {
    if n < 0 {
        return Err(E::invalid_value(
            de::Unexpected::Signed(n),
            &"non-negative integer",
        ));
    }
    usize::try_from(n)
        .map_err(|_| E::invalid_value(de::Unexpected::Other("integer"), &"integer in usize range"))
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
    let v: Option<IntOrStr> = Option::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(IntOrStr::Int(n)) => i64_to_usize(n).map(Some),
        Some(IntOrStr::Str(s)) => parse_usize_str(&s).map(Some),
    }
}

fn parse_u32_str<E: de::Error>(s: &str) -> Result<u32, E> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(E::invalid_value(
            de::Unexpected::Str(s),
            &"integer in string form (digits only)",
        ));
    }
    s.parse::<u32>()
        .map_err(|_| E::invalid_value(de::Unexpected::Str(s), &"integer in u32 range"))
}

fn i64_to_u32<E: de::Error>(n: i64) -> Result<u32, E> {
    if n < 0 {
        return Err(E::invalid_value(
            de::Unexpected::Signed(n),
            &"non-negative integer",
        ));
    }
    u32::try_from(n)
        .map_err(|_| E::invalid_value(de::Unexpected::Other("integer"), &"integer in u32 range"))
}

/// Deserialize `Option<u32>` from integer, digit-string, or null/absent.
///
/// # Errors
///
/// Same semantics as [`deserialize_opt_usize`], scoped to `u32` range.
pub fn deserialize_opt_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    let v: Option<IntOrStr> = Option::deserialize(d)?;
    match v {
        None => Ok(None),
        Some(IntOrStr::Int(n)) => i64_to_u32(n).map(Some),
        Some(IntOrStr::Str(s)) => parse_u32_str(&s).map(Some),
    }
}

/// Deserialize `NonZeroU32` from integer or digit-string. Rejects 0
/// and overflow.
///
/// # Errors
///
/// In addition to the integer-range errors from `parse_u32_str` /
/// `i64_to_u32`, returns an error when the parsed value is `0`.
pub fn deserialize_nonzero_u32<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<core::num::NonZeroU32, D::Error> {
    let v = IntOrStr::deserialize(d)?;
    let n: u32 = match v {
        IntOrStr::Int(n) => i64_to_u32(n)?,
        IntOrStr::Str(s) => parse_u32_str(&s)?,
    };
    core::num::NonZeroU32::new(n)
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
) -> Result<Option<core::num::NonZeroU32>, D::Error> {
    let v: Option<IntOrStr> = Option::deserialize(d)?;
    let Some(int_or_str) = v else { return Ok(None) };
    let n: u32 = match int_or_str {
        IntOrStr::Int(n) => i64_to_u32(n)?,
        IntOrStr::Str(s) => parse_u32_str(&s)?,
    };
    let nz = core::num::NonZeroU32::new(n)
        .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Unsigned(0), &"nonzero u32"))?;
    Ok(Some(nz))
}

/// Schema for `Option<usize>` accepted as integer, digit-string, or null.
///
/// Emitted via `#[schemars(schema_with = "lenient_int::schema_opt_usize")]`.
pub fn schema_opt_usize(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 0 },
            { "type": "string", "pattern": "^[0-9]+$" },
            { "type": "null" }
        ]
    })
}

/// Schema for `Option<u32>` accepted as integer, digit-string, or null.
pub fn schema_opt_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 },
            { "type": "string", "pattern": "^[0-9]+$" },
            { "type": "null" }
        ]
    })
}

/// Schema for `NonZeroU32` accepted as positive integer or
/// positive-integer-string. No null branch — the field is required.
pub fn schema_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 1, "maximum": 4_294_967_295_u64 },
            { "type": "string", "pattern": "^[1-9][0-9]*$" }
        ]
    })
}

/// Schema for `Option<NonZeroU32>` accepted as positive integer,
/// positive-integer-string, or null.
pub fn schema_opt_nonzero_u32(_g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "oneOf": [
            { "type": "integer", "minimum": 1, "maximum": 4_294_967_295_u64 },
            { "type": "string", "pattern": "^[1-9][0-9]*$" },
            { "type": "null" }
        ]
    })
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
