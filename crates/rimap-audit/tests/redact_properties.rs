//! Property tests for argument redaction.

#![expect(clippy::unwrap_used, reason = "tests")]

use proptest::prelude::*;
use rimap_audit::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, VerbatimType, hash_arguments,
};
use rimap_core::tool::ToolName;
use serde_json::{Map, Value};

fn schema() -> RedactionSchema {
    // Property-test fixture; the specific ToolName is irrelevant — only the
    // per-field policies are exercised. Reuse an existing variant rather
    // than inventing one.
    RedactionSchema::new(
        ToolName::Search,
        &[
            ("folder", FieldPolicy::Verbatim(VerbatimType::String)),
            ("uid", FieldPolicy::Verbatim(VerbatimType::U64)),
            ("subject", FieldPolicy::RedactString),
            ("body", FieldPolicy::RedactString),
            ("to", FieldPolicy::SaltedHash),
            ("password", FieldPolicy::Forbidden),
        ],
    )
}

fn salt() -> RedactionSalt {
    RedactionSalt::from_bytes([0x42_u8; 32])
}

prop_compose! {
    fn arb_input()(
        folder in prop::option::of("[A-Za-z]{1,10}"),
        uid in prop::option::of(any::<u32>()),
        subject in prop::option::of("[^\\n]{0,40}"),
        body in prop::option::of("[^\\n]{0,200}"),
        to in prop::option::of("[a-z]{1,8}@[a-z]{1,8}\\.test"),
        password in prop::option::of("[^\\n]{1,20}"),
        mystery in prop::option::of("[a-z]{1,8}"),
    ) -> Value {
        let mut m = Map::new();
        if let Some(v) = folder { m.insert("folder".into(), Value::String(v)); }
        if let Some(v) = uid { m.insert("uid".into(), Value::from(v)); }
        if let Some(v) = subject { m.insert("subject".into(), Value::String(v)); }
        if let Some(v) = body { m.insert("body".into(), Value::String(v)); }
        if let Some(v) = to { m.insert("to".into(), Value::String(v)); }
        if let Some(v) = password { m.insert("password".into(), Value::String(v)); }
        if let Some(v) = mystery { m.insert("mystery".into(), Value::String(v)); }
        Value::Object(m)
    }
}

proptest! {
    #[test]
    fn forbidden_fields_never_appear(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let obj = out.as_object().unwrap();
        prop_assert!(!obj.contains_key("password"));
    }

    #[test]
    fn verbatim_fields_pass_through_unchanged(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let in_obj = input.as_object().unwrap();
        prop_assume!(in_obj.contains_key("folder") || in_obj.contains_key("uid"));
        let out = r.apply(&input);
        let out_obj = out.as_object().unwrap();
        if let Some(v) = in_obj.get("folder") {
            prop_assert_eq!(out_obj.get("folder"), Some(v));
        }
        if let Some(v) = in_obj.get("uid") {
            prop_assert_eq!(out_obj.get("uid"), Some(v));
        }
    }

    #[test]
    fn forbidden_field_is_always_dropped_when_present(
        pw in "[^\\n]{1,20}",
        subject in prop::option::of("[^\\n]{0,40}"),
    ) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let mut m = Map::new();
        m.insert("password".to_string(), Value::String(pw));
        if let Some(v) = subject {
            m.insert("subject".to_string(), Value::String(v));
        }
        let input = Value::Object(m);
        let out = r.apply(&input);
        let obj = out.as_object().unwrap();
        prop_assert!(!obj.contains_key("password"));
    }

    #[test]
    fn redacted_strings_have_length_marker(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let in_obj = input.as_object().unwrap();
        let out_obj = out.as_object().unwrap();
        for key in ["subject", "body"] {
            if let Some(Value::String(orig)) = in_obj.get(key) {
                let v = out_obj.get(key).unwrap();
                let s = v.as_str().unwrap();
                let expected = format!("<redacted:{}>", orig.len());
                prop_assert_eq!(s, &expected);
            }
        }
    }

    #[test]
    fn output_is_always_an_object(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        prop_assert!(out.is_object());
    }

    #[test]
    fn hash_arguments_is_deterministic(input in arb_input()) {
        let a = hash_arguments(&input);
        let b = hash_arguments(&input);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn salted_hash_is_deterministic_within_process(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let a = r.apply(&input);
        let b = r.apply(&input);
        prop_assert_eq!(a, b);
    }
}

// Schema fixture for the wrong-type Verbatim properties. Names mirror
// the production search schema for U64/Bool/U64Array/StringArray
// classes, so a future field addition won't silently skip a class.
fn typed_verbatim_schema() -> RedactionSchema {
    use FieldPolicy::Verbatim;
    use VerbatimType::{Bool, StringArray, U64, U64Array};
    RedactionSchema::new(
        ToolName::Search,
        &[
            ("u64_field", Verbatim(U64)),
            ("bool_field", Verbatim(Bool)),
            ("u64_array_field", Verbatim(U64Array)),
            ("string_array_field", Verbatim(StringArray)),
        ],
    )
}

proptest! {
    // Adversarial-review regression (Codex high-severity finding): a
    // string payload sent to ANY non-string Verbatim field must never
    // survive into the redacted record. We check the whole serialized
    // record for the canary and any sufficiently long substring of it
    // so a partial overlap (e.g. only the length suffix landing in
    // `<redacted:N>`) still fails the test.
    #[test]
    fn wrong_type_string_payload_never_leaks(
        canary in "[^\u{0000}\\\\\"]{8,128}",
        field_idx in 0_usize..4,
    ) {
        let fields = [
            "u64_field",
            "bool_field",
            "u64_array_field",
            "string_array_field",
        ];
        let field = fields[field_idx];
        let s = typed_verbatim_schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let input = serde_json::json!({ field: canary.clone() });
        let out = r.apply(&input);
        let serialized = serde_json::to_string(&out).unwrap();
        // The redacted record must not contain the canary itself…
        prop_assert!(
            !serialized.contains(&canary),
            "canary leaked for field {field}: {serialized}",
        );
        // …nor any 8-char window of it (the plan's "substring ≥ 8 chars"
        // criterion). For inputs ≥ 8 chars this is a stronger check than
        // the full-string assertion above.
        for window_start in 0..canary.len().saturating_sub(7) {
            // Iterate by char boundary so multi-byte UTF-8 doesn't panic.
            if !canary.is_char_boundary(window_start) {
                continue;
            }
            let window: String = canary
                .chars()
                .skip(window_start)
                .take(8)
                .collect();
            if window.len() < 8 {
                break;
            }
            prop_assert!(
                !serialized.contains(&window),
                "8-char window {window:?} of canary leaked into redacted output for field {field}: {serialized}",
            );
        }
    }

    // Symmetric property: a well-typed payload to a typed-Verbatim field
    // round-trips byte-identically. This guards against an over-eager
    // type check that would re-redact valid input and break the audit
    // shape for ordinary callers.
    #[test]
    fn well_typed_payload_passes_through_verbatim(
        n in any::<u32>(),
        b in any::<bool>(),
        arr in proptest::collection::vec(any::<u32>(), 0..6),
    ) {
        let s = typed_verbatim_schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let input = serde_json::json!({
            "u64_field": n,
            "bool_field": b,
            "u64_array_field": arr.clone(),
            "string_array_field": ["a", "bc"],
        });
        let out = r.apply(&input);
        prop_assert_eq!(out["u64_field"].as_u64(), Some(u64::from(n)));
        prop_assert_eq!(out["bool_field"].as_bool(), Some(b));
        let out_arr: Vec<u64> = out["u64_array_field"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let expected: Vec<u64> = arr.into_iter().map(u64::from).collect();
        prop_assert_eq!(out_arr, expected);
        prop_assert_eq!(&out["string_array_field"], &serde_json::json!(["a", "bc"]));
    }
}
