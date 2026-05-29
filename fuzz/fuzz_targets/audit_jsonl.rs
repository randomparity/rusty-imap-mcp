#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_audit::{RedactionSalt, parse_line, redact};

fuzz_target!(|data: &[u8]| {
    let Ok(record) = parse_line(data) else {
        return;
    };

    let salt = RedactionSalt::from_bytes([0x42_u8; 32]);
    let redacted = redact(&record, &salt);
    let serialized = serde_json::to_vec(&redacted)
        .expect("redacted record must serialize via serde_json");
    let _reparsed: rimap_audit::AuditRecord = serde_json::from_slice(&serialized)
        .expect("redacted record must round-trip through serde_json");

    // For tool_start payloads, every non-Verbatim string
    // value in the input's arguments_redacted must be replaced by
    // redact() — i.e., the post-redact value at the same key must not
    // be byte-equal to the input value. This is exactly what redact()
    // is contracted to do: replace each non-Verbatim string with a
    // synthesized marker (`<redacted:N>`, `<redacted:?>`, or
    // `salted:HEX`). A leak would mean the input survived unchanged.
    //
    // Scoped to arguments_redacted because that is the only thing
    // redact() touches; outer record fields (account, tool, etc.) are
    // intentional Verbatim metadata. Per-key leaf comparison rather
    // than serialization substring search to avoid false positives
    // where a short input happens to be a substring of a synthesized
    // marker (e.g. input "ed:12" inside output "<redacted:12>").
    if let rimap_audit::Payload::ToolStart(ref start_in) = record.payload {
        use rimap_audit::ToolRedactionSchema;
        let schema = start_in.tool.redaction_schema();

        let rimap_audit::Payload::ToolStart(ref start_out) = redacted.payload else {
            panic!("redact() must not change the payload variant");
        };

        let (
            serde_json::Value::Object(map_in),
            serde_json::Value::Object(map_out),
        ) = (&start_in.arguments_redacted, &start_out.arguments_redacted)
        else {
            return;
        };

        for (name, value_in) in map_in {
            let policy = schema.policy_for(name.as_str());
            if matches!(policy, rimap_audit::FieldPolicy::Verbatim(_)) {
                continue;
            }
            let serde_json::Value::String(s_in) = value_in else {
                continue;
            };
            if s_in.is_empty() {
                continue;
            }
            // Skip inputs that already look like a redaction marker;
            // these are output forms that an attacker can't realistically
            // smuggle into a real audit record, and `<redacted:13>` is a
            // self-referential fixed point (byte-equal to its own marker)
            // that would trip the leaf-equality check spuriously.
            if s_in.starts_with("<redacted:") || s_in.starts_with("salted:") {
                continue;
            }
            let Some(value_out) = map_out.get(name) else {
                // Forbidden policy drops the key. Not a leak.
                continue;
            };
            if let serde_json::Value::String(s_out) = value_out {
                assert!(
                    s_in != s_out,
                    "redact() left non-Verbatim string {s_in:?} unchanged at \
                     field {name:?} (policy={policy:?}, tool={tool:?})",
                    tool = start_in.tool,
                );
            }
        }
    }
});
