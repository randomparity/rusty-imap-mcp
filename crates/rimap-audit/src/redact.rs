//! Structural argument redaction for audit records. Each tool declares a
//! [`RedactionSchema`] that classifies its top-level argument fields:
//!
//! - [`FieldPolicy::Verbatim`] — structural fields copied into the record
//!   verbatim *if and only if* the JSON value matches the declared
//!   [`VerbatimType`]. Type mismatches fall through to [`FieldPolicy::RedactString`].
//! - [`FieldPolicy::RedactString`] — replaced with `"<redacted:N>"` where `N`
//!   is the UTF-8 byte length of the original string.
//! - [`FieldPolicy::SaltedHash`] — replaced with the first 16 hex chars of
//!   `sha256(salt || value)`. Unique within a process, unlinkable across
//!   processes.
//! - [`FieldPolicy::Forbidden`] — the field must not appear. Presence is
//!   scrubbed and a `tracing::warn!` emitted.
//!
//! Unknown top-level fields are treated as [`FieldPolicy::RedactString`] by
//! default — conservative.

use std::collections::BTreeMap;

use rand::{Rng, rng};
use rimap_core::tool::ToolName;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Per-field policy for the redaction pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPolicy {
    /// Copy the field's JSON value into the record if and only if it
    /// matches the declared [`VerbatimType`]. Type-mismatched values
    /// (e.g. a string supplied for a `U64` field) fall through to
    /// [`Self::RedactString`] so a malicious or prompt-injected client
    /// cannot smuggle arbitrary text into the audit log by mistyping a
    /// "structural" field. `tool_start` is emitted before argument
    /// deserialization runs, so the type check here is the only defense
    /// against that vector. See [`Redactor::redact_string`] for the
    /// fall-through output shape.
    Verbatim(VerbatimType),
    /// Replace string values with `"<redacted:N>"`. Non-string values are
    /// replaced with `"<redacted:?>"`.
    RedactString,
    /// Replace with `sha256(salt || canonical(value))` truncated to 16 hex
    /// chars. Useful for "same recipient across calls" correlation without
    /// leaking the recipient.
    SaltedHash,
    /// Forbidden field — must not appear in audit output. Presence is logged
    /// via `tracing::warn!` and the field is dropped.
    Forbidden,
}

/// JSON-type expected by a [`FieldPolicy::Verbatim`] field. A mismatch
/// falls through to [`FieldPolicy::RedactString`] inside [`Redactor::apply`]
/// rather than copying the value into the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbatimType {
    /// Any `Value::String`.
    String,
    /// `Value::String` capped at 32 bytes. Covers ISO 8601 date / date-time
    /// shapes (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS+HH:MM`); the cap exists
    /// to prevent a long blob from being persisted under a "date" field
    /// when the JSON type alone matches. Strict ISO parsing stays in
    /// `build_query`; the redactor's job is just to keep a blob out of
    /// the log.
    DateString,
    /// `Value::Number` that fits in a `u64`.
    U64,
    /// `Value::Bool`.
    Bool,
    /// `Value::Array` whose every element fits in a `u64`.
    U64Array,
    /// `Value::Array` whose every element fits in a `u64` *and* whose length
    /// does not exceed the embedded cap. Over-cap or wrong-typed arrays fall
    /// through to [`FieldPolicy::RedactString`] (emitting `<redacted:?>`)
    /// instead of being copied verbatim.
    ///
    /// Use this — not [`Self::U64Array`] — for *caller-supplied* UID arrays
    /// that the handler itself rejects above the same cap. `tool_start` is
    /// emitted before argument deserialization runs, so without the cap a
    /// rejected oversize request would still be cloned and persisted verbatim,
    /// amplifying audit-log and memory use.
    U64ArrayMax(usize),
    /// `Value::Array` whose every element is a `Value::String`.
    StringArray,
}

/// Length cap on [`VerbatimType::DateString`]. 32 bytes accommodates
/// `YYYY-MM-DDTHH:MM:SS+HH:MM` (25) with room for fractional seconds
/// (`.fff`) and a trailing zone suffix; longer values are treated as
/// suspicious blobs.
const DATE_STRING_MAX_BYTES: usize = 32;

/// Declarative schema for one tool's arguments. Field names are top-level
/// JSON object keys.
#[derive(Debug, Clone)]
pub struct RedactionSchema {
    /// Tool identifier. Audit records render this via [`ToolName::as_str`];
    /// tracing spans attach the same string.
    pub tool: ToolName,
    /// Policies keyed by field name.
    pub policies: BTreeMap<&'static str, FieldPolicy>,
}

impl RedactionSchema {
    /// Construct a schema from a static slice of `(name, policy)` pairs.
    #[must_use]
    pub fn new(tool: ToolName, rules: &[(&'static str, FieldPolicy)]) -> Self {
        let mut policies = BTreeMap::new();
        for (name, policy) in rules {
            policies.insert(*name, *policy);
        }
        Self { tool, policies }
    }
}

/// Per-process salt used for [`FieldPolicy::SaltedHash`]. Regenerated on each
/// process start — hashes are not comparable across processes.
#[derive(Debug, Clone)]
pub struct RedactionSalt([u8; 32]);

impl RedactionSalt {
    /// Generate a fresh salt from the OS RNG.
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0_u8; 32];
        rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct a salt from explicit bytes. Used by tests.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Applies a [`RedactionSchema`] to an argument JSON value and produces the
/// `arguments_redacted` object recorded in `tool_start`.
#[derive(Debug)]
pub struct Redactor<'a> {
    schema: &'a RedactionSchema,
    salt: &'a RedactionSalt,
}

impl<'a> Redactor<'a> {
    /// Construct a redactor against a schema and a process-lifetime salt.
    #[must_use]
    pub fn new(schema: &'a RedactionSchema, salt: &'a RedactionSalt) -> Self {
        Self { schema, salt }
    }

    /// Apply the schema to `args`, which must be a JSON object.
    ///
    /// Non-object inputs are turned into a one-field object
    /// `{"_non_object": "<redacted:?>"}` so the audit layer always writes a
    /// homogeneous shape.
    #[must_use]
    pub fn apply(&self, args: &Value) -> Value {
        let Value::Object(map) = args else {
            let mut out = Map::new();
            out.insert(
                "_non_object".to_string(),
                Value::String("<redacted:?>".to_string()),
            );
            return Value::Object(out);
        };
        let mut out = Map::new();
        for (name, value) in map {
            let policy = self
                .schema
                .policies
                .get(name.as_str())
                .copied()
                .unwrap_or(FieldPolicy::RedactString);
            match policy {
                FieldPolicy::Verbatim(vt) => match Self::verbatim_check(value, vt) {
                    Some(v) => {
                        out.insert(name.clone(), v);
                    }
                    None => {
                        out.insert(name.clone(), Self::redact_string(value));
                    }
                },
                FieldPolicy::RedactString => {
                    out.insert(name.clone(), Self::redact_string(value));
                }
                FieldPolicy::SaltedHash => {
                    out.insert(name.clone(), self.salted_hash(value));
                }
                FieldPolicy::Forbidden => {
                    tracing::warn!(
                        tool = self.schema.tool.as_str(),
                        field = name.as_str(),
                        "forbidden field present in tool arguments; dropped",
                    );
                }
            }
        }
        Value::Object(out)
    }

    /// Return `Some(value.clone())` when `value` matches the JSON shape
    /// implied by `vt`, otherwise `None`. Callers fall through to
    /// [`Self::redact_string`] on `None` so a wrong-typed payload (e.g.
    /// a string smuggled into a `U64` field) cannot reach the audit log
    /// verbatim. See [`FieldPolicy::Verbatim`] for the threat-model
    /// rationale.
    fn verbatim_check(value: &Value, vt: VerbatimType) -> Option<Value> {
        match vt {
            VerbatimType::String => value.as_str().map(|_| value.clone()),
            VerbatimType::DateString => value
                .as_str()
                .filter(|s| s.len() <= DATE_STRING_MAX_BYTES)
                .map(|_| value.clone()),
            VerbatimType::U64 => value.as_u64().map(|_| value.clone()),
            VerbatimType::Bool => value.as_bool().map(|_| value.clone()),
            VerbatimType::U64Array => value
                .as_array()
                .filter(|arr| arr.iter().all(serde_json::Value::is_u64))
                .map(|_| value.clone()),
            VerbatimType::U64ArrayMax(max) => value
                .as_array()
                .filter(|arr| arr.len() <= max && arr.iter().all(serde_json::Value::is_u64))
                .map(|_| value.clone()),
            VerbatimType::StringArray => value
                .as_array()
                .filter(|arr| arr.iter().all(serde_json::Value::is_string))
                .map(|_| value.clone()),
        }
    }

    fn redact_string(value: &Value) -> Value {
        if let Value::String(s) = value {
            Value::String(format!("<redacted:{}>", s.len()))
        } else {
            Value::String("<redacted:?>".to_string())
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "serde_json::to_vec(Value) is infallible"
    )]
    fn salted_hash(&self, value: &Value) -> Value {
        // Canonicalize via `serde_json::to_vec`; equal values hash to the same
        // bytes within a process because `serde_json` preserves Map insertion
        // order (BTreeMap in our inputs).
        let bytes = serde_json::to_vec(value).expect("serde_json::to_vec of Value is infallible");
        let mut hasher = Sha256::new();
        hasher.update(self.salt.as_bytes());
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut hex_s = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            use std::fmt::Write as _;
            let _ = write!(hex_s, "{byte:02x}");
        }
        Value::String(format!("salted:{hex_s}"))
    }
}

/// Computes `sha256(serde_json::to_vec(args))` on the *unredacted* arguments
/// for the `arguments_hash_sha256` audit field.
#[must_use]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "serde_json::to_vec(Value) is infallible"
)]
pub fn hash_arguments(args: &Value) -> String {
    let bytes = serde_json::to_vec(args).expect("serde_json::to_vec of Value is infallible");
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Re-apply the per-tool [`RedactionSchema`] to an [`AuditRecord`].
///
/// For [`crate::record::Payload::ToolStart`] this re-runs [`Redactor::apply`]
/// on `arguments_redacted` using the tool's declared schema and the
/// supplied salt. For all other payload variants the record is
/// returned unchanged (no caller-supplied strings to redact).
///
/// Re-application is safe: once the original string bytes have been
/// replaced with `"<redacted:N>"`, a salted hash, or removed entirely,
/// they cannot be reintroduced by further passes. (The `<redacted:N>`
/// length marker and salted-hash output are themselves treated as
/// strings on subsequent passes, so the field's textual content will
/// continue to evolve — but never back toward the original.)
#[must_use]
pub fn redact(
    record: &crate::record::AuditRecord,
    salt: &RedactionSalt,
) -> crate::record::AuditRecord {
    use crate::record::Payload;

    let mut out = record.clone();
    if let Payload::ToolStart(ref mut start) = out.payload {
        let schema = start.tool.redaction_schema();
        let redactor = Redactor::new(&schema, salt);
        start.arguments_redacted = redactor.apply(&start.arguments_redacted);
    }
    out
}

/// Extension trait adding a total redaction-schema dispatch on
/// [`ToolName`]. Implemented for `ToolName` in this crate; bring the trait
/// into scope to call `tool.redaction_schema()`.
///
/// The `impl` uses one exhaustive match on every `ToolName` variant so
/// forgetting to wire a schema for a new variant is a compile error, not a
/// runtime warn-and-drop.
pub trait ToolRedactionSchema {
    /// Return the [`RedactionSchema`] covering this tool's arguments.
    ///
    /// Field lists mirror the tool argument shapes documented in design
    /// spec §5 (v1 tool surface). A field not listed defaults to
    /// [`FieldPolicy::RedactString`] at runtime, so forgetting to list a
    /// structural field only produces an overly-conservative log entry,
    /// never a leak.
    fn redaction_schema(self) -> RedactionSchema;
}

impl ToolRedactionSchema for ToolName {
    fn redaction_schema(self) -> RedactionSchema {
        // Dispatch is split into per-group helpers to keep each function
        // short and to collapse variants whose argument shapes are
        // identical (folder+uid, flag shape, etc.) without masking tool
        // identity in the schema (each helper still builds the schema
        // with `self` as the tool).
        match self {
            Self::ListFolders => list_folders_schema(self),
            Self::Search => search_schema(self),
            Self::SearchAdvanced => search_advanced_schema(self),
            Self::FetchMessage | Self::FetchMessageHtml => fetch_message_schema(self),
            Self::ListAttachments | Self::MarkRead | Self::MarkUnread => folder_uid_schema(self),
            Self::DownloadAttachment => download_attachment_schema(self),
            Self::ExportMessages => export_messages_schema(self),
            Self::Flag | Self::Unflag => flag_schema(self),
            Self::MoveMessage => move_message_schema(self),
            Self::CreateDraft => create_draft_schema(self),
            Self::SendEmail => send_email_schema(self),
            Self::DeleteMessage => delete_message_schema(self),
            Self::Expunge => expunge_schema(self),
            Self::CreateFolder => create_folder_schema(self),
            Self::RenameFolder => rename_folder_schema(self),
            Self::DeleteFolder => delete_folder_schema(self),
            Self::AddLabel | Self::RemoveLabel => add_remove_label_schema(self),
            Self::ListLabels => list_labels_schema(self),
            Self::UseAccount => use_account_schema(self),
            Self::ListAccounts => list_accounts_schema(self),
        }
    }
}

fn list_folders_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::Forbidden;
    RedactionSchema::new(tool, &[("password", Forbidden), ("token", Forbidden)])
}

// SEARCH criteria policy: from/to/subject/body use `RedactString`,
// not `SaltedHash`. The Sprint 2 review brief recommended SaltedHash
// so incident responders could answer "did this LLM session search
// for the same string twice?" — but that adds within-process
// correlation surface for low-entropy queries (e.g. `{"from":"alice@x"}`)
// and offers little forensic value beyond what `arguments_hash_sha256`
// already provides at the record level. RedactString is the more
// conservative choice (less leakage, no correlation by design) and
// still records the byte length for unusual-payload detection.
// Decision recorded in #22.
//
// `search` and `search_advanced` take the identical argument set, so this
// single security-critical table is shared by both schemas — a one-sided
// edit is now impossible. A `const` cannot use the per-fn `use` shorthands,
// so the variants are spelled out in full.
const SEARCH_POLICIES: &[(&str, FieldPolicy)] = &[
    ("folder", FieldPolicy::Verbatim(VerbatimType::String)),
    ("limit", FieldPolicy::Verbatim(VerbatimType::U64)),
    ("offset", FieldPolicy::Verbatim(VerbatimType::U64)),
    ("larger", FieldPolicy::Verbatim(VerbatimType::U64)),
    ("smaller", FieldPolicy::Verbatim(VerbatimType::U64)),
    ("since", FieldPolicy::Verbatim(VerbatimType::DateString)),
    ("before", FieldPolicy::Verbatim(VerbatimType::DateString)),
    (
        "sent_since",
        FieldPolicy::Verbatim(VerbatimType::DateString),
    ),
    (
        "sent_before",
        FieldPolicy::Verbatim(VerbatimType::DateString),
    ),
    ("seen", FieldPolicy::Verbatim(VerbatimType::Bool)),
    ("answered", FieldPolicy::Verbatim(VerbatimType::Bool)),
    ("flagged", FieldPolicy::Verbatim(VerbatimType::Bool)),
    ("draft", FieldPolicy::Verbatim(VerbatimType::Bool)),
    ("has_attachment", FieldPolicy::Verbatim(VerbatimType::Bool)),
    ("from", FieldPolicy::RedactString),
    ("to", FieldPolicy::RedactString),
    ("cc", FieldPolicy::RedactString),
    ("bcc", FieldPolicy::RedactString),
    ("subject", FieldPolicy::RedactString),
    ("body", FieldPolicy::RedactString),
    ("text", FieldPolicy::RedactString),
    ("advanced_query", FieldPolicy::RedactString),
    ("headers", FieldPolicy::SaltedHash),
    ("password", FieldPolicy::Forbidden),
    ("token", FieldPolicy::Forbidden),
];

fn search_schema(tool: ToolName) -> RedactionSchema {
    RedactionSchema::new(tool, SEARCH_POLICIES)
}

fn search_advanced_schema(tool: ToolName) -> RedactionSchema {
    RedactionSchema::new(tool, SEARCH_POLICIES)
}

fn fetch_message_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{Bool, String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("include_html", Verbatim(Bool)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

/// Shared schema for tools whose v1 argument shape is just
/// `{folder, uid}` plus the credential tombstones: `list_attachments`,
/// `mark_read`, `mark_unread`.
fn folder_uid_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn download_attachment_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("part", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

/// Upper bound on the `uids` array copied verbatim into `tool_start` for
/// `export_messages`. Mirrors the handler's `MAX_EXPORT_UIDS` validation cap
/// (`crates/rimap-server/src/tools/retrieval/export_messages.rs`). The audit
/// envelope redacts arguments *before* the handler runs that validation, so
/// without this cap a rejected oversize request would still be cloned and
/// persisted verbatim. Over-cap arrays fall through to `RedactString`.
const EXPORT_UIDS_REDACT_CAP: usize = 100;

fn export_messages_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, RedactString, Verbatim};
    use VerbatimType::{Bool, String as VtString, U64, U64ArrayMax};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uids", Verbatim(U64ArrayMax(EXPORT_UIDS_REDACT_CAP))),
            ("expected_uidvalidity", Verbatim(U64)),
            ("max_total_bytes", Verbatim(U64)),
            ("allow_partial", Verbatim(Bool)),
            ("dest_dir", RedactString),
            ("filename", RedactString),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn flag_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("flag", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn move_message_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("destination", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn create_draft_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, RedactString, SaltedHash, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("in_reply_to_uid", Verbatim(U64)),
            ("to", SaltedHash),
            ("cc", SaltedHash),
            ("bcc", SaltedHash),
            ("subject", RedactString),
            ("body_text", RedactString),
            ("body_html", RedactString),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn send_email_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, RedactString, SaltedHash, Verbatim};
    use VerbatimType::{String as VtString, StringArray, U64};
    RedactionSchema::new(
        tool,
        &[
            ("to", SaltedHash),
            ("cc", SaltedHash),
            ("bcc", SaltedHash),
            ("subject", RedactString),
            ("body", RedactString),
            ("in_reply_to", Verbatim(VtString)),
            ("references", Verbatim(StringArray)),
            ("message_id", Verbatim(VtString)),
            ("smtp_response", RedactString),
            ("sent_copy_uid", Verbatim(U64)),
            ("folder", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn delete_message_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("message_id", Verbatim(VtString)),
            ("destination", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn expunge_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64, U64Array};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("expunged_count", Verbatim(U64)),
            ("expunged_uids", Verbatim(U64Array)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn create_folder_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::String as VtString;
    RedactionSchema::new(
        tool,
        &[
            ("name", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn rename_folder_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::String as VtString;
    RedactionSchema::new(
        tool,
        &[
            ("old_name", Verbatim(VtString)),
            ("new_name", Verbatim(VtString)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn delete_folder_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, Verbatim};
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[
            ("name", Verbatim(VtString)),
            ("message_count", Verbatim(U64)),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}

fn add_remove_label_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::Verbatim;
    use VerbatimType::{String as VtString, U64, U64Array};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uid", Verbatim(U64)),
            ("uids", Verbatim(U64Array)),
            ("label", Verbatim(VtString)),
        ],
    )
}

fn list_labels_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::Verbatim;
    use VerbatimType::{String as VtString, U64};
    RedactionSchema::new(
        tool,
        &[("folder", Verbatim(VtString)), ("uid", Verbatim(U64))],
    )
}

fn use_account_schema(tool: ToolName) -> RedactionSchema {
    // `account` stays `RedactString` — NOT a typed `Verbatim(String)` —
    // because the handler's bidi/zero-width pre-check runs AFTER
    // `tool_start` is emitted. The typed Verbatim policies elsewhere in
    // this module cover the "wrong JSON type smuggles a string into the
    // log" vector, but a well-typed `Value::String` carrying spoofed
    // bidi/zero-width codepoints would still pass the type check. The
    // handler returns `ERR_INVALID_INPUT` for spoofed input so
    // downstream correlation via `tool_end.code` is unaffected (#111).
    use FieldPolicy::RedactString;
    RedactionSchema::new(tool, &[("account", RedactString)])
}

fn list_accounts_schema(tool: ToolName) -> RedactionSchema {
    RedactionSchema::new(tool, &[])
}

/// Registry of per-tool redaction schemas. Built by iterating every
/// [`ToolName`] variant and calling [`ToolRedactionSchema::redaction_schema`],
/// so the list cannot desync from the enum.
#[must_use]
pub fn schemas() -> Vec<RedactionSchema> {
    ToolName::all()
        .into_iter()
        .map(ToolRedactionSchema::redaction_schema)
        .collect()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use serde_json::json;

    use rimap_core::tool::ToolName;

    use crate::redact::{
        FieldPolicy, RedactionSalt, RedactionSchema, Redactor, VerbatimType, hash_arguments,
    };

    fn schema() -> RedactionSchema {
        RedactionSchema::new(
            ToolName::CreateDraft,
            &[
                ("to", FieldPolicy::SaltedHash),
                ("subject", FieldPolicy::RedactString),
                ("body_text", FieldPolicy::RedactString),
                ("in_reply_to_uid", FieldPolicy::Verbatim(VerbatimType::U64)),
                ("password", FieldPolicy::Forbidden),
            ],
        )
    }

    fn salt() -> RedactionSalt {
        RedactionSalt::from_bytes([7_u8; 32])
    }

    #[test]
    fn verbatim_fields_pass_through() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"in_reply_to_uid": 12345}));
        assert_eq!(out["in_reply_to_uid"], json!(12345));
    }

    #[test]
    fn verbatim_u64_rejects_string_payload() {
        // A client mistypes (or maliciously pokes) a structural u64 field
        // with a string. The verbatim policy must NOT copy the raw string
        // into the audit log; the value falls through to RedactString.
        let canary = "u64-canary-leak";
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        for field in ["limit", "offset", "larger", "smaller"] {
            let input = json!({ field: canary });
            let out = r.apply(&input);
            assert_eq!(
                out[field],
                json!(format!("<redacted:{}>", canary.len())),
                "field {field} leaked a string payload verbatim",
            );
            let serialized = serde_json::to_string(&out).unwrap();
            assert!(
                !serialized.contains(canary),
                "canary appeared in redacted output for field {field}: {serialized}",
            );
        }
    }

    #[test]
    fn verbatim_bool_rejects_string_payload() {
        let canary = "bool-canary-leak";
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        for field in ["seen", "answered", "flagged", "draft", "has_attachment"] {
            let input = json!({ field: canary });
            let out = r.apply(&input);
            assert_eq!(
                out[field],
                json!(format!("<redacted:{}>", canary.len())),
                "field {field} leaked a string payload verbatim",
            );
            let serialized = serde_json::to_string(&out).unwrap();
            assert!(
                !serialized.contains(canary),
                "canary appeared in redacted output for field {field}: {serialized}",
            );
        }
    }

    #[test]
    fn verbatim_date_string_rejects_oversized_value() {
        // A 64-byte "date" string violates the 32-byte cap. Falls through
        // to RedactString and the original bytes never reach the log.
        let canary = "x".repeat(64);
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        for field in ["since", "before", "sent_since", "sent_before"] {
            let input = json!({ field: canary.clone() });
            let out = r.apply(&input);
            assert_eq!(
                out[field],
                json!(format!("<redacted:{}>", canary.len())),
                "oversized date field {field} leaked verbatim",
            );
        }
    }

    #[test]
    fn verbatim_date_string_accepts_iso_dates() {
        // Well-typed ISO date values stay verbatim — the 32-byte cap
        // accommodates `YYYY-MM-DDTHH:MM:SS+HH:MM` and similar shapes.
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let input = json!({
            "since": "2026-05-19",
            "before": "2026-05-19T12:00:00+00:00",
        });
        let out = r.apply(&input);
        assert_eq!(out["since"], json!("2026-05-19"));
        assert_eq!(out["before"], json!("2026-05-19T12:00:00+00:00"));
    }

    #[test]
    fn verbatim_u64_array_rejects_non_array() {
        let canary = "array-canary-leak";
        let schema = crate::redact::schemas()
            .into_iter()
            .find(|s| s.tool == ToolName::Expunge)
            .expect("expunge schema exists");
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let out = r.apply(&json!({ "expunged_uids": canary }));
        assert_eq!(
            out["expunged_uids"],
            json!(format!("<redacted:{}>", canary.len()))
        );
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(!serialized.contains(canary));
    }

    #[test]
    fn verbatim_u64_array_rejects_mixed_element_types() {
        let schema = crate::redact::schemas()
            .into_iter()
            .find(|s| s.tool == ToolName::Expunge)
            .expect("expunge schema exists");
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let canary = "mixed-canary-leak";
        let out = r.apply(&json!({ "expunged_uids": [1, canary, 3] }));
        // Whole array is wrong-typed → falls through to RedactString,
        // which for a non-string value emits `<redacted:?>`. The canary
        // must NOT appear anywhere in the redacted output.
        assert_eq!(out["expunged_uids"], json!("<redacted:?>"));
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains(canary),
            "canary leaked through array fall-through: {serialized}",
        );
    }

    #[test]
    fn verbatim_string_array_rejects_mixed_element_types() {
        let schema = crate::redact::schemas()
            .into_iter()
            .find(|s| s.tool == ToolName::SendEmail)
            .expect("send_email schema exists");
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let out = r.apply(&json!({ "references": ["<a@x>", 42, "<b@x>"] }));
        assert_eq!(out["references"], json!("<redacted:?>"));
    }

    #[test]
    fn verbatim_string_rejects_non_string() {
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let out = r.apply(&json!({"folder": 12345}));
        // Number is not a string → falls through, gets `<redacted:?>`.
        assert_eq!(out["folder"], json!("<redacted:?>"));
    }

    #[test]
    fn search_canary_never_leaks_through_any_verbatim_field() {
        // Codex adversarial-review regression: drive every Verbatim
        // field on the search schema with a TYPE-MISMATCHED poison
        // payload and verify the audit-record JSON never contains the
        // canary. Per-field class:
        //   * Verbatim(String)         → poison with an array (non-string).
        //   * Verbatim(U64)            → poison with a string.
        //   * Verbatim(Bool)           → poison with a string.
        //   * Verbatim(DateString)     → poison with a string > 32 bytes
        //                                AND poison with an array
        //                                (cap and type both exercised).
        // A well-typed but adversarial value (e.g. a short malformed
        // string in a DateString field) is out of scope at the redactor
        // layer; the plan keeps strict format parsing inside
        // `build_query`.
        let canary = "secret-leak-canary";
        let oversized = "x".repeat(64) + canary;
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);

        let string_field_poisons: &[(&str, serde_json::Value)] = &[("folder", json!([canary]))];
        let u64_field_poisons: &[(&str, serde_json::Value)] = &[
            ("limit", json!(canary)),
            ("offset", json!(canary)),
            ("larger", json!(canary)),
            ("smaller", json!(canary)),
        ];
        let bool_field_poisons: &[(&str, serde_json::Value)] = &[
            ("seen", json!(canary)),
            ("answered", json!(canary)),
            ("flagged", json!(canary)),
            ("draft", json!(canary)),
            ("has_attachment", json!(canary)),
        ];
        let date_field_poisons: &[(&str, serde_json::Value)] = &[
            ("since", json!(oversized)),
            ("before", json!([canary])),
            ("sent_since", json!(oversized)),
            ("sent_before", json!([canary])),
        ];
        let all_cases = string_field_poisons
            .iter()
            .chain(u64_field_poisons)
            .chain(bool_field_poisons)
            .chain(date_field_poisons);
        for (field, poison) in all_cases {
            let input = json!({ *field: poison.clone() });
            let out = r.apply(&input);
            let serialized = serde_json::to_string(&out).unwrap();
            assert!(
                !serialized.contains(canary),
                "canary leaked for field {field}: {serialized}",
            );
        }
    }

    #[test]
    fn strings_are_replaced_with_length_markers() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"subject": "hi there"}));
        assert_eq!(out["subject"], json!("<redacted:8>"));
    }

    #[test]
    fn non_string_redactable_fields_get_question_mark() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"subject": 42}));
        assert_eq!(out["subject"], json!("<redacted:?>"));
    }

    #[test]
    #[expect(
        clippy::many_single_char_names,
        reason = "s/r/a/b/c are idiomatic in compact test assertions"
    )]
    fn salted_hash_is_deterministic_for_same_process() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let a = r.apply(&json!({"to": "alice@example.test"}));
        let b = r.apply(&json!({"to": "alice@example.test"}));
        assert_eq!(a, b);
        let c = r.apply(&json!({"to": "bob@example.test"}));
        assert_ne!(a, c);
        let prefix = a["to"].as_str().unwrap();
        assert!(prefix.starts_with("salted:"));
    }

    #[test]
    fn salted_hash_differs_across_processes() {
        let s = schema();
        let salt_a = RedactionSalt::from_bytes([1_u8; 32]);
        let salt_b = RedactionSalt::from_bytes([2_u8; 32]);
        let ra = Redactor::new(&s, &salt_a);
        let rb = Redactor::new(&s, &salt_b);
        let a = ra.apply(&json!({"to": "alice@example.test"}));
        let b = rb.apply(&json!({"to": "alice@example.test"}));
        assert_ne!(a, b);
    }

    #[test]
    fn forbidden_fields_are_dropped() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"password": "hunter2", "in_reply_to_uid": 1}));
        assert!(!out.as_object().unwrap().contains_key("password"));
        assert_eq!(out["in_reply_to_uid"], json!(1));
    }

    #[test]
    fn unknown_fields_default_to_string_redaction() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"mystery": "value"}));
        assert_eq!(out["mystery"], json!("<redacted:5>"));
    }

    #[test]
    fn non_object_input_produces_placeholder() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!("bare string"));
        assert_eq!(out["_non_object"], json!("<redacted:?>"));
    }

    #[test]
    fn hash_arguments_is_stable_and_hex_encoded() {
        let a = hash_arguments(&json!({"uid": 1, "folder": "INBOX"}));
        let b = hash_arguments(&json!({"uid": 1, "folder": "INBOX"}));
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_salt_is_not_all_zeros() {
        let salt = RedactionSalt::new_random();
        assert!(salt.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn every_v1_tool_has_a_schema() {
        let table = crate::redact::schemas();
        for tool in ToolName::all() {
            assert!(
                table.iter().any(|s| s.tool == tool),
                "missing redaction schema for {}",
                tool.as_str(),
            );
        }
    }

    #[test]
    fn schemas_do_not_have_duplicate_tools() {
        let table = crate::redact::schemas();
        let mut seen = std::collections::BTreeSet::new();
        for schema in table {
            assert!(
                seen.insert(schema.tool),
                "duplicate redaction schema for {}",
                schema.tool.as_str(),
            );
        }
    }

    #[test]
    fn create_draft_schema_hashes_recipients_and_redacts_body() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::CreateDraft)
            .expect("create_draft schema exists");
        assert_eq!(
            schema.policies.get("to").copied(),
            Some(FieldPolicy::SaltedHash),
        );
        assert_eq!(
            schema.policies.get("body_text").copied(),
            Some(FieldPolicy::RedactString),
        );
        assert_eq!(
            schema.policies.get("subject").copied(),
            Some(FieldPolicy::RedactString),
        );
    }

    #[test]
    fn search_schema_keeps_structural_fields_verbatim() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::Search)
            .expect("search schema exists");
        assert_eq!(
            schema.policies.get("folder").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
        );
        assert_eq!(
            schema.policies.get("body").copied(),
            Some(FieldPolicy::RedactString),
        );
    }

    #[test]
    fn send_email_schema_matches_spec_field_names() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::SendEmail)
            .expect("send_email schema exists");
        assert_eq!(
            schema.policies.get("in_reply_to").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
            "in_reply_to should be Verbatim(String) per spec",
        );
        assert_eq!(
            schema.policies.get("references").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::StringArray)),
            "references should be Verbatim(StringArray) per spec",
        );
        assert_eq!(
            schema.policies.get("message_id").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
            "message_id result field should be Verbatim(String)",
        );
        assert_eq!(
            schema.policies.get("smtp_response").copied(),
            Some(FieldPolicy::RedactString),
            "smtp_response should be RedactString",
        );
        assert_eq!(
            schema.policies.get("sent_copy_uid").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::U64)),
            "sent_copy_uid should be Verbatim(U64)",
        );
        assert_eq!(
            schema.policies.get("folder").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
            "folder (Sent) should be Verbatim(String)",
        );
        assert!(
            !schema.policies.contains_key("in_reply_to_uid"),
            "in_reply_to_uid is not a spec field",
        );
        assert!(
            !schema.policies.contains_key("in_reply_to_folder"),
            "in_reply_to_folder is not a spec field",
        );
    }

    #[test]
    fn use_account_schema_redacts_account_field() {
        // MCP-INJ-03 / MAIL-AUD-02: `account` must be RedactString so
        // spoofed bidi/zero-width codepoints cannot reach the JSONL
        // audit log before the handler's pre-check runs.
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::UseAccount)
            .expect("use_account schema exists");
        assert_eq!(
            schema.policies.get("account").copied(),
            Some(FieldPolicy::RedactString),
        );
    }

    #[test]
    fn delete_message_schema_has_result_fields() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::DeleteMessage)
            .expect("delete_message schema exists");
        assert_eq!(
            schema.policies.get("message_id").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
        );
        assert_eq!(
            schema.policies.get("destination").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::String)),
        );
    }

    #[test]
    fn expunge_schema_has_result_fields() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::Expunge)
            .expect("expunge schema exists");
        assert_eq!(
            schema.policies.get("expunged_count").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::U64)),
        );
        assert_eq!(
            schema.policies.get("expunged_uids").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::U64Array)),
        );
    }

    #[test]
    fn delete_folder_schema_has_result_fields() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == ToolName::DeleteFolder)
            .expect("delete_folder schema exists");
        assert_eq!(
            schema.policies.get("message_count").copied(),
            Some(FieldPolicy::Verbatim(VerbatimType::U64)),
        );
    }

    fn search_schema_for_tool(tool: ToolName) -> RedactionSchema {
        let table = crate::redact::schemas();
        table
            .into_iter()
            .find(|s| s.tool == tool)
            .expect("schema exists for tool")
    }

    #[test]
    fn search_schema_redacts_all_content_fields() {
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let out = r.apply(&json!({
            "from": "alice@example.test",
            "to": "bob@example.test",
            "cc": "carol@example.test",
            "bcc": "dave@example.test",
            "subject": "hello world",
            "body": "needle",
            "text": "any-field-needle",
            "advanced_query": "FROM alice",
        }));
        assert_eq!(out["from"], json!("<redacted:18>"));
        assert_eq!(out["to"], json!("<redacted:16>"));
        assert_eq!(out["cc"], json!("<redacted:18>"));
        assert_eq!(out["bcc"], json!("<redacted:17>"));
        assert_eq!(out["subject"], json!("<redacted:11>"));
        assert_eq!(out["body"], json!("<redacted:6>"));
        assert_eq!(out["text"], json!("<redacted:16>"));
        assert_eq!(out["advanced_query"], json!("<redacted:10>"));
    }

    #[test]
    fn search_schema_preserves_structural_fields() {
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let input = json!({
            "folder": "INBOX",
            "limit": 50,
            "offset": 10,
            "larger": 1000_u64,
            "smaller": 5000_u64,
            "since": "2026-01-01",
            "before": "2026-12-31",
            "sent_since": "2026-02-01",
            "sent_before": "2026-11-30",
            "seen": true,
            "answered": false,
            "flagged": true,
            "draft": false,
            "has_attachment": true,
        });
        let out = r.apply(&input);
        // Every structural field round-trips with original JSON type/value.
        assert_eq!(out, input);
        // Spot-check that types are preserved (not stringified).
        assert!(out["limit"].is_u64());
        assert!(out["larger"].is_u64());
        assert!(out["seen"].is_boolean());
        assert!(out["folder"].is_string());
        assert!(out["since"].is_string());
    }

    #[test]
    fn search_schema_hashes_headers_array() {
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let headers_a = json!({
            "headers": [
                {"name": "X-Custom", "value": "alpha"},
                {"name": "List-Id", "value": "<list@example.test>"},
            ],
        });
        let headers_b = json!({
            "headers": [
                {"name": "X-Custom", "value": "beta"},
            ],
        });
        let a1 = r.apply(&headers_a);
        let a2 = r.apply(&headers_a);
        let b = r.apply(&headers_b);
        let hash_a = a1["headers"].as_str().expect("salted hash is a string");
        assert!(hash_a.starts_with("salted:"));
        assert_eq!(hash_a.len(), "salted:".len() + 16);
        assert_eq!(a1["headers"], a2["headers"]);
        assert_ne!(a1["headers"], b["headers"]);
    }

    #[test]
    fn search_schema_drops_password_and_token() {
        let schema = search_schema_for_tool(ToolName::Search);
        let salt = salt();
        let r = Redactor::new(&schema, &salt);
        let out = r.apply(&json!({
            "folder": "INBOX",
            "password": "hunter2",
            "token": "abcdef",
        }));
        let map = out.as_object().expect("object output");
        assert!(!map.contains_key("password"));
        assert!(!map.contains_key("token"));
        assert_eq!(out["folder"], json!("INBOX"));
    }

    #[test]
    fn search_advanced_schema_matches_search_policy() {
        let search = search_schema_for_tool(ToolName::Search);
        let advanced = search_schema_for_tool(ToolName::SearchAdvanced);
        let salt = salt();
        let sample = json!({
            "folder": "INBOX",
            "limit": 25,
            "answered": true,
            "larger": 1024_u64,
            "sent_since": "2026-03-01",
            "from": "alice@example.test",
            "cc": "carol@example.test",
            "bcc": "dave@example.test",
            "body": "needle",
            "text": "scan-needle",
            "advanced_query": "ALL",
            "headers": [{"name": "X-Custom", "value": "x"}],
            "password": "hunter2",
            "token": "abcdef",
        });
        let from_search = Redactor::new(&search, &salt).apply(&sample);
        let from_advanced = Redactor::new(&advanced, &salt).apply(&sample);
        assert_eq!(from_search, from_advanced);
    }

    #[test]
    fn export_messages_schema_redacts_paths_keeps_identifiers() {
        let salt = salt();
        let schema = crate::redact::schemas()
            .into_iter()
            .find(|s| s.tool == ToolName::ExportMessages)
            .expect("export_messages schema exists");
        let args = json!({
            "folder": "INBOX",
            "uids": [101_u64, 102_u64],
            "expected_uidvalidity": 12345_u64,
            "dest_dir": "/home/user/secret-dir",
            "filename": "private-series",
            "password": "hunter2",
            "token": "s3cr3t-token"
        });
        let out = Redactor::new(&schema, &salt).apply(&args);
        // Structural fields are preserved verbatim.
        assert_eq!(out["folder"], json!("INBOX"));
        assert_eq!(out["expected_uidvalidity"], json!(12345_u64));
        // Requested UID set is recorded verbatim (recoverable for audit).
        assert_eq!(out["uids"], json!([101_u64, 102_u64]));
        // dest_dir / filename must not appear verbatim.
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(!serialized.contains("/home/user/secret-dir"));
        assert!(!serialized.contains("private-series"));
        // password / token are Forbidden — keys must be absent.
        assert!(!serialized.contains("hunter2"));
        assert!(!out.as_object().unwrap().contains_key("password"));
        assert!(!serialized.contains("s3cr3t-token"));
        assert!(!out.as_object().unwrap().contains_key("token"));
    }

    #[test]
    fn export_messages_schema_caps_oversize_uid_array() {
        // Codex adversarial-review regression: the audit envelope redacts
        // arguments BEFORE the handler's 100-UID validation runs. An array
        // over the cap must NOT be copied verbatim into `tool_start` — it
        // falls through to RedactString so a rejected oversize request cannot
        // bloat the audit log. A <=cap array still round-trips verbatim.
        let salt = salt();
        let schema = crate::redact::schemas()
            .into_iter()
            .find(|s| s.tool == ToolName::ExportMessages)
            .expect("export_messages schema exists");
        let r = Redactor::new(&schema, &salt);

        // 101 numeric UIDs — one past the cap. A distinctive sentinel value
        // lets us prove the array bytes never reach the redacted output.
        let sentinel: u64 = 999_888_777;
        let mut oversize: Vec<serde_json::Value> = (1..=100_u64).map(|n| json!(n)).collect();
        oversize.push(json!(sentinel));
        let out = r.apply(&json!({ "uids": serde_json::Value::Array(oversize) }));
        assert_eq!(
            out["uids"],
            json!("<redacted:?>"),
            "oversize uid array must fall through to RedactString",
        );
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains(&sentinel.to_string()),
            "oversize uid array leaked verbatim into audit output: {serialized}",
        );

        // Exactly at the cap (100) still passes through verbatim.
        let at_cap: Vec<serde_json::Value> = (1..=100_u64).map(|n| json!(n)).collect();
        let out = r.apply(&json!({ "uids": serde_json::Value::Array(at_cap.clone()) }));
        assert_eq!(out["uids"], serde_json::Value::Array(at_cap));
    }
}

#[cfg(test)]
mod redact_record_tests {
    use rimap_core::{Posture, tool::ToolName};
    use serde_json::json;
    use time::macros::datetime;

    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{AuditRecord, Payload, PostureEffective, ToolStart};
    use crate::redact::{RedactionSalt, redact};

    fn salt() -> RedactionSalt {
        RedactionSalt::from_bytes([0x42_u8; 32])
    }

    fn tool_start_record(args_redacted: serde_json::Value) -> AuditRecord {
        AuditRecord {
            seq: Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-05-05 12:00:00.000 UTC)),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolStart(ToolStart {
                account: Some("acct".into()),
                tool: ToolName::Search,
                posture_effective: PostureEffective::Account(Posture::Readonly),
                arguments_redacted: args_redacted,
                arguments_hash_sha256: "0".repeat(64),
            }),
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn redact_re_redacts_tool_start_arguments() {
        let secret = "this-is-a-secret";
        let rec = tool_start_record(json!({
            "subject": secret,
        }));
        let s = salt();
        let redacted = redact(&rec, &s);
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(
            !serialized.contains(secret),
            "post-redaction serialized form leaked secret: {serialized}"
        );
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn redact_passes_through_non_tool_start_records() {
        use crate::record::{ProcessEnd, ProcessEndReason};
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::from_offset(datetime!(2026-05-05 12:00:00.000 UTC)),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };
        let redacted = redact(&rec, &salt());
        assert_eq!(rec.seq.get(), redacted.seq.get());
        assert_eq!(rec.process_id.to_string(), redacted.process_id.to_string());
        assert_eq!(
            serde_json::to_string(&rec).unwrap(),
            serde_json::to_string(&redacted).unwrap(),
        );
    }
}
