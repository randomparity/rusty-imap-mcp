//! Public types for `rimap-imap`. These are the IMAP-shaped data the read
//! ops return — RFC-5322 / MIME parsing belongs to `rimap-content` (Sprint 4).

use std::num::NonZeroU32;

/// IMAP UID. Always non-zero per RFC 3501 §2.3.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uid(NonZeroU32);

impl Uid {
    /// Construct from a raw integer. Returns `None` for `0`.
    ///
    /// Crate-private: new callers should take [`NonZeroU32`] at the
    /// deserialize seam (schema-level non-zero guarantee) and use
    /// [`Uid::from`] to convert. This fallible entry point remains
    /// because the IMAP wire format delivers UIDs as `u32` and the
    /// internal op layer has to convert those responses.
    #[must_use]
    pub(crate) fn new(n: u32) -> Option<Self> {
        NonZeroU32::new(n).map(Self)
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }

    /// Translate a schema-level [`UidSelector`] into domain UIDs.
    ///
    /// The schema-to-domain translation lives once here, at the
    /// transport seam, so batch handlers cannot re-derive it.
    #[must_use]
    pub fn uids_from_selector(selector: rimap_core::uid_selector::UidSelector) -> Vec<Self> {
        selector.into_uids().into_iter().map(Self::from).collect()
    }
}

impl From<NonZeroU32> for Uid {
    fn from(value: NonZeroU32) -> Self {
        Self(value)
    }
}


/// Opaque RFC 5322 `Message-ID` header value, as raw bytes (no decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(Vec<u8>);

impl MessageId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Underlying raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// IMAP `LIST` response entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Mailbox path reported by the server (Modified UTF-7, not decoded).
    pub name: String,
    /// Attributes reported on this mailbox.
    pub attributes: Vec<FolderAttribute>,
    /// Hierarchy delimiter (`/` for most servers; `None` for namespaces
    /// without a delimiter).
    pub delimiter: Option<char>,
    /// RFC 6154 special-use marker, if present.
    pub special_use: Option<crate::special_use::SpecialUse>,
}

impl Folder {
    /// Whether this mailbox can be `SELECT`ed. Derived from the attribute
    /// list — `\Noselect` and `\NonExistent` are non-selectable.
    #[must_use]
    pub fn selectable(&self) -> bool {
        !self
            .attributes
            .iter()
            .any(|a| matches!(a, FolderAttribute::Noselect | FolderAttribute::NonExistent))
    }
}

/// Bitflags-style selection for `STATUS` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "bitflags-style selector; each field is independent"
)]
pub struct StatusItems {
    /// Include `MESSAGES` (total count).
    pub messages: bool,
    /// Include `RECENT`.
    pub recent: bool,
    /// Include `UIDNEXT`.
    pub uid_next: bool,
    /// Include `UIDVALIDITY`.
    pub uid_validity: bool,
    /// Include `UNSEEN`.
    pub unseen: bool,
}

impl StatusItems {
    /// All items selected.
    #[must_use]
    pub fn all() -> Self {
        Self {
            messages: true,
            recent: true,
            uid_next: true,
            uid_validity: true,
            unseen: true,
        }
    }
}

/// Result of a `STATUS` command. Fields are populated only when requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderStatus {
    /// `MESSAGES`.
    pub messages: Option<u32>,
    /// `RECENT`.
    pub recent: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `UIDVALIDITY`.
    pub uid_validity: Option<u32>,
    /// `UNSEEN`.
    pub unseen: Option<u32>,
}

/// Result of a `SELECT` or `EXAMINE` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFolder {
    /// Mailbox name.
    pub name: String,
    /// `EXISTS` count.
    pub exists: u32,
    /// `RECENT` count.
    pub recent: u32,
    /// `UIDVALIDITY`, or `None` if the server did not include it in the
    /// `SELECT`/`EXAMINE` response (non-conformant but observed in the wild).
    pub uid_validity: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `READ-ONLY` if `EXAMINE`, otherwise `READ-WRITE`.
    pub read_only: bool,
}

/// IMAP message flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// `\Seen`.
    Seen,
    /// `\Answered`.
    Answered,
    /// `\Flagged`.
    Flagged,
    /// `\Deleted`.
    Deleted,
    /// `\Draft`.
    Draft,
    /// `\Recent` (RFC 3501 only; deprecated in RFC 9051).
    Recent,
    /// Server-specific keyword (anything not in the canonical list above).
    Keyword(String),
}

/// Whether to add or remove flags in a STORE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction {
    /// `+FLAGS` — add the given flags.
    Add,
    /// `-FLAGS` — remove the given flags.
    Remove,
}

/// Result of moving a single message. `new_uid` is `None` when the
/// server lacks UIDPLUS or when using the COPY+DELETE fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveResult {
    /// UID in the source folder (before the move).
    pub old_uid: Uid,
    /// UID in the destination folder (after the move). `None` if the
    /// server does not report it (no UIDPLUS, or COPY+DELETE fallback).
    pub new_uid: Option<Uid>,
    /// Why `new_uid` is `None`, if applicable.
    ///
    /// Currently always `Some("async_imap_copyuid_unavailable")` when
    /// `new_uid` is `None` — async-imap 0.11.2 does not expose
    /// `ResponseCode::CopyUid`, so the UIDPLUS COPYUID response code is
    /// never captured. A follow-up issue (#96) tracks wiring COPYUID
    /// capture once upstream exposes it.
    pub used_fallback_reason: Option<String>,
}

/// Result of appending a message to a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    /// UID assigned by the server. `None` if the server lacks UIDPLUS.
    /// async-imap 0.11's `append()` does not expose the APPENDUID
    /// response code, so this is always `None` for now.
    pub uid: Option<Uid>,
}

/// IMAP `ENVELOPE` response. Header values stay raw bytes — RFC 2047 decoding
/// is Sprint 4's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `Date` header, raw.
    pub date: Option<Vec<u8>>,
    /// `Subject` header, raw.
    pub subject_raw: Option<Vec<u8>>,
    /// `From` addresses, raw.
    pub from: Vec<Address>,
    /// `Sender` addresses, raw.
    pub sender: Vec<Address>,
    /// `Reply-To` addresses, raw.
    pub reply_to: Vec<Address>,
    /// `To` addresses, raw.
    pub to: Vec<Address>,
    /// `Cc` addresses, raw.
    pub cc: Vec<Address>,
    /// `Bcc` addresses, raw.
    pub bcc: Vec<Address>,
    /// `In-Reply-To` header, raw.
    pub in_reply_to: Option<Vec<u8>>,
    /// `Message-ID` header, raw.
    pub message_id: Option<MessageId>,
}

/// IMAP envelope address. Raw bytes; no charset decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Personal name (`name`), raw.
    pub name: Option<Vec<u8>>,
    /// Source route (`adl`), raw.
    pub adl: Option<Vec<u8>>,
    /// Mailbox local part, raw.
    pub mailbox: Option<Vec<u8>>,
    /// Host part, raw.
    pub host: Option<Vec<u8>>,
}

/// IMAP `BODYSTRUCTURE` recursive type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStructure {
    /// A single-part body.
    Single {
        /// MIME type (`text`, `image`, …).
        mime_type: String,
        /// MIME subtype (`plain`, `jpeg`, …).
        mime_subtype: String,
        /// MIME content-type parameters.
        params: Vec<(String, String)>,
        /// Transfer encoding (`7bit`, `base64`, …).
        encoding: String,
        /// Octet count.
        size: u32,
    },
    /// A `multipart/*` body.
    Multipart {
        /// Multipart subtype (`mixed`, `alternative`, …).
        subtype: String,
        /// Constituent parts.
        parts: Vec<BodyStructure>,
    },
    /// A `message/rfc822` (or similar `message/*`) body containing a fully
    /// nested embedded message. The nested `body` is the BODYSTRUCTURE of
    /// the embedded message; walk it like any other tree.
    Message {
        /// MIME subtype (typically `"rfc822"`).
        mime_subtype: String,
        /// The embedded message's body structure.
        body: Box<BodyStructure>,
    },
}

/// SEARCH query — either a structured builder or a raw passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "StructuredQuery is the dominant variant; boxing it would \
              require updating every call site for no runtime benefit"
)]
pub enum SearchQuery {
    /// Typed query built via `StructuredQuery`. This is the path all
    /// untrusted input (agent prompts, MCP tool arguments, HTTP requests)
    /// MUST take — `StructuredQuery`'s field builders apply the necessary
    /// RFC 3501 quoting and reject CR/LF/NUL bytes.
    Structured(StructuredQuery),
    /// Raw IMAP SEARCH key string, forwarded verbatim to `UID SEARCH`
    /// without further validation.
    ///
    /// # Safety boundary
    ///
    /// Callers are entirely responsible for RFC 3501 compliance. This
    /// variant bypasses async-imap's `validate_str` — embedded CR, LF, or
    /// NUL bytes will terminate the tagged command line and inject a
    /// follow-on command.
    ///
    /// Untrusted input (anything reachable from an agent prompt or an
    /// external API) MUST NOT be routed through this variant. Use
    /// [`SearchQuery::Structured`] instead. This escape hatch exists for
    /// integration tests and internal tooling where the caller controls
    /// the key.
    Raw(String),
}

/// A single `HEADER name value` SEARCH clause built into a
/// [`StructuredQuery`]. The `name` must satisfy RFC 5322 field-name
/// syntax (printable ASCII, no `:`); the `value` is quoted on emission
/// and CR/LF/NUL bytes are rejected. Both are enforced when the
/// query is compiled to an IMAP search key — see
/// `crates/rimap-imap/src/ops/search.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSearch {
    /// RFC 5322 field name (e.g. `"List-Id"`, `"X-Spam-Score"`).
    pub name: String,
    /// Substring to match within the header value.
    pub value: String,
}

/// Structured SEARCH builder. Empty builder = `ALL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredQuery {
    /// Match `FROM` substring.
    pub from: Option<String>,
    /// Match `TO` substring.
    pub to: Option<String>,
    /// Match `SUBJECT` substring.
    pub subject: Option<String>,
    /// `SINCE` (inclusive lower bound by INTERNALDATE).
    pub since: Option<::time::Date>,
    /// `BEFORE` (exclusive upper bound by INTERNALDATE).
    pub before: Option<::time::Date>,
    /// Restrict to messages with `\Seen`.
    pub seen: Option<bool>,
    /// Restrict to messages with attachments (`HAS_ATTACHMENT` heuristic;
    /// emitted as `BODY "Content-Disposition: attachment"`).
    pub has_attachment: bool,
    /// Match `CC` header substring.
    pub cc: Option<String>,
    /// Match `BCC` header substring. Reads message content, so it is
    /// gated to `SearchAdvanced` at the MCP dispatch seam.
    pub bcc: Option<String>,
    /// Match `BODY` substring (body parts only). Reads message content,
    /// so it is gated to `SearchAdvanced` at the MCP dispatch seam.
    pub body: Option<String>,
    /// Match `TEXT` substring (headers OR body). Reads message content,
    /// so it is gated to `SearchAdvanced` at the MCP dispatch seam.
    pub text: Option<String>,
    /// One or more `HEADER name value` clauses. When non-empty, reads
    /// message content, so it is gated to `SearchAdvanced` at the MCP
    /// dispatch seam.
    pub headers: Option<Vec<HeaderSearch>>,
    /// `LARGER N` (messages strictly greater than N octets).
    pub larger: Option<u64>,
    /// `SMALLER N` (messages strictly less than N octets).
    pub smaller: Option<u64>,
    /// `SENTSINCE` (inclusive lower bound by `Date:` header, not
    /// INTERNALDATE — distinct from [`Self::since`]).
    pub sent_since: Option<::time::Date>,
    /// `SENTBEFORE` (exclusive upper bound by `Date:` header).
    pub sent_before: Option<::time::Date>,
    /// Restrict to messages with `\Answered`.
    pub answered: Option<bool>,
    /// Restrict to messages with `\Flagged`.
    pub flagged: Option<bool>,
    /// Restrict to messages with `\Draft`.
    pub draft: Option<bool>,
}

/// FETCH item selection. `ENVELOPE`, `BODYSTRUCTURE`, `UID`, `FLAGS`, `SIZE`.
/// `BODY[]` has its own dedicated method (`Connection::fetch_body`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "bitflags-style selector; each field is independent"
)]
pub struct FetchSpec {
    /// Include `ENVELOPE`.
    pub envelope: bool,
    /// Include `BODYSTRUCTURE`.
    pub bodystructure: bool,
    /// Include `UID`.
    pub uid: bool,
    /// Include `FLAGS`.
    pub flags: bool,
    /// Include `RFC822.SIZE`.
    pub size: bool,
}

/// One message returned by a `fetch` call. Only the fields requested in the
/// `FetchSpec` are populated; the rest are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Message UID (always present — IMAP servers always return UID for UID FETCH).
    pub uid: Uid,
    /// `ENVELOPE` if requested.
    pub envelope: Option<Envelope>,
    /// `BODYSTRUCTURE` if requested.
    pub bodystructure: Option<BodyStructure>,
    /// `FLAGS` if requested.
    pub flags: Option<Vec<Flag>>,
    /// `RFC822.SIZE` if requested.
    pub size: Option<u32>,
}

/// RFC 3501 / RFC 5258 mailbox name attribute reported by LIST.
///
/// Maps `async_imap::types::NameAttribute` to a stable, match-friendly
/// representation. Extension attributes that the codebase does not branch
/// on land in `Other(String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderAttribute {
    /// `\Noselect` — mailbox cannot be selected.
    Noselect,
    /// `\NoInferiors` — no children may be created under this mailbox.
    NoInferiors,
    /// `\Marked` — server considers this mailbox interesting.
    Marked,
    /// `\Unmarked` — server does not consider this mailbox interesting.
    Unmarked,
    /// `\HasChildren` (RFC 5258).
    HasChildren,
    /// `\HasNoChildren` (RFC 5258).
    HasNoChildren,
    /// `\NonExistent` (RFC 5258) — mailbox name is known but does not exist.
    NonExistent,
    /// Any other attribute the server reported (extension / unknown).
    Other(String),
}

impl FolderAttribute {
    /// Translate an `async_imap::types::NameAttribute` to a typed variant.
    ///
    /// `HasChildren` / `HasNoChildren` / `NonExistent` arrive through
    /// `NameAttribute::Extension(Cow<'_, str>)` — decoded here by matching
    /// the attribute string. RFC 6154 special-use variants (`Sent`,
    /// `Trash`, etc.) are first-class in `NameAttribute` but the codebase
    /// routes them through `Folder.special_use`; here they become
    /// `Other(spelling)` so the attribute list preserves its shape without
    /// duplicating information.
    #[must_use]
    pub fn from_name_attribute(attr: &async_imap::types::NameAttribute<'_>) -> Self {
        use async_imap::types::NameAttribute;
        match attr {
            NameAttribute::NoSelect => Self::Noselect,
            NameAttribute::NoInferiors => Self::NoInferiors,
            NameAttribute::Marked => Self::Marked,
            NameAttribute::Unmarked => Self::Unmarked,
            NameAttribute::All => Self::Other("\\All".to_string()),
            NameAttribute::Archive => Self::Other("\\Archive".to_string()),
            NameAttribute::Drafts => Self::Other("\\Drafts".to_string()),
            NameAttribute::Flagged => Self::Other("\\Flagged".to_string()),
            NameAttribute::Junk => Self::Other("\\Junk".to_string()),
            NameAttribute::Sent => Self::Other("\\Sent".to_string()),
            NameAttribute::Trash => Self::Other("\\Trash".to_string()),
            NameAttribute::Extension(s) => match s.as_ref() {
                "\\HasChildren" => Self::HasChildren,
                "\\HasNoChildren" => Self::HasNoChildren,
                "\\NonExistent" => Self::NonExistent,
                _ => Self::Other(s.to_string()),
            },
            // NameAttribute is #[non_exhaustive] — fall through to preserve
            // future-added variants as `Other(debug-repr)`.
            other => Self::Other(format!("{other:?}")),
        }
    }

    /// Stable wire-safe string form for serialization (matches RFC 3501
    /// attribute spelling, including the leading backslash). Used by
    /// `rimap-server`'s `FolderEntry.flags: Vec<String>` boundary.
    #[must_use]
    pub fn as_wire_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Noselect => "\\Noselect".into(),
            Self::NoInferiors => "\\NoInferiors".into(),
            Self::Marked => "\\Marked".into(),
            Self::Unmarked => "\\Unmarked".into(),
            Self::HasChildren => "\\HasChildren".into(),
            Self::HasNoChildren => "\\HasNoChildren".into(),
            Self::NonExistent => "\\NonExistent".into(),
            Self::Other(s) => s.as_str().into(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::FolderAttribute;

    #[test]
    fn folder_attribute_round_trips_rfc_3501_variants() {
        use async_imap::types::NameAttribute;

        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::NoSelect),
            FolderAttribute::Noselect,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::NoInferiors),
            FolderAttribute::NoInferiors,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Marked),
            FolderAttribute::Marked,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Unmarked),
            FolderAttribute::Unmarked,
        );
    }

    #[test]
    fn folder_attribute_extension_decodes_children_and_nonexistent() {
        use async_imap::types::NameAttribute;
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Extension("\\HasChildren".into()),),
            FolderAttribute::HasChildren,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Extension(
                "\\HasNoChildren".into()
            ),),
            FolderAttribute::HasNoChildren,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Extension("\\NonExistent".into()),),
            FolderAttribute::NonExistent,
        );
    }

    #[test]
    fn folder_attribute_unknown_extension_becomes_other() {
        use async_imap::types::NameAttribute;
        let attr =
            FolderAttribute::from_name_attribute(&NameAttribute::Extension("\\Unknown".into()));
        assert_eq!(attr, FolderAttribute::Other("\\Unknown".to_string()));
    }

    #[test]
    fn folder_attribute_special_use_variants_become_other_preserving_spelling() {
        // RFC 6154 special-use variants are first-class in NameAttribute,
        // but the codebase routes them through Folder.special_use — so the
        // attribute list carries them as Other(spelling) to preserve shape
        // without duplicating information.
        use async_imap::types::NameAttribute;
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Sent),
            FolderAttribute::Other("\\Sent".to_string()),
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Trash),
            FolderAttribute::Other("\\Trash".to_string()),
        );
    }

    #[test]
    fn folder_selectable_when_no_noselect() {
        let f = super::Folder {
            name: "INBOX".to_string(),
            attributes: vec![super::FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(f.selectable());
    }

    #[test]
    fn folder_not_selectable_with_noselect() {
        let f = super::Folder {
            name: "[Gmail]".to_string(),
            attributes: vec![
                super::FolderAttribute::Noselect,
                super::FolderAttribute::HasChildren,
            ],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(!f.selectable());
    }

    #[test]
    fn folder_not_selectable_with_nonexistent() {
        let f = super::Folder {
            name: "orphan".to_string(),
            attributes: vec![super::FolderAttribute::NonExistent],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(!f.selectable());
    }

    #[test]
    fn folder_selectable_empty_attributes() {
        let f = super::Folder {
            name: "plain".to_string(),
            attributes: vec![],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(f.selectable());
    }

    /// Test-only UID constructor shared by the crate's unit tests. Panics
    /// on `0`; callers pass pre-validated non-zero literals.
    #[expect(clippy::expect_used, reason = "tests")]
    pub(crate) fn uid(n: u32) -> super::Uid {
        super::Uid::new(n).expect("non-zero")
    }

    #[test]
    fn uid_helper_constructs_non_zero() {
        // Regression: the shared test helper (#93) must accept any non-zero
        // u32 and round-trip through Uid::get.
        assert_eq!(uid(1).get(), 1);
        assert_eq!(uid(u32::MAX).get(), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn uid_helper_panics_on_zero() {
        // Regression: the shared helper preserves the NonZeroU32 invariant
        // by panicking on 0 (callers are test code).
        let _ = uid(0);
    }
}
