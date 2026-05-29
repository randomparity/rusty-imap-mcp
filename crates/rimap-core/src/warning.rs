//! Shared pipeline warning codes and their severity classification.
//!
//! `WarningCode` is consumed by `rimap-content` (which emits the codes
//! during parsing) and by `rimap-audit` (which records them in
//! `ResultSummary.security_warnings_emitted`). It lives in `rimap-core`
//! so both crates can reference the typed enum without a
//! `rimap-content -> rimap-audit` dependency inversion.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Classification of pipeline warnings. New variants will be added as
/// new detectors land — the enum is `#[non_exhaustive]` so matches
/// outside this crate must include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// Zero-width codepoints were present in input text and stripped.
    UnicodeZeroWidthStripped,
    /// Bidi-override codepoints were present in input text and stripped.
    UnicodeBidiOverrideStripped,
    /// C0 or C1 control codepoints (other than tab and newline) were stripped.
    UnicodeC0C1Stripped,
    /// A header containing a raw CRLF inside an RFC 2047 encoded-word
    /// was dropped before parsing continued.
    ParseHeaderSmugglingBlocked,
    /// An attachment's declared content type did not match the magic
    /// bytes of its body. Detail format: `declared=<type>,sniffed=<type>`.
    ParseMimeTypeMismatch,
    /// BODYSTRUCTURE-declared MIME type disagreed with the type reported
    /// by the MIME parser for the same part. Distinct from
    /// `ParseMimeTypeMismatch` (which compares declared type against
    /// magic-byte sniffing). Detail format:
    /// `bodystructure=<type>,parser=<type>`.
    ParseBodystructureTypeMismatch,
    /// An attachment matched multiple magic-byte signatures (polyglot
    /// file). This frequently indicates a deliberate attempt to bypass
    /// content-type sniffing by encoding one file type as another.
    ParseAttachmentPolyglot,
    /// The message body exceeded `MAX_BODY_BYTES` and was truncated.
    ParseBodyTruncated,
    /// MIME nesting depth exceeded `MAX_MIME_DEPTH`. Emitted alongside
    /// a terminal `ContentError::LimitExceeded`.
    ParseMimeDepthExceeded,
    /// MIME part count exceeded `MAX_MIME_PARTS`. Emitted alongside a
    /// terminal `ContentError::LimitExceeded`.
    ParseMimePartCountExceeded,
    /// Header count exceeded `MAX_HEADER_COUNT`. Emitted alongside a
    /// terminal `ContentError::LimitExceeded`.
    ParseHeaderCountExceeded,
    /// An attachment filename contained path separators, parent
    /// references, reserved Windows names, or other unsafe characters
    /// and was rewritten to a safe form.
    ParseAttachmentFilenameRewritten,
    /// HTML content contained hidden elements (e.g. `display:none`,
    /// `visibility:hidden`, `opacity:0`, off-screen positioning,
    /// zero font size, or background-color-matching text). Hidden
    /// content is stripped from `body_text` but may remain in
    /// `body_html` when the posture allows HTML exposure. Detail format:
    /// `method=<display_none|visibility_hidden|opacity_0|offscreen|zero_font|color_match>`
    /// optionally followed by `,count=N` when summarized.
    HtmlHiddenContentDetected,
    /// An HTML anchor's visible text contained a URL-looking token
    /// whose registrable domain differs from the anchor's `href`
    /// registrable domain. Detail format:
    /// `text_domain=<ascii>,href_domain=<ascii>`.
    ///
    /// Reflects the original message content (pre-ammonia), not the
    /// sanitized `body_html`. An anchor stripped by ammonia may still
    /// produce this warning — the warning signals the message's
    /// intent, not the sanitized output.
    HtmlLinkTextHrefMismatch,
    /// One or more `<script>` elements were removed during HTML
    /// sanitization. Detail format: `count=N`.
    HtmlScriptStripped,
    /// One or more `<style>` elements were removed during HTML
    /// sanitization. Detail format: `count=N`.
    HtmlStyleStripped,
    /// One or more `<img>` elements had their `src`/`srcset`
    /// attributes removed during HTML sanitization to prevent
    /// remote tracking-pixel loads. Detail format: `count=N`.
    HtmlRemoteImageStripped,
    /// An HTML anchor's `href` could not be resolved to a registrable
    /// domain via the Public Suffix List, but the anchor's visible text
    /// contained a URL-looking token (detected by `linkify`). This
    /// distinguishes "we checked and it's fine" from "we couldn't
    /// check." Consumers should treat the anchor with suspicion.
    HtmlAnchorUnparsableHref,
    /// A domain label contained characters from multiple Unicode
    /// scripts outside the TR39 Highly Restrictive profile. Detail
    /// format: `domain=<punycode>,scripts=<S1+S2>`.
    LookalikeMixedScript,
    /// A domain's TR39 skeleton matched a different domain's
    /// skeleton, indicating a homograph attack, OR bidi-override
    /// characters were stripped from the domain before processing.
    /// Detail format: `domain=<punycode>,skeleton_match=<other_punycode>`
    /// or `domain=<punycode>,reason=bidi_pre_strip`.
    LookalikeHomographDomain,
    /// A domain was processed in punycode form (xn--) and the
    /// Unicode U-label form is reported for informational use.
    /// Detail format: `domain=<punycode>,ulabel=<unicode>`.
    LookalikeIdnPunycode,
    /// A filename's visible extension differs from its extension
    /// after bidi-override stripping, indicating an RLO-bidi
    /// extension spoof. Detail format:
    /// `visible=<after_strip>,declared=<original>`.
    LookalikeFilenameExtensionSpoof,
    /// The IMAP server lacked the MOVE capability, so a non-atomic
    /// COPY+DELETE+EXPUNGE fallback was used instead of an atomic
    /// `UID MOVE`. The operation is not atomic: a crash or connection
    /// drop between the COPY and the EXPUNGE can leave the message
    /// duplicated in both folders. This signals non-atomicity only;
    /// the folder-wide data-loss risk is reported separately by
    /// `ServerFolderWideExpungeDataLoss`.
    ServerNonAtomicMoveFallback,
    /// The IMAP server lacked UIDPLUS, so the COPY+DELETE fallback issued a
    /// folder-wide `EXPUNGE` (RFC 3501) that removes EVERY `\Deleted` message
    /// in the source folder, not only the targeted UIDs. Messages another
    /// client flagged `\Deleted` may have been permanently destroyed.
    ServerFolderWideExpungeDataLoss,
}

/// Severity classification for [`WarningCode`] variants. Posture rules
/// can use this to partition warnings into informational signals vs.
/// adversarial signals without each caller maintaining its own
/// classification table.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    /// Emitted for normal-operation events (e.g. a legitimate
    /// newsletter larger than `MAX_BODY_BYTES`).
    Informational,
    /// Emitted when the pipeline detected and mitigated an attack
    /// signature or a policy violation.
    Adversarial,
}

impl WarningCode {
    /// Classify this warning code by severity.
    ///
    /// The match is deliberately non-wildcarded so adding a new
    /// [`WarningCode`] variant inside this crate forces an explicit
    /// severity decision via compile error. `#[non_exhaustive]` only
    /// requires a wildcard for downstream matches, not for matches
    /// inside the defining crate.
    #[must_use]
    pub fn severity(&self) -> WarningSeverity {
        match self {
            WarningCode::UnicodeZeroWidthStripped
            | WarningCode::UnicodeBidiOverrideStripped
            | WarningCode::UnicodeC0C1Stripped
            | WarningCode::ParseHeaderSmugglingBlocked
            | WarningCode::ParseMimeTypeMismatch
            | WarningCode::ParseBodystructureTypeMismatch
            | WarningCode::ParseAttachmentPolyglot
            | WarningCode::ParseMimeDepthExceeded
            | WarningCode::ParseMimePartCountExceeded
            | WarningCode::ParseHeaderCountExceeded
            | WarningCode::ParseAttachmentFilenameRewritten
            | WarningCode::HtmlHiddenContentDetected
            | WarningCode::HtmlLinkTextHrefMismatch
            | WarningCode::HtmlScriptStripped
            | WarningCode::LookalikeMixedScript
            | WarningCode::LookalikeHomographDomain
            | WarningCode::ServerFolderWideExpungeDataLoss
            | WarningCode::LookalikeFilenameExtensionSpoof => WarningSeverity::Adversarial,
            WarningCode::ParseBodyTruncated
            | WarningCode::HtmlStyleStripped
            | WarningCode::HtmlRemoteImageStripped
            | WarningCode::HtmlAnchorUnparsableHref
            | WarningCode::LookalikeIdnPunycode
            | WarningCode::ServerNonAtomicMoveFallback => WarningSeverity::Informational,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn warning_code_serializes_snake_case() {
        let code = WarningCode::UnicodeZeroWidthStripped;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"unicode_zero_width_stripped\"");
    }

    #[test]
    fn warning_code_roundtrips_through_json() {
        let original = WarningCode::ParseHeaderSmugglingBlocked;
        let json = serde_json::to_string(&original).unwrap();
        let parsed: WarningCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn severity_known_variants() {
        assert_eq!(
            WarningCode::ParseBodyTruncated.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::ParseHeaderSmugglingBlocked.severity(),
            WarningSeverity::Adversarial
        );
    }

    #[test]
    fn folder_wide_expunge_data_loss_is_adversarial() {
        // The folder-wide EXPUNGE fallback can permanently destroy messages
        // another client flagged `\Deleted`; that is a realized data-loss
        // event, not a benign informational signal.
        assert_eq!(
            WarningCode::ServerFolderWideExpungeDataLoss.severity(),
            WarningSeverity::Adversarial
        );
    }

    #[test]
    fn non_atomic_move_fallback_stays_informational() {
        // Non-atomicity (possible duplicates on a crash) is an operational
        // caveat, distinct from the data-loss variant above.
        assert_eq!(
            WarningCode::ServerNonAtomicMoveFallback.severity(),
            WarningSeverity::Informational
        );
    }
}
