//! Header-value extraction, sanitisation, and adversarial audits.
//!
//! These helpers are shared between `meta.rs` (which reads the RFC 5322
//! address/subject/date headers) and the parent module (which harvests
//! mailing-list headers and enforces header-count limits).

use mail_parser::{Address, Header, HeaderValue, Message};

use crate::error::ContentError;
use crate::output::{MailingListInfo, SecurityWarning, SelectedHeader, WarningCode};
use crate::parse::meta::format_addr;
use crate::parse::{MAX_HEADER_BYTES, MAX_HEADER_COUNT};
use crate::unicode;

/// Append the domain of every address in `group` to `out`, tagging each
/// with `label`. No-op when `group` is `None`.
pub(super) fn push_domains_from(
    group: Option<&Address<'_>>,
    label: &str,
    out: &mut Vec<(String, String)>,
) {
    let Some(address) = group else { return };
    for addr in address.iter() {
        if let Some(domain) = crate::parse::meta::addr_domain(addr) {
            out.push((domain, label.to_string()));
        }
    }
}

/// Pre-extract domains from structured `Addr.address` fields for
/// all header address sources (From, To, Cc, Reply-To). Using the
/// parser's structured data is more reliable than re-parsing the
/// rendered display string.
pub(super) fn collect_header_domains(message: &Message<'_>) -> Vec<(String, String)> {
    let mut domains = Vec::new();
    push_domains_from(message.from(), "header:from", &mut domains);
    push_domains_from(message.to(), "header:to", &mut domains);
    push_domains_from(message.cc(), "header:cc", &mut domains);
    push_domains_from(message.reply_to(), "header:reply_to", &mut domains);
    domains
}

pub(super) fn enforce_header_count(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let header_count = message.headers().len();
    if header_count > MAX_HEADER_COUNT {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseHeaderCountExceeded,
            format!("count={header_count} limit={MAX_HEADER_COUNT}"),
            "headers",
        ));
        return Err(ContentError::LimitExceeded {
            kind: "header_count",
            limit: MAX_HEADER_COUNT,
        });
    }
    Ok(())
}

/// Extract the first textual value from a `HeaderValue`, sanitize it,
/// and return `None` if the header is `Empty` or non-textual.
pub(super) fn header_value_first_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list.first()?.as_ref().to_string(),
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
    };
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Extract every textual value from a `HeaderValue` and sanitize each.
pub(super) fn header_value_all_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let raws: Vec<String> = match value {
        HeaderValue::Text(s) => vec![s.as_ref().to_string()],
        HeaderValue::TextList(list) => list.iter().map(|s| s.as_ref().to_string()).collect(),
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return Vec::new(),
    };
    raws.into_iter()
        .map(|raw| {
            let (text, mut new_warnings) =
                unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

/// Extract the caller-requested header names from `message`, sanitizing
/// each value. `raw` is the scrubbed byte slice `message` was parsed
/// from; it backs the raw-offset fallback for structured header variants
/// (`Received`, `Date`, `Content-Type`) that mail-parser does not expose
/// as plain text.
///
/// Matching is case-insensitive (RFC 5322). Repeated header lines collect
/// in message order. Requested names with no matching header are omitted
/// (absent, not an error). Output preserves the caller's requested order
/// and spelling.
pub(super) fn extract_selected_headers(
    message: &Message<'_>,
    raw: &[u8],
    wanted: &[String],
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<SelectedHeader> {
    let mut out = Vec::with_capacity(wanted.len());
    for name in wanted {
        let location = format!("header:{}", name.to_ascii_lowercase());
        let mut values = Vec::new();
        for header in message.headers() {
            if header.name().eq_ignore_ascii_case(name)
                && let Some(value) = coerce_header_value(header, raw, &location, warnings)
            {
                values.push(value);
            }
        }
        if !values.is_empty() {
            out.push(SelectedHeader {
                name: name.clone(),
                values,
            });
        }
    }
    out
}

/// Coerce any header to a sanitized string. `Text`/`TextList`/`Address`
/// use the RFC 2047-decoded typed value; structured variants
/// (`DateTime`/`ContentType`/`Received`) fall back to the raw header
/// slice so headers like `Received` stay readable. `Empty` yields `None`.
fn coerce_header_value(
    header: &Header<'_>,
    raw: &[u8],
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    match header.value() {
        HeaderValue::Text(_) | HeaderValue::TextList(_) | HeaderValue::Address(_) => {
            sanitize_header_value(header.value(), location, warnings)
        }
        HeaderValue::DateTime(_) | HeaderValue::ContentType(_) | HeaderValue::Received(_) => {
            raw_header_slice(header, raw, location, warnings)
        }
        HeaderValue::Empty => None,
    }
}

/// Sanitize the raw on-the-wire header value delimited by mail-parser's
/// byte offsets. Used for structured variants `sanitize_header_value`
/// cannot render as text. Returns `None` when the offsets are degenerate
/// or the sanitized value is empty.
fn raw_header_slice(
    header: &Header<'_>,
    raw: &[u8],
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let start = header.offset_start() as usize;
    let end = header.offset_end() as usize;
    let slice = raw.get(start..end)?;
    let (text, mut new_warnings) =
        unicode::sanitize(slice, Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    let text = text.trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

/// Extract `List-ID` / `List-Unsubscribe` / `List-Post` into a
/// `MailingListInfo`, returning `None` when none of the headers are
/// present.
pub(super) fn extract_mailing_list(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<MailingListInfo> {
    let list_id = sanitize_header_value(message.list_id(), "header:list_id", warnings);
    let list_unsubscribe = sanitize_header_value(
        message.list_unsubscribe(),
        "header:list_unsubscribe",
        warnings,
    );
    let list_post = sanitize_header_value(message.list_post(), "header:list_post", warnings);

    if list_id.is_none() && list_unsubscribe.is_none() && list_post.is_none() {
        return None;
    }
    Some(MailingListInfo {
        list_id,
        list_unsubscribe,
        list_post,
    })
}

/// Coerce a `HeaderValue` to a sanitized string. Handles `Text`,
/// `TextList`, and `Address` variants — mail-parser parses `List-*`
/// headers as addresses, so we flatten them back to a display string.
pub(super) fn sanitize_header_value(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::Address(address) => address
            .iter()
            .map(|addr| {
                audit_addr_domain_bidi(addr, location, warnings);
                format_addr(addr)
            })
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// If `raw_domain` contains any bidi-override codepoint, emit a
/// `LookalikeHomographDomain` warning with `reason=bidi_pre_strip`.
/// Detection must occur BEFORE `unicode::sanitize` strips the bidi
/// chars; afterwards no signal remains.
fn audit_domain_bidi_prestrip(
    raw_domain: &str,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    if !crate::parse::filename::contains_bidi_override(raw_domain) {
        return;
    }
    let ascii = idna::domain_to_ascii(raw_domain.trim()).unwrap_or_else(|_| "invalid".to_string());
    warnings.push(SecurityWarning::at(
        WarningCode::LookalikeHomographDomain,
        format!("domain={ascii},reason=bidi_pre_strip"),
        location,
    ));
}

/// Extract the domain from a `mail_parser::Addr` and run the
/// pre-strip bidi audit. No-op when the address is missing or has no
/// `@` separator.
pub(super) fn audit_addr_domain_bidi(
    addr: &mail_parser::Addr<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    let Some(email) = addr.address.as_deref() else {
        return;
    };
    let Some((_local, domain)) = email.rsplit_once('@') else {
        return;
    };
    audit_domain_bidi_prestrip(domain, location, warnings);
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
#[expect(clippy::panic, reason = "test failure paths")]
mod headers_tests {
    use crate::error::ContentError;
    use crate::parse::{MAX_HEADER_COUNT, parse_message};

    fn build_message_with_n_headers(n: usize) -> Vec<u8> {
        let mut raw = Vec::from(&b"From: a@example\r\n"[..]);
        for i in 0..n {
            raw.extend_from_slice(format!("X-Pad-{i}: x\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\nbody");
        raw
    }

    #[test]
    fn parse_rejects_header_count_above_max() {
        // 1 (From) + 300 (X-Pad-*) = 301 headers, well above MAX_HEADER_COUNT=256.
        // Kills: enforce_header_count -> Ok(()), and `> with ==` (since count != MAX).
        let raw = build_message_with_n_headers(300);
        let err = parse_message(&raw).unwrap_err();
        match err {
            ContentError::LimitExceeded { kind, limit } => {
                assert_eq!(kind, "header_count");
                assert_eq!(limit, MAX_HEADER_COUNT);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_accepts_header_count_at_max() {
        // From + 255 X-Pad headers = exactly 256 = MAX_HEADER_COUNT.
        // Kills: `> with >=` (with `>=`, 256 >= 256 errors; with `>`, 256 > 256 is false).
        let raw = build_message_with_n_headers(MAX_HEADER_COUNT - 1);
        let content = parse_message(&raw).expect("256 headers must parse cleanly");
        // Sanity: no LimitExceeded warning was attached either.
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::ParseHeaderCountExceeded)),
            "no ParseHeaderCountExceeded at the limit boundary",
        );
    }

    #[test]
    fn parse_extracts_in_reply_to_header() {
        // Kills: header_value_first_text -> None (the wholesale stub).
        let raw = b"From: a@example\r\n\
                    In-Reply-To: <parent-msgid@example>\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let in_reply_to = content
            .meta
            .in_reply_to
            .as_deref()
            .expect("In-Reply-To populates meta.in_reply_to");
        assert!(
            in_reply_to.contains("parent-msgid@example"),
            "in_reply_to should contain the message id, got {in_reply_to:?}",
        );
    }

    #[test]
    fn parse_extracts_references_header_with_multiple_ids() {
        // Kills: header_value_all_text -> vec![] (the wholesale stub).
        let raw = b"From: a@example\r\n\
                    References: <one@example> <two@example> <three@example>\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        assert!(
            !content.meta.references.is_empty(),
            "References must populate meta.references with at least one id",
        );
        let joined = content.meta.references.join(" ");
        assert!(joined.contains("one@example"), "missing first id");
        assert!(joined.contains("three@example"), "missing last id");
    }

    use crate::parse::parse_message_with_headers;

    #[test]
    fn selects_requested_header_case_insensitively() {
        let raw = b"From: a@example\r\n\
                    List-Unsubscribe: <mailto:unsub@example>\r\n\
                    \r\n\
                    body";
        let (_content, headers) =
            parse_message_with_headers(raw, &["list-unsubscribe".to_string()]).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "list-unsubscribe");
        assert_eq!(headers[0].values.len(), 1);
        assert!(
            headers[0].values[0].contains("unsub@example"),
            "got {:?}",
            headers[0].values,
        );
    }

    #[test]
    fn selects_header_not_in_parsed_set() {
        // MIME-Version is not part of the fixed parsed meta; extraction must
        // still surface it — the whole point of the allowlist.
        let raw = b"From: a@example\r\nMIME-Version: 1.0\r\n\r\nbody";
        let (_content, headers) =
            parse_message_with_headers(raw, &["MIME-Version".to_string()]).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].values, vec!["1.0".to_string()]);
    }

    #[test]
    fn missing_header_is_omitted_not_errored() {
        let raw = b"From: a@example\r\n\r\nbody";
        let (_content, headers) =
            parse_message_with_headers(raw, &["X-Absent".to_string()]).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn repeated_header_collects_all_values_in_order() {
        let raw = b"From: a@example\r\n\
                    Received: from one.example\r\n\
                    Received: from two.example\r\n\
                    \r\n\
                    body";
        let (_content, headers) =
            parse_message_with_headers(raw, &["Received".to_string()]).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].values.len(), 2, "got {:?}", headers[0].values);
        assert!(headers[0].values[0].contains("one.example"));
        assert!(headers[0].values[1].contains("two.example"));
    }

    #[test]
    fn empty_allowlist_yields_no_headers() {
        let raw = b"From: a@example\r\nX-Custom: value\r\n\r\nbody";
        let (_content, headers) = parse_message_with_headers(raw, &[]).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn requested_order_and_spelling_preserved() {
        let raw = b"From: a@example\r\n\
                    X-Alpha: 1\r\n\
                    X-Beta: 2\r\n\
                    \r\n\
                    body";
        let (_content, headers) =
            parse_message_with_headers(raw, &["X-Beta".to_string(), "X-Alpha".to_string()])
                .unwrap();
        assert_eq!(headers[0].name, "X-Beta");
        assert_eq!(headers[1].name, "X-Alpha");
    }

    #[test]
    fn smuggled_header_does_not_reappear_in_selection() {
        // A CRLF-smuggled `Bcc:` inside an encoded-word Subject is scrubbed
        // before parsing; requesting it must not resurrect it.
        let raw = b"From: a@example\r\n\
                    Subject: =?utf-8?B?x\r\n\
                    Bcc: victim@example\r\n\
                    ?=\r\n\
                    To: b@example\r\n\
                    \r\n\
                    body";
        let (_content, headers) = parse_message_with_headers(raw, &["Bcc".to_string()]).unwrap();
        assert!(headers.is_empty(), "smuggled Bcc must not be selectable");
    }

    #[test]
    fn control_chars_in_value_are_stripped() {
        // A NUL embedded in a custom header value must be removed by the
        // sanitizer before the value is returned.
        let raw = b"From: a@example\r\nX-Token: ab\x00cd\r\n\r\nbody";
        let (_content, headers) =
            parse_message_with_headers(raw, &["X-Token".to_string()]).unwrap();
        assert_eq!(headers.len(), 1);
        assert!(
            !headers[0].values[0].contains('\u{0}'),
            "NUL must be stripped, got {:?}",
            headers[0].values,
        );
    }

    #[test]
    fn parse_extracts_mailing_list_with_only_list_id() {
        // Kills both `&& with ||` mutations in extract_mailing_list's
        // is_none-AND-is_none-AND-is_none guard. With only list_id set, the
        // original `false && true && true` is false (returns Some); both
        // `||` mutants flip to true (return None).
        let raw = b"From: a@example\r\n\
                    List-ID: <only-id@example>\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let ml = content
            .meta
            .mailing_list
            .expect("List-ID alone must produce Some(MailingListInfo)");
        assert!(
            ml.list_id
                .as_deref()
                .unwrap_or("")
                .contains("only-id@example"),
        );
        assert!(ml.list_unsubscribe.is_none());
        assert!(ml.list_post.is_none());
    }
}
