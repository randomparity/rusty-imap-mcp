//! `SEARCH` (structured + raw passthrough).

use std::fmt::Write;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::{SearchQuery, StructuredQuery, Uid};

pub(crate) async fn search(
    session: &mut ImapSession,
    folder: &str,
    query: SearchQuery,
) -> Result<(Vec<Uid>, Option<u32>), ImapError> {
    // Read-only SELECT (EXAMINE) so the UID set and its UIDVALIDITY come
    // from the same selected-mailbox operation.
    let selected = super::folders::select(session, folder, true).await?;
    let uid_validity = selected.uid_validity;

    let key = match query {
        SearchQuery::Structured(s) => structured_to_key(&s)?,
        SearchQuery::Raw(r) => r,
    };

    let uids = session
        .uid_search(&key)
        .await
        .map_err(super::folders::map_err)?;
    Ok((
        uids.into_iter().filter_map(Uid::new).collect(),
        uid_validity,
    ))
}

fn structured_to_key(q: &StructuredQuery) -> Result<String, ImapError> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &q.from {
        parts.push(format!("FROM {}", quote(s)?));
    }
    if let Some(s) = &q.to {
        parts.push(format!("TO {}", quote(s)?));
    }
    if let Some(s) = &q.cc {
        parts.push(format!("CC {}", quote(s)?));
    }
    if let Some(s) = &q.bcc {
        parts.push(format!("BCC {}", quote(s)?));
    }
    if let Some(s) = &q.subject {
        parts.push(format!("SUBJECT {}", quote(s)?));
    }
    if let Some(s) = &q.body {
        parts.push(format!("BODY {}", quote(s)?));
    }
    if let Some(s) = &q.text {
        parts.push(format!("TEXT {}", quote(s)?));
    }
    if let Some(hs) = &q.headers {
        for h in hs {
            validate_header_name(&h.name)?;
            parts.push(format!("HEADER {} {}", h.name, quote(&h.value)?));
        }
    }
    if let Some(n) = q.larger {
        parts.push(format!("LARGER {n}"));
    }
    if let Some(n) = q.smaller {
        parts.push(format!("SMALLER {n}"));
    }
    if let Some(d) = q.since {
        parts.push(format!("SINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.before {
        parts.push(format!("BEFORE {}", format_imap_date(d)));
    }
    if let Some(d) = q.sent_since {
        parts.push(format!("SENTSINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.sent_before {
        parts.push(format!("SENTBEFORE {}", format_imap_date(d)));
    }
    push_flag_clause(&mut parts, q.seen, "SEEN", "UNSEEN");
    push_flag_clause(&mut parts, q.answered, "ANSWERED", "UNANSWERED");
    push_flag_clause(&mut parts, q.flagged, "FLAGGED", "UNFLAGGED");
    push_flag_clause(&mut parts, q.draft, "DRAFT", "UNDRAFT");
    if q.has_attachment {
        // Heuristic: scan the message body for the literal Content-Disposition
        // header. False negatives for unusual capitalization or nested MIME
        // structures are accepted — see StructuredQuery::has_attachment doc.
        parts.push("BODY \"Content-Disposition: attachment\"".to_string());
    }
    if parts.is_empty() {
        return Ok("ALL".to_string());
    }
    Ok(parts.join(" "))
}

/// Emit `yes` when the flag is `Some(true)`, `no` when `Some(false)`, and
/// nothing when `None`. Collapses the IMAP SEEN/UNSEEN, FLAGGED/UNFLAGGED,
/// ANSWERED/UNANSWERED, DRAFT/UNDRAFT match blocks into one-liners.
fn push_flag_clause(
    parts: &mut Vec<String>,
    value: Option<bool>,
    yes: &'static str,
    no: &'static str,
) {
    match value {
        Some(true) => parts.push(yes.to_string()),
        Some(false) => parts.push(no.to_string()),
        None => {}
    }
}

fn quote(s: &str) -> Result<String, ImapError> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
        return Err(ImapError::InvalidInput {
            field: "search string",
            reason: "contains forbidden control bytes (CR/LF/NUL)",
        });
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// Validate an RFC 5322 field name for use in a `HEADER` SEARCH clause.
///
/// Every byte must be in the printable ASCII range `33..=126`
/// (`!`..`~`) and must not be `b':'` (which terminates a field name).
/// This is stricter than the IMAP wire format requires but matches the
/// shape of all real-world header names and blocks command injection
/// via CR/LF/NUL or whitespace.
///
/// # Errors
///
/// Returns [`ImapError::InvalidInput`] with `field = "header name"` for
/// any disallowed byte or an empty name.
fn validate_header_name(name: &str) -> Result<(), ImapError> {
    if name.is_empty() {
        return Err(ImapError::InvalidInput {
            field: "header name",
            reason: "empty",
        });
    }
    for b in name.bytes() {
        if !(33..=126).contains(&b) || b == b':' {
            return Err(ImapError::InvalidInput {
                field: "header name",
                reason: "must be printable ASCII without ':'",
            });
        }
    }
    Ok(())
}

fn format_imap_date(d: ::time::Date) -> String {
    // IMAP SEARCH dates use "DD-Mon-YYYY" with English month abbreviations.
    let month = match d.month() {
        ::time::Month::January => "Jan",
        ::time::Month::February => "Feb",
        ::time::Month::March => "Mar",
        ::time::Month::April => "Apr",
        ::time::Month::May => "May",
        ::time::Month::June => "Jun",
        ::time::Month::July => "Jul",
        ::time::Month::August => "Aug",
        ::time::Month::September => "Sep",
        ::time::Month::October => "Oct",
        ::time::Month::November => "Nov",
        ::time::Month::December => "Dec",
    };
    let mut out = String::with_capacity(11);
    let _ = write!(out, "{:02}-{}-{}", d.day(), month, d.year());
    out
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{format_imap_date, quote, structured_to_key, validate_header_name};
    use crate::error::ImapError;
    use crate::types::StructuredQuery;

    #[test]
    fn structured_to_key_empty_query_yields_all() {
        let q = StructuredQuery::default();
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn structured_to_key_quotes_string_fields() {
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            subject: Some("hello world".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("FROM \"alice@example.com\""), "got {key}");
        assert!(key.contains("SUBJECT \"hello world\""), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_seen_or_unseen_per_option() {
        let q = StructuredQuery {
            seen: Some(true),
            ..StructuredQuery::default()
        };
        assert_eq!(structured_to_key(&q).unwrap(), "SEEN");
        let q = StructuredQuery {
            seen: Some(false),
            ..StructuredQuery::default()
        };
        assert_eq!(structured_to_key(&q).unwrap(), "UNSEEN");
        let q = StructuredQuery::default();
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn quote_escapes_backslash_and_double_quote() {
        assert_eq!(quote(r#"a"b\c"#).unwrap(), r#""a\"b\\c""#);
    }

    #[test]
    fn format_imap_date_uses_dd_mon_yyyy() {
        let d = ::time::Date::from_calendar_date(2026, ::time::Month::April, 7).unwrap();
        assert_eq!(format_imap_date(d), "07-Apr-2026");
    }

    #[test]
    fn structured_to_key_combines_multiple_criteria() {
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            since: Some(::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap()),
            seen: Some(false),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"FROM "alice@example.com" SINCE 01-Jan-2026 UNSEEN"#
        );
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn quote_rejects_embedded_newline() {
        let Err(ImapError::InvalidInput { field, reason }) = quote("injected\r\nNOOP") else {
            panic!("expected InvalidInput error");
        };
        assert_eq!(field, "search string");
        assert!(reason.contains("CR/LF/NUL"), "reason was: {reason}");
    }

    #[test]
    fn quote_rejects_embedded_lf() {
        assert!(quote("a\nb").is_err());
    }

    #[test]
    fn quote_rejects_embedded_nul() {
        assert!(quote("a\0b").is_err());
    }

    #[test]
    fn quote_accepts_clean_ascii() {
        assert_eq!(quote("Sprint 3").unwrap(), "\"Sprint 3\"");
    }

    #[test]
    fn quote_escapes_backslash_and_quote() {
        assert_eq!(quote(r#"a\b"c"#).unwrap(), r#""a\\b\"c""#);
    }

    #[test]
    fn structured_to_key_emits_cc_and_bcc() {
        let q = StructuredQuery {
            cc: Some("alice@example.com".to_string()),
            bcc: Some("bob@example.com".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains(r#"CC "alice@example.com""#), "got {key}");
        assert!(key.contains(r#"BCC "bob@example.com""#), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_body_and_text() {
        let q = StructuredQuery {
            body: Some("hello".to_string()),
            text: Some("world".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains(r#"BODY "hello""#), "got {key}");
        assert!(key.contains(r#"TEXT "world""#), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_single_header() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            headers: Some(vec![HeaderSearch {
                name: "List-Id".to_string(),
                value: "rust-users".to_string(),
            }]),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"HEADER List-Id "rust-users""#,
        );
    }

    #[test]
    fn structured_to_key_emits_multiple_headers_in_input_order() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            headers: Some(vec![
                HeaderSearch {
                    name: "List-Id".to_string(),
                    value: "rust-users".to_string(),
                },
                HeaderSearch {
                    name: "X-Mailer".to_string(),
                    value: "thunderbird".to_string(),
                },
            ]),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"HEADER List-Id "rust-users" HEADER X-Mailer "thunderbird""#,
        );
    }

    #[test]
    fn structured_to_key_header_value_with_embedded_quote_is_escaped() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            headers: Some(vec![HeaderSearch {
                name: "X-Tag".to_string(),
                value: r#"a"b"#.to_string(),
            }]),
            ..StructuredQuery::default()
        };
        assert_eq!(structured_to_key(&q).unwrap(), r#"HEADER X-Tag "a\"b""#);
    }

    #[test]
    fn structured_to_key_treats_empty_headers_vec_as_no_clause() {
        let q = StructuredQuery {
            headers: Some(Vec::new()),
            ..StructuredQuery::default()
        };
        // Empty headers carries no filter intent — emitter must not
        // produce any HEADER clause. With no other criteria the query
        // collapses to ALL.
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn structured_to_key_emits_larger_and_smaller_numeric() {
        let q = StructuredQuery {
            larger: Some(1024),
            smaller: Some(1_048_576),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("LARGER 1024"), "got {key}");
        assert!(key.contains("SMALLER 1048576"), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_sent_since_and_sent_before() {
        let q = StructuredQuery {
            sent_since: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap(),
            ),
            sent_before: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::February, 1).unwrap(),
            ),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("SENTSINCE 01-Jan-2026"), "got {key}");
        assert!(key.contains("SENTBEFORE 01-Feb-2026"), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_answered_flagged_draft_per_option() {
        let q = StructuredQuery {
            answered: Some(true),
            flagged: Some(false),
            draft: Some(true),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("ANSWERED"), "got {key}");
        assert!(key.contains("UNFLAGGED"), "got {key}");
        assert!(key.contains("DRAFT"), "got {key}");

        let q = StructuredQuery {
            answered: Some(false),
            flagged: Some(true),
            draft: Some(false),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("UNANSWERED"), "got {key}");
        assert!(key.contains("FLAGGED"), "got {key}");
        assert!(key.contains("UNDRAFT"), "got {key}");
    }

    #[test]
    fn structured_to_key_combines_old_and_new_fields_in_emit_order() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            cc: Some("team@example.com".to_string()),
            body: Some("ship it".to_string()),
            headers: Some(vec![HeaderSearch {
                name: "List-Id".to_string(),
                value: "rust".to_string(),
            }]),
            larger: Some(2048),
            sent_since: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::March, 15).unwrap(),
            ),
            answered: Some(true),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"FROM "alice@example.com" CC "team@example.com" BODY "ship it" HEADER List-Id "rust" LARGER 2048 SENTSINCE 15-Mar-2026 ANSWERED"#,
        );
    }

    #[test]
    fn validate_header_name_accepts_canonical_names() {
        validate_header_name("Message-ID").unwrap();
        validate_header_name("X-Foo").unwrap();
        validate_header_name("List-Id").unwrap();
        validate_header_name("Content-Type").unwrap();
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn validate_header_name_rejects_empty() {
        let Err(ImapError::InvalidInput { field, reason }) = validate_header_name("") else {
            panic!("expected InvalidInput error");
        };
        assert_eq!(field, "header name");
        assert!(reason.contains("empty"), "reason was: {reason}");
    }

    #[test]
    fn validate_header_name_rejects_colon() {
        assert!(validate_header_name("X-Foo:").is_err());
    }

    #[test]
    fn validate_header_name_rejects_space() {
        assert!(validate_header_name("X Foo").is_err());
    }

    #[test]
    fn validate_header_name_rejects_crlf() {
        assert!(validate_header_name("X-Foo\r\nBCC").is_err());
        assert!(validate_header_name("X\rFoo").is_err());
        assert!(validate_header_name("X\nFoo").is_err());
    }

    #[test]
    fn validate_header_name_rejects_nul() {
        assert!(validate_header_name("X-Foo\0").is_err());
    }

    #[test]
    fn validate_header_name_rejects_high_bit_byte() {
        assert!(validate_header_name("X-Föo").is_err());
    }
}
