//! Cross-cutting input-validation helpers for tool handlers.

use rimap_core::folder_name::FolderName;
use rimap_core::RimapError;

/// Validate `name` as a structurally well-formed IMAP folder, mapping
/// any rejection into [`RimapError::invalid_input`] prefixed with
/// `label`. The prefix names the field the client passed in (e.g.
/// `"folder"`, `"destination"`, `"drafts folder"`) so the resulting
/// error text points at the offending input.
///
/// Consolidates the `FolderName::new(...).map_err(|e| ...)` shape
/// used at the top of every folder-taking tool handler plus
/// `message_builder`'s threading check. `send_email` does NOT use
/// this helper because its resolved-Sent-folder failure routes
/// through `sent_copy.failed` rather than returning an error to the
/// caller.
///
/// # Errors
///
/// Returns [`RimapError::invalid_input`] when [`FolderName::new`]
/// rejects `name`.
pub(crate) fn validate_folder_input(label: &str, name: &str) -> Result<(), RimapError> {
    FolderName::new(name).map_err(|e| RimapError::invalid_input(format!("{label}: {e}")))?;
    Ok(())
}

/// Maximum number of header names accepted by `fetch_message`'s
/// `include_headers` allowlist. Bounds response size and per-request
/// extraction cost.
pub(crate) const MAX_INCLUDE_HEADERS: usize = 16;

/// Validate and normalize a `fetch_message` `include_headers` allowlist.
///
/// Rejects a request of more than [`MAX_INCLUDE_HEADERS`] names, and any
/// name that is not a structurally valid RFC 5322 field name (non-empty,
/// printable US-ASCII 33–126, excluding `:`). Names are deduplicated
/// case-insensitively, keeping the first spelling seen, so extraction is
/// predictable and bounded.
///
/// # Errors
///
/// Returns [`RimapError::invalid_input`] when the count cap is exceeded or
/// a name is empty or contains an invalid character.
pub(crate) fn validate_include_headers(names: &[String]) -> Result<Vec<String>, RimapError> {
    if names.len() > MAX_INCLUDE_HEADERS {
        return Err(RimapError::invalid_input(format!(
            "include_headers: at most {MAX_INCLUDE_HEADERS} names allowed, got {}",
            names.len()
        )));
    }
    let mut seen_lower: Vec<String> = Vec::with_capacity(names.len());
    let mut out: Vec<String> = Vec::with_capacity(names.len());
    for name in names {
        validate_header_name(name)?;
        let lower = name.to_ascii_lowercase();
        if seen_lower.contains(&lower) {
            continue;
        }
        seen_lower.push(lower);
        out.push(name.clone());
    }
    Ok(out)
}

/// Reject a header name that is empty or carries a byte outside the RFC
/// 5322 field-name set (printable US-ASCII 33–126, excluding `:`).
fn validate_header_name(name: &str) -> Result<(), RimapError> {
    if name.is_empty() {
        return Err(RimapError::invalid_input(
            "include_headers: header name must not be empty".to_string(),
        ));
    }
    for byte in name.bytes() {
        if !(33..=126).contains(&byte) || byte == b':' {
            return Err(RimapError::invalid_input(format!(
                "include_headers: invalid header name {name:?} (RFC 5322 field \
                 names are printable ASCII without ':' or spaces)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{MAX_INCLUDE_HEADERS, validate_folder_input, validate_include_headers};

    #[test]
    fn include_headers_accepts_valid_names() {
        let names = vec!["List-Unsubscribe".to_string(), "X-App-Id".to_string()];
        let out = validate_include_headers(&names).unwrap();
        assert_eq!(out, names);
    }

    #[test]
    fn include_headers_deduplicates_case_insensitively() {
        let names = vec![
            "List-Id".to_string(),
            "list-id".to_string(),
            "LIST-ID".to_string(),
        ];
        let out = validate_include_headers(&names).unwrap();
        assert_eq!(out, vec!["List-Id".to_string()]);
    }

    #[test]
    fn include_headers_rejects_over_cap() {
        let names: Vec<String> = (0..=MAX_INCLUDE_HEADERS)
            .map(|i| format!("X-{i}"))
            .collect();
        let err = validate_include_headers(&names).unwrap_err();
        assert!(err.to_string().contains("at most"), "got: {err}");
    }

    #[test]
    fn include_headers_at_cap_is_accepted() {
        let names: Vec<String> = (0..MAX_INCLUDE_HEADERS).map(|i| format!("X-{i}")).collect();
        assert!(validate_include_headers(&names).is_ok());
    }

    #[test]
    fn include_headers_rejects_empty_name() {
        let err = validate_include_headers(&[String::new()]).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn include_headers_rejects_colon_space_and_control() {
        for bad in ["List:Id", "X Header", "X-\u{202e}", "X-\0"] {
            let err = validate_include_headers(&[bad.to_string()]).unwrap_err();
            assert!(
                err.to_string().contains("invalid header name"),
                "expected rejection for {bad:?}, got: {err}",
            );
        }
    }

    #[test]
    fn accepts_well_formed_folder() {
        assert!(validate_folder_input("folder", "INBOX").is_ok());
        assert!(validate_folder_input("drafts folder", "[Gmail]/Drafts").is_ok());
    }

    #[test]
    fn rejects_bidi_override_with_label_in_message() {
        let err = validate_folder_input("folder", "INBOX\u{202e}txt").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("folder:"),
            "expected label prefix in error, got: {msg}",
        );
    }

    #[test]
    fn rejects_unicode_tag_characters() {
        // U+E0041 is a Tag Character (prompt-injection vector).
        let err = validate_folder_input("folder", "Work\u{e0041}").unwrap_err();
        assert!(err.to_string().contains("folder:"));
    }

    #[test]
    fn label_is_forwarded_into_error_text() {
        let err = validate_folder_input("destination", "bad\0folder").unwrap_err();
        assert!(
            err.to_string().contains("destination:"),
            "expected 'destination:' prefix, got: {err}",
        );
    }
}
