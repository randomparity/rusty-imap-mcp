//! Shared RFC 5322 message construction for `create_draft` and `send_email`.
//!
//! Extracted from `create_draft` to avoid duplication. Both tool handlers
//! call `build_message_headers` and `apply_threading_headers`; only the
//! delivery step differs (IMAP APPEND vs SMTP send).

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::message_id::MessageId;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountState;

/// An email address with optional display name.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct AddressInput {
    /// Display name (optional).
    pub name: Option<String>,
    /// Email address.
    pub address: String,
}

pub(crate) const MAX_RECIPIENTS: usize = 100;
pub(crate) const MAX_SUBJECT_LEN: usize = 1000;
pub(crate) const MAX_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_REFERENCES: usize = 50;

/// Common input fields shared by `create_draft` and `send_email`.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ComposeInput {
    /// Recipient addresses.
    pub to: Vec<AddressInput>,
    /// CC addresses.
    pub cc: Option<Vec<AddressInput>>,
    /// BCC addresses.
    pub bcc: Option<Vec<AddressInput>>,
    /// Email subject.
    pub subject: String,
    /// Plain text body.
    pub body_text: String,
    /// UID of message to reply to (for threading headers).
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_nonzero_u32"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_nonzero_u32")]
    pub in_reply_to_uid: Option<core::num::NonZeroU32>,
    /// Folder containing the message to reply to (default INBOX).
    pub in_reply_to_folder: Option<String>,
}

/// Validate all user-supplied fields in a compose input.
pub(crate) fn validate_compose_input(input: &ComposeInput) -> Result<(), rimap_core::RimapError> {
    if input.to.is_empty() {
        return Err(rimap_core::RimapError::invalid_input(
            "at least one To recipient is required",
        ));
    }

    let total_recipients = input.to.len()
        + input.cc.as_ref().map_or(0, Vec::len)
        + input.bcc.as_ref().map_or(0, Vec::len);
    if total_recipients > MAX_RECIPIENTS {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "too many recipients ({total_recipients}); max is {MAX_RECIPIENTS}"
        )));
    }

    if input.subject.len() > MAX_SUBJECT_LEN {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "subject too long ({} bytes); max is {MAX_SUBJECT_LEN}",
            input.subject.len()
        )));
    }

    if input.body_text.len() > MAX_BODY_BYTES {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "body_text too large ({} bytes); max is {MAX_BODY_BYTES}",
            input.body_text.len()
        )));
    }

    validate_addresses("To", &input.to)?;
    if let Some(cc) = &input.cc {
        validate_addresses("CC", cc)?;
    }
    if let Some(bcc) = &input.bcc {
        validate_addresses("BCC", bcc)?;
    }
    if input
        .subject
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
    {
        return Err(rimap_core::RimapError::invalid_input(
            "subject contains forbidden characters",
        ));
    }
    if let Some(folder) = &input.in_reply_to_folder {
        crate::tools::validation::validate_folder_input("in_reply_to_folder", folder)?;
    }
    Ok(())
}

/// Reject strings that could inject RFC 5322 headers.
pub(crate) fn validate_header_text(field: &str, value: &str) -> Result<(), rimap_core::RimapError> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0' || b == b'<' || b == b'>')
    {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "{field} contains forbidden characters"
        )));
    }
    Ok(())
}

fn validate_addresses(field: &str, addrs: &[AddressInput]) -> Result<(), rimap_core::RimapError> {
    for addr in addrs {
        validate_header_text(&format!("{field} address"), &addr.address)?;
        if let Some(name) = &addr.name {
            validate_header_text(&format!("{field} name"), name)?;
        }
    }
    Ok(())
}

/// Generate a Message-ID using the From address domain.
pub(crate) fn generate_message_id(from_addr: &str) -> String {
    let domain = from_addr.rsplit('@').next().unwrap_or("local");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}.{}@{domain}", std::process::id(), nanos)
}

/// Set From, To, CC, BCC, Subject, body, and Message-ID on a builder.
pub(crate) fn build_message_headers<'a>(
    from_addr: &'a str,
    input: &'a ComposeInput,
) -> MessageBuilder<'a> {
    let msg_id = generate_message_id(from_addr);
    let builder = MessageBuilder::new()
        .from(from_addr)
        .to(addresses_to_builder(&input.to))
        .subject(input.subject.as_str())
        .text_body(input.body_text.as_str())
        .message_id(msg_id);

    let builder = if let Some(cc) = input.cc.as_ref().filter(|v| !v.is_empty()) {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    if let Some(bcc) = input.bcc.as_ref().filter(|v| !v.is_empty()) {
        builder.bcc(addresses_to_builder(bcc))
    } else {
        builder
    }
}

fn addresses_to_builder(addrs: &[AddressInput]) -> Address<'_> {
    if addrs.len() == 1 {
        return single_address(&addrs[0]);
    }
    let list: Vec<Address<'_>> = addrs.iter().map(single_address).collect();
    Address::new_list(list)
}

fn single_address(addr: &AddressInput) -> Address<'_> {
    match &addr.name {
        Some(name) => Address::new_address(Some(name.as_str()), addr.address.as_str()),
        None => Address::new_address(None::<&str>, addr.address.as_str()),
    }
}

/// Truncate a References chain to at most `MAX_REFERENCES` entries.
pub(crate) fn cap_references(mut refs: Vec<String>) -> Vec<String> {
    if refs.len() <= MAX_REFERENCES {
        return refs;
    }
    let root = refs.remove(0);
    let keep_recent = MAX_REFERENCES - 1;
    let start = refs.len().saturating_sub(keep_recent);
    let mut result = Vec::with_capacity(MAX_REFERENCES);
    result.push(root);
    result.extend(refs.into_iter().skip(start));
    result
}

/// Fetch referenced message and set In-Reply-To / References headers.
pub(crate) async fn apply_threading_headers<'a>(
    account: &AccountState,
    builder: MessageBuilder<'a>,
    reply_uid: core::num::NonZeroU32,
    in_reply_to_folder: Option<&str>,
) -> Result<MessageBuilder<'a>, rimap_core::RimapError> {
    let folder = in_reply_to_folder.unwrap_or("INBOX");
    let uid = rimap_imap::types::Uid::from(reply_uid);

    let raw = account.imap.fetch_body(folder, uid, None).await?;
    let headers = rimap_content::extract_threading_headers(&raw);

    let Some(msg_id) = headers.message_id else {
        return Ok(builder);
    };

    let builder = builder.in_reply_to(msg_id.clone());

    let mut ref_ids = headers.references;
    ref_ids.push(msg_id);
    let ref_ids = cap_references(ref_ids);

    Ok(builder.references(MessageId::new_list(ref_ids.into_iter())))
}

/// Build raw RFC 5322 bytes from compose input, applying threading
/// if `in_reply_to_uid` is set.
pub(crate) async fn build_message(
    account: &AccountState,
    from_addr: &str,
    input: &ComposeInput,
) -> Result<Vec<u8>, rimap_core::RimapError> {
    let builder = build_message_headers(from_addr, input);

    let builder = if let Some(reply_uid) = input.in_reply_to_uid {
        Box::pin(apply_threading_headers(
            account,
            builder,
            reply_uid,
            input.in_reply_to_folder.as_deref(),
        ))
        .await?
    } else {
        builder
    };

    builder
        .write_to_vec()
        .map_err(|e| rimap_core::RimapError::InternalSourced {
            message: "failed to build message".into(),
            source: Box::new(e),
        })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use mail_builder::MessageBuilder;
    use mail_builder::headers::address::Address;
    use mail_builder::headers::message_id::MessageId;

    use super::{
        AddressInput, ComposeInput, addresses_to_builder, cap_references, validate_compose_input,
    };

    /// Build a minimal draft, parse it, verify headers round-trip.
    #[test]
    fn round_trip_simple_draft() {
        let input = ComposeInput {
            to: vec![AddressInput {
                name: Some("Bob".into()),
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![AddressInput {
                name: None,
                address: "cc@example.com".into(),
            }]),
            bcc: None,
            subject: "Test subject".into(),
            body_text: "Hello, world!".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };

        let builder = super::build_message_headers("alice@example.com", &input);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        let from = parsed.from().unwrap().first().unwrap();
        assert_eq!(from.address().unwrap(), "alice@example.com");

        let to = parsed.to().unwrap().first().unwrap();
        assert_eq!(to.name().unwrap(), "Bob");
        assert_eq!(to.address().unwrap(), "bob@example.com");

        let cc = parsed.cc().unwrap().first().unwrap();
        assert_eq!(cc.address().unwrap(), "cc@example.com");

        assert_eq!(parsed.subject().unwrap(), "Test subject");
        assert_eq!(parsed.body_text(0).unwrap().as_ref(), "Hello, world!");
        assert!(parsed.message_id().is_some());
    }

    /// Build an "original" message, then a reply, verify threading.
    #[test]
    fn threading_headers_round_trip() {
        let original = MessageBuilder::new()
            .from("sender@example.com")
            .to("me@example.com")
            .message_id("original-id-123@example.com")
            .references(MessageId::new_list(["root-id@example.com"].into_iter()))
            .subject("Original")
            .text_body("original body")
            .write_to_vec()
            .unwrap();

        let parsed_original = mail_parser::MessageParser::new().parse(&original).unwrap();

        let orig_msg_id = parsed_original.message_id().unwrap();
        assert_eq!(orig_msg_id, "original-id-123@example.com");

        let mut ref_ids: Vec<String> = Vec::new();
        match parsed_original.references() {
            mail_parser::HeaderValue::Text(t) => {
                ref_ids.push(t.to_string());
            }
            mail_parser::HeaderValue::TextList(list) => {
                for r in list {
                    ref_ids.push(r.to_string());
                }
            }
            _ => {}
        }
        ref_ids.push(orig_msg_id.to_string());

        let reply = MessageBuilder::new()
            .from("me@example.com")
            .to("sender@example.com")
            .subject("Re: Original")
            .text_body("reply body")
            .in_reply_to(orig_msg_id.to_string())
            .references(MessageId::new_list(ref_ids.into_iter()))
            .write_to_vec()
            .unwrap();

        let parsed_reply = mail_parser::MessageParser::new().parse(&reply).unwrap();

        let in_reply_to = parsed_reply.in_reply_to();
        assert_eq!(
            in_reply_to.as_text().unwrap(),
            "original-id-123@example.com"
        );

        match parsed_reply.references() {
            mail_parser::HeaderValue::TextList(list) => {
                let refs: Vec<&str> = list.iter().map(AsRef::as_ref).collect();
                assert_eq!(
                    refs,
                    vec!["root-id@example.com", "original-id-123@example.com",]
                );
            }
            other => {
                panic!("expected TextList for References, got {other:?}")
            }
        }
    }

    /// Multiple To addresses produce a single To header with all
    /// addresses.
    #[test]
    fn multiple_to_addresses() {
        let addrs = vec![
            AddressInput {
                name: Some("A".into()),
                address: "a@example.com".into(),
            },
            AddressInput {
                name: None,
                address: "b@example.com".into(),
            },
        ];
        let addr = addresses_to_builder(&addrs);
        let builder = MessageBuilder::new()
            .from("from@example.com")
            .to(addr)
            .subject("multi")
            .text_body("body");
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        let to_addrs = parsed.to().unwrap();
        let list = to_addrs.as_list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].address().unwrap(), "a@example.com");
        assert_eq!(list[1].address().unwrap(), "b@example.com");
    }

    /// Single address does not wrap in a list.
    #[test]
    fn single_address_no_list_wrap() {
        let addrs = vec![AddressInput {
            name: None,
            address: "solo@example.com".into(),
        }];
        let addr = addresses_to_builder(&addrs);
        if let Address::Address(email) = &addr {
            assert_eq!(email.email, "solo@example.com");
        } else {
            panic!("expected Address::Address for single input");
        }
    }

    fn make_input(to: Vec<AddressInput>) -> ComposeInput {
        ComposeInput {
            to,
            cc: None,
            bcc: None,
            subject: "Test".into(),
            body_text: "body".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn crlf_in_address_rejected() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "a@b>\r\nBcc: spy@evil".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn crlf_in_name_rejected() {
        let input = make_input(vec![AddressInput {
            name: Some("Evil\r\nBcc: spy@evil".into()),
            address: "ok@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn angle_brackets_in_address_rejected() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "<injected>@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn empty_to_rejected() {
        let input = make_input(vec![]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
        assert!(
            err.to_string().contains("at least one To"),
            "unexpected message: {err}",
        );
    }

    #[test]
    fn subject_crlf_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "Hello\r\nBcc: spy@evil".into();
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn cc_address_validated() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.cc = Some(vec![AddressInput {
            name: None,
            address: "bad\n@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn message_id_uses_from_domain() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "bob@example.com".into(),
        }]);
        let builder = super::build_message_headers("alice@secret-host.internal", &input);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        let mid = parsed.message_id().unwrap();
        assert!(
            mid.ends_with("@secret-host.internal"),
            "Message-ID should use from domain: {mid}",
        );
    }

    #[test]
    fn valid_input_passes() {
        let input = make_input(vec![AddressInput {
            name: Some("Bob".into()),
            address: "bob@example.com".into(),
        }]);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn references_chain_capped_at_50() {
        let refs: Vec<String> = (0..200).map(|i| format!("msg-{i}@example.com")).collect();
        let capped = cap_references(refs);
        assert_eq!(capped.len(), 50);
        assert_eq!(capped[0], "msg-0@example.com");
        assert_eq!(capped[49], "msg-199@example.com");
    }

    #[test]
    fn references_chain_under_cap_unchanged() {
        let refs: Vec<String> = (0..10).map(|i| format!("msg-{i}@example.com")).collect();
        let capped = cap_references(refs);
        assert_eq!(capped.len(), 10);
    }

    #[test]
    fn too_many_recipients_rejected() {
        let addrs: Vec<AddressInput> = (0..101)
            .map(|i| AddressInput {
                name: None,
                address: format!("user{i}@example.com"),
            })
            .collect();
        let input = make_input(addrs);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn too_many_recipients_across_fields_rejected() {
        let to: Vec<AddressInput> = (0..50)
            .map(|i| AddressInput {
                name: None,
                address: format!("to{i}@example.com"),
            })
            .collect();
        let cc: Vec<AddressInput> = (0..30)
            .map(|i| AddressInput {
                name: None,
                address: format!("cc{i}@example.com"),
            })
            .collect();
        let bcc: Vec<AddressInput> = (0..21)
            .map(|i| AddressInput {
                name: None,
                address: format!("bcc{i}@example.com"),
            })
            .collect();
        let mut input = make_input(to);
        input.cc = Some(cc);
        input.bcc = Some(bcc);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn exactly_max_recipients_accepted() {
        let addrs: Vec<AddressInput> = (0..100)
            .map(|i| AddressInput {
                name: None,
                address: format!("user{i}@example.com"),
            })
            .collect();
        let input = make_input(addrs);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn subject_too_long_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "x".repeat(1001);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn subject_at_max_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "x".repeat(1000);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn body_too_large_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.body_text = "x".repeat(1_048_577);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn body_at_max_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.body_text = "x".repeat(1_048_576);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn in_reply_to_folder_with_crlf_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("bad\r\nfolder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_with_null_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("bad\0folder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_valid_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("INBOX".into());
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn empty_cc_does_not_panic() {
        let input = ComposeInput {
            to: vec![AddressInput {
                name: None,
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![]),
            bcc: Some(vec![]),
            subject: "Test".into(),
            body_text: "body".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };
        validate_compose_input(&input).unwrap();
        let builder = super::build_message_headers("alice@example.com", &input);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(parsed.cc().is_none());
        assert!(parsed.bcc().is_none());
    }
}
