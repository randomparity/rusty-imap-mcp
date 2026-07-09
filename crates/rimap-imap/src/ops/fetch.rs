//! `FETCH ENVELOPE BODYSTRUCTURE UID FLAGS RFC822.SIZE`. The streaming
//! `FETCH BODY[]` path is in Task 13.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::{Address, BodyStructure, Envelope, FetchSpec, FetchedMessage, MessageId, Uid};

/// Maximum BODYSTRUCTURE nesting depth before we refuse to descend.
/// Real-world MIME almost never exceeds ~10 levels; 64 is a generous
/// `DoS` guard that still covers legitimate deeply-nested forwarded
/// messages and `message/rfc822` chains.
const MAX_BODYSTRUCTURE_DEPTH: u32 = 64;

/// Maximum parts in a single Multipart before we truncate. Protects
/// against pathological `multipart/mixed` with millions of children.
const MAX_MULTIPART_PARTS: usize = 1024;

/// Compress a slice of UIDs into IMAP `sequence-set` range syntax per
/// RFC 3501 §9. Runs of two or more contiguous UIDs become `start:end`;
/// isolated UIDs stay as bare numbers. Sorts the input first because
/// callers may pass unsorted UIDs.
///
/// Examples:
/// - `[]`              → `""`
/// - `[42]`            → `"42"`
/// - `[1, 3]`          → `"1,3"`
/// - `[1, 2, 3]`       → `"1:3"`
/// - `[1,2,3,5,7,8,9]` → `"1:3,5,7:9"`
fn compress_uid_set(uids: &[Uid]) -> String {
    if uids.is_empty() {
        return String::new();
    }

    let mut sorted: Vec<u32> = uids.iter().map(|u| u.get()).collect();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = String::new();
    let mut run_start = sorted[0];
    let mut run_end = sorted[0];

    for &uid in &sorted[1..] {
        // `run_end + 1` cannot overflow because `sorted` is monotonically
        // increasing after `sort_unstable + dedup`, so any `uid` that
        // compares equal to `run_end + 1` must satisfy `run_end < uid`,
        // which means `run_end < u32::MAX`. Use `checked_add` to make the
        // invariant explicit and to future-proof against a refactor
        // changing the input type.
        if run_end.checked_add(1) != Some(uid) {
            emit_run(&mut out, run_start, run_end);
            run_start = uid;
        }
        run_end = uid;
    }
    emit_run(&mut out, run_start, run_end);
    out
}

fn emit_run(out: &mut String, start: u32, end: u32) {
    use std::fmt::Write as _;
    if !out.is_empty() {
        out.push(',');
    }
    if start == end {
        let _ = write!(out, "{start}");
    } else {
        let _ = write!(out, "{start}:{end}");
    }
}

/// Verify an optional UIDVALIDITY expectation against the server-observed value.
///
/// Returns `Err(ImapError::UidValidityChanged)` when `expected` is `Some(v)` and
/// `observed` is `Some(actual)` with `actual != v`. When `observed` is `None`, the
/// server omitted the value: a warning is emitted and the guard is skipped. When
/// `expected` is `None`, the call is a no-op.
pub(crate) fn check_uidvalidity(
    folder: &str,
    expected: Option<u32>,
    observed: Option<u32>,
) -> Result<(), ImapError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match observed {
        Some(actual) if actual != expected => Err(ImapError::UidValidityChanged {
            folder: folder.to_owned(),
            expected,
            actual,
        }),
        None => {
            tracing::warn!(
                folder = %folder,
                expected,
                "expected_uidvalidity set but server omitted UIDVALIDITY; \
                 proceeding without guard",
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Like [`check_uidvalidity`] but **fail-closed**: when `expected` is set,
/// an absent observed UIDVALIDITY is an error, not a warning.
pub(crate) fn require_uidvalidity(
    folder: &str,
    expected: Option<u32>,
    observed: Option<u32>,
) -> Result<(), ImapError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match observed {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ImapError::UidValidityChanged {
            folder: folder.to_owned(),
            expected,
            actual,
        }),
        None => Err(ImapError::UidValidityUnavailable {
            folder: folder.to_owned(),
        }),
    }
}

pub(crate) async fn fetch(
    session: &mut ImapSession,
    folder: &str,
    uids: &[Uid],
    spec: FetchSpec,
    expected_uidvalidity: Option<u32>,
) -> Result<(Vec<FetchedMessage>, Option<u32>), ImapError> {
    let selected = super::folders::select(session, folder, true).await?;
    let uid_validity = selected.uid_validity;

    check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;

    if uids.is_empty() {
        return Ok((Vec::new(), uid_validity));
    }
    // Compress to IMAP sequence-set range syntax to stay under Dovecot's
    // ~8KB command-line cap. Plain comma-joined lists exceed the cap
    // around ~2000 UIDs.
    let uid_set = compress_uid_set(uids);

    let items = build_fetch_items(spec);
    let mut stream = session
        .uid_fetch(&uid_set, &items)
        .await
        .map_err(super::folders::map_err)?;

    // Policy: warn-and-continue on a per-item missing/zero UID, rather than
    // fail-closed. This is deliberately different from the fail-closed
    // UIDVALIDITY handling in `require_uidvalidity` (used by the body/size
    // paths): a missing UIDVALIDITY breaks the anti-reuse guard for the whole
    // response, so it must fail closed, whereas a single item with an absent or
    // zero UID only costs that one message and is recoverable by skipping it.
    // The aggregated `warn!` below is the operator-facing signal; the tool
    // result the agent sees is intentionally unchanged (issue #518 specifies
    // "skip-with-warning", and the fetch tool contract is a non-goal here).
    // Consequence: a hostile server can make a folder appear to hold fewer
    // messages by omitting/zeroing UIDs, visible only in the operator log — an
    // accepted, documented risk; surfacing the drop in-band to the agent is a
    // possible follow-up, not part of this change.
    let mut out = Vec::with_capacity(uids.len());
    let mut skipped_uids: u64 = 0;
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        let Some(uid_raw) = msg.uid else {
            skipped_uids += 1;
            continue;
        };
        let Some(uid) = Uid::new(uid_raw) else {
            skipped_uids += 1;
            continue;
        };

        let envelope = if spec.envelope {
            convert_envelope(msg.envelope())
        } else {
            None
        };
        let bodystructure = if spec.bodystructure {
            convert_bodystructure(msg.bodystructure())
        } else {
            None
        };
        let flags = if spec.flags {
            Some(msg.flags().map(|f| convert_flag(&f)).collect())
        } else {
            None
        };
        let size = if spec.size { msg.size } else { None };

        out.push(FetchedMessage {
            uid,
            envelope,
            bodystructure,
            flags,
            size,
        });
    }
    if skipped_uids > 0 {
        tracing::warn!(
            folder = %folder,
            skipped_uids,
            "FETCH response omitted or zeroed the UID on one or more items; \
             skipping them (possible malformed or hostile server)",
        );
    }
    Ok((out, uid_validity))
}

/// Fetch the full `BODY[]` of a single UID. Aborts with `ImapError::SizeLimit`
/// if the projected total would exceed `limit`. The caller MUST drop the
/// session on overflow — the IMAP response state is half-consumed and
/// cannot be reused.
///
/// # Errors
/// - `ImapError::SizeLimit { limit }` if the body exceeds `limit` bytes.
/// - `ImapError::Protocol(_)` if the server returned no body data for the UID.
/// - `ImapError::ConnectionLost` if the underlying transport tore down.
/// - Other `async-imap` errors propagated through `super::folders::map_err`.
///
/// NOTE: This is the **defense-in-depth fallback**. The primary size
/// enforcement is `preflight_fetch_size` + `preflight_size_check`,
/// which rejects oversize messages before the body fetch begins.
/// This post-parse check catches the case where the server
/// misreports `RFC822.SIZE`. `async-imap` delivers each `Fetch`
/// response as a parsed unit, so the body bytes are already in
/// memory before this check fires.
pub(crate) async fn fetch_body(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    limit: u64,
    expected_uidvalidity: Option<u32>,
) -> Result<Vec<u8>, ImapError> {
    let selected = super::folders::select(session, folder, true).await?;
    require_uidvalidity(folder, expected_uidvalidity, selected.uid_validity)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "BODY.PEEK[]")
        .await
        .map_err(super::folders::map_err)?;

    let mut acc: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    let mut found = false;

    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        if let Some(body) = msg.body() {
            found = true;
            let new_total = project_size(total, body.len(), limit)?;
            acc.extend_from_slice(body);
            total = new_total;
        }
    }

    if !found {
        return Err(ImapError::Protocol(async_imap::error::Error::Bad(
            "FETCH BODY[] returned no body".to_string(),
        )));
    }
    Ok(acc)
}

/// Projection helper: extend `total` by `chunk` and return the new total,
/// or `Err(ImapError::SizeLimit { limit })` if it would exceed `limit`.
/// Saturates `chunk` at `u64::MAX` to handle hypothetical platforms where
/// `usize > u64`.
fn project_size(total: u64, chunk: usize, limit: u64) -> Result<u64, ImapError> {
    let chunk_u64 = u64::try_from(chunk).unwrap_or(u64::MAX);
    let projected = total.saturating_add(chunk_u64);
    if projected > limit {
        Err(ImapError::SizeLimit { limit })
    } else {
        Ok(projected)
    }
}

/// Check whether a server-reported `RFC822.SIZE` exceeds `limit`.
/// Returns `Ok(())` when the size is absent (server did not report it)
/// or within the limit. Returns `Err(ImapError::SizeLimit)` when the
/// reported size strictly exceeds `limit`.
pub(crate) fn preflight_size_check(server_size: Option<u32>, limit: u64) -> Result<(), ImapError> {
    if let Some(size) = server_size
        && u64::from(size) > limit
    {
        return Err(ImapError::SizeLimit { limit });
    }
    Ok(())
}

/// Issue `UID FETCH <uid> (RFC822.SIZE)` and return the server-reported
/// size, or `None` if the server omitted it.
pub(crate) async fn preflight_fetch_size(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    expected_uidvalidity: Option<u32>,
) -> Result<Option<u32>, ImapError> {
    let selected = super::folders::select(session, folder, true).await?;
    require_uidvalidity(folder, expected_uidvalidity, selected.uid_validity)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "RFC822.SIZE")
        .await
        .map_err(super::folders::map_err)?;

    let mut size: Option<u32> = None;
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        if msg.uid == Some(uid.get()) {
            size = msg.size;
        }
    }
    Ok(size)
}

fn build_fetch_items(spec: FetchSpec) -> String {
    let mut parts: Vec<&str> = vec!["UID"]; // always request UID
    if spec.envelope {
        parts.push("ENVELOPE");
    }
    if spec.bodystructure {
        parts.push("BODYSTRUCTURE");
    }
    if spec.flags {
        parts.push("FLAGS");
    }
    if spec.size {
        parts.push("RFC822.SIZE");
    }
    format!("({})", parts.join(" "))
}

// ENVELOPE conversion.
fn convert_envelope(env: Option<&async_imap::imap_proto::Envelope<'_>>) -> Option<Envelope> {
    let env = env?;
    Some(Envelope {
        date: env.date.as_ref().map(|b| b.to_vec()),
        subject_raw: env.subject.as_ref().map(|b| b.to_vec()),
        from: convert_addresses(env.from.as_deref()),
        sender: convert_addresses(env.sender.as_deref()),
        reply_to: convert_addresses(env.reply_to.as_deref()),
        to: convert_addresses(env.to.as_deref()),
        cc: convert_addresses(env.cc.as_deref()),
        bcc: convert_addresses(env.bcc.as_deref()),
        in_reply_to: env.in_reply_to.as_ref().map(|b| b.to_vec()),
        message_id: env.message_id.as_ref().map(|b| MessageId::new(b.to_vec())),
    })
}

fn convert_addresses(addrs: Option<&[async_imap::imap_proto::Address<'_>]>) -> Vec<Address> {
    addrs
        .unwrap_or(&[])
        .iter()
        .map(|a| Address {
            name: a.name.as_ref().map(|b| b.to_vec()),
            adl: a.adl.as_ref().map(|b| b.to_vec()),
            mailbox: a.mailbox.as_ref().map(|b| b.to_vec()),
            host: a.host.as_ref().map(|b| b.to_vec()),
        })
        .collect()
}

// BODYSTRUCTURE recursive conversion. Walk the imap_proto BodyStructure enum
// and produce our own BodyStructure type.
fn convert_bodystructure(
    bs: Option<&async_imap::imap_proto::BodyStructure<'_>>,
) -> Option<BodyStructure> {
    bs.map(|b| convert_bs_inner(b, 0))
}

/// Recursively convert an `imap_proto::BodyStructure` into our own type.
///
/// Depth and breadth caps prevent stack overflow and excessive allocation from
/// hostile IMAP servers:
/// - Nesting beyond [`MAX_BODYSTRUCTURE_DEPTH`] (64) returns a synthetic
///   `application/octet-stream` sentinel instead of recursing further.
/// - Multipart bodies with more than [`MAX_MULTIPART_PARTS`] (1024) children
///   are silently truncated at the cap.
fn convert_bs_inner(
    bs: &async_imap::imap_proto::BodyStructure<'_>,
    depth: u32,
) -> crate::types::BodyStructure {
    use async_imap::imap_proto::BodyStructure as ImapProtoBodyStructure;

    if depth >= MAX_BODYSTRUCTURE_DEPTH {
        // Truncate — return a synthetic leaf so the rest of the tree still
        // round-trips without propagating an error all the way out.
        return crate::types::BodyStructure::Single {
            mime_type: "application".to_string(),
            mime_subtype: "octet-stream".to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size: 0,
        };
    }

    match bs {
        ImapProtoBodyStructure::Multipart {
            common,
            bodies,
            extension: _,
        } => {
            let subtype = common.ty.subtype.to_string();
            let parts = bodies
                .iter()
                .take(MAX_MULTIPART_PARTS)
                .map(|b| convert_bs_inner(b, depth + 1))
                .collect();
            crate::types::BodyStructure::Multipart { subtype, parts }
        }
        ImapProtoBodyStructure::Basic {
            common,
            other,
            extension: _,
        }
        | ImapProtoBodyStructure::Text {
            common,
            other,
            lines: _,
            extension: _,
        } => {
            let mime_type = common.ty.ty.to_string();
            let mime_subtype = common.ty.subtype.to_string();
            let params = common
                .ty
                .params
                .as_ref()
                .map(|p| {
                    p.iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let encoding = match &other.transfer_encoding {
                async_imap::imap_proto::ContentEncoding::SevenBit => "7bit".to_string(),
                async_imap::imap_proto::ContentEncoding::EightBit => "8bit".to_string(),
                async_imap::imap_proto::ContentEncoding::Binary => "binary".to_string(),
                async_imap::imap_proto::ContentEncoding::Base64 => "base64".to_string(),
                async_imap::imap_proto::ContentEncoding::QuotedPrintable => {
                    "quoted-printable".to_string()
                }
                async_imap::imap_proto::ContentEncoding::Other(s) => s.to_string(),
            };
            let size = other.octets;
            crate::types::BodyStructure::Single {
                mime_type,
                mime_subtype,
                params,
                encoding,
                size,
            }
        }
        ImapProtoBodyStructure::Message { common, body, .. } => {
            let mime_subtype = common.ty.subtype.to_string();
            crate::types::BodyStructure::Message {
                mime_subtype,
                body: Box::new(convert_bs_inner(body, depth + 1)),
            }
        }
    }
}

// FLAG conversion. Match against the typed async_imap::types::Flag enum.
fn convert_flag(f: &async_imap::types::Flag<'_>) -> crate::types::Flag {
    use async_imap::types::Flag as AsyncImapFlag;

    match f {
        AsyncImapFlag::Seen => crate::types::Flag::Seen,
        AsyncImapFlag::Answered => crate::types::Flag::Answered,
        AsyncImapFlag::Flagged => crate::types::Flag::Flagged,
        AsyncImapFlag::Deleted => crate::types::Flag::Deleted,
        AsyncImapFlag::Draft => crate::types::Flag::Draft,
        AsyncImapFlag::Recent => crate::types::Flag::Recent,
        AsyncImapFlag::MayCreate => crate::types::Flag::Keyword("\\*".to_string()),
        AsyncImapFlag::Custom(s) => crate::types::Flag::Keyword(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_BODYSTRUCTURE_DEPTH, check_uidvalidity, compress_uid_set, convert_bs_inner,
        preflight_size_check, project_size, require_uidvalidity,
    };
    use crate::error::ImapError;
    use crate::types::tests::uid;
    use async_imap::imap_proto::{
        BodyContentCommon, BodyContentSinglePart, BodyStructure as ImapProtoBodyStructure,
        ContentEncoding, ContentType,
    };
    use std::borrow::Cow;

    fn make_basic_leaf() -> ImapProtoBodyStructure<'static> {
        ImapProtoBodyStructure::Basic {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("text"),
                    subtype: Cow::Borrowed("plain"),
                    params: None,
                },
                disposition: None,
                language: None,
                location: None,
            },
            other: BodyContentSinglePart {
                id: None,
                md5: None,
                description: None,
                transfer_encoding: ContentEncoding::SevenBit,
                octets: 42,
            },
            extension: None,
        }
    }

    #[test]
    #[expect(clippy::panic, reason = "test")]
    fn convert_bs_inner_preserves_message_variant_with_nested_body() {
        // Construct an inner Basic text/plain part
        let inner_bs = make_basic_leaf();

        // Construct a Message body with the Basic part inside
        let msg_bs = ImapProtoBodyStructure::Message {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("message"),
                    subtype: Cow::Borrowed("rfc822"),
                    params: None,
                },
                disposition: None,
                language: None,
                location: None,
            },
            other: BodyContentSinglePart {
                id: None,
                md5: None,
                description: None,
                transfer_encoding: ContentEncoding::SevenBit,
                octets: 1024,
            },
            envelope: async_imap::imap_proto::Envelope {
                date: None,
                subject: None,
                from: None,
                sender: None,
                reply_to: None,
                to: None,
                cc: None,
                bcc: None,
                in_reply_to: None,
                message_id: None,
            },
            body: Box::new(inner_bs),
            lines: 10,
            extension: None,
        };

        let result = convert_bs_inner(&msg_bs, 0);

        // Verify the Message variant is preserved and the nested body is intact
        match result {
            crate::types::BodyStructure::Message { mime_subtype, body } => {
                assert_eq!(mime_subtype, "rfc822");
                match body.as_ref() {
                    crate::types::BodyStructure::Single {
                        mime_type,
                        mime_subtype: inner_subtype,
                        size,
                        ..
                    } => {
                        assert_eq!(mime_type, "text");
                        assert_eq!(inner_subtype, "plain");
                        assert_eq!(*size, 42);
                    }
                    other => panic!("expected inner Single variant, got {other:?}"),
                }
            }
            other => panic!("expected Message variant, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn bodystructure_depth_cap_returns_sentinel_at_boundary() {
        // Passing depth = MAX_BODYSTRUCTURE_DEPTH directly must immediately
        // return the synthetic sentinel without recursing into the tree.
        let leaf = make_basic_leaf();
        let result = convert_bs_inner(&leaf, MAX_BODYSTRUCTURE_DEPTH);
        match result {
            crate::types::BodyStructure::Single {
                mime_type,
                mime_subtype,
                ..
            } => {
                assert_eq!(
                    mime_type, "application",
                    "expected synthetic sentinel mime_type"
                );
                assert_eq!(
                    mime_subtype, "octet-stream",
                    "expected synthetic sentinel mime_subtype"
                );
            }
            other => panic!("expected synthetic Single sentinel, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn bodystructure_depth_cap_truncates_pathological_input() {
        // Build a 100-deep Message → Message → ... → Basic chain.
        // convert_bs_inner must return without stack-overflowing, and the node
        // at depth 64 must be the synthetic sentinel.
        let mut bs = make_basic_leaf();
        for _ in 0..100 {
            bs = ImapProtoBodyStructure::Message {
                common: BodyContentCommon {
                    ty: ContentType {
                        ty: Cow::Borrowed("message"),
                        subtype: Cow::Borrowed("rfc822"),
                        params: None,
                    },
                    disposition: None,
                    language: None,
                    location: None,
                },
                other: BodyContentSinglePart {
                    id: None,
                    md5: None,
                    description: None,
                    transfer_encoding: ContentEncoding::SevenBit,
                    octets: 0,
                },
                envelope: async_imap::imap_proto::Envelope {
                    date: None,
                    subject: None,
                    from: None,
                    sender: None,
                    reply_to: None,
                    to: None,
                    cc: None,
                    bcc: None,
                    in_reply_to: None,
                    message_id: None,
                },
                body: Box::new(bs),
                lines: 0,
                extension: None,
            };
        }

        // Reaching this line without a stack overflow is the primary assertion.
        let result = convert_bs_inner(&bs, 0);

        // Navigate 64 levels deep to confirm the sentinel is there.
        let mut current = &result;
        for level in 0..MAX_BODYSTRUCTURE_DEPTH {
            match current {
                crate::types::BodyStructure::Message { body, .. } => {
                    current = body.as_ref();
                }
                crate::types::BodyStructure::Single {
                    mime_type,
                    mime_subtype,
                    ..
                } => {
                    // Hit a leaf — must be the sentinel and we must still be within cap.
                    assert_eq!(
                        mime_type, "application",
                        "sentinel mime_type wrong at level {level}"
                    );
                    assert_eq!(
                        mime_subtype, "octet-stream",
                        "sentinel mime_subtype wrong at level {level}"
                    );
                    return;
                }
                other @ crate::types::BodyStructure::Multipart { .. } => {
                    panic!("unexpected variant at level {level}: {other:?}")
                }
            }
        }
        // At depth MAX_BODYSTRUCTURE_DEPTH the next node must be the sentinel.
        match current {
            crate::types::BodyStructure::Single {
                mime_type,
                mime_subtype,
                ..
            } => {
                assert_eq!(mime_type, "application");
                assert_eq!(mime_subtype, "octet-stream");
            }
            other => panic!("expected sentinel at cap depth, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn project_size_under_limit_returns_new_total() {
        let result = project_size(100, 50, 1000).unwrap();
        assert_eq!(result, 150);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn project_size_at_exact_limit_is_accepted() {
        let result = project_size(950, 50, 1000).unwrap();
        assert_eq!(result, 1000);
    }

    #[test]
    #[expect(clippy::panic, reason = "tests")]
    fn project_size_over_limit_returns_size_limit_error() {
        let result = project_size(950, 51, 1000);
        match result {
            Err(ImapError::SizeLimit { limit }) => assert_eq!(limit, 1000),
            other => panic!("expected SizeLimit, got {other:?}"),
        }
    }

    #[test]
    fn compress_empty_input() {
        assert_eq!(compress_uid_set(&[]), "");
    }

    #[test]
    fn compress_single_uid() {
        assert_eq!(compress_uid_set(&[uid(42)]), "42");
    }

    #[test]
    fn compress_two_non_adjacent() {
        assert_eq!(compress_uid_set(&[uid(1), uid(3)]), "1,3");
    }

    #[test]
    fn compress_three_contiguous() {
        assert_eq!(compress_uid_set(&[uid(1), uid(2), uid(3)]), "1:3");
    }

    #[test]
    fn compress_mixed_runs_and_singletons() {
        let input = [uid(1), uid(2), uid(3), uid(5), uid(7), uid(8), uid(9)];
        assert_eq!(compress_uid_set(&input), "1:3,5,7:9");
    }

    #[test]
    fn compress_unsorted_input_is_sorted_first() {
        let input = [uid(9), uid(7), uid(8), uid(1), uid(2), uid(3), uid(5)];
        assert_eq!(compress_uid_set(&input), "1:3,5,7:9");
    }

    #[test]
    fn compress_duplicates_are_collapsed() {
        let input = [uid(1), uid(1), uid(2), uid(2), uid(3)];
        assert_eq!(compress_uid_set(&input), "1:3");
    }

    #[test]
    fn compress_handles_u32_max_boundary() {
        // Verify the checked_add guard: the final UID is u32::MAX, and
        // we must NOT attempt u32::MAX + 1 inside the run extension.
        let input = [uid(u32::MAX - 1), uid(u32::MAX)];
        assert_eq!(compress_uid_set(&input), "4294967294:4294967295");
    }

    #[test]
    fn compress_singleton_u32_max() {
        let input = [uid(u32::MAX)];
        assert_eq!(compress_uid_set(&input), "4294967295");
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn preflight_size_check_rejects_oversize() {
        let limit = 5_000_000;
        let result = preflight_size_check(Some(10_000_000), limit);
        match result {
            Err(ImapError::SizeLimit { limit: l }) => assert_eq!(l, limit),
            other => panic!("expected SizeLimit, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test")]
    fn preflight_size_check_accepts_within_limit() {
        preflight_size_check(Some(1_000_000), 5_000_000).unwrap();
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test")]
    fn preflight_size_check_accepts_at_exact_limit() {
        // u32::MAX fits in u64, so use a smaller example for clarity.
        let limit = 5_000_000;
        preflight_size_check(Some(5_000_000), limit).unwrap();
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test")]
    fn preflight_size_check_passes_when_server_omits_size() {
        preflight_size_check(None, 5_000_000).unwrap();
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn check_uidvalidity_none_expected_is_noop() {
        // No expected → no error, regardless of observed value.
        check_uidvalidity("INBOX", None, Some(100)).unwrap();
        check_uidvalidity("INBOX", None, None).unwrap();
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn check_uidvalidity_match_proceeds() {
        check_uidvalidity("INBOX", Some(42), Some(42)).unwrap();
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    #[expect(clippy::panic, reason = "tests")]
    fn check_uidvalidity_mismatch_returns_error() {
        let err = check_uidvalidity("INBOX", Some(42), Some(100)).unwrap_err();
        match err {
            ImapError::UidValidityChanged {
                folder,
                expected,
                actual,
            } => {
                assert_eq!(folder, "INBOX");
                assert_eq!(expected, 42);
                assert_eq!(actual, 100);
            }
            other => panic!("expected UidValidityChanged, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn check_uidvalidity_server_omitted_is_not_error() {
        // Server omitted UIDVALIDITY (None) → warn and proceed, no error.
        check_uidvalidity("INBOX", Some(42), None).unwrap();
    }

    #[test]
    fn require_uidvalidity_strict() {
        // expected=None: no-op (download_attachment path).
        assert!(require_uidvalidity("INBOX", None, None).is_ok());
        assert!(require_uidvalidity("INBOX", None, Some(7)).is_ok());
        // expected=Some: match ok, mismatch and ABSENT both error.
        assert!(require_uidvalidity("INBOX", Some(7), Some(7)).is_ok());
        assert!(matches!(
            require_uidvalidity("INBOX", Some(7), Some(8)),
            Err(crate::error::ImapError::UidValidityChanged { .. })
        ));
        assert!(matches!(
            require_uidvalidity("INBOX", Some(7), None),
            Err(crate::error::ImapError::UidValidityUnavailable { .. })
        ));
    }

    // NOTE: The round-trip parser in this proptest is a SIMPLIFIED model.
    // It splits on ',' and ':' and does not use `imap-proto`'s
    // sequence-set parser. The proptest therefore proves internal
    // consistency of `compress_uid_set` against its own inverse, not
    // server-level acceptance. Real IMAP parsers accept the same grammar
    // per RFC 3501 §9, so the internal consistency is a load-bearing
    // proxy for wire-format correctness.
    proptest::proptest! {
        #[test]
        #[expect(clippy::unwrap_used, reason = "tests")]
        fn compress_round_trip_via_split(
            // Full u32 range exercises the u32::MAX boundary (SC-FUZZ-01).
            mut uids in proptest::collection::vec(1_u32..=u32::MAX, 1..200)
        ) {
            uids.sort_unstable();
            uids.dedup();
            let typed: Vec<crate::types::Uid> =
                uids.iter().map(|n| crate::types::Uid::new(*n).unwrap()).collect();
            let compressed = compress_uid_set(&typed);

            // Parse the compressed form back into a sorted Vec<u32> and
            // assert it equals the input.
            let mut parsed: Vec<u32> = Vec::new();
            for chunk in compressed.split(',') {
                if let Some((lo, hi)) = chunk.split_once(':') {
                    let lo: u32 = lo.parse().unwrap();
                    let hi: u32 = hi.parse().unwrap();
                    for n in lo..=hi {
                        parsed.push(n);
                    }
                } else {
                    parsed.push(chunk.parse().unwrap());
                }
            }
            assert_eq!(parsed, uids);
        }
    }
}
