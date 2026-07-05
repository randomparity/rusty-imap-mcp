//! `LIST`, `STATUS`, `SELECT` / `EXAMINE` against an active `async-imap` session.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::{Folder, FolderAttribute, FolderStatus, SelectedFolder, StatusItems};

/// Validate a mailbox name returned by the server BEFORE it flows into
/// subsequent IMAP commands or MCP responses.
///
/// Rejects NUL and all C0/C1 control characters (`\x01`–`\x1f`, `\x7f`).
/// Bidi override and zero-width characters are NOT rejected here —
/// `rimap-server` sanitizes them at the response boundary via
/// `rimap_content::unicode::sanitize`, which surfaces them as warnings
/// rather than dropping the folder.
///
/// # Errors
/// Returns `ImapError::Protocol` with a descriptive message if the name
/// contains a disallowed control character.
pub(crate) fn validate_server_folder_name(name: &str) -> Result<(), ImapError> {
    for (i, b) in name.bytes().enumerate() {
        if b == 0 || b < 0x20 || b == 0x7f {
            return Err(ImapError::Protocol(async_imap::error::Error::Bad(format!(
                "server returned mailbox name containing control \
                     byte 0x{b:02x} at offset {i}"
            ))));
        }
    }
    Ok(())
}

pub(crate) async fn list(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<Folder>, ImapError> {
    let mut stream = session
        .list(Some(""), Some(pattern))
        .await
        .map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(name) = stream.next().await {
        let name = name.map_err(map_err)?;
        let folder_name = name.name().to_string();
        // Validate server-returned name. Drop names with control bytes
        // — logged at warn level so operators see malformed LIST
        // responses without losing the whole call. #95.
        if let Err(e) = validate_server_folder_name(&folder_name) {
            tracing::warn!(
                error = %e,
                "dropping LIST entry with invalid mailbox name",
            );
            continue;
        }
        let attrs = name.attributes();
        let special_use = crate::special_use::classify_special_use(attrs);
        out.push(Folder {
            name: folder_name,
            attributes: attrs
                .iter()
                .map(FolderAttribute::from_name_attribute)
                .collect(),
            delimiter: name.delimiter().and_then(|s| s.chars().next()),
            special_use,
        });
    }
    Ok(out)
}

pub(crate) async fn status(
    session: &mut ImapSession,
    folder: &str,
    items: StatusItems,
) -> Result<FolderStatus, ImapError> {
    validate_server_folder_name(folder)?;
    let item_str = build_status_items(items);
    let mailbox = session.status(folder, &item_str).await.map_err(map_err)?;
    // STATUS response populates only the requested fields.
    // The async-imap Mailbox type uses u32 for exists/recent (from SELECT),
    // but STATUS might not return them. We map them to Option<u32> for our API.
    Ok(FolderStatus {
        messages: if items.messages {
            Some(mailbox.exists)
        } else {
            None
        },
        recent: if items.recent {
            Some(mailbox.recent)
        } else {
            None
        },
        uid_next: mailbox.uid_next,
        uid_validity: mailbox.uid_validity,
        unseen: mailbox.unseen,
    })
}

/// LIST + STATUS combined, using a LIST-then-STATUS-per-folder pass
/// (async-imap does not yet expose the RFC 5819 extended LIST command).
///
/// Returns (folder, status) pairs. `status` is `None` for non-selectable
/// folders.
///
/// # Errors
/// Propagates `ImapError` from LIST / STATUS.
pub(crate) async fn list_with_status(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<(Folder, Option<FolderStatus>)>, ImapError> {
    let folders = list(session, pattern).await?;
    let mut out = Vec::with_capacity(folders.len());
    for folder in folders {
        let folder_status = if folder.selectable() {
            let items = StatusItems {
                messages: true,
                recent: false,
                uid_next: false,
                uid_validity: true,
                unseen: true,
            };
            Some(status(session, &folder.name, items).await?)
        } else {
            None
        };
        out.push((folder, folder_status));
    }
    Ok(out)
}

pub(crate) async fn select(
    session: &mut ImapSession,
    folder: &str,
    read_only: bool,
) -> Result<SelectedFolder, ImapError> {
    validate_server_folder_name(folder)?;
    let mailbox = if read_only {
        session.examine(folder).await.map_err(map_err)?
    } else {
        session.select(folder).await.map_err(map_err)?
    };
    Ok(SelectedFolder {
        name: folder.to_string(),
        exists: mailbox.exists,
        recent: mailbox.recent,
        uid_validity: mailbox.uid_validity,
        uid_next: mailbox.uid_next,
        read_only,
    })
}

fn build_status_items(items: StatusItems) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(5);
    if items.messages {
        parts.push("MESSAGES");
    }
    if items.recent {
        parts.push("RECENT");
    }
    if items.uid_next {
        parts.push("UIDNEXT");
    }
    if items.uid_validity {
        parts.push("UIDVALIDITY");
    }
    if items.unseen {
        parts.push("UNSEEN");
    }
    format!("({})", parts.join(" "))
}

/// Classify an async-imap error into our `ImapError` taxonomy.
///
/// Checks async-imap's payload-less `Error::ConnectionLost` variant first —
/// emitted on idle-EOF / graceful stream close, with no `Io` payload or
/// source chain to inspect — then walks the `std::error::Error::source()`
/// chain looking for a `std::io::Error` whose `ErrorKind` indicates a dead
/// TCP connection (`ConnectionReset`, `ConnectionAborted`, `BrokenPipe`,
/// `UnexpectedEof`, `NotConnected`). Those surface as `ConnectionLost` so the
/// caller can drop the cached session and lazy-reconnect on the next op.
/// Anything else becomes `Protocol`.
///
/// The previous implementation substring-matched the lowercased `Display`
/// text, which missed async-imap's `Io(BrokenPipe)` formatting (the text
/// "I/O error: Broken pipe" does not contain the word "connection") and
/// left the session cached in a dead state. See #38 for the follow-up.
///
/// Before the `ConnectionLost` arm was added (#449), the unit variant fell
/// through to `Protocol`, which `with_session`'s invalidation set excludes —
/// the dead session stayed cached until process restart.
pub(super) fn map_err(err: async_imap::error::Error) -> ImapError {
    if is_connection_lost(&err) {
        ImapError::ConnectionLost
    } else {
        ImapError::Protocol(err)
    }
}

fn is_connection_lost(err: &async_imap::error::Error) -> bool {
    use std::error::Error as _;

    // async-imap's payload-less unit variant, emitted on idle-EOF / graceful
    // stream close. It carries no `Io` payload and no source chain, so it
    // must be checked explicitly rather than falling into the chain walk
    // below.
    if matches!(err, async_imap::error::Error::ConnectionLost) {
        return true;
    }

    // Check the top-level error first — async-imap's `Io` variant wraps
    // the `io::ImapError` directly.
    if let async_imap::error::Error::Io(io_err) = err
        && is_dead_tcp_kind(io_err.kind())
    {
        return true;
    }

    // Otherwise walk the source chain in case a future async-imap version
    // wraps the io::ImapError more deeply.
    let mut src: Option<&(dyn std::error::Error + 'static)> = err.source();
    while let Some(cause) = src {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>()
            && is_dead_tcp_kind(io_err.kind())
        {
            return true;
        }
        src = cause.source();
    }

    false
}

#[expect(
    clippy::match_like_matches_macro,
    reason = "explicit match names the dead-TCP kinds for documentation; \
              ErrorKind is #[non_exhaustive] so the open arm is required anyway"
)]
fn is_dead_tcp_kind(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof
        | ErrorKind::NotConnected => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_items_empty_selection_renders_empty_parens() {
        let items = StatusItems {
            messages: false,
            recent: false,
            uid_next: false,
            uid_validity: false,
            unseen: false,
        };
        assert_eq!(build_status_items(items), "()");
    }

    #[test]
    fn status_items_preserves_canonical_order() {
        // IMAP STATUS items are space-separated and not order-sensitive per
        // RFC 3501, but this op always emits in the declared struct order
        // so the wire format is stable for golden tests.
        let items = StatusItems {
            messages: true,
            recent: true,
            uid_next: true,
            uid_validity: true,
            unseen: true,
        };
        assert_eq!(
            build_status_items(items),
            "(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)"
        );
    }

    #[test]
    fn status_items_single_flag_emits_single_token() {
        let items = StatusItems {
            messages: false,
            recent: false,
            uid_next: true,
            uid_validity: false,
            unseen: false,
        };
        assert_eq!(build_status_items(items), "(UIDNEXT)");
    }

    #[test]
    fn is_dead_tcp_kind_covers_documented_dead_kinds() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::NotConnected,
        ] {
            assert!(is_dead_tcp_kind(kind), "expected dead: {kind:?}");
        }
    }

    #[test]
    fn is_dead_tcp_kind_rejects_non_dead_kinds() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::Other,
        ] {
            assert!(!is_dead_tcp_kind(kind), "expected alive: {kind:?}");
        }
    }

    #[test]
    fn map_err_routes_io_broken_pipe_to_connection_lost() {
        // Regression: the previous substring matcher missed async-imap's
        // Io(BrokenPipe) formatting because "I/O error: Broken pipe" does
        // not contain the word "connection". Guard that here.
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        let mapped = map_err(async_imap::error::Error::Io(io));
        assert!(matches!(mapped, ImapError::ConnectionLost));
    }

    #[test]
    fn map_err_routes_io_timed_out_to_protocol() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let mapped = map_err(async_imap::error::Error::Io(io));
        assert!(matches!(mapped, ImapError::Protocol(_)));
    }

    #[test]
    fn map_err_routes_bad_response_to_protocol() {
        let mapped = map_err(async_imap::error::Error::Bad("BAD".to_string()));
        assert!(matches!(mapped, ImapError::Protocol(_)));
    }

    #[test]
    fn map_err_routes_connection_lost_unit_variant_to_connection_lost() {
        // Regression for #449: async-imap 0.11.2 emits the payload-less
        // `Error::ConnectionLost` on idle-EOF / graceful stream close. It has
        // no `Io` payload and no source chain, so the old `is_connection_lost`
        // (which only inspected `Error::Io` and its source chain) fell
        // through to `ImapError::Protocol`, which is excluded from
        // `with_session`'s invalidation set — the dead session stayed cached
        // forever. Assert the unit variant is classified as
        // `ImapError::ConnectionLost` so the caller drops and reconnects.
        let mapped = map_err(async_imap::error::Error::ConnectionLost);
        assert!(matches!(mapped, ImapError::ConnectionLost));
    }

    #[test]
    fn validate_server_folder_name_rejects_nul() {
        let result = super::validate_server_folder_name("INBOX\0");
        assert!(matches!(result, Err(ImapError::Protocol(_))));
    }

    #[test]
    fn validate_server_folder_name_rejects_c0_c1() {
        for bad in ["\x01INBOX", "INBOX\x1f", "INBOX\x7f", "A\x0aB"] {
            let result = super::validate_server_folder_name(bad);
            assert!(
                matches!(result, Err(ImapError::Protocol(_))),
                "bad = {bad:?}"
            );
        }
    }

    #[test]
    fn validate_server_folder_name_accepts_normal() {
        assert!(super::validate_server_folder_name("INBOX").is_ok());
        assert!(super::validate_server_folder_name("[Gmail]/All Mail").is_ok());
        assert!(super::validate_server_folder_name("Folder with spaces").is_ok());
        // Bidi / ZWJ are accepted here (baseline permissive); Task 6 handles
        // them downstream via rimap_content::unicode::sanitize.
        assert!(super::validate_server_folder_name("folder\u{202e}txt").is_ok());
    }
}
