//! An `IMAP4rev2` (RFC 9051) advertisement is an advertisement of MOVE and
//! UIDPLUS, because RFC 9051 folds both into the base protocol and a
//! conforming server need not list either atom separately (#686).
//!
//! Read with #649's atom-by-atom logic, such a listing yields `Known { false,
//! false }` — and that pair is exactly what
//! `ops::expunge::fallback_uses_folder_wide_expunge` selects the RFC 3501
//! folder-wide `EXPUNGE` on, removing every `\Deleted` message in the mailbox
//! rather than the requested UIDs, against a server that in fact supports `UID
//! EXPUNGE`. That is the #649 data-loss path reached by a different route.
//!
//! ## Why the scripted listing carries *both* revision atoms
//!
//! Because a listing carrying only `IMAP4rev2` cannot be delivered to this
//! client at all. `imap-proto`'s `capability_data` parser (read against
//! 0.16.7, the current release) runs its result through
//! `ensure_capabilities_contains_imap4rev`, which rejects any `CAPABILITY`
//! response that does not contain the `IMAP4rev1` atom — so a rev2-only line
//! fails to parse, and the *pre-login* `CAPABILITY` command fails the connect
//! with `ImapError::Protocol` long before `read_capabilities` runs. That
//! remainder of #686 is upstream and is tracked separately; see
//! `Connection::read_capabilities`.
//!
//! `IMAP4rev1 IMAP4rev2` is the shape RFC 9051 Appendix A names for a server
//! that wants to remain compatible with `IMAP4rev1`, so it is both the reachable
//! case and a real one.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::ServerCapabilities;
use rimap_imap::types::Uid;

/// Generous command timeout so the loopback dialog cannot race a `Timeout`
/// (mirrors `capability_unknown_refusal`).
const BACKSTOP: Duration = Duration::from_secs(5);

fn uid(value: u32) -> Uid {
    Uid::from(NonZeroU32::new(value).unwrap())
}

/// A listing whose extension atoms are absent but which advertises
/// `IMAP4rev2` must be `Known { true, true }`, and the delete it serves must
/// issue the atomic `UID MOVE` rather than the COPY + folder-wide `EXPUNGE`
/// fallback.
///
/// The script carries no fallback dialog on purpose: the fallback's first
/// command is `UID COPY`, which desynchronizes against this script and fails
/// the `expect` below rather than quietly proving nothing.
#[tokio::test]
async fn a_rev2_listing_advertises_move_and_uidplus_without_naming_them() {
    let mut steps = login_preamble("IMAP4rev1 IMAP4rev2");
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        // delete_message flags `\Deleted` before moving, whichever path runs.
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "UID MOVE" },
        Step::Send(b"* OK [COPYUID 7 5 10] Moved\r\n* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK MOVE completed",
        },
    ]);

    let server = FakeImapServer::start(steps).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let (result, _uidvalidity) = conn
        .delete_message("INBOX", uid(5), "Trash", None)
        .await
        .expect("an IMAP4rev2 server supports UID MOVE whether or not it lists the atom");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: true,
            has_uidplus: true,
        },
        "RFC 9051 folds MOVE (RFC 6851) and UIDPLUS (RFC 4315) into the base \
         protocol, so an IMAP4rev2 advertisement is an advertisement of both",
    );
    assert!(
        !result.used_fallback,
        "MOVE is part of IMAP4rev2, so the non-atomic COPY fallback must not run",
    );
    assert!(
        !result.folder_wide_expunge,
        "the folder-wide EXPUNGE removes every \\Deleted message in INBOX \
         rather than UID 5, against a server that supports UID EXPUNGE",
    );

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        dialog.contains("UID MOVE"),
        "the atomic UID MOVE must reach the wire: {dialog}",
    );
    assert!(
        !dialog.contains("EXPUNGE"),
        "no EXPUNGE of any form may follow an IMAP4rev2 advertisement — the \
         atomic move needs none, and the folder-wide form is the data-loss \
         path #649 closed: {dialog}",
    );
}

/// The fold keys on the revision atom, not on "some atom we recognise". An
/// `IMAP4rev1`-only listing that names neither extension is still an
/// affirmative `neither`, and still takes the documented folder-wide fallback.
///
/// Without this, "`IMAP4rev2` implies both" and "any readable listing implies
/// both" are indistinguishable — and the second silently issues `UID MOVE` to
/// every pre-MOVE RFC 3501 server.
#[tokio::test]
async fn a_rev1_only_listing_is_unaffected_by_the_rev2_fold() {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]);

    let server = FakeImapServer::start(steps).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let (result, _uidvalidity) = conn
        .delete_message("INBOX", uid(5), "Trash", None)
        .await
        .expect("an IMAP4rev1-only server is a known state, not an unknown one");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: false,
            has_uidplus: false,
        },
        "an IMAP4rev1 listing without MOVE or UIDPLUS is an affirmative \
         `neither`, and the rev2 fold must not touch it",
    );
    assert!(result.used_fallback);
    assert!(result.folder_wide_expunge);

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        !dialog.contains("UID MOVE"),
        "UID MOVE must never be issued to a server that did not advertise it: {dialog}",
    );
}
