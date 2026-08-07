//! RFC 3501 §9 defines a capability as an `atom`, and IMAP protocol keywords
//! are case-insensitive, so `* CAPABILITY IMAP4rev1 Move UidPlus` advertises
//! exactly what `MOVE UIDPLUS` advertises. Read byte-exactly, it advertises
//! neither (#735).
//!
//! That is the unsafe direction of the mistake. Unlike `ServerCapabilities::
//! Unknown`, which refuses, a false `Known { false, false }` proceeds — and
//! that pair is the one
//! `ops::expunge::fallback_uses_folder_wide_expunge` selects the folder-wide
//! RFC 3501 `EXPUNGE` on, removing every `\Deleted` message in the mailbox
//! against a server that in fact supports `UID EXPUNGE`. So these tests assert
//! the wire, not just the flags: the dialogs are scripted so a client reading
//! the atoms case-sensitively desynchronizes and fails rather than quietly
//! proving nothing.
//!
//! `IMAP4rev1` itself is spelled conventionally throughout: `imap-proto`
//! already parses it with `tag_no_case` into its own `Capability::Imap4rev1`
//! variant, so its case is not what is under test here — the extension atoms
//! and `IMAP4rev2`, which land in `Capability::Atom` with the server's own
//! spelling, are.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::ServerCapabilities;
use rimap_imap::types::Uid;

/// Generous command timeout so the loopback dialog cannot race a `Timeout`
/// (mirrors `imap4rev2_capabilities`).
const BACKSTOP: Duration = Duration::from_secs(5);

fn uid(value: u32) -> Uid {
    Uid::from(NonZeroU32::new(value).unwrap())
}

/// The delete dialog a MOVE-capable server serves: flag `\Deleted`, then the
/// atomic `UID MOVE`, which expunges nothing.
fn delete_via_uid_move() -> Vec<Step> {
    vec![
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
    ]
}

/// Drive `delete_message` against a server advertising `caps`, asserting the
/// atomic `UID MOVE` ran and no `EXPUNGE` of any form reached the wire.
///
/// The script carries no fallback dialog on purpose: the fallback's first
/// *divergent* command is `UID COPY` (the `UID STORE` before it is shared),
/// which desynchronizes against it and fails the `expect` below rather than
/// quietly proving nothing. That desync is what carries the test — the wire
/// assertions afterwards only see lines the script had a step for.
async fn assert_move_and_uidplus_advertised(caps: &str) {
    let mut steps = login_preamble(caps);
    steps.extend(delete_via_uid_move());

    let server = FakeImapServer::start(steps).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let (result, _uidvalidity) = conn
        .delete_message("INBOX", uid(5), "Trash", None)
        .await
        .expect("a server advertising MOVE in any case supports UID MOVE");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: true,
            has_uidplus: true,
        },
        "capability atoms are case-insensitive (RFC 3501 §9), so `{caps}` \
         advertises both",
    );
    assert!(
        !result.used_fallback,
        "MOVE was advertised, so the non-atomic COPY fallback must not run",
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
        "no EXPUNGE of any form may follow a MOVE advertisement — the atomic \
         move needs none, and the folder-wide form is the data-loss path #649 \
         closed: {dialog}",
    );
}

/// The `AUTH=` arm is not a gap, it is the point: `imap-proto` strips the
/// prefix with `tag_no_case` into `Capability::Auth`, so a server offering the
/// SASL mechanisms `AUTH=MOVE` and `AUTH=UIDPLUS` advertises no extension at
/// all. Matching those would read capabilities out of an authentication list.
///
/// The scripted dialog is the folder-wide fallback, so a client that answered
/// the probes from the mechanism names stays on `UID MOVE` and desynchronizes.
#[tokio::test]
async fn auth_mechanisms_are_not_capability_atoms() {
    let mut steps = login_preamble("IMAP4rev1 AUTH=MOVE AUTH=UIDPLUS");
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
        .expect("an IMAP4rev1 listing is a known state, not an unknown one");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: false,
            has_uidplus: false,
        },
        "`AUTH=MOVE` names a SASL mechanism, not the MOVE extension",
    );
    assert!(result.used_fallback);
    assert!(result.folder_wide_expunge);

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        !dialog.contains("UID MOVE"),
        "UID MOVE must never be issued to a server that only named it after \
         `AUTH=`: {dialog}",
    );
}

/// The issue's own listing: `Move` and `UidPlus`, conformant and mixed-case.
#[tokio::test]
async fn mixed_case_move_and_uidplus_atoms_are_advertised() {
    assert_move_and_uidplus_advertised("IMAP4rev1 Move UidPlus").await;
}

/// The `IMAP4rev2` probe lands on the same `Capability::Atom` arm — `imap-proto`
/// has no rev2 variant — so it carries the same defect and needs the same fix
/// (#686 added the probe, #735 fixes its case handling).
#[tokio::test]
async fn a_lowercase_rev2_atom_still_folds_into_move_and_uidplus() {
    assert_move_and_uidplus_advertised("IMAP4rev1 imap4rev2").await;
}

/// A lowercase `uidplus` with no MOVE is `Known { false, true }` — the one pair
/// that reaches the scoped `UID EXPUNGE`. Read case-sensitively it collapses to
/// `Known { false, false }` and the fallback expunges the whole folder.
#[tokio::test]
async fn a_lowercase_uidplus_atom_scopes_the_expunge_to_uids() {
    let mut steps = login_preamble("IMAP4rev1 uidplus");
    steps.extend([
        // move_messages: SELECT source (read-write; select(...,false)).
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        // STATUS "Archive" (UIDVALIDITY) — dest probe after COPY.
        Step::Expect { verb: "STATUS" },
        Step::Send(b"* STATUS \"Archive\" (UIDVALIDITY 7)\r\n".to_vec()),
        Step::Reply {
            text: "OK STATUS completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        // The scoped RFC 4315 form. A client that read `uidplus` as absent
        // issues a folder-wide `EXPUNGE` here and fails this expectation.
        Step::Expect {
            verb: "UID EXPUNGE",
        },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK UID EXPUNGE completed",
        },
    ]);

    let server = FakeImapServer::start(steps).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid(5)], None)
        .await
        .expect("a server advertising UIDPLUS in any case supports UID EXPUNGE");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: false,
            has_uidplus: true,
        },
        "`uidplus` is UIDPLUS; MOVE was genuinely not advertised",
    );
    assert!(
        outcome.used_fallback,
        "no MOVE was advertised, so the COPY fallback is correct here",
    );
    assert!(
        !outcome.folder_wide_expunge,
        "UIDPLUS was advertised, so the expunge must be scoped to UID 5",
    );

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        dialog.contains("UID EXPUNGE"),
        "the scoped RFC 4315 UID EXPUNGE must reach the wire: {dialog}",
    );
}
