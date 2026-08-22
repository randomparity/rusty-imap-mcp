# Agent Workflows

Reference for MCP clients (agents) calling `rusty-imap-mcp` tools. Also
published as the MCP resource `rimap://docs/workflows`; the numeric limits
below are pinned by a test against the Rust constants that enforce them, so
this doc cannot drift silently. See [Security postures](postures.md) (also
published as `rimap://docs/postures`) for the posture matrix.

## search → fetch → act

The core pattern for every read-then-mutate task:

1. `search` a folder for candidate messages. Each match reports its `uid`
   and the folder's `uid_validity`.
2. `fetch_message` (or `list_attachments` / `download_attachment`) to read
   content by `uid`.
3. Apply a mutation (`flag`, `move_message`, `delete_message`, ...) or call
   `export_messages`, passing the `uid_validity` observed in step 1 back as
   `expected_uidvalidity` (see below).

## UIDVALIDITY pinning

IMAP UIDs are only stable as long as a folder's UIDVALIDITY does not change.
A folder recreated or renumbered between an agent's `search` and its later
mutation call can silently repoint a UID at a different message.

Every mutation tool and `export_messages` accepts an optional
`expected_uidvalidity` (required for `export_messages`). Pass the
`uid_validity` value `search` reported for the folder:

```
search(folder) → { uid, uid_validity }
                        │
                        ▼
flag / move_message / delete_message / export_messages(
    ..., expected_uidvalidity: uid_validity
)
```

If the folder's UIDVALIDITY no longer matches, the call fails with
`ERR_UID_VALIDITY_CHANGED` instead of silently acting on the wrong message.
Omitting `expected_uidvalidity` skips the guard (back-compat; not
recommended for anything but exploratory reads).

## Attachment retrieval

Attachments are not enumerated in `fetch_message`'s response; two
follow-up calls are required:

1. `list_attachments(folder, uid)` — returns each attachment's `part_id`,
   `mime_type`, `size_bytes`, and `filename`.
2. `download_attachment(folder, uid, part_id)` — writes the named part to
   the download sandbox and returns its path.

## Draft lifecycle

`create_draft` (available from `draft-safe` posture) appends a message to
the account's Drafts folder with the `\Draft` flag and a `$PendingReview`
keyword. This is a hard stop, not a formality: **no MCP tool sends a
message already sitting in Drafts.** A human must open the draft in their
mail client, review it, and send it themselves. `send_email` (available
only from `full` posture) composes and sends independently — it does not
operate on drafts.

## `export_messages` (opt-in)

`export_messages` writes raw, unsanitized message bytes to a single
`mboxrd`-framed file — the bridge for turning emailed patches into
`git am`-able commits. It is **denied in every posture** and must be
enabled explicitly:

```toml
[security.tools]
export_messages = "allow"
```

`expected_uidvalidity` is *required*, not optional, for this tool. See
[configuration.md](configuration.md#the-export_messages-tool) for the full
parameter reference and sandbox requirements.

## Numeric limits

| Limit | Value |
|-------|-------|
| Batch mutation UIDs (`flag`, `add_label`, `move_message`, ...) | 100 |
| `search` results per call | 100 |
| Fetched message body size | 1048576 bytes (1 MiB) |
| `export_messages` UID count | 100 |
| `export_messages` total size | 104857600 bytes (100 MiB) |
| `send_email` / `create_draft` recipients (To + Cc + Bcc) | 100 |

Exceeding a limit fails the call with a validation error rather than
silently truncating.
