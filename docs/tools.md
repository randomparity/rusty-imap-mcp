<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Regenerate with `just gen-tools-doc`. Source: the live tool
     catalog (`dump-tool-doc`) rendered by scripts/gen-tools-doc.py.
     A CI drift check fails if this file is out of sync. -->

# MCP Tool Reference

This reference is generated from the server's live tool catalog. It
lists every MCP tool the server can advertise, its parameters, its
response fields, and the minimum account posture required to call it.

Posture gating is summarized per tool as a minimum posture; see
[postures.md](postures.md) for the full posture matrix and
[security-model.md](security-model.md) for the trust model. Denial
and error shapes are described in each tool's own text.

The server advertises 24 tools.

## `list_folders`

**List IMAP Folders** — minimum posture: `readonly`

List every IMAP folder on the account. Use it to discover folder names before searching, moving, or fetching; most other tools take a `folder` argument.

### Parameters

_No parameters._

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folders` | array of FolderEntry | All folders returned by the server. |
| `security_warnings` | array of SecurityWarning | Security warnings accumulated while sanitizing folder names and flags against bidi overrides, zero-width characters, and C0/C1 control bytes (#98). Serialized only when non-empty. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `search`

**Search Messages** — minimum posture: `readonly`

Find message UIDs in a folder by structured criteria (sender, subject, date, flags, size). The UID-discovery step feeding fetch_message, mark_read, move_message and other per-message tools; it also returns the folder's uid_validity, which mark_read/mark_unread, flag/unflag, add_label/remove_label/list_labels, move_message, delete_message, and export_messages accept as an optional guard against UID reuse. Ordered oldest-first by UID (set newest_first to reverse); paginate with offset/limit and next_offset. Set thread_of_uid to retrieve a whole conversation instead of a filtered search.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `advanced_query` | string or null | no | Raw IMAP SEARCH query. Denied unless the account posture is `full` or `destructive`. Check the `rimap://accounts/<name>` resource for this account's posture and available tools. |
| `answered` | boolean or null | no | Filter by answered/unanswered status. |
| `bcc` | string or null | no | Filter by `Bcc` header substring. Gated like a content search (it can expose recipients): denied unless the account posture is `full` or `destructive`. Check the `rimap://accounts/<name>` resource for this account's posture and available tools. |
| `before` | string or null | no | Messages before this ISO date (exclusive) by INTERNALDATE. |
| `body` | string or null | no | Substring search across body parts. Searches message content, so it is denied unless the account posture is `full` or `destructive`. Check the `rimap://accounts/<name>` resource for this account's posture and available tools. |
| `body_preview_bytes` | integer or string (nullable) | no | When set, include a short plain-text body preview per result under `untrusted.messages[].body_preview` — the first N bytes of the sanitized body, capped at 1024. This turns "summarize my inbox" into a single call instead of one `fetch_message` per message. Previews are provided for up to the first 50 results of the page; request `limit` ≤ 50 or page with `next_offset` to preview more. Available at every posture `search` is: a preview returns a truncated body of an already-matched message (like `fetch_message`) and does not filter on content, so it is not gated like `body`/ `text`. `0` or omitted returns no previews. |
| `cc` | string or null | no | Filter by `Cc` header substring. |
| `draft` | boolean or null | no | Filter by draft/non-draft status. |
| `flagged` | boolean or null | no | Filter by flagged/unflagged status. |
| `folder` | string | yes | IMAP folder to search in. |
| `from` | string or null | no | Filter by `From` header substring. |
| `has_attachment` | boolean or null | no | Filter for messages with attachments. |
| `headers` | array or null | no | One or more `HEADER name value` filters. When non-empty this is gated like a content search: denied unless the account posture is `full` or `destructive`. Check the `rimap://accounts/<name>` resource for this account's posture and available tools. |
| `larger` | integer or string (nullable) | no | Match messages strictly larger than this many octets. |
| `limit` | integer or string (nullable) | no | Max results to return (default 100, max 100). |
| `newest_first` | boolean or null | no | Return results newest-first (UID descending) instead of the default oldest-first (UID ascending). Reverses the already matched UID list before paginating — no IMAP SORT extension is used or required. Default `false`. |
| `offset` | integer or string (nullable) | no | Offset into the result set (default 0), counted in whichever order `newest_first` selects. See "Result ordering" above. |
| `seen` | boolean or null | no | Filter by seen/unseen status. |
| `sent_before` | string or null | no | Messages before this ISO date (exclusive) by the message's `Date:` header — distinct from `before` which uses INTERNALDATE. |
| `sent_since` | string or null | no | Messages since this ISO date (inclusive) by the message's `Date:` header — distinct from `since` which uses INTERNALDATE. |
| `since` | string or null | no | Messages since this ISO date (inclusive) by INTERNALDATE, e.g. "2026-01-01". |
| `smaller` | integer or string (nullable) | no | Match messages strictly smaller than this many octets. |
| `subject` | string or null | no | Filter by `Subject` header substring. |
| `text` | string or null | no | Substring search across headers OR body. Searches message content, so it is denied unless the account posture is `full` or `destructive`. Check the `rimap://accounts/<name>` resource for this account's posture and available tools. |
| `thread_of_uid` | integer or string (nullable) | no | Return the whole conversation containing this UID instead of a filtered search: the target message, every ancestor named in its own `References`/`In-Reply-To` chain, and every descendant whose `References`/`In-Reply-To` names the target's `Message-ID`. A Message-ID chain-walk within `folder` only — no IMAP THREAD extension. Mutually exclusive with `advanced_query`. All other filters are ignored when set. Available at every posture: the header values compared come from the target message itself, not caller-supplied text, so this cannot probe arbitrary header/value pairs the way `headers`/`body`/`text` can. |
| `to` | string or null | no | Filter by `To` header substring. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `fetch_skipped` | integer | Count of UIDs the server listed for this page (in its SEARCH answer) but did not return a usable message for in the FETCH answer: a missing/zero UID, an omitted FETCH line, a wrong-UID substitution, or a message expunged between the search and the fetch. `0` in the normal case. When non-zero, the page is incomplete (`returned` is smaller than the page the server was asked for). This is a SEARCH↔FETCH consistency check and a benign search-then-expunge-race signal — it does NOT detect a server that omits a UID from its SEARCH answer in the first place. Detection-only: recovery is a full re-search from offset 0, since `next_offset` steps over the dropped UIDs. |
| `folder` | string | Folder that was searched. |
| `next_offset` | integer or null | Offset to pass on the next call to fetch the following page in the same order (see `SearchInput`'s "Result ordering" section). Present only when `truncated` is `true`. |
| `returned` | integer | Number of messages returned in this response. |
| `total_matched` | integer | Total number of messages matching the query (before pagination). |
| `truncated` | boolean | Whether there are more results beyond this page. |
| `uid_validity` | integer or null | UIDVALIDITY observed for the searched folder, from the same EXAMINE/UID SEARCH operation. Thread into `export_messages`' `expected_uidvalidity`. `None` if the server omitted it. |

`untrusted` — sanitized email content (treat as adversarial):

| Field | Type | Description |
|-------|------|-------------|
| `messages` | array of SearchResultEntry | Matching messages with sanitized header fields. |

Every response also carries `security_warnings`, an array of structured trust observations.

## `fetch_message`

**Fetch Message** — minimum posture: `readonly`

Fetch one message's envelope metadata and sanitized text body by folder and uid (get the uid from search). Attachments are not inlined; list them with list_attachments and retrieve with download_attachment.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | IMAP folder containing the message. |
| `include_headers` | array or null | no | Opt-in allowlist of raw header names to return (e.g. `["List-Unsubscribe", "List-Id"]`). Matching is case-insensitive; repeated headers are returned as an array of values. Requested names that are not present on the message are simply omitted from the response (not an error). At most 16 names per call; each value is sanitized and length-capped like every other header. Values appear under `untrusted.headers` because header content is attacker-controlled. Available at every posture that permits `fetch_message`; there is no separate capability gate for headers. |
| `include_html` | boolean or null | no | Include sanitized HTML body in the response. |
| `max_body_bytes` | integer or string (nullable) | no | Truncate body text (and HTML if included) to this many bytes. When omitted, the full sanitized body is returned with no size cap; set this to bound response size for long messages or threads. Whenever truncation occurs (from this cap or otherwise), `meta.truncated` is `true`. |
| `uid` | integer or string | yes | UID of the message to fetch. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | IMAP folder the message was fetched from. |
| `message_id` | string or null | RFC 2822 `Message-ID` header, if present. |
| `size` | integer | Raw size of the message body in bytes. |
| `truncated` | boolean | Whether the body was truncated to `max_body_bytes`. |
| `uid` | integer | UID of the fetched message. |

`untrusted` — sanitized email content (treat as adversarial):

| Field | Type | Description |
|-------|------|-------------|
| `attachments` | array of AttachmentMeta | MIME attachment parts found in the message. |
| `body_html` | string or null | Sanitized HTML body, present only when `include_html=true`. |
| `body_text` | string | Plain-text body (sanitized). |
| `cc` | array of string | `Cc` header recipients. |
| `date` | string or null | `Date` header as an RFC 3339 / ISO 8601 timestamp in UTC, e.g. `"2025-01-29T17:35:39Z"`; `null` when the header is absent. The instant is normalized to UTC by the content pipeline, so the offset is always `Z`. Mirrors `search`'s string-valued `date`. |
| `from` | string or null | `From` header. |
| `headers` | object or null | Requested raw headers (from `include_headers`), each mapped to its sanitized value(s). Present only when `include_headers` was supplied; contains only the requested names that were present on the message. Values are attacker-controlled email content. |
| `reply_to` | string or null | `Reply-To` header. |
| `subject` | string or null | `Subject` header. |
| `to` | array of string | `To` header recipients. |

Every response also carries `security_warnings`, an array of structured trust observations.

## `list_attachments`

**List Message Attachments** — minimum posture: `readonly`

List a message's attachments with filename, MIME type, size, and the part_id. Provides the part_id that download_attachment requires; get the message uid from search first.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | IMAP folder containing the message. |
| `uid` | integer or string | yes | UID of the message. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `attachment_count` | integer | Number of attachment parts found. |
| `folder` | string | IMAP folder the message was fetched from. |
| `uid` | integer | UID of the inspected message. |

`untrusted` — sanitized email content (treat as adversarial):

| Field | Type | Description |
|-------|------|-------------|
| `attachments` | array of AttachmentInfo | Attachment parts found in the MIME tree. |

Every response also carries `security_warnings`, an array of structured trust observations.

## `download_attachment`

**Download Attachment** — minimum posture: `readonly`

Download one attachment (by folder, uid, and the part_id from list_attachments) into the server's download sandbox and return its path. File bytes are not returned inline.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `dest_dir` | string or null | no | Optional destination directory. Must be within the configured download root. |
| `folder` | string | yes | IMAP folder containing the message. |
| `part_id` | string | yes | MIME part ID of the attachment (e.g. "2", "1.2"). |
| `uid` | integer or string | yes | UID of the message. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | IMAP folder the message was fetched from. |
| `mime_declared` | string | `Content-Type` declared by the MIME part (`type/subtype`). |
| `mime_sniffed` | string or null | Magic-byte-sniffed MIME type, if any signature matched. |
| `part_id` | string | IMAP part ID that was extracted. |
| `path` | string | Absolute path of the written attachment inside the sandbox. |
| `sha256` | string | SHA-256 of the decoded bytes, hex-encoded. |
| `size_bytes` | integer | Attachment body size in bytes (post-transfer-decoding). |
| `uid` | integer | UID of the parent message. |

`untrusted` — sanitized email content (treat as adversarial):

| Field | Type | Description |
|-------|------|-------------|
| `filename_original` | string or null | Original filename from `Content-Disposition` / `Content-Type` name parameter (sanitized). |

Every response also carries `security_warnings`, an array of structured trust observations.

## `export_messages`

**Export Messages** — minimum posture: not advertised by any posture (enable via `[security.tools]`)

Export multiple messages by UID as a single git am-able mbox file in the download sandbox. Discover UIDs with `search` and pass its uid_validity. Disabled unless enabled in [security.tools].

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `allow_partial` | boolean or null | no | When true, write the successes to a `.partial.mbox` artifact instead of failing the whole call. Default false (all-or-nothing). |
| `dest_dir` | string or null | no | Optional destination directory. Must be within the download root. |
| `expected_uidvalidity` | integer or string | yes | UIDVALIDITY observed when the UID list was discovered (e.g. from `search`). Required: pins mailbox identity across search→export. |
| `filename` | string or null | no | Optional advisory basename prefix (sanitized). |
| `folder` | string | yes | IMAP folder containing the messages. |
| `max_total_bytes` | integer or string (nullable) | no | Aggregate byte cap; clamped to 104857600 (100 MiB). |
| `uids` | array of integer | yes | UIDs to export, in mbox (patch) order. Non-empty, max 100, de-duped. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `complete` | boolean | True iff every requested UID was exported. |
| `failed` | array of FailedUid | Requested UIDs that failed, with reasons. |
| `folder` | string | Folder the messages were exported from. |
| `message_count` | integer | Number of messages written to the artifact. |
| `partial_path` | string or null | Path of a `.partial.mbox` artifact. Present only on a partial export; omitted otherwise. |
| `path` | string or null | `git am`-ready mbox path. Present only on a complete export; omitted from the response otherwise. |
| `sha256` | string | SHA-256 of the written mbox, hex-encoded. |
| `succeeded` | array of ExportedUid | Exported UIDs, in mbox order, with sizes. |
| `total_bytes` | integer | Total bytes written. |
| `uid_validity` | integer | UIDVALIDITY the export was pinned to. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `mark_read`

**Mark Messages Read** — minimum posture: `draft-safe`

Mark messages read (Seen) in a folder. Accepts a single `uid` or up to 100 `uids` from search. Reversible with mark_unread.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying flags. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the flags were updated in. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `mark_unread`

**Mark Messages Unread** — minimum posture: `draft-safe`

Mark messages unread (clear Seen) in a folder. Accepts a single `uid` or up to 100 `uids`. Inverse of mark_read.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying flags. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the flags were updated in. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `flag`

**Flag Messages** — minimum posture: `draft-safe`

Add the flagged (starred) status to messages in a folder. Accepts a single `uid` or up to 100 `uids` from search. Remove it with unflag.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying flags. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the flags were updated in. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `unflag`

**Unflag Messages** — minimum posture: `draft-safe`

Remove the flagged (starred) status from messages. Accepts a single `uid` or up to 100 `uids`. Inverse of flag.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying flags. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the flags were updated in. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `add_label`

**Add Label to Messages** — minimum posture: `draft-safe`

Add an IMAP keyword label to messages in a folder. Accepts a single `uid` or up to 100 `uids` from search. Remove it with remove_label; inspect current labels with list_labels.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying the label. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |
| `label` | string | yes | Custom keyword label to add or remove. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the label was applied to. |
| `label` | string | Label that was added or removed. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `remove_label`

**Remove Label from Messages** — minimum posture: `draft-safe`

Remove an IMAP keyword label from messages. Accepts a single `uid` or up to 100 `uids`. Inverse of add_label.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before applying the label. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |
| `label` | string | yes | Custom keyword label to add or remove. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the label was applied to. |
| `label` | string | Label that was added or removed. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |
| `uids_updated` | array of integer | UIDs that were updated. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `list_labels`

**List Labels on Message** — minimum posture: `readonly`

List the IMAP keyword labels set on a single message (by folder and uid from search).

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before fetching labels. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Target folder. |
| `uid` | integer or string | yes | Message UID. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `folder` | string | Folder the labels were fetched from. |
| `labels` | array of string | Custom keyword labels on the message. |
| `uid` | integer | UID of the message. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the EXAMINE used for this operation. `None` when the server's EXAMINE response omitted the response code. (#70) |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `move_message`

**Move Messages** — minimum posture: `draft-safe`

Move messages from one folder to another (destination by name; see list_folders). Accepts a single `uid` or up to 100 `uids` from search. Moved messages receive new UIDs in the destination folder.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `destination` | string | yes | Destination folder. |
| `expected_source_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the source folder's UIDVALIDITY matches this value before performing the move. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Source folder. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `destination` | string | Destination folder. |
| `destination_uid_validity` | integer or null | Destination-folder UIDVALIDITY observed after the COPY+DELETE fallback path. `None` on the UID MOVE happy path (destination UIDVALIDITY not observable without an extra STATUS) or when the server omitted the response code. (#70) |
| `folder` | string | Source folder. |
| `moves` | array of MoveEntry | Per-UID move results. |
| `source_uid_validity` | integer or null | Source-folder UIDVALIDITY observed at the guard STATUS probe, or at the source SELECT if no guard was requested. `None` when the server omitted the response code or no guard/probe occurred. (#70) |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `create_draft`

**Create Draft Email** — minimum posture: `draft-safe`

Save a new email as a draft flagged $PendingReview for a human to review and send from their own mail client. This ends the workflow: the draft cannot be sent through this server, so do not follow up with send_email (that would send a duplicate and bypass the human-review gate). Optional attachments are read from the server's download sandbox by path (only files the server downloaded/exported or the operator placed there; max 20 files, 10 MiB each, 25 MiB total). Optional body_html is sanitized (scripts, event handlers, remote content, and javascript: URLs are stripped) and always sent alongside the required plain-text body_text as a text/plain alternative; supplying body_html requires the full posture (create_draft.include_html).

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `attachments` | array or null | no | Attachments sourced from the download sandbox. |
| `bcc` | array or null | no | BCC addresses. |
| `body_html` | string or null | no | Optional sanitized HTML body. When present, the message is `multipart/alternative` (text first, sanitized HTML second). Requires `full` posture for `create_draft` (`create_draft.include_html`). |
| `body_text` | string | yes | Plain text body. Always sent, and used as the `text/plain` alternative when `body_html` is present. |
| `cc` | array or null | no | CC addresses. |
| `in_reply_to_folder` | string or null | no | Folder containing the message to reply to (default INBOX). |
| `in_reply_to_uid` | integer or string (nullable) | no | UID of message to reply to (for threading headers). |
| `subject` | string | yes | Email subject. |
| `to` | array of AddressInput | yes | Recipient addresses. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `attachments` | array of AttachmentSummary | Attachments placed on the draft (basename + byte count), in order. |
| `folder` | string | Folder the draft was appended to. |
| `keywords` | array of string | IMAP keywords applied to the draft. |
| `message_id` | string or null | RFC 2822 `Message-ID` assigned to the draft. |
| `uid` | integer or null | UID assigned by the server, if returned. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `send_email`

**Send Email** — minimum posture: `full`

Send a new email immediately via SMTP from the account. This is an autonomous send; when a human should review first, use create_draft instead. Requires the full or destructive posture; a lower posture is denied with ERR_POSTURE_DENIED (see the rimap://docs/postures resource). Optional attachments are read from the server's download sandbox by path (only files the server downloaded/exported or the operator placed there; max 20 files, 10 MiB each, 25 MiB total). Optional body_html is sanitized and always sent alongside the required plain-text body_text as a text/plain alternative.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `attachments` | array or null | no | Attachments sourced from the download sandbox. |
| `bcc` | array or null | no | BCC addresses. |
| `body_html` | string or null | no | Optional sanitized HTML body. When present, the message is `multipart/alternative` (text first, sanitized HTML second). Requires `full` posture for `create_draft` (`create_draft.include_html`). |
| `body_text` | string | yes | Plain text body. Always sent, and used as the `text/plain` alternative when `body_html` is present. |
| `cc` | array or null | no | CC addresses. |
| `in_reply_to_folder` | string or null | no | Folder containing the message to reply to (default INBOX). |
| `in_reply_to_uid` | integer or string (nullable) | no | UID of message to reply to (for threading headers). |
| `subject` | string | yes | Email subject. |
| `to` | array of AddressInput | yes | Recipient addresses. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `attachments` | array of AttachmentSummary | Attachments placed on the sent message (basename + byte count), in order. |
| `message_id` | string or null | RFC 2822 `Message-ID` assigned to the outgoing message. |
| `sent` | boolean | Whether the message was delivered via SMTP. |
| `sent_copy` | SentCopyInfo | Result of the best-effort copy to the Sent folder. |
| `smtp_status` | string | Human-readable SMTP delivery status. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `forward`

**Forward Message** — minimum posture: `full`

Forward an existing message (by folder + uid) to new recipients as a message/rfc822 attachment, with an optional comment. Re-sends the account's own stored mail via SMTP; the original is attached verbatim. Same posture gate as send_email.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `bcc` | array or null | no | BCC addresses (delivered via the SMTP envelope only; never written into the message headers). |
| `cc` | array or null | no | CC addresses. |
| `comment` | string or null | no | Optional note placed above the forwarded message as the body. |
| `folder` | string | yes | Folder containing the message to forward. |
| `to` | array of AddressInput | yes | Recipient addresses. |
| `uid` | integer or string | yes | UID of the message to forward. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | string or null | RFC 2822 `Message-ID` assigned to the outgoing forward. |
| `sent` | boolean | Whether the message was delivered via SMTP. |
| `sent_copy` | SentCopyInfo | Result of the best-effort copy to the Sent folder. |
| `smtp_status` | string | Human-readable SMTP delivery status. |
| `source_folder` | string | Folder the forwarded message was fetched from. |
| `source_uid` | integer | UID of the forwarded source message. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `delete_message`

**Delete Message** — minimum posture: `full`

Delete a single message (by folder and uid) by moving it to Trash, which is recoverable. This does not erase it; permanent removal is the separate, irreversible expunge step. Pass expected_uidvalidity to guard against a changed folder.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `expected_uidvalidity` | integer or string (nullable) | no | When set, the handler verifies the folder's UIDVALIDITY matches this value before deleting the message. A mismatch returns `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard. |
| `folder` | string | yes | Source folder containing the message. |
| `uid` | integer or string | yes | UID of the message to delete. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `deleted` | boolean | Always `true` when the handler returns `Ok`. |
| `destination` | string | Trash folder the message was moved to — the account's resolved `\Trash` SPECIAL-USE mailbox name, or the literal `"Trash"` fallback. |
| `folder` | string | Source folder the message was deleted from. |
| `moved_to_trash` | boolean | Whether the message was moved to the trash folder. |
| `uid` | integer | UID of the deleted message. |
| `uid_validity` | integer or null | UIDVALIDITY observed at the SELECT used for this operation. `None` when the server's SELECT response omitted the response code. (#70) |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `expunge`

**Expunge Folder** — minimum posture: `destructive`

Permanently and irreversibly erase every message already flagged for deletion in a folder; the second step after delete_message. Only allowed for folders the operator has allowlisted in the server's [security].expunge_folders (empty = deny-all by default) and at the destructive posture. A denial returns ERR_EXPUNGE_DENIED (folder not allowlisted) or ERR_POSTURE_DENIED (posture too low); neither is overridable through MCP, so the operator must change the server config. See the rimap://docs/postures resource.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | Folder to expunge. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `deleted_uids_before_expunge` | array of integer | UIDs that had the `\Deleted` flag set before expunge. |
| `expunged_count` | integer | Number of messages permanently removed. |
| `folder` | string | Folder that was expunged. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `create_folder`

**Create IMAP Folder** — minimum posture: `full`

Create a new IMAP folder by name. A name colliding with a protected folder (INBOX, Sent, Drafts, Trash by default, set by the server's [security].protected_folders) is refused with ERR_PROTECTED_FOLDER. Requires the full or destructive posture, else ERR_POSTURE_DENIED. Both are server-side policy the agent cannot override; see the rimap://docs/postures resource.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | Folder to create. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `created` | boolean | Always `true` when the handler returns `Ok`. |
| `folder` | string | Name of the created folder. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `rename_folder`

**Rename IMAP Folder** — minimum posture: `full`

Rename an IMAP folder. Renaming a protected folder or reusing a protected name (INBOX, Sent, Drafts, Trash by default, from the server's [security].protected_folders) is refused with ERR_PROTECTED_FOLDER. Requires the full or destructive posture, else ERR_POSTURE_DENIED. These are server-side policy, not overridable through MCP; see the rimap://docs/postures resource.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | Current folder name. |
| `new_folder` | string | yes | New folder name. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `new_folder` | string | New folder name. |
| `old_folder` | string | Previous folder name. |
| `renamed` | boolean | Always `true` when the handler returns `Ok`. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `delete_folder`

**Delete IMAP Folder** — minimum posture: `destructive`

Delete an IMAP folder and everything inside it; this is irreversible. A protected folder (INBOX, Sent, Drafts, Trash by default, from the server's [security].protected_folders) is refused with ERR_PROTECTED_FOLDER, and a folder not allowlisted in [security].expunge_folders is refused with ERR_EXPUNGE_DENIED. Requires the destructive posture, else ERR_POSTURE_DENIED. All are server-side policy the agent cannot override; see the rimap://docs/postures resource.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `folder` | string | yes | Folder to delete. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `deleted` | boolean | Always `true` when the handler returns `Ok`. |
| `folder` | string | Name of the deleted folder. |
| `message_count` | integer | Number of messages that were in the folder before deletion. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `use_account`

**Select Active Account** — minimum posture: not advertised by any posture (enable via `[security.tools]`)

Select the active account so tools/list advertises its tools. Optional: every account stays callable by its <account>.<tool> name regardless of which is active. Discover account names with list_accounts.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `account` | string | yes | Account name to make active. Selecting an account narrows the `tools/list` advertisement to that account's tools; every account stays callable by its `<account>.<tool>` name regardless. |

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `account` | string | The account that is now active. |
| `previous` | string or null | The previously active account, or `None` if none was set. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.

## `list_accounts`

**List Email Accounts** — minimum posture: not advertised by any posture (enable via `[security.tools]`)

List the configured email accounts (name and whether SMTP is set up). In multi-account setups, start here to learn the <account> prefix for namespaced tool calls; read the rimap://accounts/<name> resource for an account's posture and available tools.

### Parameters

_No parameters._

### Response

`meta` — trusted server metadata:

| Field | Type | Description |
|-------|------|-------------|
| `accounts` | array of AccountEntry | All configured accounts. |
| `count` | integer | Total number of configured accounts. |

`untrusted` — sanitized email content (treat as adversarial):

_No fields._

Every response also carries `security_warnings`, an array of structured trust observations.
