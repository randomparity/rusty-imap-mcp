# Security Postures

rusty-imap-mcp uses four security postures to control which tools are
available. The posture is set in the config file under
`[security].posture` and defaults to `draft-safe`.

## Posture values

| Posture | Description |
|---------|-------------|
| `readonly` | Read-only operations. No flag changes, no drafts, no moves. |
| `draft-safe` | Read + safe mutations: flag/label changes, moves, and draft creation with `$PendingReview`. Default. |
| `full` | Everything in `draft-safe` plus send, delete, folder management, HTML bodies, advanced search. |
| `destructive` | Everything in `full` plus permanent deletion: expunge and delete_folder. |

## Tool matrix

Each row is a dispatchable capability. Some MCP tools expose multiple
gated capabilities (e.g. `search` has a separate `search.advanced_query`
capability).

| Capability | `readonly` | `draft-safe` | `full` | `destructive` |
|------------|:----------:|:------------:|:------:|:-------------:|
| `list_folders` | allowed | allowed | allowed | allowed |
| `search` | allowed | allowed | allowed | allowed |
| `search.advanced_query` | denied | denied | allowed | allowed |
| `fetch_message` | allowed | allowed | allowed | allowed |
| `fetch_message.include_html` | denied | denied | allowed | allowed |
| `list_attachments` | allowed | allowed | allowed | allowed |
| `download_attachment` | allowed | allowed | allowed | allowed |
| `export_messages` | denied¹ | denied¹ | denied¹ | denied¹ |
| `mark_read` | denied | allowed | allowed | allowed |
| `mark_unread` | denied | allowed | allowed | allowed |
| `flag` | denied | allowed | allowed | allowed |
| `unflag` | denied | allowed | allowed | allowed |
| `add_label` | denied | allowed | allowed | allowed |
| `remove_label` | denied | allowed | allowed | allowed |
| `list_labels` | allowed | allowed | allowed | allowed |
| `move_message` | denied | allowed | allowed | allowed |
| `create_draft` | denied | allowed | allowed | allowed |
| `create_draft.include_html` | denied | denied | allowed | allowed |
| `send_email` | denied | denied | allowed | allowed |
| `forward` | denied | denied | allowed | allowed |
| `delete_message` | denied | denied | allowed | allowed |
| `create_folder` | denied | denied | allowed | allowed |
| `rename_folder` | denied | denied | allowed | allowed |
| `expunge` | denied | denied | denied | allowed |
| `delete_folder` | denied | denied | denied | allowed |

`use_account` and `list_accounts` are infrastructure tools that bypass
posture checks entirely and are always available.

¹ `export_messages` is denied in every posture and is enabled only by an
explicit `export_messages = "allow"` override in `[security.tools]`. It
writes a raw, unsanitized mbox to the download sandbox, so when enabled it
also requires a server-private download root (config validation rejects a
group/world-writable `download_dir` on Unix). See
[configuration.md](configuration.md#the-export_messages-tool).

## Compose attachments and HTML

`create_draft` and `send_email` accept optional `attachments` and `body_html`.

**Attachments are sourced only from the download sandbox.** An attachment is
referenced by a `path` that must resolve inside the download-sandbox root; the
server reads it through the same containment used for `download_attachment`
(canonicalize + `starts_with(root)` + a held directory fd, refusing to follow a
symlink at the final component). An agent can therefore attach only a file the
server itself downloaded or exported, or one the operator deliberately placed in
the sandbox — never an arbitrary host path. Caps: at most 20 attachments,
10 MiB per file, 25 MiB total (raw bytes; base64 adds ~33% on the wire).

**Shared-sandbox trust model (multi-account operators).** The download root is a
single process-global directory shared by every configured account. Allowing
compose to read files back out of it means that, on a server hosting more than
one account, those accounts **share a file staging area**: a file one account
downloads or exports can be attached to outbound mail sent from another account.
This is an accepted product trade-off, not a defect — it does not widen the
boundary beyond "files the server wrote or the operator placed in the root," and
it never permits reading arbitrary host paths. The request arguments redact
attachment paths, but every send/draft records the attachment basenames and byte
counts in the audit `tool_end` result so an operator can see which sandbox file
left the boundary. Deployments that need hard cross-account file isolation should
run separate servers with separate download roots.

**HTML bodies require `full`.** `body_html` is sanitized through the same
tag-allowlist pipeline used for inbound mail (scripts, event handlers, remote
content, and `javascript:` URLs are stripped) and is always sent alongside the
required plain-text `body_text` as a `text/plain` alternative. Because HTML is a
richer surface than plain text, supplying `body_html` to `create_draft` is gated
at `full` via the `create_draft.include_html` capability, even though a
plain-text draft is allowed at `draft-safe`. `send_email` already requires
`full`, so it carries no separate HTML sub-capability.

## Per-tool overrides

The base posture can be adjusted per-tool in the config file:

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"                # deny even though draft-safe allows it
"search.advanced_query" = "allow" # allow even though draft-safe denies it
```

- `"allow"` grants the tool regardless of what the posture would deny.
- `"deny"` blocks the tool regardless of what the posture would allow.
- An override that matches the posture's default is a no-op (not an error).

## Tool advertisement


### Common override patterns

Real-world examples of per-tool overrides:

#### Preserve unread state in draft-safe

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"
```

Use case: Agent can search, fetch, and compose drafts, but cannot
accidentally mark messages as read. Useful when the agent is triaging
or summarizing without taking action.

#### Enable advanced search in draft-safe

```toml
[security]
posture = "draft-safe"

[security.tools]
"search.advanced_query" = "allow"
```

Use case: Agent needs to search message bodies or headers but should
not send email. The `advanced_query` escape hatch allows body/text/bcc
searches while keeping `send_email` denied.

**Security note:** Body search is classified as a "content oracle"
because it scans untrusted adversarial message content. Enable only if
you trust the agent not to exfiltrate search results.

#### Block downloads in readonly

```toml
[security]
posture = "readonly"

[security.tools]
download_attachment = "deny"
```

Use case: Agent can read message metadata and text but cannot write
files to the sandbox. Useful for pure analysis workflows where
attachment content is not needed.

#### Allow HTML in draft-safe

```toml
[security]
posture = "draft-safe"

[security.tools]
"fetch_message.include_html" = "allow"
```

Use case: Agent needs to analyze HTML structure (e.g., detecting
phishing via link/text mismatches) but should not send email. The
`.include_html` sub-capability is gated separately because HTML
parsing increases attack surface.

**Security note:** HTML parts are sanitized but still carry higher
risk than plain text. Enable only if the agent's task requires HTML.

#### Deny sending in full posture

```toml
[security]
posture = "full"

[security.tools]
send_email = "deny"
```

Use case: Agent can delete messages and manage folders but cannot send
email. Useful when SMTP credentials are not available or when you want
the agent to clean up the mailbox without outbound access.


Tools denied by the effective matrix (posture + overrides) are **not
advertised** via the MCP `list_tools` response. Denial is enforced at
both discovery and dispatch (defense in depth).

## Folder safety (full and destructive postures)

- `protected_folders` (default: INBOX, Sent, Drafts, Trash) blocks
  `rename_folder` and `delete_folder` on critical folders.
- `expunge_folders` (default empty = deny all) is an allowlist for
  `expunge` and `delete_folder`.

## `$PendingReview` flag

In `draft-safe` and above, `create_draft` appends messages to the
Drafts folder with the `\Draft` flag and a `$PendingReview` keyword.
This acts as a human-in-the-loop gate: the agent can compose a draft,
but a human must review and send it from their mail client.
