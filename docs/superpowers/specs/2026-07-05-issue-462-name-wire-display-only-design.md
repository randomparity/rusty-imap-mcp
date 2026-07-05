# `name_wire` is a display/diagnostic field, not a round-trip input

Issue: #462 (epic #446, FABLE_RELEASE_AUDIT finding M-12, Medium).

## Problem

`FolderEntry.name_wire` (`crates/rimap-server/src/tools/admin/list_folders.rs`)
is populated only when `rimap_content::sanitize` changes a folder name
(`clean_name != folder.name`). Its schema doc tells agents to "Pass this back
for SELECT / STATUS / MOVE / FETCH", and `escape_wire_name`'s own doc claims
"Clients round-trip by applying the inverse of this escape convention." Both
claims are false: no server input path decodes the `\u{H..}` escape.
`validate_folder_input` (`validation.rs`) validates every folder-taking arg
through `FolderName::new` only. An agent that echoes `name_wire` back sends the
literal escaped ASCII string (e.g. `Inbox\u{202e}gnilleS`) and gets
`ERR_NOT_FOUND`, because the real server folder holds the actual U+202E byte.

## Why the round-trip is unfixable without a regression

`sanitize` is `decode → NFKC → line-endings → filter_codepoints → truncate`.
Two disjoint reasons a name changes, both dead-ends for a round-trip:

1. **Dangerous codepoints** (bidi U+202A–202E/2066–2069, zero-width, BOM, C0/C1
   controls, Unicode Tag chars). `FolderName::new` *rejects every one of these*
   by design (`crates/rimap-core/src/folder_name.rs`,
   `is_rejected_display_codepoint`). So the raw name cannot be passed on input at
   all — the folder is intentionally non-addressable. The escaped literal is
   accepted by validation (it is plain ASCII) but does not match the server's
   folder, so it fails at the IMAP layer with `ERR_NOT_FOUND`.
2. **NFKC-only changes** (e.g. ligature `ﬁ`→`fi`). Here the raw name *would*
   pass validation and match the server, but the escaped `name_wire`
   (`\u{fb01}le`) still does not.

## Decision: (a) correct the docs — `name_wire` is display/diagnostic-only

Chosen over the issue's other two options because they are unsound here:

- **Server-side decoder** (issue option 1): introduces genuine ambiguity — a
  real folder whose name literally contains the text `\u{5c}` is
  indistinguishable from the escape of a backslash. Explicitly out of scope.
- **Expose raw UTF-8 name** (issue option 2): would fail input validation for
  the dangerous-codepoint class (see reason 1 above), so it does not create a
  working round-trip; worse, it **reintroduces the #98 injection vector** by
  shipping live bidi / Tag codepoints to the agent under the trusted `meta`
  envelope — the exact bytes sanitization exists to neutralize. The `\u{H..}`
  escape's real, load-bearing purpose is *safe transmission* of those raw bytes
  as inert ASCII, not round-tripping.

So the escape stays (it safely surfaces what the server sent, for diagnostics),
and the docs stop over-promising. `name_wire` is documented as a display /
diagnostic representation of the raw bytes, explicitly **not** a valid input
token. Folders whose names required sanitization are not addressable through
folder-input tools — by design, because the input validator refuses the
dangerous codepoints. This is the minimal, non-breaking (no schema field
added/removed), collision-free fix.

Accepted limitation: NFKC-normalized folders remain non-addressable via these
tools. This is the security-conservative tradeoff and is consistent with the
codebase already refusing dangerous folder names on input; making that narrow
class addressable would require a conditional raw/escaped form the agent cannot
disambiguate.

## Changes

- Rewrite the `escape_wire_name` doc comment (drop the "clients round-trip by
  applying the inverse" claim; describe it as a safe-transmission escape).
- Rewrite the `FolderEntry.name_wire` field doc: display/diagnostic-only, not an
  input; such folders are not addressable by folder-input tools.
- Regenerate `crates/rimap-server/tests/fixtures/rimap-tool-schemas/list_folders.schema.json`
  (the field doc is an output-schema description; CI fails on drift).

## Tests

Lock the chosen contract in `list_folders.rs`:

- For a sanitizer-modified (bidi) folder, `name_wire` is present, but the raw
  name it represents is **rejected** by `validate_folder_input` — proving there
  is no valid input path and the "display-only" doc is accurate.
- The escaped `name_wire` string is not equal to the raw folder name (it is not
  a verbatim round-trip token).

## Out of scope

The five folder-input callers and `rimap-authz/folder_guard.rs` are untouched —
no decode path is added. `validate_folder_input` is unchanged.
