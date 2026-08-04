# ADR-0014: `[defaults]` merges into an account field by field, through all-`Option` override structs

**Status:** Accepted · 2026-08-04 · issue [#624](https://github.com/randomparity/rusty-imap-mcp/issues/624)

## Context

`RawAccountConfig` carried `security: Option<SecurityConfig>` and
`limits: Option<LimitsConfig>` — the `Option` wrapping the *whole* block. The
composition step in `validate::compose::validate_multi_inner` then read:

```rust
let limits = raw.limits.unwrap_or_else(|| config.defaults.limits.clone());
```

So the `Option` answered only "did this account write an `[accounts.limits]`
table at all", and any account that did discarded `[defaults.limits]` entirely.
Every field the account left unwritten fell back to its **serde default**, not
to the operator's configured default.

The distinction is erased at deserialization, not at composition: once serde has
filled `LimitsConfig`'s `#[serde(default = "...")]` fields, `commands_per_second
= 10` written by the operator and `commands_per_second = 10` supplied by
`default_cps()` are the same bytes. No smarter merge over the concrete struct
can recover the difference, so the fix has to change what the account block
deserializes *into*.

The failure is silent by construction. Nothing in validation rejects a serde
default — they are all inside their own valid ranges — so the config loads and
the operator gets values they did not configure. Two instances have real weight:

- `limits.tool_call_timeout_seconds` (ADR-0012) is the first limits field an
  operator has a strong reason to raise deployment-wide. An account carrying an
  `[accounts.limits]` block for an unrelated reason silently reverted to the
  300s default.
- `security.protected_folders` reverted to the built-in four-folder list rather
  than the deployment's list. An operator tightening one security field could
  loosen the rest without any diagnostic.

The documentation already described the intended behaviour rather than the
shipped behaviour: `docs/configuration.md` said "fields not specified in the
per-account section inherit from defaults", and `docs/multi-account.md` said
"tools not mentioned in per-account inherit from defaults". Both were false for
any account that wrote the enclosing table.

## Decision

- **Deserialize account overrides into all-`Option` partial structs.**
  `AccountSecurityOverrides`, `AccountLimitsOverrides`, and
  `AccountLookalikeOverrides` mirror `SecurityConfig`, `LimitsConfig`, and
  `LookalikeConfig` with every field `Option<T>`, no `#[serde(default = ...)]`
  value functions, and `deny_unknown_fields` retained. `None` means the key was
  absent from the account's table; `Some(v)` means the operator wrote it. Each
  carries `merge_onto(base) -> Concrete`, which takes the base by value and
  replaces only the `Some` fields.

  The rejected alternative was deserializing to `toml::Table` and merging
  untyped before typing. It moves the schema out of the type system: an
  unknown or misspelled key inside an account block would survive the merge
  and be caught (or not) only after typing, and `deny_unknown_fields` on the
  concrete struct would then blame the merged result rather than the account
  that wrote it. The mirror structs cost duplication, which the round-trip
  test in `model.rs` pins field-for-field.

- **Tables merge per key; scalars and arrays replace.** `[accounts.limits]`,
  `[accounts.security]`, `[accounts.security.lookalike]`, and
  `[accounts.security.tools]` each merge into the corresponding `[defaults]`
  table key by key. A scalar (`posture`, `commands_per_second`) or an array
  (`protected_folders`, `expunge_folders`, `known_domains`) replaces the
  inherited value outright when present.

  `tools` merging per key rather than wholesale is the same defect one level
  down, and the one with the security flavour: a `[defaults.security.tools]`
  entry denying a tool would otherwise vanish for any account that allowed an
  unrelated one. It is also what `docs/multi-account.md` already documented.
  The operation this gives up is "inherit nothing for this tool" — an account
  can no longer erase an inherited entry, only overwrite its verdict. Nothing
  becomes unreachable: the two verdicts are the whole domain, so an account
  wanting posture's answer writes that verdict explicitly.

  Arrays replace rather than union because a union cannot be narrowed. An
  account that must *not* protect a folder the deployment protects would have
  no way to say so, and `protected_folders` / `expunge_folders` are validated
  against each other for overlap — a silent union could manufacture the
  conflict that check exists to reject.

- **`credentials` gets a mirror struct too**, despite having one field.
  `CredentialsConfig::fallback` carries `#[serde(default)]`, so an empty
  `[accounts.credentials]` table deserialized to
  `Some(CredentialsConfig { fallback: KeyringThenEnv })` — not `None` — and
  `map_or` then returned the built-in fallback rather than the operator's
  `[defaults.credentials]` value. That is the same defect, in the more
  dangerous direction: it silently restores the shared env-var fallback that
  `keyring-only` exists to prevent (#78).

## Consequences

- An account's effective `limits`/`security`/`credentials` is now `[defaults]`
  overlaid with exactly the keys that account wrote. This is a behaviour change
  for any existing config where an account writes a partial block: fields it
  omits now resolve to the operator's `[defaults]` value instead of the
  built-in one.

- **The movement is not symmetric — three of these directions widen what an
  account may do**, because the built-in default an account used to fall back
  to is the restrictive end of each range. On upgrade, an account carrying a
  partial `[accounts.security]` block gains:

  - every `[defaults.security.tools]` verdict, including the `allow` entries.
    `EffectiveMatrix` treats an explicit `Allow` as permitting the tool
    *regardless of posture*, so an account the operator marked
    `posture = "readonly"` can acquire `delete_message`, `export_messages`, or
    `send_email` from a default block it previously ignored;
  - the deployment's `expunge_folders` list in place of the built-in empty
    one — the one path by which a folder the operator believed unexpungeable
    becomes expungeable, since `expunge` is allowlist-gated;
  - the deployment's `protected_folders` list in place of the built-in
    `INBOX`/`Sent`/`Drafts`/`Trash`, which is a *narrowing* of protection
    whenever the default list is shorter.

  This is the documented semantics finally taking effect rather than a new
  policy, but it re-grants silently. Operators upgrading a multi-account
  config should run `rusty-imap-mcp --dry-run`, which prints each
  account's effective matrix, and diff it against the previous release.
  Accepting the widening rather than adding a compatibility mode is
  deliberate: a mode that preserved the old behaviour would preserve the
  defect, and "replace, don't deprecate" leaves no second resolution path to
  reason about.

- Some configs that previously started will now fail validation, all in the
  fail-closed direction: an inherited `send_email = "allow"` requires
  `[accounts.smtp]`, an inherited `export_messages = "allow"` requires a
  server-private `[attachments].download_dir`, and an inherited
  `protected_folders` can now overlap an account's own `expunge_folders`.
  A startup error naming the account is the correct outcome for each.

- Per-account validation is unchanged and still runs on the merged result, so a
  merge that produces an out-of-range combination (an inherited
  `tool_call_timeout_seconds` too small for an account's raised
  `command_timeout_seconds`) is still rejected at startup, with the account's
  own budgets — the property
  `multi_account_inherited_ceiling_checked_against_account_imap_budgets`
  already pinned.

- `RawAccountConfig::security` and `::limits` change type. They are public, so
  this is a breaking change to the `rimap-config` API; the crate is pre-1.0 and
  the only consumers are in-workspace.

- Adding a field to `SecurityConfig`, `LimitsConfig`, or `LookalikeConfig` now
  requires adding it to the mirror struct and its `merge_onto`. The
  field-coverage test in `model.rs` fails when the mirror falls behind, so the
  omission surfaces at test time rather than as another silently-dropped
  default.
