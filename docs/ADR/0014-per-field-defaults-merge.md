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

- **`credentials` keeps its existing shape.** `CredentialsConfig` has one
  field, so `Option<CredentialsConfig>` and a one-field partial are the same
  thing; adding a mirror struct for it would be duplication with no behaviour
  attached. Growing a second field is what would make it a defect, and the
  merge tests here are the place that would catch it.

## Consequences

- An account's effective `limits`/`security` is now `[defaults]` overlaid with
  exactly the keys that account wrote. This is a behaviour change for any
  existing config where an account writes a partial block: fields it omits now
  resolve to the operator's `[defaults]` value instead of the built-in one.
  That is the fix, but it does move values under a running deployment — an
  operator who worked around #624 by relying on the revert-to-built-in
  behaviour will see their accounts pick up the `[defaults]` values.

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
