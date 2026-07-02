# Per-protocol password env vars (#260)

## Context

Credential resolution (`crates/rimap-config/src/credential.rs`) walks three
sources per `(account, username, host)` triple:

1. OS keychain, new namespaced key `<account-id>/<username>@<host>`.
2. OS keychain, legacy key `<username>@<host>` (back-compat read).
3. Environment variable `RUSTY_IMAP_MCP_PASSWORD` — consulted only in
   `FallbackMode::KeyringThenEnv`.

There are two resolution entry points, and each already knows which protocol
it serves:

- **IMAP** — `KeyringCredentialResolver` (built at
  `crates/rimap-server/src/main.rs:450`, injected into the IMAP `Connection`)
  implements `rimap_core::CredentialResolver` and calls `resolve_credential`
  from its `resolve()` method.
- **SMTP** — `build_smtp_client` (`crates/rimap-server/src/main.rs:487`) calls
  `rimap_config::resolve_credential` directly.

Both call sites pass the *same* env-var name, `RUSTY_IMAP_MCP_PASSWORD`. The
env-var fallback path therefore cannot supply IMAP and SMTP credentials
independently: whichever password is set in the single env var is sent to both
servers. For deployments whose IMAP and SMTP credentials diverge (historic
outsourced-SMTP setups, some corporate stacks, CI environments that break the
moment the two credentials differ, or diagnostic workflows that want to verify
one protocol's auth via env without disturbing the other's keyring entry), the
env-var fallback is unusable — the operator's only recourse today is the
keyring.

The keyring path already supports independent per-protocol credentials, because
its key embeds `<username>@<host>` and IMAP/SMTP generally differ on at least
one. The single env var was a deliberate footgun-reduction choice (see
`FallbackMode` doc-comment in `crates/rimap-config/src/model.rs` and #78): a
shared env-var fallback in a multi-account world can silently send one
account's password to another account's server.

## Goal

Let the env-var fallback supply IMAP and SMTP credentials independently, without
weakening the `KeyringOnly` opt-out and without regressing the existing
single-env-var deployments.

Add two protocol-scoped variables:

- `RUSTY_IMAP_MCP_IMAP_PASSWORD`
- `RUSTY_IMAP_MCP_SMTP_PASSWORD`

Keep `RUSTY_IMAP_MCP_PASSWORD` as a back-compat fallback consulted when the
protocol-scoped variable is unset.

## Resolution order

Per protocol `P ∈ {IMAP, SMTP}`, with `PROTO_ENV(P)` being
`RUSTY_IMAP_MCP_IMAP_PASSWORD` or `RUSTY_IMAP_MCP_SMTP_PASSWORD`:

1. Keyring new key `<account-id>/<username>@<host>` — unchanged.
2. Keyring legacy key `<username>@<host>` — unchanged.
3. `PROTO_ENV(P)` — **new.** Consulted only in `KeyringThenEnv`.
4. `RUSTY_IMAP_MCP_PASSWORD` — existing, back-compat. Consulted only in
   `KeyringThenEnv`.
5. Fail with `ConfigError::NoCredential`.

`KeyringOnly` stops after step 2, exactly as today — steps 3 and 4 are both
skipped. The operator who opted out of env-var fallback for footgun reasons
keeps that guarantee; adding protocol-scoped vars does not change which modes
consult the environment.

"Unset or empty" is the trigger to fall through at steps 3 and 4, matching the
existing `!env.is_empty()` guard so a defined-but-empty variable does not mask a
downstream source.

### Observability

When step 4 fires (legacy `RUSTY_IMAP_MCP_PASSWORD` supplied the credential)
**and** `PROTO_ENV(P)` was unset, emit a one-shot `tracing::warn!` naming the
protocol-scoped variable the operator should migrate to. This is the discovery
mechanism for the new vars. The warning fires per resolution attempt (same
cadence as the existing legacy-keyring-key warning); it does not dedupe across
attempts, consistent with the existing warnings in this function.

The audit-log `CredentialSource` enum is **unchanged**: any env-var resolution
(step 3 or step 4) records `CredentialSource::EnvVar`. See "Rejected
alternatives" — splitting the provenance enum expands the serialized audit
schema and the conformance fixtures for forensics no operator has requested, and
the step-4 `warn!` already surfaces legacy-var use.

## Approach

Thread the protocol through `resolve_credential` as a new `Protocol` enum,
newtype-style (per repo convention: "Enums for state machines, not boolean
flags"), defined in `rimap-config`:

```rust
/// Which protocol a credential is being resolved for. Selects the
/// protocol-scoped env-var fallback name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Imap,
    Smtp,
}
```

`Protocol::env_var_name(self) -> &'static str` returns
`RUSTY_IMAP_MCP_IMAP_PASSWORD` / `RUSTY_IMAP_MCP_SMTP_PASSWORD`.

`resolve_credential` gains a `protocol: Protocol` parameter. Its env-var block
becomes: try `protocol.env_var_name()`, then `PASSWORD_ENV_VAR`, both gated on
`KeyringThenEnv` and `!empty`.

**IMAP path — bake the protocol into the resolver at construction.** This
mirrors the existing seam: `KeyringCredentialResolver` already "bakes the
keyring-vs-env-var fallback policy in at construction time so the IMAP transport
never sees `FallbackMode`" (`credential.rs` doc-comment). Add a `protocol` field
set by `KeyringCredentialResolver::new`, so the `rimap_core::CredentialResolver`
trait signature — used across `rimap-imap` — is **untouched**. The IMAP resolver
is constructed with `Protocol::Imap`.

**SMTP path — pass `Protocol::Smtp` explicitly.** `build_smtp_client` already
calls `resolve_credential` directly; it passes `Protocol::Smtp`.

### Why bake into the resolver rather than widen the trait

The `CredentialResolver` trait is implemented by `rimap-imap` test fixtures and
consumed inside `Connection::connect_and_login`. Widening its `resolve` signature
with a protocol argument would ripple into every fixture and the transport crate
for no benefit — the IMAP connection only ever resolves IMAP credentials. Baking
the protocol in at construction keeps the change inside `rimap-config` +
`main.rs` and preserves the trait's narrowness (the same reason `FallbackMode`
is baked in, not passed per-call).

## Files touched

- `crates/rimap-config/src/credential.rs` — `Protocol` enum, new
  `resolve_credential` param, `KeyringCredentialResolver` field + constructor
  arg, env-var block, `warn!`. Unit tests for the new order.
- `crates/rimap-config/src/lib.rs` — re-export `Protocol` if the crate root
  re-exports `resolve_credential` (it does).
- `crates/rimap-server/src/main.rs` — construct the IMAP resolver with
  `Protocol::Imap`; pass `Protocol::Smtp` in `build_smtp_client`.
- `docs/troubleshooting.md` — the "Fallback: environment variable" subsection
  currently says the fallback is single-valued and steers split-credential
  setups to `keyring-only`; update it to document the two new vars and the
  resolution order (keyring-only remains a valid choice, no longer the *only*
  one).

Verified **not** touched: `crates/rimap-server/src/cli/migrate_keyring.rs`
references `resolve_credential` only in comments — it constructs no resolver.
- `crates/rimap-config/src/model.rs` — extend the `FallbackMode` doc-comment if
  it enumerates the env var by name.

## Acceptance criteria

1. In `KeyringThenEnv` with keyring empty: `RUSTY_IMAP_MCP_IMAP_PASSWORD`
   resolves the IMAP credential; `RUSTY_IMAP_MCP_SMTP_PASSWORD` resolves the
   SMTP credential; the two can hold different values and neither leaks to the
   other protocol.
2. In `KeyringThenEnv` with the protocol-scoped var unset but
   `RUSTY_IMAP_MCP_PASSWORD` set: resolution succeeds from the legacy var and a
   `tracing::warn!` naming the protocol-scoped var is emitted.
3. In `KeyringThenEnv` with the protocol-scoped var **set**: the legacy var is
   not consulted and no migration warning fires.
4. A protocol-scoped var set to empty string falls through to the legacy var
   (and then to failure), never masking it.
5. In `KeyringOnly`: neither the protocol-scoped var nor the legacy var is
   consulted; behavior is byte-for-byte unchanged from today.
6. Keyring hits (new key, legacy key) still win over every env var, unchanged.
7. `just ci` is green; MSRV 1.88.0 build passes; `cargo-deny` clean; no new
   dependency.

## Rejected alternatives

- **Widen `CredentialResolver::resolve` with a protocol argument.** Ripples into
  every `rimap-imap` fixture and the transport crate; the IMAP connection only
  ever needs IMAP credentials. Baking the protocol into the resolver at
  construction is strictly less surface. (See "Why bake…" above.)
- **Split `CredentialSource::EnvVar` into per-protocol / legacy variants.**
  Expands the serialized audit schema and the MCP conformance fixtures for
  forensics no operator has asked for; the step-4 `warn!` already gives operators
  the discovery/migration signal. Deferred until a concrete forensic need exists.
- **Per-account env vars (`RUSTY_IMAP_MCP_PASSWORD__<account>`).** Explicitly out
  of scope in #260 — trades one footgun for a worse one; the keyring already
  handles per-account by key path.
- **Close as wontfix.** The issue offers this; `/work-issue 260` selects
  implementation. The keyring remains the canonical multi-credential path, but
  the env-var fallback should not silently cross-wire protocols when an operator
  reaches for it.
