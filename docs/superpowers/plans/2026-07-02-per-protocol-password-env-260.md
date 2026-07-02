# Per-protocol password env vars (#260) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the env-var credential fallback supply IMAP and SMTP passwords independently via `RUSTY_IMAP_MCP_IMAP_PASSWORD` / `RUSTY_IMAP_MCP_SMTP_PASSWORD`, keeping `RUSTY_IMAP_MCP_PASSWORD` as a back-compat fallback.

**Architecture:** Thread a `Protocol` enum through `resolve_credential`. The IMAP path bakes `Protocol::Imap` into `KeyringCredentialResolver` at construction (so the `rimap_core::CredentialResolver` trait is untouched); the SMTP path passes `Protocol::Smtp` directly. Env-var resolution walks protocol-scoped var → legacy var, both gated on `KeyringThenEnv`. Two `tracing::warn!`s name whichever var actually fired.

**Tech Stack:** Rust 2024, `secrecy::SecretString`, `tracing`, `temp_env` (test-only), `cargo-nextest`.

**Spec:** `docs/superpowers/specs/2026-07-02-issue-260-per-protocol-password-env-design.md`

## Global Constraints

- Zero warnings: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must be clean (pedantic on).
- No `unwrap()`/`panic!`/`println!`/`dbg!` in non-test source. No `#[allow]` — use `#[expect(..., reason = "...")]`.
- MSRV 1.88.0 must build (`just test-msrv`). Edition 2024.
- No new runtime dependency.
- 100-char lines; absolute imports only; Google-style docstrings on public APIs (`#![deny(missing_docs)]` is active in `rimap-config`).
- Newtypes/enums over primitives and bool flags.
- Never commit on `main`. Feature branch `feat/per-protocol-password-env-260` (already created).
- Full local guardrail: `just ci`. Fast inner loop: `just check`, `just test-fast`, `just lint`.
- Conventional commits, imperative ≤72-char subject, `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.

---

### Task 1: `Protocol` enum + env-var names

**Files:**
- Modify: `crates/rimap-config/src/credential.rs` (add consts + enum near `PASSWORD_ENV_VAR` at line 20; add unit test in the existing `mod tests`)
- Modify: `crates/rimap-config/src/lib.rs:15-18` (re-export)

**Interfaces:**
- Produces:
  - `pub const IMAP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_IMAP_PASSWORD";`
  - `pub const SMTP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_SMTP_PASSWORD";`
  - `pub enum Protocol { Imap, Smtp }` with `pub fn env_var_name(self) -> &'static str`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/rimap-config/src/credential.rs`:

```rust
#[test]
fn protocol_maps_to_scoped_env_var_names() {
    use crate::credential::Protocol;
    assert_eq!(Protocol::Imap.env_var_name(), "RUSTY_IMAP_MCP_IMAP_PASSWORD");
    assert_eq!(Protocol::Smtp.env_var_name(), "RUSTY_IMAP_MCP_SMTP_PASSWORD");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-config protocol_maps_to_scoped_env_var_names 2>&1 | tail -20`
Expected: FAIL — `Protocol` not found / does not compile.

- [ ] **Step 3: Write minimal implementation**

In `crates/rimap-config/src/credential.rs`, immediately after the `PASSWORD_ENV_VAR` const (line 20):

```rust
/// Environment variable checked as the IMAP-scoped fallback (before the
/// legacy [`PASSWORD_ENV_VAR`]).
pub const IMAP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_IMAP_PASSWORD";

/// Environment variable checked as the SMTP-scoped fallback (before the
/// legacy [`PASSWORD_ENV_VAR`]).
pub const SMTP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_SMTP_PASSWORD";

/// Which protocol a credential is being resolved for. Selects the
/// protocol-scoped environment-variable fallback name. Baked into
/// [`KeyringCredentialResolver`] at construction for the IMAP path;
/// passed directly by the SMTP path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// IMAP transport — uses [`IMAP_PASSWORD_ENV_VAR`].
    Imap,
    /// SMTP transport — uses [`SMTP_PASSWORD_ENV_VAR`].
    Smtp,
}

impl Protocol {
    /// The protocol-scoped password environment-variable name.
    #[must_use]
    pub fn env_var_name(self) -> &'static str {
        match self {
            Protocol::Imap => IMAP_PASSWORD_ENV_VAR,
            Protocol::Smtp => SMTP_PASSWORD_ENV_VAR,
        }
    }
}
```

Then extend the re-export block in `crates/rimap-config/src/lib.rs:15-18`:

```rust
pub use crate::credential::{
    CredentialStore, IMAP_PASSWORD_ENV_VAR, KEYCHAIN_SERVICE, KeyringCredentialResolver,
    KeyringStore, PASSWORD_ENV_VAR, Protocol, SMTP_PASSWORD_ENV_VAR, account_key,
    resolve_credential,
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rimap-config protocol_maps_to_scoped_env_var_names 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

Run: `just lint 2>&1 | tail -5` (expect clean)

```bash
git add crates/rimap-config/src/credential.rs crates/rimap-config/src/lib.rs
git commit -m "feat(config): add Protocol enum and per-protocol env var names"
```

---

### Task 2: Thread `Protocol` through resolution + corrected warns + wire call sites

This task changes the public signature of `resolve_credential` and the `KeyringCredentialResolver::new` constructor, so it MUST update every caller in the same commit to keep the workspace compiling (`main.rs` `build_smtp_client` and the IMAP resolver construction, plus all in-crate tests). It also extracts a pure `resolve_env_fallback` helper so "which var fired" is directly unit-testable without a tracing subscriber.

**Files:**
- Modify: `crates/rimap-config/src/credential.rs` — add `resolve_env_fallback` helper; add `protocol: Protocol` param to `resolve_credential` (line 102); rewrite the env-var block (lines 150-163); add `protocol` field to `KeyringCredentialResolver` (line 223) + `new` (line 244); pass `self.protocol` in `resolve` (line 263); update every in-crate test call to `resolve_credential`.
- Modify: `crates/rimap-server/src/main.rs` — IMAP resolver construction (line 451) passes `Protocol::Imap`; `build_smtp_client` `resolve_credential` call (line 494) passes `Protocol::Smtp`; add import.
- Modify (test-crate constructor call sites — the `new` signature change breaks all of these; all are IMAP connections, so all pass `Protocol::Imap`):
  - `crates/rimap-imap/tests/integration/proton.rs:88`
  - `crates/rimap-imap/tests/integration/dovecot.rs:147` and `:298`
  - `crates/rimap-imap/tests/integration/support/container.rs:716`
  - `crates/rimap-server/tests/e2e.rs:177`
  - `crates/rimap-server/tests/e2e_wire.rs:877`
  - `crates/rimap-server/tests/server_capabilities.rs:108`

**Interfaces:**
- Consumes: `Protocol`, `IMAP_PASSWORD_ENV_VAR`, `SMTP_PASSWORD_ENV_VAR`, `PASSWORD_ENV_VAR` (Task 1).
- Produces:
  - `fn resolve_env_fallback(proto_var: &'static str) -> Option<(&'static str, String)>` (module-private) — returns `(var_name_that_fired, value)`; tries `proto_var` (non-empty) then `PASSWORD_ENV_VAR` (non-empty).
  - `pub fn resolve_credential(store, account_id, username, host, fallback_mode, protocol: Protocol) -> Result<(SecretString, CredentialSource), ConfigError>`
  - `pub fn KeyringCredentialResolver::new(store, fallback_mode, protocol: Protocol) -> Self`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/rimap-config/src/credential.rs`. Import `Protocol` and the new consts at the top of the module (`use crate::credential::{... Protocol, IMAP_PASSWORD_ENV_VAR, SMTP_PASSWORD_ENV_VAR};`) and `use crate::credential::resolve_env_fallback;`. `temp_env::with_vars` sets multiple vars atomically (unset with `None::<&str>`).

```rust
#[test]
fn env_fallback_prefers_proto_var_then_legacy() {
    // proto var present -> proto var fires
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, Some("imap_secret")),
            (PASSWORD_ENV_VAR, Some("legacy_secret")),
        ],
        || {
            let (var, val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
            assert_eq!(var, IMAP_PASSWORD_ENV_VAR);
            assert_eq!(val, "imap_secret");
        },
    );
    // proto var unset -> legacy fires and is reported as the source
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, None::<&str>),
            (PASSWORD_ENV_VAR, Some("legacy_secret")),
        ],
        || {
            let (var, val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
            assert_eq!(var, PASSWORD_ENV_VAR);
            assert_eq!(val, "legacy_secret");
        },
    );
    // proto var empty -> falls through to legacy
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, Some("")),
            (PASSWORD_ENV_VAR, Some("legacy_secret")),
        ],
        || {
            let (var, _val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
            assert_eq!(var, PASSWORD_ENV_VAR);
        },
    );
    // both unset -> None
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, None::<&str>),
            (PASSWORD_ENV_VAR, None::<&str>),
        ],
        || assert!(resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).is_none()),
    );
}

#[test]
fn imap_and_smtp_env_vars_resolve_independently() {
    let store = MockStore::default();
    let id = AccountId::default_account();
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
            (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
            (PASSWORD_ENV_VAR, None::<&str>),
        ],
        || {
            let (imap, _) = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringThenEnv, Protocol::Imap,
            )
            .unwrap();
            let (smtp, _) = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringThenEnv, Protocol::Smtp,
            )
            .unwrap();
            assert_eq!(imap.expose_secret(), "imap_pw");
            assert_eq!(smtp.expose_secret(), "smtp_pw");
        },
    );
}

#[test]
fn proto_var_does_not_leak_to_other_protocol() {
    // Only the IMAP var is set; an SMTP resolution with no legacy var must fail.
    let store = MockStore::default();
    let id = AccountId::default_account();
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
            (SMTP_PASSWORD_ENV_VAR, None::<&str>),
            (PASSWORD_ENV_VAR, None::<&str>),
        ],
        || {
            let err = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringThenEnv, Protocol::Smtp,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::NoCredential { .. }));
        },
    );
}

#[test]
fn proto_var_wins_over_legacy_var() {
    let store = MockStore::default();
    let id = AccountId::default_account();
    temp_env::with_vars(
        [
            (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
            (PASSWORD_ENV_VAR, Some("legacy_pw")),
        ],
        || {
            let (got, src) = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringThenEnv, Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "imap_pw");
            assert_eq!(src, rimap_core::CredentialSource::EnvVar);
        },
    );
}

#[test]
fn keyring_error_falls_back_to_proto_var() {
    // Criterion 6 path: keyring transport errors, only the protocol-scoped
    // var is set (legacy unset). Resolution must succeed from the proto var.
    let store = MockStore::failing();
    let id = AccountId::default_account();
    temp_env::with_vars(
        [
            (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
            (PASSWORD_ENV_VAR, None::<&str>),
        ],
        || {
            let (got, src) = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringThenEnv, Protocol::Smtp,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "smtp_pw");
            assert_eq!(src, rimap_core::CredentialSource::EnvVar);
        },
    );
}

#[test]
fn keyring_only_ignores_proto_var() {
    let store = MockStore::default();
    let id = AccountId::default_account();
    temp_env::with_vars(
        [
            (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
            (PASSWORD_ENV_VAR, Some("legacy_pw")),
        ],
        || {
            let err = resolve_credential(
                &store, &id, "alice", "host", FallbackMode::KeyringOnly, Protocol::Smtp,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::NoCredential { .. }));
        },
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rimap-config credential:: 2>&1 | tail -30`
Expected: FAIL to compile — `resolve_env_fallback` missing and `resolve_credential` arity wrong.

- [ ] **Step 3: Write minimal implementation**

**3a.** Add the helper above `resolve_credential` in `crates/rimap-config/src/credential.rs`:

```rust
/// Resolve the env-var fallback for one protocol: try the protocol-scoped
/// `proto_var` first, then the legacy [`PASSWORD_ENV_VAR`]. A defined-but-empty
/// value is treated as unset so it never masks a later source. Returns the
/// variable name that actually supplied the value, so callers can log the true
/// source. Callers gate this on [`FallbackMode::KeyringThenEnv`].
fn resolve_env_fallback(proto_var: &'static str) -> Option<(&'static str, String)> {
    let non_empty = |name: &'static str| -> Option<(&'static str, String)> {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => Some((name, v)),
            Ok(_) | Err(_) => None,
        }
    };
    match non_empty(proto_var) {
        Some(hit) => Some(hit),
        None => non_empty(PASSWORD_ENV_VAR),
    }
}
```

**3b.** Change `resolve_credential`'s signature (line 102) to add the parameter after `fallback_mode`:

```rust
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
    fallback_mode: crate::model::FallbackMode,
    protocol: Protocol,
) -> Result<(SecretString, rimap_core::CredentialSource), ConfigError> {
```

**3c.** Replace the env-var block (current lines 150-163) with:

```rust
    if fallback_mode == crate::model::FallbackMode::KeyringThenEnv
        && let Some((var_name, value)) = resolve_env_fallback(protocol.env_var_name())
    {
        if let Some(e) = &keyring_error {
            tracing::warn!(
                account_id = %account_id.as_str(),
                host = %host,
                error = %e,
                "keyring lookup failed; using `{var_name}` env-var fallback",
            );
        }
        if var_name == PASSWORD_ENV_VAR {
            tracing::warn!(
                account_id = %account_id.as_str(),
                host = %host,
                "credential resolved via legacy `{PASSWORD_ENV_VAR}`; set \
                 `{}` to scope this credential to one protocol",
                protocol.env_var_name(),
            );
        }
        return Ok((SecretString::from(value), CredentialSource::EnvVar));
    }
```

**3d.** Add the `protocol` field to `KeyringCredentialResolver` (struct at line 223):

```rust
#[derive(Clone)]
pub struct KeyringCredentialResolver {
    store: std::sync::Arc<dyn CredentialStore>,
    fallback_mode: crate::model::FallbackMode,
    protocol: Protocol,
}
```

Add `.field("protocol", &self.protocol)` to the `Debug` impl (after the `fallback_mode` field, line ~235).

Update `new` (line 244):

```rust
    #[must_use]
    pub fn new(
        store: std::sync::Arc<dyn CredentialStore>,
        fallback_mode: crate::model::FallbackMode,
        protocol: Protocol,
    ) -> Self {
        Self {
            store,
            fallback_mode,
            protocol,
        }
    }
```

Update the `resolve` call (line 263) to pass `self.protocol`:

```rust
        resolve_credential(
            &*self.store,
            account,
            username,
            host,
            self.fallback_mode,
            self.protocol,
        )
        .map_err(|e| {
            let reason = e.to_string();
            rimap_core::CredentialResolverError::with_source(reason, e)
        })
```

**3e.** Update every existing in-crate test call to `resolve_credential` (currently 15 call sites in `mod tests`, lines ~366-585) to append `, Protocol::Imap` as the final argument. These are back-compat behavior tests for the keyring/legacy/single-env paths; `Protocol::Imap` preserves their intent (the legacy `PASSWORD_ENV_VAR` still resolves because it is the second fallback). The `PASSWORD_ENV_VAR`-only tests (`keychain_hit_wins_over_env`, `env_used_when_keychain_empty`, `permissive_mode_still_uses_env_var`, etc.) keep asserting `from_env` because the legacy var is still consulted when the (unset) IMAP var misses.

**3f.** Wire `crates/rimap-server/src/main.rs`. Add to the imports near the top (find the existing `use rimap_config::...` group):

```rust
use rimap_config::credential::Protocol;
```

IMAP resolver (line 451):

```rust
        let resolver: Arc<dyn rimap_core::CredentialResolver> =
            Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
                credentials.clone(),
                acfg.fallback_mode,
                Protocol::Imap,
            ));
```

`build_smtp_client` (line 494):

```rust
    let (smtp_password, _src) = rimap_config::resolve_credential(
        &**credentials,
        &acfg.id,
        &smtp_cfg.username,
        &smtp_cfg.host,
        acfg.fallback_mode,
        Protocol::Smtp,
    )
    .with_context(|| format!("resolving SMTP credential for account {}", acfg.id.as_str()))?;
```

**3g.** Update the seven test-crate constructor call sites listed in **Files**. Each currently reads:

```rust
Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
    store,
    rimap_config::model::FallbackMode::KeyringThenEnv,
))
```
(or the `use`-imported short forms `KeyringCredentialResolver::new(store, FallbackMode::KeyringThenEnv)` in `container.rs`, `e2e_wire.rs`, `server_capabilities.rs`). Append `Protocol::Imap` as the third argument, fully qualified to avoid touching each file's imports:

```rust
Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
    store,
    rimap_config::model::FallbackMode::KeyringThenEnv,
    rimap_config::credential::Protocol::Imap,
))
```

Verify none was missed:

Run: `rg -n 'KeyringCredentialResolver::new' --type rust`
Expected: every call site now passes a `Protocol` argument (8 total: main.rs + 7 test sites).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rimap-config credential:: 2>&1 | tail -30`
Expected: PASS (new + all pre-existing credential tests).

Run: `cargo test --workspace --all-features --no-run 2>&1 | tail -15`
Expected: the whole workspace — including the gated integration/e2e test crates that construct `KeyringCredentialResolver` — compiles. (`cargo check -p rimap-server` alone would NOT build those test targets, masking a break until Task 4.)

- [ ] **Step 5: Full guardrail + commit**

Run: `just lint 2>&1 | tail -8` (expect clean — watch for pedantic on the new code)
Run: `just test-fast 2>&1 | tail -8` (expect green)

```bash
git add crates/rimap-config/src/credential.rs crates/rimap-server/src/main.rs \
  crates/rimap-imap/tests/integration/proton.rs \
  crates/rimap-imap/tests/integration/dovecot.rs \
  crates/rimap-imap/tests/integration/support/container.rs \
  crates/rimap-server/tests/e2e.rs \
  crates/rimap-server/tests/e2e_wire.rs \
  crates/rimap-server/tests/server_capabilities.rs
git commit -m "feat(config): resolve per-protocol password env vars"
```

---

### Task 3: Documentation

**Files:**
- Modify: `docs/troubleshooting.md:215-228` ("Fallback: environment variable" subsection)
- Modify: `crates/rimap-config/src/model.rs:71-79` (`FallbackMode::KeyringThenEnv` doc-comment)

**Interfaces:** none (docs only).

- [ ] **Step 1: Update troubleshooting.md**

Replace the block at `docs/troubleshooting.md:215-228` (from `**The env-var fallback is single-valued.**` through the `fallback = "keyring-only"` code fence that follows the prose) with:

```markdown
**Per-protocol env vars.** Three password variables are consulted, in
order, only when `fallback = "keyring-then-env"` (the default):

1. `RUSTY_IMAP_MCP_IMAP_PASSWORD` (IMAP lookups) /
   `RUSTY_IMAP_MCP_SMTP_PASSWORD` (SMTP lookups) — the protocol-scoped var.
2. `RUSTY_IMAP_MCP_PASSWORD` — the legacy shared var, back-compat.

If your IMAP and SMTP passwords are identical (Gmail App Passwords,
Proton Bridge passwords), `RUSTY_IMAP_MCP_PASSWORD` alone still works.
If they differ, set the two protocol-scoped vars so each protocol gets
its own credential — the shared var can otherwise feed the wrong
password to one protocol. When a credential resolves from the legacy
`RUSTY_IMAP_MCP_PASSWORD` while the protocol-scoped var is unset, the
server logs a `warn` pointing at the scoped var to set.

```jsonc
"env": {
  "RUSTY_IMAP_MCP_IMAP_PASSWORD": "...",
  "RUSTY_IMAP_MCP_SMTP_PASSWORD": "...",
  "RUSTY_IMAP_MCP_CONFIG": "..."
}
```

For split-credential setups that want the strongest guarantee (a keyring
miss fails loud instead of consulting *any* env var), keep using the
keyring with `fallback = "keyring-only"`:

```toml
[defaults.credentials]
fallback = "keyring-only"
```
```

(Keep the existing paragraph that follows about where the `fallback` field lives and the single-account migration note — do not delete it.)

- [ ] **Step 2: Update the FallbackMode doc-comment**

In `crates/rimap-config/src/model.rs`, replace the `KeyringThenEnv` bullet (lines 71-79) so it names the protocol-scoped vars:

```rust
/// - `KeyringThenEnv` (default) — try the keyring; on either a miss or
///   a hard keyring failure (e.g. no D-Bus session available, as in CI
///   runners and Docker containers), fall back to the protocol-scoped
///   `RUSTY_IMAP_MCP_IMAP_PASSWORD` / `RUSTY_IMAP_MCP_SMTP_PASSWORD`,
///   then the legacy shared `RUSTY_IMAP_MCP_PASSWORD`; if none is set,
///   fail. Suitable for CI/test and single-account deployments,
///   including headless environments without a running secret-service.
///   When the fallback fires because of a keyring transport error rather
///   than a plain miss, the resolver emits a `tracing::warn!` naming the
///   env var used, so the misconfiguration is still visible to operators.
```

- [ ] **Step 3: Verify docs build clean**

Run: `cargo doc -p rimap-config --no-deps 2>&1 | tail -5` (expect no intra-doc-link warnings)
Run: `git diff --check` (expect no whitespace errors)

- [ ] **Step 4: Commit**

```bash
git add docs/troubleshooting.md crates/rimap-config/src/model.rs
git commit -m "docs: document per-protocol password env vars (#260)"
```

---

### Task 4: Full CI gate

- [ ] **Step 1: Run the full local-CI equivalent**

Run: `just ci 2>&1 | tail -30`
Expected: all checks green (fmt, clippy, check macOS, test stable, test MSRV, cargo-deny, zizmor).

If MSRV (`just test-msrv`) surfaces a syntax issue with `let ... && let ... else` chains: the `if let Some(..) = ... && let Some(..) = ...` form in Task 2 step 3c uses let-chains stabilized in 1.88 — confirm it builds on 1.88.0. If not, rewrite as a nested `if let` (outer `if fallback_mode == KeyringThenEnv { if let Some((var_name, value)) = resolve_env_fallback(...) { ... } }`).

- [ ] **Step 2: Confirm no stray changes**

Run: `git status --short` (expect clean)

---

## Self-Review

**Spec coverage:**
- Resolution order steps 1-2 (keyring) — unchanged, covered by existing tests (Task 2 step 3e keeps them green).
- Step 3 (protocol-scoped var) — Task 2, `imap_and_smtp_env_vars_resolve_independently`, `proto_var_does_not_leak_to_other_protocol`.
- Step 4 (legacy var) + migration warn — Task 2, `env_fallback_prefers_proto_var_then_legacy` (source reporting), warn code in 3c.
- Step 5 (fail) — `proto_var_does_not_leak_to_other_protocol`, `keyring_only_ignores_proto_var`.
- KeyringOnly gating (criterion 5) — `keyring_only_ignores_proto_var`.
- Empty-string fall-through (criterion 4) — `env_fallback_prefers_proto_var_then_legacy` (empty case).
- Keyring wins over env (criterion 6-old/now 7) — existing `keychain_hit_wins_over_env` (kept, `Protocol::Imap`).
- Corrected keyring-error warn naming (criterion 6) — helper returns the fired var name; warn in 3c uses it; `resolve_env_fallback` test asserts the returned name.
- IMAP-untouched trait — verified: `CredentialResolver::resolve` signature unchanged; only the resolver struct/ctor gain `protocol`. The ctor change does ripple to eight `KeyringCredentialResolver::new` call sites (main.rs + seven test crates), all enumerated in Task 2 with `Protocol::Imap`; Task 2 step 4 builds the whole workspace's test targets (`cargo test --workspace --no-run`) so any missed site fails before commit, not at Task 4.
- Docs (troubleshooting + model.rs) — Task 3.
- No new dependency, MSRV, zero-warnings — Task 4 + Global Constraints.

**Placeholder scan:** none — every code step shows full code.

**Type consistency:** `resolve_env_fallback(&'static str) -> Option<(&'static str, String)>`, `Protocol::env_var_name(self) -> &'static str`, `resolve_credential(..., protocol: Protocol)`, `KeyringCredentialResolver::new(store, fallback_mode, protocol)` — consistent across Tasks 1-3.
