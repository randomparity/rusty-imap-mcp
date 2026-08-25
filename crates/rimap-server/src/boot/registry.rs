//! Account registry: holds per-account runtime state and resolves
//! which account a request targets.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use governor::NotUntil;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_authz::breaker::SystemClock;
use rimap_authz::rate_limit::{DefaultInstant, retry_after_ms};
use rimap_authz::{DispatchGuard, FolderGuard};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::RimapError;
use rimap_core::account::AccountId;
use rimap_imap::{Connection, ConnectionConfig, SpecialUseMap};
use rimap_smtp::SmtpSender;

/// In-memory, unkeyed governor limiter used for infrastructure tools.
type InfrastructureLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Translate a `governor` rejection into the dedicated
/// [`RimapError::RateLimited`] variant so the typed `retry_after_ms` reaches
/// MCP `data` (#303) — the same structured contract the per-account limiter
/// gets via `From<AuthzError>`. The underlying ms math is shared with the
/// per-account governor via [`retry_after_ms`]; this wrapper skips the
/// intermediate `AuthzError` but lands on the same `RimapError` variant.
fn infra_rate_limited(not_until: &NotUntil<DefaultInstant>, clock: &DefaultClock) -> RimapError {
    let wait_ms = retry_after_ms(not_until, clock);
    RimapError::RateLimited {
        retry_after_ms: wait_ms,
    }
}

/// Sustained rate for the infrastructure-tool limiter. The `unwrap` runs
/// in `const` context, so a zero literal would fail the build rather than
/// panic at runtime.
const INFRA_RATE_PER_SEC: NonZeroU32 = NonZeroU32::new(5).unwrap();

/// Burst allowance for the infrastructure-tool limiter. See
/// [`INFRA_RATE_PER_SEC`] for why the `unwrap` is sound.
const INFRA_BURST: NonZeroU32 = NonZeroU32::new(10).unwrap();

/// Per-account runtime bundle.
///
/// Manual `Debug` impl prints only the account id, since several
/// inner types do not implement `Debug`.
pub struct AccountState {
    /// Validated account identifier.
    pub id: AccountId,
    /// IMAP connection for this account.
    pub imap: Connection,
    /// Optional SMTP sender (present when sending is configured). A
    /// trait object so tests can inject an in-memory fake in place of
    /// the real `SmtpClient`.
    pub smtp: Option<Box<dyn SmtpSender>>,
    /// Rate-limit and circuit-breaker guard.
    pub guard: DispatchGuard<SystemClock>,
    /// Folder-level access guard.
    pub folder_guard: FolderGuard,
    /// Attachment download sandbox root. Carried on `AccountState` so
    /// tool handlers keep a uniform `handle(account, input)` shape.
    pub download_dir: Arc<Path>,
    /// RFC 6154 special-use folder name resolutions, populated at boot
    /// from one `LIST` call. Consulted by `create_draft`, `send_email`,
    /// and expanded into `folder_guard`'s protected list.
    pub special_use: SpecialUseMap,
    /// Wall-clock ceiling on one tool call against this account, from
    /// `limits.tool_call_timeout_seconds` (#594, ADR-0012). The `[imap]`
    /// budgets bound each stage; this bounds their sum plus the retry.
    pub tool_call_timeout: Duration,
}

impl std::fmt::Debug for AccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountState")
            .field("id", &self.id)
            .field("smtp", &self.smtp.is_some())
            .field("special_use_drafts", &self.special_use.drafts())
            .field("special_use_sent", &self.special_use.sent())
            .field("special_use_trash", &self.special_use.trash())
            .finish_non_exhaustive()
    }
}

/// Holds all configured accounts and the active account selection.
///
/// The active selection is **process-wide**, not per-session: there is one
/// `AccountRegistry` per process and the current stdio transport serves a
/// single client session, so "process-wide" and "session" coincide today.
/// Under reveal-on-select (#439) this slot also drives `tools/list`
/// advertisement (`None` → infrastructure tools only; `Some(x)` → account
/// `x`'s tools). stdio single-session only — revisit this coupling before
/// adding any multiplexed (HTTP/SSE) transport, where one client's
/// `use_account` would flip every session's advertised catalog.
pub struct AccountRegistry {
    accounts: BTreeMap<AccountId, AccountState>,
    /// Process-wide active account selection (see the struct doc).
    active: ArcSwapOption<AccountId>,
    /// Process-wide rate limiter for infrastructure tools
    /// (`use_account`, `list_accounts`). Prevents an injected prompt
    /// from flip-flopping the active account faster than a human
    /// would. 5 req/sec sustained, burst of 10.
    infrastructure_limiter: InfrastructureLimiter,
    /// Clock used by the infrastructure limiter; stored so that
    /// `wait_time_from` can format retry hints.
    clock: DefaultClock,
}

impl AccountRegistry {
    /// Build a registry from the given accounts.
    #[must_use]
    pub fn new(accounts: BTreeMap<AccountId, AccountState>) -> Self {
        let quota = Quota::per_second(INFRA_RATE_PER_SEC).allow_burst(INFRA_BURST);
        Self {
            accounts,
            active: ArcSwapOption::empty(),
            infrastructure_limiter: RateLimiter::direct(quota),
            clock: DefaultClock::default(),
        }
    }

    /// Check the infrastructure-tool rate limit. Called by
    /// `dispatch_infrastructure` before executing `use_account` or
    /// `list_accounts`.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::RateLimited`] carrying the typed
    /// `retry_after_ms` hint when the limit is exceeded, so the retry
    /// timing reaches MCP `data` as a structured field (#303).
    pub fn check_infrastructure_rate(&self) -> Result<(), RimapError> {
        self.infrastructure_limiter
            .check()
            .map_err(|not_until| infra_rate_limited(&not_until, &self.clock))
    }

    /// Resolve which account a request targets.
    ///
    /// Resolution order:
    /// 1. Explicit name passed by the caller (the `<account>` namespace
    ///    of an `<account>.<tool>` invocation).
    /// 2. Auto-select when exactly one account is configured.
    /// 3. Error listing available accounts.
    ///
    /// The session-active account (`use_account`) is intentionally NOT a
    /// resolution input: account-scoped tools are dispatched by their
    /// advertised `<account>.<tool>` name, so `explicit` is always set for
    /// them. The active account governs only which tools `list_tools`
    /// advertises (see [`AccountRegistry::active_name`]); every account
    /// stays callable by namespace regardless of the active selection.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if the explicit name
    /// does not match any configured account, or
    /// [`RimapError::NoAccount`] if no account can be determined.
    pub fn resolve(&self, explicit: Option<&str>) -> Result<&AccountState, RimapError> {
        if let Some(name) = explicit {
            return self
                .find_by_name(name)
                .ok_or_else(|| RimapError::UnknownAccount {
                    name: name.to_string(),
                    available: self.account_name_strings(),
                });
        }

        // Auto-select when there is exactly one account.
        if let Some((_, state)) = (self.accounts.len() == 1)
            .then(|| self.accounts.iter().next())
            .flatten()
        {
            return Ok(state);
        }

        Err(RimapError::NoAccount {
            available: self.account_name_strings(),
        })
    }

    /// The session-active account name, or `None` when no `use_account`
    /// selection is in effect. Read by `list_tools` to narrow the
    /// advertised tool set to a single account; not consulted by
    /// [`AccountRegistry::resolve`].
    #[must_use]
    pub fn active_name(&self) -> Option<String> {
        self.active.load_full().as_deref().map(ToString::to_string)
    }

    /// Set the session-active account, returning the previous account
    /// name (if any). The selection narrows `list_tools` advertisement
    /// (see [`AccountRegistry::active_name`]); it does not gate dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`RimapError::UnknownAccount`] if `name` does not
    /// match any configured account.
    pub fn set_active(&self, name: &str) -> Result<Option<String>, RimapError> {
        // Parse into AccountId first so the O(log n) BTreeMap lookup does
        // typed comparison; falls back to `UnknownAccount` either way.
        let id = AccountId::new(name)
            .ok()
            .filter(|id| self.accounts.contains_key(id))
            .ok_or_else(|| RimapError::UnknownAccount {
                name: name.to_string(),
                available: self.account_name_strings(),
            })?;

        let prev = self.active.swap(Some(Arc::new(id)));
        Ok(prev.as_deref().map(ToString::to_string))
    }

    /// List all configured account names as owned strings, in sorted
    /// order. Used to populate the `available` field on
    /// [`RimapError::NoAccount`] and [`RimapError::UnknownAccount`].
    #[must_use]
    fn account_name_strings(&self) -> Vec<String> {
        self.accounts.keys().map(ToString::to_string).collect()
    }

    /// Borrow the full accounts map.
    #[must_use]
    pub fn accounts(&self) -> &BTreeMap<AccountId, AccountState> {
        &self.accounts
    }

    /// Look up an account by its string name. Parses into `AccountId`
    /// first so the `BTreeMap` lookup is O(log n) typed equality rather
    /// than O(n) string scanning.
    fn find_by_name(&self, name: &str) -> Option<&AccountState> {
        let id = AccountId::new(name).ok()?;
        self.accounts.get(&id)
    }
}

/// Map a per-account config to a `ConnectionConfig`.
#[must_use]
pub fn build_account_connection(
    id: &rimap_core::account::AccountId,
    acfg: &ValidatedAccountConfig,
) -> ConnectionConfig {
    let account = id
        .as_optional()
        .map(rimap_core::account::AccountId::as_str)
        .map(str::to_string);
    let mut config = ConnectionConfig::new(
        id.clone(),
        acfg.imap.host.clone(),
        acfg.imap.port,
        acfg.imap.encryption,
        acfg.imap.username.clone(),
        Duration::from_secs(u64::from(acfg.imap.connect_timeout_seconds)),
        Duration::from_secs(u64::from(acfg.imap.command_timeout_seconds)),
        acfg.limits.max_fetch_body_bytes,
        acfg.limits.max_append_bytes,
    );
    config.account = account;
    config.pinned_fingerprint = acfg.tls_fingerprint;
    config
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use unwrap_err for assertions")]
mod tests {
    use super::*;

    // We test resolution logic through the public API using an empty
    // registry. Constructing `AccountState` requires real IMAP
    // connections, so full-path tests live in integration/e2e suites.

    #[test]
    fn empty_registry_returns_no_account() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.resolve(None).unwrap_err();
        assert!(matches!(err, RimapError::NoAccount { available } if available.is_empty()));
    }

    #[test]
    fn explicit_unknown_returns_unknown_account() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.resolve(Some("work")).unwrap_err();
        assert!(matches!(err, RimapError::UnknownAccount { name, .. } if name == "work"));
    }

    #[test]
    fn set_active_unknown_returns_error() {
        let reg = AccountRegistry::new(BTreeMap::new());
        let err = reg.set_active("nope").unwrap_err();
        assert!(matches!(err, RimapError::UnknownAccount { name, .. } if name == "nope"));
    }

    #[test]
    fn resolve_ignores_active_selection() {
        // The session-active account (use_account) must NOT influence
        // resolve: account-scoped tools dispatch by their <account>.<tool>
        // namespace, so `explicit` is always set for them. With two
        // accounts and one made active, resolve(None) must still return
        // NoAccount rather than the active account — proving the dead
        // session-default resolution branch is gone (#401).
        use crate::test_support::make_test_account_state;

        let work = make_test_account_state("work");
        let personal = make_test_account_state("personal");
        let mut accounts = BTreeMap::new();
        accounts.insert(work.id.clone(), work);
        accounts.insert(personal.id.clone(), personal);
        let reg = AccountRegistry::new(accounts);

        reg.set_active("work").unwrap();
        assert_eq!(reg.active_name().as_deref(), Some("work"));

        let err = reg.resolve(None).unwrap_err();
        assert!(
            matches!(err, RimapError::NoAccount { .. }),
            "resolve(None) must not fall back to the active account; got {err:?}",
        );

        // The namespace still resolves the account directly.
        let state = reg.resolve(Some("work")).unwrap();
        assert_eq!(state.id.as_str(), "work");
    }

    #[test]
    fn resolve_auto_selects_single_account_regardless_of_active() {
        // With exactly one account, resolve(None) auto-selects it whether
        // or not it has been made active — auto-select, not session
        // default, is the mechanism.
        use crate::test_support::make_test_account_state;

        let solo = make_test_account_state("solo");
        let mut accounts = BTreeMap::new();
        accounts.insert(solo.id.clone(), solo);
        let reg = AccountRegistry::new(accounts);

        let state = reg.resolve(None).unwrap();
        assert_eq!(state.id.as_str(), "solo");

        reg.set_active("solo").unwrap();
        let state = reg.resolve(None).unwrap();
        assert_eq!(state.id.as_str(), "solo");
    }

    #[test]
    fn active_name_none_until_set() {
        use crate::test_support::make_test_account_state;

        let work = make_test_account_state("work");
        let mut accounts = BTreeMap::new();
        accounts.insert(work.id.clone(), work);
        let reg = AccountRegistry::new(accounts);

        assert!(reg.active_name().is_none(), "no active account initially");
        let prev = reg.set_active("work").unwrap();
        assert!(prev.is_none(), "first selection has no previous");
        assert_eq!(reg.active_name().as_deref(), Some("work"));
    }

    #[test]
    fn account_name_strings_empty() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.account_name_strings().is_empty());
    }

    #[test]
    fn accounts_returns_map() {
        let reg = AccountRegistry::new(BTreeMap::new());
        assert!(reg.accounts().is_empty());
    }

    #[test]
    fn debug_format_includes_account_state_fields() {
        // The manual `Debug` impl writes a non-trivial set of fields
        // (id, smtp.is_some(), special_use_drafts/sent/trash). The
        // stub-Ok(()) mutation at line 77 produces no output. Assert
        // the struct name appears in the formatted string so that
        // mutation is observable.
        use crate::test_support::make_test_account_state;
        let state = make_test_account_state("formatting-test-account");
        let formatted = format!("{state:?}");
        assert!(
            formatted.contains("AccountState"),
            "Debug must include struct name; got {formatted:?}",
        );
        assert!(
            formatted.contains("formatting-test-account"),
            "Debug must include account id; got {formatted:?}",
        );
    }

    #[test]
    fn check_infrastructure_rate_rejects_after_burst_exhaustion() {
        // The limiter is configured for 5 req/sec sustained with a
        // burst of 10. Hammering it in a tight loop must eventually
        // trip the rate-limit; the cargo-mutants stub-Ok(()) mutation
        // at line 125 would never reject.
        let reg = AccountRegistry::new(BTreeMap::new());
        let mut admitted = 0;
        let mut rejected_with_rate_limited = false;
        for _ in 0..50 {
            match reg.check_infrastructure_rate() {
                Ok(()) => admitted += 1,
                Err(err) => {
                    // First rejection: confirm it's the dedicated RateLimited
                    // variant carrying the typed retry hint (#303), not a
                    // stringified Authz error.
                    assert!(
                        matches!(err, RimapError::RateLimited { .. }),
                        "expected RimapError::RateLimited, got {err:?}",
                    );
                    rejected_with_rate_limited = true;
                    break;
                }
            }
        }
        assert!(
            rejected_with_rate_limited,
            "must reject within 50 burst calls; admitted={admitted}",
        );
    }

    #[test]
    fn account_name_strings_returns_populated_sorted_names() {
        // The existing `account_name_strings_empty` test only covers
        // the empty-registry case; the cargo-mutants `vec![]` stub at
        // line 199 also returns empty, so the existing test does not
        // distinguish. A populated registry kills the mutation.
        use crate::test_support::make_test_account_state;
        let alpha = make_test_account_state("alpha");
        let beta = make_test_account_state("beta");
        let mut accounts = BTreeMap::new();
        accounts.insert(alpha.id.clone(), alpha);
        accounts.insert(beta.id.clone(), beta);
        let reg = AccountRegistry::new(accounts);

        let names = reg.account_name_strings();
        assert_eq!(
            names,
            vec!["alpha".to_string(), "beta".to_string()],
            "account_name_strings must return all configured account ids in BTreeMap (sorted) order",
        );
    }

    #[test]
    fn build_account_connection_omits_account_field_for_default_name() {
        // `ConnectionConfig.account` is `Some(name)` for non-default
        // accounts and `None` for the legacy "default" sentinel. The
        // cargo-mutants `replace == with !=` mutation at line 223
        // would flip the assignment, breaking the audit-log
        // "infrastructure vs per-account" rendering.
        use rimap_config::model::{ImapConfig, ImapEncryption};
        use rimap_config::validate::ValidatedAccountConfig;
        use rimap_core::account::AccountId;
        use rimap_core::posture::Posture;

        let mut acfg = ValidatedAccountConfig::new_for_tests(AccountId::default_account(), {
            let mut imap = ImapConfig::new("imap.example.com".into(), 993, "u@example.com".into());
            imap.encryption = ImapEncryption::Tls;
            imap
        });
        acfg.security.posture = Posture::DraftSafe;

        let default_id = AccountId::new(rimap_core::account::DEFAULT_ACCOUNT_NAME).unwrap();
        let conn_default = build_account_connection(&default_id, &acfg);
        assert!(
            conn_default.account.is_none(),
            "default account name must produce account = None; got {:?}",
            conn_default.account,
        );

        let work_id = AccountId::new("work").unwrap();
        let conn_work = build_account_connection(&work_id, &acfg);
        assert_eq!(
            conn_work.account,
            Some("work".to_string()),
            "non-default account name must produce account = Some(name)",
        );
    }

    #[test]
    fn concurrent_active_swap_and_resolve() {
        // Exercises the ArcSwapOption-backed active slot under
        // concurrent writers and readers. The registry is empty
        // (AccountState requires live IMAP connections), so resolve()
        // must always return NoAccount regardless of interleaving;
        // the property under test is that readers never observe a
        // torn or invalid state and the process does not panic.
        use std::sync::Arc;
        use std::thread;

        let reg = Arc::new(AccountRegistry::new(BTreeMap::new()));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    // set_active on an unknown name must return
                    // UnknownAccount, not panic, even when other
                    // threads are swapping or loading concurrently.
                    let err = reg.set_active("nope").unwrap_err();
                    assert!(matches!(err, RimapError::UnknownAccount { .. }));
                }
            }));
        }

        for _ in 0..2 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let err = reg.resolve(None).unwrap_err();
                    assert!(matches!(err, RimapError::NoAccount { .. }));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    #[tokio::test]
    async fn account_state_dispatches_send_through_injected_fake() {
        // Acceptance for #453: an AccountState can hold a fake sender and
        // dispatch to it with no live SMTP server. The `spy` clone shares
        // the injected fake's capture log, so we can inspect what the
        // seam submitted after boxing it into the AccountState.
        use rimap_smtp::SendEnvelope;
        use rimap_smtp::testing::FakeSmtpSender;

        use crate::test_support::make_test_account_state;

        let fake = FakeSmtpSender::new();
        let spy = fake.clone();

        let mut state = make_test_account_state("sender-seam");
        state.smtp = Some(Box::new(fake));

        let envelope = SendEnvelope::new("me@test.invalid".into(), vec!["you@test.invalid".into()]);
        let smtp = state.smtp.as_ref().unwrap();
        let response = smtp
            .send_raw(&envelope, b"From: me\r\n\r\nbody")
            .await
            .unwrap();

        assert_eq!(response, "250 2.0.0 OK");
        assert_eq!(spy.call_count(), 1);
        let calls = spy.calls();
        assert_eq!(calls[0].envelope.to, vec!["you@test.invalid".to_string()]);
        assert_eq!(calls[0].raw, b"From: me\r\n\r\nbody");
    }
}
