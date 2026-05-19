//! Tool-name parsing and account-namespace prefix handling.
//!
//! Splits a wire-format MCP tool name like `work.send_email` into
//! `(Some("work"), "send_email")`, refines base [`ToolName`] variants to
//! sub-capabilities based on argument shape, and identifies the legacy
//! single-account deployment used to suppress namespacing.

use std::str::FromStr;

use rimap_core::account::{AccountId, DEFAULT_ACCOUNT_NAME};
use rimap_core::tool::ToolName;
use rmcp::model::ErrorData;

use crate::boot::registry::AccountState;

/// Whether the registry holds exactly one account and its id is the
/// legacy `"default"` value. Used to preserve bare (non-namespaced)
/// tool names for single-account deployments.
pub(super) fn is_legacy_single_account(
    accounts: &std::collections::BTreeMap<AccountId, AccountState>,
) -> bool {
    accounts.len() == 1
        && accounts
            .keys()
            .next()
            .is_some_and(|id| id.as_str() == DEFAULT_ACCOUNT_NAME)
}

/// Promote a base `ToolName` to a sub-capability variant based on args.
/// Keeps sub-capability posture checks at the dispatch seam rather than
/// scattered across handlers.
pub(super) fn refine_tool_name(
    base: ToolName,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ToolName {
    let Some(args) = args else {
        return base;
    };
    // Exhaustive match so a new ToolName variant forces an explicit
    // refinement decision at the dispatch seam rather than silently
    // falling through a catch-all.
    match base {
        ToolName::FetchMessage
            if args
                .get("include_html")
                .and_then(serde_json::Value::as_bool)
                == Some(true) =>
        {
            ToolName::FetchMessageHtml
        }
        ToolName::Search if promotes_search_to_advanced(args) => ToolName::SearchAdvanced,
        ToolName::ListFolders
        | ToolName::Search
        | ToolName::SearchAdvanced
        | ToolName::FetchMessage
        | ToolName::FetchMessageHtml
        | ToolName::ListAttachments
        | ToolName::DownloadAttachment
        | ToolName::MarkRead
        | ToolName::MarkUnread
        | ToolName::Flag
        | ToolName::Unflag
        | ToolName::AddLabel
        | ToolName::RemoveLabel
        | ToolName::ListLabels
        | ToolName::MoveMessage
        | ToolName::CreateDraft
        | ToolName::SendEmail
        | ToolName::DeleteMessage
        | ToolName::Expunge
        | ToolName::CreateFolder
        | ToolName::RenameFolder
        | ToolName::DeleteFolder
        | ToolName::UseAccount
        | ToolName::ListAccounts => base,
    }
}

/// Whether the `search` argument shape forces promotion to
/// `SearchAdvanced`. Triggers on any content-oracle input:
/// `advanced_query`, `body`, `text`, `bcc`, or a non-empty `headers`
/// array. Envelope/flag fields (`cc`, `larger`, `sent_*`, `answered`,
/// `flagged`, `draft`) do NOT promote — they map to IMAP-indexed
/// metadata, not content scans, and stay under the low-posture
/// `Search` seat.
fn promotes_search_to_advanced(args: &serde_json::Map<String, serde_json::Value>) -> bool {
    // Use as_str() rather than is_some() so explicit JSON null (e.g.
    // {"body": null}) is treated as absent — serde deserializes
    // Option<String> = null as None, and promoting a no-op filter to
    // SearchAdvanced would produce a misleading PostureDenied.
    if args
        .get("advanced_query")
        .and_then(serde_json::Value::as_str)
        .is_some()
        || args
            .get("body")
            .and_then(serde_json::Value::as_str)
            .is_some()
        || args
            .get("text")
            .and_then(serde_json::Value::as_str)
            .is_some()
        || args
            .get("bcc")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        return true;
    }
    // headers triggers only when present AND non-empty (as_array filters
    // non-array types automatically).
    matches!(
        args.get("headers").and_then(serde_json::Value::as_array),
        Some(arr) if !arr.is_empty(),
    )
}

/// Whether `raw` is a bare simple (undotted) tool name for a non-infrastructure
/// tool. Used by `call_tool` to reject bare forms in multi-account mode
/// where the advertised contract is `<account>.<tool>` (#73).
///
/// Returns `true` only if ALL of:
/// - `raw` contains no `.` (so sub-capability dotted tools like
///   `search.advanced_query` return `false` — they must remain valid bare).
/// - `raw` parses as a known `ToolName`.
/// - The resolved tool is NOT `UseAccount` / `ListAccounts` (infrastructure
///   tools are always addressed bare regardless of account mode).
#[must_use]
pub(crate) fn is_bare_simple_tool_name(raw: &str) -> bool {
    if raw.contains('.') {
        return false;
    }
    let Ok(tool) = ToolName::from_str(raw) else {
        return false;
    };
    !matches!(tool, ToolName::UseAccount | ToolName::ListAccounts)
}

/// Enforce the multi-account namespace contract: in non-legacy
/// (multi-account) mode, bare simple non-infrastructure tool names
/// must be rejected with `INVALID_PARAMS`. Legacy single-account
/// deployments and dotted/infrastructure tool names always pass.
pub(super) fn validate_bare_tool_namespace(
    legacy_single_account: bool,
    raw_name: &str,
) -> Result<(), ErrorData> {
    if !legacy_single_account && is_bare_simple_tool_name(raw_name) {
        return Err(ErrorData::invalid_params(
            format!(
                "tool name must be namespaced in multi-account mode: \
                 <account>.{raw_name}",
            ),
            None,
        ));
    }
    Ok(())
}

/// Split a possibly-namespaced MCP tool name into `(account, tool)`.
///
/// Preserves sub-capability tool names that contain dots (e.g.
/// `search.advanced_query`): if the raw name parses as a `ToolName`
/// directly, return it as bare.
pub(super) fn split_tool_name(raw: &str) -> (Option<&str>, &str) {
    if ToolName::from_str(raw).is_ok() {
        return (None, raw);
    }
    match raw.split_once('.') {
        Some((prefix, rest))
            if is_valid_account_prefix(prefix) && ToolName::from_str(rest).is_ok() =>
        {
            (Some(prefix), rest)
        }
        Some(_) | None => (None, raw),
    }
}

/// Structural check on an account-namespace prefix. Mirrors the
/// `AccountId` character rules (ASCII alphanumerics + hyphens, 1–64
/// chars) without allocating.
fn is_valid_account_prefix(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests use unwrap_err for assertions on namespace-validation errors"
)]
mod tests {
    use rimap_core::tool::ToolName;

    use super::{
        is_bare_simple_tool_name, refine_tool_name, split_tool_name, validate_bare_tool_namespace,
    };

    #[test]
    fn split_tool_name_bare() {
        assert_eq!(split_tool_name("send_email"), (None, "send_email"));
    }

    #[test]
    fn split_tool_name_namespaced() {
        assert_eq!(
            split_tool_name("work.send_email"),
            (Some("work"), "send_email"),
        );
    }

    #[test]
    fn split_tool_name_preserves_dotted_sub_capability() {
        // `search.advanced_query` is a valid ToolName and must not be
        // interpreted as account="search", tool="advanced_query".
        assert_eq!(
            split_tool_name("search.advanced_query"),
            (None, "search.advanced_query"),
        );
        assert_eq!(
            split_tool_name("fetch_message.include_html"),
            (None, "fetch_message.include_html"),
        );
    }

    #[test]
    fn split_tool_name_unknown_returns_bare() {
        // Unknown names pass through; `from_str` at the caller rejects.
        assert_eq!(split_tool_name("garbage"), (None, "garbage"));
        assert_eq!(split_tool_name("work.garbage"), (None, "work.garbage"),);
    }

    #[test]
    fn split_tool_name_rejects_invalid_prefix() {
        // Underscore is not valid in an account prefix.
        assert_eq!(
            split_tool_name("bad_name.send_email"),
            (None, "bad_name.send_email"),
        );
    }

    #[test]
    fn refine_tool_name_promotes_sub_capabilities() {
        let mut args = serde_json::Map::new();
        args.insert("include_html".into(), serde_json::Value::Bool(true));
        assert_eq!(
            refine_tool_name(ToolName::FetchMessage, Some(&args)),
            ToolName::FetchMessageHtml,
        );

        let mut args = serde_json::Map::new();
        args.insert(
            "advanced_query".into(),
            serde_json::Value::String("FROM x".into()),
        );
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_namespaced() {
        assert!(!is_bare_simple_tool_name("work.send_email"));
        assert!(!is_bare_simple_tool_name("personal.list_folders"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_sub_capability_dotted() {
        assert!(!is_bare_simple_tool_name("search.advanced_query"));
        assert!(!is_bare_simple_tool_name("fetch_message.include_html"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_infrastructure_tools() {
        assert!(!is_bare_simple_tool_name("use_account"));
        assert!(!is_bare_simple_tool_name("list_accounts"));
    }

    #[test]
    fn is_bare_simple_tool_name_rejects_unknown_names() {
        assert!(!is_bare_simple_tool_name("nuke_inbox"));
    }

    #[test]
    fn is_bare_simple_tool_name_accepts_bare_simple_tool_names() {
        for name in ["send_email", "list_folders", "search", "mark_read"] {
            assert!(
                is_bare_simple_tool_name(name),
                "expected bare simple: {name}",
            );
        }
    }

    #[test]
    fn is_legacy_single_account_classifies_each_branch() {
        // Pin the three observable outcomes of `is_legacy_single_account`:
        //   - true  : exactly one account, whose id is the legacy
        //             "default" sentinel (auto-namespace suppression).
        //   - false : any other shape — zero accounts, multiple
        //             accounts, or a single account with a non-default
        //             name.
        //
        // The four cargo-mutants survivors on this function (stub-false,
        // `&&` → `||`, `len() == 1` → `!=`, `id == DEFAULT` → `!=`) are
        // each killed by at least one of the cases below.
        use rimap_core::account::DEFAULT_ACCOUNT_NAME;
        use std::collections::BTreeMap;

        use super::is_legacy_single_account;
        use crate::test_support::make_test_account_state;

        // 0 accounts → false (sanity baseline; does not distinguish all
        // mutants on its own).
        let zero: BTreeMap<_, _> = BTreeMap::new();
        assert!(!is_legacy_single_account(&zero));

        // 1 account named "default" → true. Kills:
        //   - stub-false (returns false when original is true).
        //   - `len() == 1` → `!=` (would short-circuit to false).
        //   - `id == DEFAULT` → `!=` (would flip the closure to false).
        let default_state = make_test_account_state(DEFAULT_ACCOUNT_NAME);
        let mut single_default = BTreeMap::new();
        single_default.insert(default_state.id.clone(), default_state);
        assert!(is_legacy_single_account(&single_default));

        // 1 account NOT named "default" → false. Reinforces the
        // `id == DEFAULT` → `!=` kill at the "non-default" branch
        // (without this case the mutation would only be observable for
        // the true→false transition above).
        let other_state = make_test_account_state("work");
        let mut single_other = BTreeMap::new();
        single_other.insert(other_state.id.clone(), other_state);
        assert!(!is_legacy_single_account(&single_other));

        // 2 accounts including "default" → false. Kills:
        //   - `&&` → `||` (would short-circuit to true because the
        //     first key is "default" and the predicate becomes
        //     `false || true`).
        let default_state2 = make_test_account_state(DEFAULT_ACCOUNT_NAME);
        let personal_state = make_test_account_state("personal");
        let mut two_accts = BTreeMap::new();
        two_accts.insert(default_state2.id.clone(), default_state2);
        two_accts.insert(personal_state.id.clone(), personal_state);
        assert!(!is_legacy_single_account(&two_accts));
    }

    #[test]
    fn validate_bare_tool_namespace_truth_table() {
        // Five cases cover every mutation surface on
        // `validate_bare_tool_namespace`'s composite guard
        // (`!legacy_single_account && is_bare_simple_tool_name(raw)`).
        //
        // Case 3 (multi-account + bare simple tool) specifically kills
        // the `delete ! in <impl ServerHandler>::call_tool` mutation
        // formerly annotated as a known-equivalent test-infrastructure
        // gap — under the mutation the helper would return `Ok(())`
        // and let the bare call through, but the unmutated function
        // returns `Err(INVALID_PARAMS)`.

        // Case 1: legacy mode + bare simple → Ok (legacy preserves
        // bare names regardless of tool simplicity).
        assert!(validate_bare_tool_namespace(true, "send_email").is_ok());

        // Case 2: legacy mode + namespaced → Ok (dotted prefix is fine
        // anywhere).
        assert!(validate_bare_tool_namespace(true, "work.send_email").is_ok());

        // Case 3: multi-account + bare simple → INVALID_PARAMS. Kills
        // `delete !`: the mutated form `legacy_single_account && ...`
        // returns `Ok(())` here (the legacy_single_account=false branch
        // short-circuits the `&&`).
        let err = validate_bare_tool_namespace(false, "send_email").unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("multi-account mode"),
            "message should explain the contract: {message}",
            message = err.message,
        );
        assert!(
            err.message.contains("send_email"),
            "message should echo the tool name: {message}",
            message = err.message,
        );

        // Case 4: multi-account + namespaced → Ok (the dotted form is
        // exactly what the multi-account contract requires).
        assert!(validate_bare_tool_namespace(false, "work.send_email").is_ok());

        // Case 5: multi-account + infrastructure tool → Ok.
        // `is_bare_simple_tool_name` returns false for `use_account` /
        // `list_accounts`, so the composite short-circuits to `Ok(())`
        // regardless of mode (infrastructure tools are always bare).
        assert!(validate_bare_tool_namespace(false, "use_account").is_ok());
        assert!(validate_bare_tool_namespace(false, "list_accounts").is_ok());
    }

    #[test]
    fn refine_tool_name_is_identity_for_all_other_variants() {
        // Any variant without a refinement rule must pass through
        // unchanged, including when args are absent or irrelevant. A new
        // ToolName variant will fail to compile in `refine_tool_name`'s
        // exhaustive match until a refinement decision is made.
        let mut args = serde_json::Map::new();
        args.insert("include_html".into(), serde_json::Value::Bool(true));
        args.insert(
            "advanced_query".into(),
            serde_json::Value::String("FROM x".into()),
        );
        for name in ToolName::all() {
            let refined_no_args = refine_tool_name(name, None);
            assert_eq!(refined_no_args, name, "{name:?} changed with no args");
            let refined = refine_tool_name(name, Some(&args));
            match name {
                ToolName::FetchMessage => assert_eq!(refined, ToolName::FetchMessageHtml),
                ToolName::Search => assert_eq!(refined, ToolName::SearchAdvanced),
                other => assert_eq!(refined, other, "{other:?} unexpectedly refined"),
            }
        }
    }

    #[test]
    fn refine_tool_name_promotes_search_on_body() {
        let mut args = serde_json::Map::new();
        args.insert("body".into(), serde_json::Value::String("hello".into()));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_text() {
        let mut args = serde_json::Map::new();
        args.insert("text".into(), serde_json::Value::String("anywhere".into()));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_bcc() {
        let mut args = serde_json::Map::new();
        args.insert(
            "bcc".into(),
            serde_json::Value::String("blind@example.com".into()),
        );
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_non_empty_headers() {
        let mut args = serde_json::Map::new();
        args.insert(
            "headers".into(),
            serde_json::json!([{"name": "List-Id", "value": "rust"}]),
        );
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_does_not_promote_on_empty_headers_array() {
        let mut args = serde_json::Map::new();
        args.insert("headers".into(), serde_json::json!([]));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::Search,
        );
    }

    #[test]
    fn refine_tool_name_does_not_promote_on_explicit_null_body() {
        // JSON {"body": null} must NOT promote: serde deserializes
        // Option<String> = null as None, so the filter is a no-op
        // and promotion would yield a misleading PostureDenied.
        let mut args = serde_json::Map::new();
        args.insert("body".into(), serde_json::Value::Null);
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::Search,
        );
    }

    #[test]
    fn refine_tool_name_does_not_promote_on_envelope_or_flag_fields() {
        // cc/larger/sent_since/answered are NOT content-oracle inputs;
        // they ride the existing low-posture Search seat.
        for field in ["cc", "larger", "sent_since", "answered"] {
            let mut args = serde_json::Map::new();
            args.insert(field.into(), serde_json::json!("payload"));
            assert_eq!(
                refine_tool_name(ToolName::Search, Some(&args)),
                ToolName::Search,
                "{field} unexpectedly promoted",
            );
        }
    }
}
