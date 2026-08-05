//! Per-account boot tool matrix: the explicit per-tool verdicts an account
//! carries and which config layer wrote each one (#632).
//!
//! Three consumers report the same thing — the boot `tracing::info!` line,
//! the `process_start` audit record, and `--dry-run` — so all three derive
//! their rows from [`account_tool_matrix`] here. Adding provenance to one
//! renderer and not the others is what this module exists to prevent.

use rimap_audit::record::{AccountToolMatrix, ToolVerdict, VerdictSource};
use rimap_config::model::Verdict;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::tool::ToolName;

/// Collect one account's effective posture and its explicit per-tool
/// verdicts, in [`ToolName`] declaration order.
///
/// A verdict is `Account` when the account's own `[accounts.security.tools]`
/// block wrote that key and `Inherited` when it reached the account through
/// `[defaults.security.tools]`. Tools with no explicit verdict are omitted:
/// they follow the base posture.
#[must_use]
pub fn account_tool_matrix(acfg: &ValidatedAccountConfig) -> AccountToolMatrix {
    let tools = ToolName::all()
        .into_iter()
        .filter_map(|tool| {
            let verdict = acfg.tool_overrides.get(&tool)?;
            Some(ToolVerdict {
                tool,
                allow: matches!(*verdict, Verdict::Allow),
                source: if acfg.account_written_tools.contains(&tool) {
                    VerdictSource::Account
                } else {
                    VerdictSource::Inherited
                },
            })
        })
        .collect();
    AccountToolMatrix {
        account: acfg.id.as_str().to_string(),
        posture: acfg.security.posture,
        tools,
    }
}

/// Render one verdict as `<tool>=<allow|deny>(<account|inherited>)`.
#[must_use]
pub fn render_verdict(verdict: &ToolVerdict) -> String {
    let allow = if verdict.allow { "allow" } else { "deny" };
    let source = match verdict.source {
        VerdictSource::Account => "account",
        VerdictSource::Inherited => "inherited",
    };
    format!("{}={allow}({source})", verdict.tool)
}

/// Emit the boot log line for one account.
///
/// An inherited `allow` on an account the operator tightened is the case
/// worth seeing here; it is visible as `…=allow(inherited)` beside a
/// `posture` the verdict outranks.
pub fn log_account_matrix(matrix: &AccountToolMatrix) {
    let overrides = if matrix.tools.is_empty() {
        "none".to_string()
    } else {
        matrix
            .tools
            .iter()
            .map(render_verdict)
            .collect::<Vec<_>>()
            .join(" ")
    };
    tracing::info!(
        account = %matrix.account,
        posture = %matrix.posture,
        tool_overrides = %overrides,
        "effective tool matrix",
    );
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_audit::record::VerdictSource;
    use rimap_config::loader::load_and_validate;
    use rimap_config::validate::ValidatedAccountConfig;
    use rimap_core::account::AccountId;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;
    use tempfile::TempDir;

    use super::{account_tool_matrix, render_verdict};

    /// Write a two-layer config whose `[defaults.security.tools]` allows
    /// `delete_message` and whose `work` account tightens posture to
    /// `readonly` without restating that tool — the #632 reproduction.
    fn inherited_allow_config(dir: &TempDir) -> PathBuf {
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[defaults.security]
posture = "full"

[defaults.security.tools]
delete_message = "allow"

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[accounts.security.tools]
search = "deny"

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    fn work_account(dir: &TempDir) -> ValidatedAccountConfig {
        let path = inherited_allow_config(dir);
        let multi = load_and_validate(&path).unwrap();
        multi.accounts[&AccountId::new("work").unwrap()].clone()
    }

    #[test]
    fn inherited_allow_on_tightened_posture_is_marked_inherited() {
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&work_account(&dir));

        assert_eq!(matrix.account, "work");
        assert_eq!(matrix.posture, Posture::Readonly);

        let deletion = matrix
            .tools
            .iter()
            .find(|v| v.tool == ToolName::DeleteMessage)
            .expect("delete_message inherited from [defaults.security.tools]");
        assert!(deletion.allow, "the inherited verdict is an allow");
        assert_eq!(deletion.source, VerdictSource::Inherited);

        let search = matrix
            .tools
            .iter()
            .find(|v| v.tool == ToolName::Search)
            .expect("search written by the account");
        assert!(!search.allow);
        assert_eq!(search.source, VerdictSource::Account);
    }

    #[test]
    fn only_explicit_verdicts_are_listed() {
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&work_account(&dir));
        assert_eq!(
            matrix.tools.len(),
            2,
            "exactly the two tools with explicit verdicts: {:?}",
            matrix.tools,
        );
    }

    #[test]
    fn rows_follow_tool_declaration_order() {
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&work_account(&dir));
        let declared: Vec<_> = ToolName::all()
            .into_iter()
            .filter(|t| matrix.tools.iter().any(|v| v.tool == *t))
            .collect();
        let rendered: Vec<_> = matrix.tools.iter().map(|v| v.tool).collect();
        assert_eq!(rendered, declared);
    }

    #[test]
    fn render_verdict_names_both_the_verdict_and_its_source() {
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&work_account(&dir));
        let rendered: Vec<_> = matrix.tools.iter().map(render_verdict).collect();
        assert!(
            rendered.contains(&"delete_message=allow(inherited)".to_string()),
            "{rendered:?}",
        );
        assert!(
            rendered.contains(&"search=deny(account)".to_string()),
            "{rendered:?}",
        );
    }
}
