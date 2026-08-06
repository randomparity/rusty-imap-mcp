//! Per-account boot policy matrix: the explicit per-tool verdicts an account
//! carries and which config layer wrote each one (#632), plus the resolved
//! `protected_folders` / `expunge_folders` the `FolderGuard` is built from
//! and where each of those came from (#696).
//!
//! Consumers report the same thing — the boot `tracing::info!` lines, the
//! `process_start` audit record, and `--dry-run` — so all of them derive
//! their rows from [`account_tool_matrix`] here. Adding provenance to one
//! renderer and not the others is what this module exists to prevent.
//!
//! # One producer, two states of knowledge
//!
//! Special-use discovery needs a live IMAP session, and two of the three
//! consumers do not have one:
//!
//! - `--dry-run` never opens an IMAP session for this purpose at all;
//! - `process_start` is written by [`crate::boot::audit_init`] *before* the
//!   account registry is built, so no `LIST` has run when the record is
//!   emitted.
//!
//! Only the registry path, after
//! [`crate::boot::discovery::merge_protected_folders`], holds the union the
//! guard is actually built from. Rather than let the two pre-discovery
//! callers silently render a shorter list that looks complete,
//! [`account_tool_matrix`] takes the discovered names as an `Option` and the
//! renderers say which state they are in.

use rimap_audit::record::{
    AccountToolMatrix, FolderEntry, FolderSource, SpecialUseDiscovery, ToolVerdict, VerdictSource,
};
use rimap_config::model::Verdict;
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::tool::ToolName;

/// Collect one account's resolved dispatch policy: effective posture, its
/// explicit per-tool verdicts in [`ToolName`] declaration order, and its two
/// folder lists.
///
/// A verdict is `Account` when the account's own `[accounts.security.tools]`
/// block wrote that key and `Inherited` when it reached the account through
/// `[defaults.security.tools]`. Tools with no explicit verdict are omitted:
/// they follow the base posture.
///
/// `resolved_protected` is the post-discovery protected list — the very
/// slice [`crate::boot::discovery::merge_protected_folders`] returned and
/// `FolderGuard::new` was handed:
///
/// - `Some(names)` — discovery ran. `protected_folders` is `names`, entry
///   for entry and in order, each classified against the configured list:
///   anything the config does not name is [`FolderSource::Discovered`].
///   Passing the guard's own list rather than the discovered names alone is
///   deliberate — it makes the recorded list the guard's list by
///   construction, not by a second merge that could drift from the first.
/// - `None` — discovery has not run at this call site. `protected_folders`
///   is the configured list alone. This is not the same claim as
///   `Some(&[])`, which asserts the guard was built with nothing protected.
///
/// The two do not merely differ in this function's output: they set
/// [`AccountToolMatrix::special_use_discovery`], so the distinction survives
/// into the record and a reader never has to know which call site wrote it.
#[must_use]
pub fn account_tool_matrix(
    acfg: &ValidatedAccountConfig,
    resolved_protected: Option<&[String]>,
) -> AccountToolMatrix {
    let tools = ToolName::all()
        .into_iter()
        .filter_map(|tool| {
            let verdict = acfg.tool_overrides.get(&tool)?;
            Some(ToolVerdict::new(
                tool,
                matches!(*verdict, Verdict::Allow),
                if acfg.account_written_tools.contains(&tool) {
                    VerdictSource::Account
                } else {
                    VerdictSource::Inherited
                },
            ))
        })
        .collect();
    AccountToolMatrix::new(
        acfg.id.as_str().to_string(),
        acfg.security.posture,
        tools,
        protected_entries(acfg, resolved_protected),
        if resolved_protected.is_some() {
            SpecialUseDiscovery::Ran
        } else {
            SpecialUseDiscovery::NotRun
        },
        folder_entries(
            &acfg.security.expunge_folders,
            acfg.account_written_expunge_folders,
        ),
    )
}

/// Tag every name in one configured list with the layer that wrote the list.
///
/// Whole-list, not per-entry: an account's `[accounts.security]` folder list
/// replaces the inherited one outright, so either every entry is
/// account-written or none is.
fn folder_entries(folders: &[String], account_written: bool) -> Vec<FolderEntry> {
    let source = if account_written {
        FolderSource::Account
    } else {
        FolderSource::Inherited
    };
    folders
        .iter()
        .map(|folder| FolderEntry::new(folder.clone(), source))
        .collect()
}

/// Build the `protected_folders` entries.
///
/// With `resolved_protected` absent this is just the configured list tagged
/// with its layer. With it present the resolved list drives the iteration and
/// the configured list is only a lookup table: a name it does not hold —
/// compared case-insensitively, as
/// [`crate::boot::discovery::merge_protected_folders`] dedups — came from
/// special-use discovery. Classifying rather than re-merging is what keeps
/// this from being able to disagree with the guard.
fn protected_entries(
    acfg: &ValidatedAccountConfig,
    resolved_protected: Option<&[String]>,
) -> Vec<FolderEntry> {
    let configured = &acfg.security.protected_folders;
    let Some(resolved) = resolved_protected else {
        return folder_entries(configured, acfg.account_written_protected_folders);
    };
    let configured_source = if acfg.account_written_protected_folders {
        FolderSource::Account
    } else {
        FolderSource::Inherited
    };
    resolved
        .iter()
        .map(|folder| {
            let source = if configured.iter().any(|c| c.eq_ignore_ascii_case(folder)) {
                configured_source
            } else {
                FolderSource::Discovered
            };
            FolderEntry::new(folder.clone(), source)
        })
        .collect()
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

/// Render one folder entry as `<folder>(<account|inherited|discovered>)`.
#[must_use]
pub fn render_folder_entry(entry: &FolderEntry) -> String {
    let source = match entry.source {
        FolderSource::Account => "account",
        FolderSource::Inherited => "inherited",
        FolderSource::Discovered => "discovered",
    };
    format!("{}({source})", entry.folder)
}

/// Render one folder list for a single-line consumer, or `none` when empty.
#[must_use]
fn render_folder_list(entries: &[FolderEntry]) -> String {
    if entries.is_empty() {
        return "none".to_string();
    }
    entries
        .iter()
        .map(render_folder_entry)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Emit the boot log line for one account's resolved folder policy.
///
/// Separate from [`log_account_matrix`], and emitted later, because the two
/// lines know different things at different points: the tool matrix is
/// logged before the account connects, so an account that never comes up
/// still leaves it behind (#632), while this line is worth logging only once
/// special-use discovery has contributed to `protected_folders` — which is
/// after the `FolderGuard` exists.
///
/// `expunge_folders` entries marked `inherited` are the ones to look for: a
/// folder is expungeable that the operator did not ask to make expungeable on
/// this account (#624 / #696).
pub fn log_account_folder_policy(matrix: &AccountToolMatrix) {
    tracing::info!(
        account = %matrix.account,
        protected_folders = %render_folder_list(&matrix.protected_folders),
        expunge_folders = %render_folder_list(&matrix.expunge_folders),
        special_use_discovery = match matrix.special_use_discovery {
            SpecialUseDiscovery::Ran => "ran",
            SpecialUseDiscovery::NotRun => "not_run",
        },
        "effective folder policy",
    );
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_audit::record::{FolderSource, SpecialUseDiscovery, VerdictSource};
    use rimap_config::loader::load_and_validate;
    use rimap_config::validate::ValidatedAccountConfig;
    use rimap_core::account::AccountId;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;
    use tempfile::TempDir;

    use super::{account_tool_matrix, render_folder_list, render_verdict};

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
        let matrix = account_tool_matrix(&work_account(&dir), None);

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
        let matrix = account_tool_matrix(&work_account(&dir), None);
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
        let matrix = account_tool_matrix(&work_account(&dir), None);
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
        let matrix = account_tool_matrix(&work_account(&dir), None);
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

    /// Two accounts against one `[defaults.security]` that names both folder
    /// lists: `work` restates neither and inherits both, `personal` writes
    /// its own `expunge_folders`.
    fn inherited_folders_config(dir: &TempDir) -> PathBuf {
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent"]
expunge_folders = ["Trash"]

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[[accounts]]
name = "personal"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@personal.test"

[accounts.security]
protected_folders = ["Archive"]
expunge_folders = ["Junk"]

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

    fn folder_account(dir: &TempDir, name: &str) -> ValidatedAccountConfig {
        let path = inherited_folders_config(dir);
        let multi = load_and_validate(&path).unwrap();
        multi.accounts[&AccountId::new(name).unwrap()].clone()
    }

    #[test]
    fn expunge_folders_inherited_from_defaults_are_marked_inherited() {
        // The #696 case: `Trash` is expungeable on an account whose own
        // `[accounts.security]` block never mentioned it.
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&folder_account(&dir, "work"), None);

        assert_eq!(
            matrix.expunge_folders.len(),
            1,
            "{:?}",
            matrix.expunge_folders
        );
        assert_eq!(matrix.expunge_folders[0].folder, "Trash");
        assert_eq!(matrix.expunge_folders[0].source, FolderSource::Inherited);

        let protected: Vec<_> = matrix
            .protected_folders
            .iter()
            .map(|e| (e.folder.as_str(), e.source))
            .collect();
        assert_eq!(
            protected,
            vec![
                ("INBOX", FolderSource::Inherited),
                ("Sent", FolderSource::Inherited),
            ],
        );
    }

    #[test]
    fn account_written_folder_lists_are_marked_account() {
        let dir = TempDir::new().unwrap();
        let matrix = account_tool_matrix(&folder_account(&dir, "personal"), None);
        assert_eq!(matrix.expunge_folders[0].folder, "Junk");
        assert_eq!(matrix.expunge_folders[0].source, FolderSource::Account);
        assert_eq!(matrix.protected_folders[0].folder, "Archive");
        assert_eq!(matrix.protected_folders[0].source, FolderSource::Account);
    }

    #[test]
    fn resolved_protected_list_marks_names_the_config_never_named_as_discovered() {
        // What the boot path passes: the merged list `FolderGuard::new` was
        // handed. `[Gmail]/Sent Mail` is in it and in no config layer, so it
        // can only have come from special-use discovery.
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        let resolved = crate::boot::discovery::merge_protected_folders(
            &acfg.security.protected_folders,
            vec!["[Gmail]/Sent Mail".to_string()],
        );
        let matrix = account_tool_matrix(&acfg, Some(&resolved));

        let rendered: Vec<_> = matrix
            .protected_folders
            .iter()
            .map(|e| (e.folder.as_str(), e.source))
            .collect();
        assert_eq!(
            rendered,
            vec![
                ("INBOX", FolderSource::Inherited),
                ("Sent", FolderSource::Inherited),
                ("[Gmail]/Sent Mail", FolderSource::Discovered),
            ],
        );
    }

    #[test]
    fn resolved_protected_classification_is_case_insensitive() {
        // `merge_protected_folders` dedups case-insensitively, so a server
        // reporting `sent` for a configured `Sent` yields one entry. That
        // entry is configured, not discovered — a case difference must not
        // be enough to attribute an operator's folder to the server.
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        let resolved = crate::boot::discovery::merge_protected_folders(
            &acfg.security.protected_folders,
            vec!["sent".to_string()],
        );
        let matrix = account_tool_matrix(&acfg, Some(&resolved));
        assert_eq!(matrix.protected_folders.len(), 2, "{resolved:?}");
        assert!(
            matrix
                .protected_folders
                .iter()
                .all(|e| e.source == FolderSource::Inherited),
            "{:?}",
            matrix.protected_folders,
        );
    }

    #[test]
    fn no_discovery_input_yields_the_configured_list_only() {
        // `None` and `Some(&[])` are different claims; `None` must not
        // fabricate a discovered entry, and must not drop a configured one.
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        let matrix = account_tool_matrix(&acfg, None);
        assert_eq!(
            matrix
                .protected_folders
                .iter()
                .map(|e| e.folder.clone())
                .collect::<Vec<_>>(),
            acfg.security.protected_folders,
        );
        assert!(
            matrix
                .protected_folders
                .iter()
                .all(|e| e.source != FolderSource::Discovered),
        );
    }

    #[test]
    fn an_empty_resolved_list_records_nothing_protected() {
        // `Some(&[])` is the guard being built with an empty protected list.
        // It must render as empty, not fall back to the configured list.
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        let matrix = account_tool_matrix(&acfg, Some(&[]));
        assert!(matrix.protected_folders.is_empty());
        assert_eq!(render_folder_list(&matrix.protected_folders), "none");
    }

    #[test]
    fn the_discovery_argument_sets_the_recorded_discovery_state() {
        // `None` and `Some` must stay apart *in the record*, not only in this
        // function's output — an empty union and an un-run discovery are
        // different claims and both can produce an empty list.
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        assert_eq!(
            account_tool_matrix(&acfg, None).special_use_discovery,
            SpecialUseDiscovery::NotRun,
        );
        assert_eq!(
            account_tool_matrix(&acfg, Some(&[])).special_use_discovery,
            SpecialUseDiscovery::Ran,
        );
        assert_eq!(
            account_tool_matrix(&acfg, Some(&acfg.security.protected_folders))
                .special_use_discovery,
            SpecialUseDiscovery::Ran,
        );
    }

    #[test]
    fn render_folder_list_names_every_entry_and_its_source() {
        let dir = TempDir::new().unwrap();
        let acfg = folder_account(&dir, "work");
        let resolved = crate::boot::discovery::merge_protected_folders(
            &acfg.security.protected_folders,
            vec!["[Gmail]/Trash".to_string()],
        );
        let matrix = account_tool_matrix(&acfg, Some(&resolved));
        assert_eq!(
            render_folder_list(&matrix.protected_folders),
            "INBOX(inherited) Sent(inherited) [Gmail]/Trash(discovered)",
        );
        assert_eq!(
            render_folder_list(&matrix.expunge_folders),
            "Trash(inherited)",
        );
    }

    #[test]
    fn a_flat_config_reports_its_folder_lists_as_account_written() {
        // A flat config has no `[defaults]` layer, so `inherited` would send
        // an operator looking for a block that does not exist.
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
expunge_folders = ["Junk"]

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        );
        std::fs::write(&config_path, body).unwrap();
        let raw = rimap_config::loader::load_from_path(&config_path).unwrap();
        let multi = rimap_config::validate::validate_legacy_as_multi(raw).unwrap();
        let acfg = &multi.accounts[&AccountId::default_account()];

        let matrix = account_tool_matrix(acfg, None);
        assert_eq!(matrix.expunge_folders[0].folder, "Junk");
        assert_eq!(matrix.expunge_folders[0].source, FolderSource::Account);
        assert!(
            matrix
                .protected_folders
                .iter()
                .all(|e| e.source == FolderSource::Account),
            "{:?}",
            matrix.protected_folders,
        );
    }
}
