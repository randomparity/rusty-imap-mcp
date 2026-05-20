//! Folder management tool handlers: create, rename, delete.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `create_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFolderInput {
    /// Folder to create.
    pub folder: String,
}

/// Input for `rename_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFolderInput {
    /// Current folder name.
    pub folder: String,
    /// New folder name.
    pub new_folder: String,
}

/// Input for `delete_folder`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFolderInput {
    /// Folder to delete.
    pub folder: String,
}

/// Trusted metadata for a `create_folder` response.
#[derive(Debug, Serialize)]
pub struct CreateFolderMeta {
    /// Always `true` when the handler returns `Ok`.
    pub created: bool,
    /// Name of the created folder.
    pub folder: String,
}

/// Trusted metadata for a `rename_folder` response.
#[derive(Debug, Serialize)]
pub struct RenameFolderMeta {
    /// Always `true` when the handler returns `Ok`.
    pub renamed: bool,
    /// Previous folder name.
    pub old_folder: String,
    /// New folder name.
    pub new_folder: String,
}

/// Trusted metadata for a `delete_folder` response.
#[derive(Debug, Serialize)]
pub struct DeleteFolderMeta {
    /// Always `true` when the handler returns `Ok`.
    pub deleted: bool,
    /// Name of the deleted folder.
    pub folder: String,
    /// Number of messages that were in the folder before deletion.
    pub message_count: u32,
}

/// `create_folder` handler.
///
/// # Errors
///
/// `FolderGuard::check_protected` runs before any IMAP traffic and is
/// the first source of errors:
/// - `RimapError::Authz { code: InvalidFolderName, ... }` if the name
///   fails structural validation (empty, too long, forbidden chars).
/// - `RimapError::Authz { code: ProtectedFolder, ... }` if the name is
///   in the protected list or is INBOX.
///
/// After the guard passes, `RimapError::Imap { ... }` may be propagated
/// from the underlying CREATE (e.g. LOGIN failures, server rejection,
/// transport errors).
pub async fn handle_create_folder(
    account: &AccountState,
    input: CreateFolderInput,
) -> Result<ToolResponse<CreateFolderMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    account
        .folder_guard
        .check_protected(&input.folder, "create")?;

    account.imap.create_folder(&input.folder).await?;

    Ok(ToolResponse::meta_only(CreateFolderMeta {
        created: true,
        folder: input.folder,
    }))
}

/// `rename_folder` handler.
///
/// # Errors
///
/// `FolderGuard::check_rename` runs before any IMAP traffic and is the
/// first source of errors:
/// - `RimapError::Authz { code: InvalidFolderName, ... }` if either the
///   source or destination name fails structural validation.
/// - `RimapError::Authz { code: ProtectedFolder, ... }` if either name
///   is in the protected list or is INBOX.
///
/// After the guard passes, `RimapError::Imap { ... }` may be propagated
/// from the underlying RENAME (e.g. LOGIN failures, server rejection,
/// transport errors).
pub async fn handle_rename_folder(
    account: &AccountState,
    input: RenameFolderInput,
) -> Result<ToolResponse<RenameFolderMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;
    crate::tools::validation::validate_folder_input("new_folder", &input.new_folder)?;

    account
        .folder_guard
        .check_rename(&input.folder, &input.new_folder)?;

    account
        .imap
        .rename_folder(&input.folder, &input.new_folder)
        .await?;

    Ok(ToolResponse::meta_only(RenameFolderMeta {
        renamed: true,
        old_folder: input.folder,
        new_folder: input.new_folder,
    }))
}

/// `delete_folder` handler.
///
/// # Errors
///
/// `FolderGuard` runs before any IMAP traffic and is the first source
/// of errors:
/// - `RimapError::Authz { code: InvalidFolderName, ... }` if the name
///   fails structural validation (from `check_protected` or
///   `check_expunge`).
/// - `RimapError::Authz { code: ProtectedFolder, ... }` if the name is
///   in the protected list or is INBOX.
/// - `RimapError::Authz { code: ExpungeDenied, ... }` if the folder is
///   not in the expunge allowlist.
///
/// After the guards pass, `RimapError::Imap { ... }` may be propagated
/// from the underlying STATUS and DELETE (e.g. LOGIN failures, server
/// rejection, transport errors).
pub async fn handle_delete_folder(
    account: &AccountState,
    input: DeleteFolderInput,
) -> Result<ToolResponse<DeleteFolderMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    account
        .folder_guard
        .check_protected(&input.folder, "delete")?;

    account.folder_guard.check_expunge(&input.folder)?;

    let status = account
        .imap
        .status(
            &input.folder,
            rimap_imap::types::StatusItems {
                messages: true,
                recent: false,
                uid_next: false,
                uid_validity: false,
                unseen: false,
            },
        )
        .await?;
    let message_count = status.messages.unwrap_or(0);

    account.imap.delete_folder(&input.folder).await?;

    Ok(ToolResponse::meta_only(DeleteFolderMeta {
        deleted: true,
        folder: input.folder,
        message_count,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_authz::FolderGuard;
    use rimap_core::error::ErrorCode;

    #[test]
    fn rename_to_protected_folder_rejected() {
        let guard = FolderGuard::new(&["Sent".into(), "Drafts".into()], &[]);
        let err = guard.check_rename("temp", "Sent").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }

    #[test]
    fn rename_to_inbox_rejected() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_rename("temp", "INBOX").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }

    #[test]
    fn create_inbox_rejected_even_with_empty_protected_list() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_protected("INBOX", "create").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedFolder);
    }
}
