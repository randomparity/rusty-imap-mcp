//! Two-account multi-account TOML builder for Phase 3's wire-driven
//! Dovecot e2e. Both accounts target the same Dovecot user
//! (`rimap-test@dovecot`); the surface under test is the posture
//! matrix on the wire, not authentication isolation.

use std::path::Path;

/// Build the multi-account TOML for `e2e_wire.rs`. Caller is
/// responsible for writing the returned string to `config_path` and
/// for placing `audit_path` and `download_dir` inside `allowed_base`.
///
/// `fingerprint_hex` and `port` should be obtained from the
/// `DovecotHarness` at the call site:
/// ```ignore
/// let cfg = build_dovecot_config(
///     &dovecot.fingerprint().to_hex(),
///     dovecot.port(),
///     &audit_path,
///     &allowed_base,
///     &download_dir,
/// );
/// ```
pub fn build_dovecot_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "draftsafe"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[[accounts]]
name = "readonly"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "readonly"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}

/// Build a single-account destructive-posture TOML for
/// `e2e_wire_destructive.rs` (#455). The account exercises the
/// destructive IMAP path: `delete_message` (needs `full`+) and
/// `expunge` (needs `destructive` posture *and* an allowlisted folder).
///
/// `Trash` is placed in `expunge_folders` and removed from
/// `protected_folders`. The two lists are mutually exclusive — the
/// config validator (`validate_folder_safety`) rejects any folder in
/// both, and always force-protects INBOX — so `Sent`/`Drafts` stay
/// protected while `Trash` becomes expungeable. `INBOX` remains
/// unexpungeable (never allowlisted), which is what the
/// `ERR_EXPUNGE_DENIED` cases assert.
pub fn build_dovecot_destructive_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "destructive"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "destructive"
protected_folders = ["INBOX", "Sent", "Drafts"]
expunge_folders = ["Trash"]

# The destructive posture enables send_email, which the validator
# requires an [smtp] section for. This suite exercises the destructive
# mailbox path only, so deny send_email rather than wiring SMTP.
[accounts.security.tools]
send_email = "deny"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}

/// Build the two-account TOML for `e2e_wire_folder_management.rs` (#456).
///
/// The `destructive` account drives the create -> rename -> delete
/// round-trip and the folder-guard denials. `delete_folder` runs
/// `FolderGuard::check_expunge` after `check_protected`, so the folder it
/// deletes must be in `expunge_folders`; the round-trip renames into
/// `e2e-folder-dst`, which is why that name — and only that name — is
/// allowlisted. `INBOX`/`Sent`/`Drafts` stay protected so the
/// `ERR_PROTECTED_FOLDER` cases fire, and a never-allowlisted folder
/// exercises the `ERR_EXPUNGE_DENIED` path on `delete_folder`.
///
/// The `full` account exists only to prove the posture boundary on the
/// wire: `full` advertises `create_folder`/`rename_folder` but not
/// `delete_folder` (destructive-only), and calling `full.delete_folder`
/// is refused with `ERR_POSTURE_DENIED`.
///
/// Both accounts deny `send_email`: the `full` and `destructive` postures
/// enable it, but the config validator requires an `[smtp]` section for a
/// send-capable tool, and this suite exercises the folder path only.
///
/// The `e2e-folder-dst` literal in `expunge_folders` MUST stay in sync
/// with the `DST_FOLDER` constant in `e2e_wire_folder_management.rs`.
pub fn build_dovecot_folder_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "destructive"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "destructive"
protected_folders = ["INBOX", "Sent", "Drafts"]
expunge_folders = ["e2e-folder-dst"]

[accounts.security.tools]
send_email = "deny"

[[accounts]]
name = "full"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "full"

[accounts.security.tools]
send_email = "deny"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}

/// Build a single-account `full`-posture TOML for the `e2e_wire.rs`
/// full-posture round-trips (#460). The `full` posture is the least
/// privilege that permits both `search.advanced_query` (`SearchAdvanced`)
/// and `fetch_message.include_html` (`FetchMessageHtml`) — both are denied
/// under `draft-safe` and `readonly` — so it is the posture under which
/// those two sub-capabilities are exercised as ALLOW round-trips.
///
/// `send_email` is denied via a tool override: the `full` posture enables
/// it, but the config validator requires an `[smtp]` section for a
/// send-capable tool, and this path exercises IMAP retrieval only. Same
/// pattern as [`build_dovecot_destructive_config`] and
/// [`build_dovecot_folder_config`].
pub fn build_dovecot_full_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "full"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "full"

[accounts.security.tools]
send_email = "deny"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}

/// Per-binary dead-code suppression. `mcp_wire_conformance.rs`
/// compiles this module through `support/wire/mod.rs` but never calls
/// these builders; if we relied on `#[expect(dead_code)]` instead, that
/// expectation would be unfulfilled in the binaries that *do* use them
/// (`e2e_wire.rs`, `e2e_wire_destructive.rs`,
/// `e2e_wire_folder_management.rs`) and
/// `clippy::allow_attributes = "deny"` forbids `#[allow]`. Referencing
/// each function inside a never-called helper marks it as used in every
/// compilation unit.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code in mcp_wire_conformance.rs"
)]
fn force_use_for_dead_code_link() {
    let _ = build_dovecot_config;
    let _ = build_dovecot_destructive_config;
    let _ = build_dovecot_folder_config;
    let _ = build_dovecot_full_config;
}
