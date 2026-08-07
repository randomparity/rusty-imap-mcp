//! Audit record schema per design spec §10. Every record carries the shared
//! header (`seq`, `ts`, `process_id`, `kind`) plus a kind-specific payload.
//! Serialization uses `#[serde(tag = "kind")]` to produce a flat JSON object
//! per line (JSONL).
//!
//! # Adding a field
//!
//! Every payload struct is `#[non_exhaustive]`, so adding a field is additive
//! at the Rust API level: no downstream crate can name the full set of fields
//! in a struct expression, and none has to be recompiled against a wider one.
//! It is additive on disk too, because readers tolerate an absent field via
//! `#[serde(default)]`. Both halves are required — see `docs/audit-log.md`
//! ("Compatibility contract"), which is the normative statement of what a
//! reader may assume.
//!
//! That covers every kind, including `auth`: [`AuthEvent`] is *defined* in
//! `rimap_core::auth_event` and only re-exported here, but it carries the
//! attribute too (#716) and is built through `AuthEvent::new`.
//!
//! `#[non_exhaustive]` is a Rust-visibility construct only. It does not touch
//! serde, so an unchanged record serializes to byte-identical JSONL. The
//! golden lines in `tests/non_exhaustive_record.rs` hold that, and are the
//! reason this change is safe to make against an append-only file.
//!
//! Because the attribute rejects *every* cross-crate struct expression —
//! functional-update syntax included (rustc E0639) — types something outside
//! this crate constructs carry a `new` taking the fields with no meaningful
//! default. Reach the rest by assignment: the fields stay `pub`.
//! [`ProcessEnd::new`] is the one deliberate exception to "no meaningful
//! default"; see it for why.
//!
//! The newtypes in [`ids`] are deliberately left exhaustive; see that module.
//! So are the enums here ([`Payload`], [`ProcessEndReason`], [`ToolStatus`],
//! [`VerdictSource`], [`FolderSource`], [`SpecialUseDiscovery`],
//! [`PostureEffective`]), matching #665's treatment of
//! `rimap_config::model`. A new variant is a new `kind` or a new value of an
//! existing one — a reader that does not know it cannot do anything useful
//! with the record, so forcing downstream matches through a wildcard arm
//! would convert a compile error into a silently ignored record.

use std::path::PathBuf;

use rimap_core::{ErrorCode, Posture, WarningCode, tool::ToolName};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod ids;

use crate::record::ids::{ProcessId, Seq, Timestamp};

/// The effective posture recorded on a `tool_start` record.
///
/// `Account` carries the per-account posture that governed dispatch;
/// `Infrastructure` marks records for infra-level tools (`use_account`,
/// `list_accounts`) that bypass per-account posture gating by design.
///
/// The serde form is a flat JSON string that matches the historical
/// on-disk representation: `Posture::as_str()` (kebab-case) for account
/// postures and the literal `"infrastructure"` for the infra variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureEffective {
    /// Per-account posture effective at dispatch time.
    Account(Posture),
    /// Infra-level tool dispatch; no per-account posture applies.
    Infrastructure,
}

impl PostureEffective {
    /// Stable string form used on disk.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account(p) => p.as_str(),
            Self::Infrastructure => "infrastructure",
        }
    }

    /// Build from an optional posture: `None` maps to `Infrastructure`.
    #[must_use]
    pub fn from_optional(posture: Option<Posture>) -> Self {
        match posture {
            Some(p) => Self::Account(p),
            None => Self::Infrastructure,
        }
    }
}

impl Serialize for PostureEffective {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PostureEffective {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::str::FromStr;
        let s = String::deserialize(deserializer)?;
        if s == "infrastructure" {
            return Ok(Self::Infrastructure);
        }
        Posture::from_str(&s)
            .map(Self::Account)
            .map_err(serde::de::Error::custom)
    }
}

/// Why a process exited. Best-effort: only the SIGINT/SIGTERM/EOF paths set
/// this; a hard crash will simply leave the last record as `tool_end` or
/// whatever else was most recently flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEndReason {
    /// SIGINT received (Ctrl-C).
    SignalInt,
    /// SIGTERM received.
    SignalTerm,
    /// Stdin EOF on the MCP transport.
    Eof,
    /// Fatal error path (e.g. config load failure after first record).
    Error,
}

/// Per-account summary for multi-account `process_start` records.
///
/// `posture` serializes via [`rimap_core::Posture`]'s kebab-case serde,
/// which matches [`rimap_core::Posture::as_str`] byte-for-byte so the
/// on-disk form is identical to the prior string-typed field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccountSummary {
    /// Account name from config.
    pub name: String,
    /// Effective posture for this account.
    pub posture: Posture,
    /// IMAP host for this account.
    pub imap_host: String,
}

impl AccountSummary {
    /// Construct an `AccountSummary` from typed parts.
    #[must_use]
    pub fn new(name: String, posture: Posture, imap_host: String) -> Self {
        Self {
            name,
            posture,
            imap_host,
        }
    }
}

/// Which config layer wrote one explicit per-tool verdict.
///
/// `[accounts.security.tools]` and `[defaults.security.tools]` merge per key
/// into a single map at composition time; this is the distinction that merge
/// would otherwise erase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    /// Written in the account's own `[accounts.security.tools]` block.
    Account,
    /// Inherited from `[defaults.security.tools]`.
    Inherited,
}

/// One explicit per-tool verdict and the config layer that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolVerdict {
    /// The tool the verdict names. Serializes via [`ToolName::as_str`].
    pub tool: ToolName,
    /// `true` for an explicit `allow`, `false` for an explicit `deny`.
    ///
    /// A bool rather than a mirror of `rimap_config::model::Verdict`:
    /// `rimap-audit` deliberately depends on `rimap-core` alone, and a
    /// second two-variant enum for the same idea would be a defect surface
    /// with no on-disk gain.
    pub allow: bool,
    /// Whether the account wrote this verdict or inherited it.
    pub source: VerdictSource,
}

impl ToolVerdict {
    /// Construct a verdict. Every field is load-bearing, so all three are
    /// parameters.
    #[must_use]
    pub fn new(tool: ToolName, allow: bool, source: VerdictSource) -> Self {
        Self {
            tool,
            allow,
            source,
        }
    }
}

/// Where one entry of a resolved folder list came from.
///
/// Unlike `[security.tools]`, the folder lists merge *whole-list*: an
/// account's `[accounts.security] expunge_folders` replaces the inherited
/// list outright rather than unioning with it (`AccountSecurityOverrides::
/// merge_onto`). So the layer is a property of the list, and every entry of
/// one configured list shares it.
///
/// [`Self::Discovered`] is the exception, and it is not a config layer at
/// all: `protected_folders` gains server-declared RFC 6154 special-use names
/// at boot, after the config merge, from
/// `rimap_server::boot::discovery::merge_protected_folders`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderSource {
    /// The account's own `[accounts.security]` block wrote this list — or
    /// the config is flat (single-account), where there is no `[defaults]`
    /// layer the list could have been inherited *from*.
    Account,
    /// The account's own block did **not** write this list: it arrived from
    /// `[defaults.security]`, or — when neither layer names it — from the
    /// built-in default. Both are "the operator did not ask for this on this
    /// account", which is the distinction worth recording (#624 / ADR-0013).
    Inherited,
    /// Appended at boot from a special-use folder the IMAP server declared,
    /// not present in any config layer. Only `protected_folders` grows this
    /// way, and only on a code path that has an IMAP session.
    Discovered,
}

/// Whether special-use discovery had run when a matrix was built.
///
/// Without this, `protected_folders` cannot distinguish two different
/// claims that happen to look alike: a server that declared no special-use
/// folders, and a producer that never asked. The second is the normal case
/// for `process_start`, which is written before the account registry exists.
/// An absent field means *unknown*, and the reader is told to substitute
/// [`Self::NotRun`] — see `docs/audit-log.md` ("Compatibility contract").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialUseDiscovery {
    /// Discovery had not run when this matrix was built, so
    /// `protected_folders` is the configured list and nothing in it can be
    /// [`FolderSource::Discovered`]. **Not** a statement that the server
    /// declares no special-use folders.
    ///
    /// Also the value a record predating this field reads as, where it is
    /// vacuous rather than wrong: such a record carries no folder entries at
    /// all, so there is no list whose completeness could be misjudged.
    #[default]
    NotRun,
    /// Discovery ran, and `protected_folders` is the union the `FolderGuard`
    /// was built from. An empty list here is the affirmative claim that the
    /// guard protects nothing.
    Ran,
}

/// One entry of a resolved folder list and where it came from.
///
/// A struct expression is rejected outside this crate:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::record::FolderEntry {
///     folder: "INBOX".to_owned(),
///     source: rimap_audit::record::FolderSource::Account,
/// };
/// ```
///
/// And so is functional-update syntax, spreading a value this crate did hand
/// out — `..` is still a struct expression (E0639):
///
/// ```compile_fail,E0639
/// let base = rimap_audit::record::FolderEntry::new(
///     "INBOX".to_owned(),
///     rimap_audit::record::FolderSource::Account,
/// );
/// let _ = rimap_audit::record::FolderEntry { folder: "Sent".to_owned(), ..base };
/// ```
///
/// The supported form is [`FolderEntry::new`]:
///
/// ```
/// let entry = rimap_audit::record::FolderEntry::new(
///     "INBOX".to_owned(),
///     rimap_audit::record::FolderSource::Inherited,
/// );
/// assert_eq!(entry.folder, "INBOX");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FolderEntry {
    /// The folder name exactly as the guard was built with it — a config
    /// literal, or a server-native name such as `[Gmail]/Sent Mail`.
    pub folder: String,
    /// Which layer put this entry in the list.
    pub source: FolderSource,
}

impl FolderEntry {
    /// Construct an entry. Both fields are load-bearing, so both are
    /// parameters.
    #[must_use]
    pub fn new(folder: String, source: FolderSource) -> Self {
        Self { folder, source }
    }
}

/// One account's resolved dispatch policy as of boot: effective posture, the
/// explicit per-tool verdicts, and the two folder lists the `FolderGuard` is
/// built from.
///
/// The name predates the folder lists (#632 added the type for verdicts
/// alone, #696 the lists); it is kept because `tool_matrix` is the on-disk
/// field name on [`ProcessStart`], and renaming a type to chase a field it
/// does not own would buy nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccountToolMatrix {
    /// Account name from config.
    pub account: String,
    /// Effective base posture for this account.
    pub posture: Posture,
    /// Explicit verdicts only, in tool declaration order. Tools with no
    /// override follow `posture` through the compile-time posture table,
    /// which the record's `version` / `git_commit` already identify — so
    /// listing them per boot would be redundant bulk.
    #[serde(default)]
    pub tools: Vec<ToolVerdict>,
    /// Resolved `protected_folders`, in list order.
    ///
    /// Read this together with [`Self::special_use_discovery`], which says
    /// whether the list can contain [`FolderSource::Discovered`] entries at
    /// all. Special-use discovery needs an IMAP session, and the
    /// `process_start` record is written before one exists.
    #[serde(default)]
    pub protected_folders: Vec<FolderEntry>,
    /// Whether [`Self::protected_folders`] reflects special-use discovery.
    ///
    /// Kept beside the list rather than inferred from it: an empty or
    /// discovery-free list is otherwise ambiguous between "the server
    /// declared nothing" and "nobody asked the server".
    #[serde(default)]
    pub special_use_discovery: SpecialUseDiscovery,
    /// Resolved `expunge_folders`, in list order. Never carries a
    /// [`FolderSource::Discovered`] entry: discovery only ever widens
    /// protection, never expungeability.
    ///
    /// An `inherited` entry here is the widening worth looking for — it is
    /// the one way a folder becomes expungeable that it was not before
    /// (#624).
    #[serde(default)]
    pub expunge_folders: Vec<FolderEntry>,
}

impl AccountToolMatrix {
    /// Construct a matrix. Every list is a parameter rather than a defaulted
    /// empty one, because for each of them the empty value is an affirmative
    /// claim a caller must make deliberately: no explicit verdicts, nothing
    /// protected, nothing expungeable. The one producer resolves all three
    /// before it can build the matrix at all.
    ///
    /// `special_use_discovery` is a parameter for the same reason. A caller
    /// that let it default would be claiming its `protected_folders` predates
    /// discovery, which is the one thing the field exists to state.
    #[must_use]
    pub fn new(
        account: String,
        posture: Posture,
        tools: Vec<ToolVerdict>,
        protected_folders: Vec<FolderEntry>,
        special_use_discovery: SpecialUseDiscovery,
        expunge_folders: Vec<FolderEntry>,
    ) -> Self {
        Self {
            account,
            posture,
            tools,
            protected_folders,
            special_use_discovery,
            expunge_folders,
        }
    }
}

/// Payload of the `folder_policy` kind: the folder lists one account's
/// `FolderGuard` was actually built from (#761, ADR-0021).
///
/// # Why this is not a field on `process_start`
///
/// `protected_folders` gains the server's RFC 6154 special-use names at boot,
/// and that union — not the configured list — is what `check_protected`
/// enforces. `process_start` is written before any IMAP session exists, so it
/// can only ever carry the configured list, and says so with
/// [`SpecialUseDiscovery::NotRun`]. Moving it later would leave an account
/// that fails to connect with no `process_start` at all, losing the property
/// #632 exists to guarantee. So the enforced policy gets its own kind,
/// emitted per account once the guard is built, and `process_start` is
/// untouched in both timing and content.
///
/// The two are complementary rather than redundant: `process_start` covers
/// every configured account whether or not it came up, this covers exactly
/// the accounts something is being enforced for. A `process_start` naming
/// three accounts beside two `folder_policy` records says which account
/// failed to boot.
///
/// The fields mirror the folder half of an [`AccountToolMatrix`] entry, in
/// the same order, so the configured and enforced policies are directly
/// diffable. `posture` and `tools` are not repeated: they do not change
/// between the two emission points and `process_start` already carries them.
///
/// A struct expression is rejected outside this crate:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::record::FolderPolicy {
///     account: "work".to_owned(),
///     protected_folders: Vec::new(),
///     special_use_discovery: rimap_audit::record::SpecialUseDiscovery::Ran,
///     expunge_folders: Vec::new(),
/// };
/// ```
///
/// And so is functional-update syntax spreading a value this crate did hand
/// out — `..` is still a struct expression (E0639). Spreading from the
/// type's own constructor rather than from `Default` is deliberate: this type
/// has no `Default`, so `..Default::default()` would fail with E0277 and the
/// `compile_fail` would pass while testing nothing (#715).
///
/// ```compile_fail,E0639
/// let base = rimap_audit::record::FolderPolicy::new(
///     "work".to_owned(),
///     Vec::new(),
///     rimap_audit::record::SpecialUseDiscovery::Ran,
///     Vec::new(),
/// );
/// let _ = rimap_audit::record::FolderPolicy { account: "personal".to_owned(), ..base };
/// ```
///
/// The supported form is [`FolderPolicy::new`]:
///
/// ```
/// use rimap_audit::record::{FolderEntry, FolderSource, FolderPolicy, SpecialUseDiscovery};
/// let policy = FolderPolicy::new(
///     "work".to_owned(),
///     vec![FolderEntry::new("[Gmail]/Sent Mail".to_owned(), FolderSource::Discovered)],
///     SpecialUseDiscovery::Ran,
///     vec![],
/// );
/// assert_eq!(policy.protected_folders[0].source, FolderSource::Discovered);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FolderPolicy {
    /// Account name from config.
    pub account: String,
    /// The resolved `protected_folders` the guard was handed, in the order it
    /// was handed them. Unlike the `process_start` rendering, this one can
    /// carry [`FolderSource::Discovered`] entries — carrying them is the
    /// reason the kind exists.
    pub protected_folders: Vec<FolderEntry>,
    /// Always [`SpecialUseDiscovery::Ran`] on a correctly-wired record, and
    /// carried anyway.
    ///
    /// Not redundancy: it is a constant of correct *wiring*, not of the type.
    /// The lists come from `account_tool_matrix`, whose `Option` argument is
    /// what separates "discovery ran, this is the guard's list" from "this is
    /// the configured list". A producer that passed `None` would emit the
    /// configured list looking exactly like the enforced union — with this
    /// field it instead emits `not_run` on a `folder_policy` line, which is
    /// visibly wrong and assertable. See ADR-0021.
    pub special_use_discovery: SpecialUseDiscovery,
    /// The resolved `expunge_folders` the guard was handed. Never carries a
    /// [`FolderSource::Discovered`] entry: discovery only widens protection,
    /// never expungeability.
    pub expunge_folders: Vec<FolderEntry>,
}

impl FolderPolicy {
    /// Construct a policy record. Every field is a parameter, including the
    /// two lists whose empty value is an affirmative claim — nothing
    /// protected, nothing expungeable — and `special_use_discovery`, whose
    /// whole purpose is to be passed through from the matrix rather than
    /// assumed.
    ///
    /// No `#[serde(default)]` on any field, and so none of them defaults
    /// here: these are the kind's birth fields, present on every line it has
    /// ever written. Defaulting them would let a truncated line parse as a
    /// policy record claiming nothing was protected.
    #[must_use]
    pub fn new(
        account: String,
        protected_folders: Vec<FolderEntry>,
        special_use_discovery: SpecialUseDiscovery,
        expunge_folders: Vec<FolderEntry>,
    ) -> Self {
        Self {
            account,
            protected_folders,
            special_use_discovery,
            expunge_folders,
        }
    }
}

/// Payload of the `process_start` kind. Fields chosen to chain history across
/// restarts (see spec §10 startup self-check).
///
/// Nothing outside this crate constructs a `ProcessStart` directly — the
/// writer builds it from [`crate::ProcessStartInputs`] — so it carries no
/// constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProcessStart {
    /// Semver of the running binary.
    pub version: String,
    /// Git commit SHA embedded at build (via `vergen` when wired in Sprint 5;
    /// populated as an empty string until then).
    pub git_commit: String,
    /// Effective base posture at startup (single-account mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<Posture>,
    /// Per-account summaries (multi-account mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<AccountSummary>>,
    /// Per-account posture and explicit per-tool verdicts, each marked
    /// account-written or inherited (#632). Unlike `posture` / `accounts`
    /// above, this carries one entry per account in both single- and
    /// multi-account mode, so the posture a process booted with is
    /// reconstructable from the log without knowing which mode it ran in.
    ///
    /// `#[serde(default)]` because `process_start` records written before
    /// #632 carry no such field, and must keep deserializing as empty.
    #[serde(default)]
    pub tool_matrix: Vec<AccountToolMatrix>,
    /// Absolute path of the loaded config file.
    pub config_path: PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Sequence number of the last record in the file at startup, if any.
    pub previous_last_seq: Option<Seq>,
    /// Process ID of the previous run, if the file was non-empty.
    pub previous_process_id: Option<ProcessId>,
    /// The inode of the audit file as this process observed it on open.
    /// On Windows this field stores `0` (inode concept does not apply).
    pub previous_file_inode: u64,
    /// Whether the observed inode differs from the inode recorded in the most
    /// recent prior `process_start`. Tamper signal.
    pub audit_file_inode_changed: bool,
}

/// Payload of the `process_end` kind.
///
/// # The attribute is load-bearing
///
/// A doctest compiles as its own crate, so `#[non_exhaustive]` is in force in
/// the block below exactly as it is for a downstream consumer. That makes this
/// the workspace's only *enforcing* check on the attribute: the integration
/// tests in `tests/non_exhaustive_record.rs` document the idiom, but every
/// construct in them compiles just as well on an exhaustive struct, so they
/// would stay green if the attribute were dropped in a conflict resolution.
/// These two do not.
///
/// A struct expression is rejected:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::record::ProcessEnd {
///     reason: rimap_audit::record::ProcessEndReason::Eof,
///     total_tool_calls: 0,
///     records_lost: 0,
///     undrained_dispatches: 0,
/// };
/// ```
///
/// And so is functional-update syntax, which is the premise this change was
/// twice reported to have gotten wrong -- `..Default::default()` is still a
/// struct expression:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::record::ToolStart {
///     tool: rimap_core::tool::ToolName::Search,
///     ..Default::default()
/// };
/// ```
///
/// The supported form is [`ProcessEnd::new`] plus field assignment:
///
/// ```
/// use rimap_audit::record::{ProcessEnd, ProcessEndReason};
/// let end = ProcessEnd::new(ProcessEndReason::Eof, 12, 0, 0);
/// assert_eq!(end.total_tool_calls, 12);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProcessEnd {
    /// Why the process exited.
    pub reason: ProcessEndReason,
    /// Number of tool calls dispatched in this process.
    pub total_tool_calls: u64,
    /// Number of records this process failed to persist and told no caller
    /// about — read from
    /// [`AuditWriter::suppressed_failures`](crate::AuditWriter::suppressed_failures)
    /// at shutdown. Non-zero means this file has a hole in it: some event
    /// happened that left no record. The two sources are deliberately merged
    /// into one count; see that accessor for why.
    ///
    /// `#[serde(default)]` because `process_end` records written before #647
    /// carry no such field, and must keep deserializing as zero.
    #[serde(default)]
    pub records_lost: u64,
    /// Tool dispatches — or audit writes one of them offloaded — still
    /// registered when the shutdown drain's budget expired. Non-zero means the
    /// terminal-record guarantee is **not backed** for this run: what those
    /// dispatches wrote may be sequenced after this record, may have been lost
    /// to process exit, or may have landed in time after all. See
    /// `docs/audit-log.md`, "`process_end` is terminal", and ADR-0015.
    ///
    /// It measures an exceeded bound, not an observed disorder. Every counted
    /// dispatch had already been cancelled when the count was read, and the
    /// server then spends up to its drainer-join budget before writing this
    /// record — so one that missed the drain by a millisecond may well finish
    /// inside that window. Alert on a non-zero count and treat the run as
    /// unverified; do not read it as proof that a record followed this one.
    ///
    /// A dispatch that offloaded an audit write takes a second registration for
    /// it (#672), so this bounds the number of dispatches involved from above
    /// rather than counting them exactly.
    ///
    /// `#[serde(default)]` because `process_end` records written before #680
    /// carry no such field, and must keep deserializing as zero.
    #[serde(default)]
    pub undrained_dispatches: u64,
}

impl ProcessEnd {
    /// Construct a `process_end` payload.
    ///
    /// `records_lost` and `undrained_dispatches` are parameters rather than
    /// defaulted fields, departing from #665's rule that a constructor takes
    /// exactly the fields serde treats as required. A zero in either is not an
    /// absent value: it is an affirmative, durable claim — that this process's
    /// record stream has no hole in it, and that no dispatch outlived the
    /// shutdown drain. A caller that never assigned the field would publish
    /// that claim without measuring it.
    ///
    /// [`ToolStartInputs::new`](crate::ToolStartInputs::new) departs for the
    /// same reason, and its doc states the rule the three share.
    /// Production reads `records_lost` from
    /// [`AuditWriter::suppressed_failures`](crate::AuditWriter::suppressed_failures)
    /// (#647) and `undrained_dispatches` from the return of the server's
    /// dispatch drain (#680); a synthetic record passes the counts it means to
    /// assert.
    #[must_use]
    pub fn new(
        reason: ProcessEndReason,
        total_tool_calls: u64,
        records_lost: u64,
        undrained_dispatches: u64,
    ) -> Self {
        Self {
            reason,
            total_tool_calls,
            records_lost,
            undrained_dispatches,
        }
    }
}

/// Top-level audit record enum. One variant per `kind` discriminator.
/// Serialized as a flat JSON object per line with `seq`, `ts`, `process_id`,
/// `kind`, and the kind-specific fields merged in via `#[serde(flatten)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuditRecord {
    /// Per-process monotonic sequence number.
    pub seq: Seq,
    /// Millisecond-precision UTC timestamp.
    pub ts: Timestamp,
    /// Per-process ULID.
    pub process_id: ProcessId,
    /// The kind-specific payload. `#[serde(flatten)]` + the inner `tag = "kind"`
    /// produces a single flat object with a `kind` discriminator.
    #[serde(flatten)]
    pub payload: Payload,
}

impl AuditRecord {
    /// Assemble a record from its header and payload. Every field is part of
    /// the header contract, so all four are parameters.
    #[must_use]
    pub fn new(seq: Seq, ts: Timestamp, process_id: ProcessId, payload: Payload) -> Self {
        Self {
            seq,
            ts,
            process_id,
            payload,
        }
    }
}

// `AuthEvent` and `AuthResult` live in `rimap_core::auth_event` so
// `rimap-imap` can construct them without depending on this crate.
// Re-exported here under their canonical names for ergonomic access
// from within `rimap-audit` (writer, reader, on-disk format tests).
//
// `AuthEvent` is `#[non_exhaustive]` like the payloads defined here (#716),
// so the "Adding a field" note in the module docs covers it; its constructor
// is `AuthEvent::new`. Being defined in another crate, the attribute is in
// force on it *inside* `rimap-audit` too, unlike the local payloads.
// `AuthResult` is an enum and stays exhaustive, matching #665 and #706.
pub use rimap_core::auth_event::{AuthEvent, AuthResult};

/// Payload of the `tool_start` kind. Recorded before dispatch begins so a
/// crash mid-call still leaves a breadcrumb.
///
/// Built by the writer from [`crate::ToolStartInputs`]; no external
/// construction site, so no constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolStart {
    /// Account name this tool call targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The v1 tool name. Serializes via [`ToolName::as_str`].
    pub tool: ToolName,
    /// Effective posture at dispatch time (after any config-override merge).
    pub posture_effective: PostureEffective,
    /// Redacted arguments object produced by `redact::Redactor`.
    pub arguments_redacted: serde_json::Value,
    /// SHA-256 of the canonical JSON serialization of the *unredacted* payload,
    /// hex-encoded. Enables integrity checks without leaking content.
    pub arguments_hash_sha256: String,
}

/// Outcome status for a tool call. `Ok` means a structured result was
/// returned; `Error` means dispatch failed and `error_code` is populated;
/// `Cancelled` means the tool call was cancelled (e.g. client disconnect, runtime shutdown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Tool call succeeded.
    Ok,
    /// Tool call failed.
    Error,
    /// Tool call was cancelled (e.g. client disconnect, runtime shutdown).
    /// Written by the cancellation drop-guard on future drop; see #99.
    Cancelled,
}

/// A coarse summary of what a tool returned. Structured so reviewers can
/// reconstruct activity without reading message bodies.
///
/// This is the **un-redacted result-provenance sink** of the `tool_end`
/// record: unlike `arguments_redacted`, its fields are serialized verbatim
/// (e.g. raw `message_ids_returned`). Any field added here therefore bypasses
/// the argument redaction schema and MUST be consciously reviewed for
/// sensitivity before being recorded durably.
///
/// Every field is `#[serde(default)]`, so `Default` is the whole constructor
/// this type needs: build with `ResultSummary::default()` and assign what the
/// tool actually produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct ResultSummary {
    /// RFC 822 `Message-ID` values returned to the caller.
    #[serde(default)]
    pub message_ids_returned: Vec<String>,
    /// Approximate bytes returned to the caller (post-truncation).
    #[serde(default)]
    pub bytes_returned: u64,
    /// Whether the server truncated the result to fit a limit.
    #[serde(default)]
    pub truncated: bool,
    /// Security warning codes emitted alongside the payload (e.g.
    /// `lookalike_mixed_script`). Serialized as `snake_case` strings
    /// via [`WarningCode`]'s serde impl, matching the on-disk form
    /// the field carried when it was typed `Vec<String>`.
    #[serde(default)]
    pub security_warnings_emitted: Vec<WarningCode>,
    /// Absolute path of a durable artifact this tool wrote (e.g.
    /// `download_attachment`, `export_messages`), if any. Recorded so the
    /// actual on-disk scope is reconstructable post-incident (#316). Omitted
    /// from the on-disk record when absent, so tools that write nothing keep
    /// their prior `tool_end` shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// SHA-256 (hex) of the written artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// Byte length of the written artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    /// UIDs actually exported (the `export_messages` succeeded partition), in
    /// caller order. Empty (and omitted) for tools that do not export.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uids_exported: Vec<u32>,
    /// Requested UIDs that were not exported (the `export_messages` failed
    /// partition). Empty (and omitted) for tools that do not export.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uids_failed: Vec<u32>,
    /// Sandbox files attached to an outbound `send_email` / `create_draft`
    /// message (basename + byte count), in caller order. The compensating
    /// forensic control for the accepted shared-sandbox model: the request
    /// args redact attachment paths, so this is where "which sandbox file left
    /// the boundary" is durably recorded. Empty (and omitted) for every other
    /// tool and for messages with no attachments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments_sent: Vec<AttachmentProvenance>,
}

/// Basename and byte count of one attachment recorded in a `tool_end`
/// [`ResultSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttachmentProvenance {
    /// Basename of the attached sandbox file (never a full path).
    pub filename: String,
    /// Raw byte length before base64 inflation.
    pub bytes: u64,
}

impl AttachmentProvenance {
    /// Record one attachment. Both fields are required to identify it.
    #[must_use]
    pub fn new(filename: String, bytes: u64) -> Self {
        Self { filename, bytes }
    }
}

/// Snapshot of the provenance ring buffer at `tool_end` time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Provenance {
    /// Configured window in seconds.
    pub window_seconds: u32,
    /// Message IDs read by this process within the window, oldest to newest.
    pub message_ids_recently_read: Vec<String>,
}

impl Provenance {
    /// Snapshot the ring buffer. `message_ids_recently_read` has no
    /// `#[serde(default)]`: an empty list and an absent one mean different
    /// things to a reader, so the caller states which it has.
    #[must_use]
    pub fn new(window_seconds: u32, message_ids_recently_read: Vec<String>) -> Self {
        Self {
            window_seconds,
            message_ids_recently_read,
        }
    }
}

/// Payload of the `tool_end` kind.
///
/// Built by the writer from [`crate::ToolEndInputs`]; no external
/// construction site, so no constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ToolEnd {
    /// Account name this tool call targeted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// `seq` of the paired `tool_start` record.
    pub start_seq: Seq,
    /// Tool name (duplicated from `tool_start` for self-contained log lines).
    pub tool: ToolName,
    /// Outcome.
    pub status: ToolStatus,
    /// On `status = Error`, the stable error code; `None` on success.
    pub error_code: Option<ErrorCode>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Coarse result summary.
    pub result_summary: ResultSummary,
    /// Provenance snapshot at end-of-call time.
    pub provenance: Provenance,
}

/// Payload of the `config` kind. Declared now so Sprint 5 can emit it; no
/// code path writes it yet — and so no external construction site, and no
/// constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConfigEvent {
    /// Path the config was loaded from.
    pub path: PathBuf,
    /// SHA-256 of the config file contents, hex-encoded.
    pub hash_sha256: String,
}

/// Payload enum discriminated by the `kind` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Process startup event — always the first record of a given `process_id`.
    ProcessStart(ProcessStart),
    /// Process shutdown event — best-effort.
    ProcessEnd(ProcessEnd),
    /// IMAP authentication attempt.
    Auth(AuthEvent),
    /// A tool call has entered the dispatch chain.
    ToolStart(ToolStart),
    /// A tool call has exited the dispatch chain.
    ToolEnd(ToolEnd),
    /// Config-related event (declared for Sprint 5; not emitted in Sprint 2).
    Config(ConfigEvent),
    /// One account's enforced folder policy, written once its `FolderGuard`
    /// exists (#761).
    FolderPolicy(FolderPolicy),
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use rimap_core::{Posture, tool::ToolName};

    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{
        AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart, ToolStatus,
    };

    fn sample_start() -> AuditRecord {
        sample_start_with(Vec::new())
    }

    fn process_start_of(rec: &AuditRecord) -> Option<&ProcessStart> {
        match &rec.payload {
            Payload::ProcessStart(start) => Some(start),
            _ => None,
        }
    }

    fn sample_start_with(tool_matrix: Vec<crate::record::AccountToolMatrix>) -> AuditRecord {
        AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessStart(ProcessStart {
                version: "0.1.0".to_string(),
                git_commit: String::new(),
                posture: Some(Posture::DraftSafe),
                accounts: None,
                tool_matrix,
                config_path: PathBuf::from("/tmp/config.toml"),
                config_hash_sha256: "abcd".repeat(16),
                previous_last_seq: None,
                previous_process_id: None,
                previous_file_inode: 12345,
                audit_file_inode_changed: false,
            }),
        }
    }

    #[test]
    fn process_start_serializes_with_flat_kind_discriminator() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_start");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["posture"], "draft-safe");
        assert!(v["accounts"].is_null(), "accounts should be omitted");
        assert!(v["ts"].is_string());
        assert_eq!(v["previous_file_inode"], 12345);
        assert_eq!(v["audit_file_inode_changed"], false);
    }

    #[test]
    fn process_start_round_trips_through_serde() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_start_tool_matrix_serializes_verdicts_with_provenance() {
        use crate::record::{AccountToolMatrix, ToolVerdict, VerdictSource};

        let rec = sample_start_with(vec![AccountToolMatrix {
            account: "work".to_string(),
            posture: Posture::Readonly,
            tools: vec![
                ToolVerdict {
                    tool: ToolName::DeleteMessage,
                    allow: true,
                    source: VerdictSource::Inherited,
                },
                ToolVerdict {
                    tool: ToolName::Search,
                    allow: false,
                    source: VerdictSource::Account,
                },
            ],
            protected_folders: Vec::new(),
            special_use_discovery: crate::record::SpecialUseDiscovery::NotRun,
            expunge_folders: Vec::new(),
        }]);

        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tool_matrix"][0]["account"], "work");
        assert_eq!(v["tool_matrix"][0]["posture"], "readonly");
        assert_eq!(v["tool_matrix"][0]["tools"][0]["tool"], "delete_message");
        assert_eq!(v["tool_matrix"][0]["tools"][0]["allow"], true);
        assert_eq!(v["tool_matrix"][0]["tools"][0]["source"], "inherited");
        assert_eq!(v["tool_matrix"][0]["tools"][1]["tool"], "search");
        assert_eq!(v["tool_matrix"][0]["tools"][1]["allow"], false);
        assert_eq!(v["tool_matrix"][0]["tools"][1]["source"], "account");

        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_start_tool_matrix_serializes_folder_lists_with_provenance() {
        use crate::record::{AccountToolMatrix, FolderEntry, FolderSource, SpecialUseDiscovery};

        let rec = sample_start_with(vec![AccountToolMatrix::new(
            "work".to_string(),
            Posture::Readonly,
            Vec::new(),
            vec![
                FolderEntry::new("INBOX".to_string(), FolderSource::Inherited),
                FolderEntry::new("[Gmail]/Sent Mail".to_string(), FolderSource::Discovered),
            ],
            SpecialUseDiscovery::Ran,
            vec![FolderEntry::new(
                "Trash".to_string(),
                FolderSource::Inherited,
            )],
        )]);

        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let matrix = &v["tool_matrix"][0];
        assert_eq!(matrix["protected_folders"][0]["folder"], "INBOX");
        assert_eq!(matrix["protected_folders"][0]["source"], "inherited");
        assert_eq!(
            matrix["protected_folders"][1]["folder"],
            "[Gmail]/Sent Mail"
        );
        assert_eq!(matrix["protected_folders"][1]["source"], "discovered");
        assert_eq!(matrix["special_use_discovery"], "ran");
        assert_eq!(matrix["expunge_folders"][0]["folder"], "Trash");
        assert_eq!(matrix["expunge_folders"][0]["source"], "inherited");

        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn an_empty_protected_list_is_not_the_same_line_as_an_unprobed_one() {
        // The distinction the field exists for. Both matrices serialize an
        // empty `protected_folders`; only `special_use_discovery` says
        // whether that means "the guard protects nothing" or "nobody asked".
        use crate::record::{AccountToolMatrix, SpecialUseDiscovery};

        let line_for = |discovery| {
            serde_json::to_string(&sample_start_with(vec![AccountToolMatrix::new(
                "work".to_string(),
                Posture::Readonly,
                Vec::new(),
                Vec::new(),
                discovery,
                Vec::new(),
            )]))
            .unwrap()
        };

        let probed = line_for(SpecialUseDiscovery::Ran);
        let unprobed = line_for(SpecialUseDiscovery::NotRun);
        assert_ne!(
            probed, unprobed,
            "an empty union and an un-run discovery must not share a line",
        );

        let v: Value = serde_json::from_str(&probed).unwrap();
        assert_eq!(v["tool_matrix"][0]["special_use_discovery"], "ran");
        let v: Value = serde_json::from_str(&unprobed).unwrap();
        assert_eq!(v["tool_matrix"][0]["special_use_discovery"], "not_run");
    }

    #[test]
    fn tool_matrix_entry_without_folder_lists_parses_as_empty() {
        // A `process_start` written between #632 and #696 carries a
        // `tool_matrix` whose entries have no folder keys. Raw JSONL rather
        // than a re-serialized struct, because `#[serde(default)]` is exactly
        // what a round-trip would hide.
        let line = r#"{"seq":1,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_start","version":"0.1.0","git_commit":"","posture":"readonly","tool_matrix":[{"account":"work","posture":"readonly","tools":[]}],"config_path":"/tmp/config.toml","config_hash_sha256":"00","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":7,"audit_file_inode_changed":false}"#;
        assert!(
            !line.contains("protected_folders") && !line.contains("expunge_folders"),
            "fixture must be the pre-#696 shape",
        );
        let rec: AuditRecord = serde_json::from_str(line).unwrap();
        let start = process_start_of(&rec).expect("fixture is a process_start");
        let entry = start.tool_matrix.first().expect("one matrix entry");
        // Empty here means *unknown*, not "nothing was protected" — see
        // `docs/audit-log.md` ("Compatibility contract").
        assert!(entry.protected_folders.is_empty());
        assert!(entry.expunge_folders.is_empty());
        // And the discovery state reads as `NotRun`, which is vacuous rather
        // than wrong on a line that carries no folder entries at all.
        assert_eq!(
            entry.special_use_discovery,
            crate::record::SpecialUseDiscovery::NotRun,
        );
    }

    #[test]
    fn process_start_without_tool_matrix_parses_as_empty() {
        // A record written before #632 carries no `tool_matrix` key. Asserted
        // against raw JSONL rather than a re-serialized struct, because
        // `#[serde(default)]` is exactly the thing a round-trip would hide.
        let line = r#"{"seq":1,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_start","version":"0.1.0","git_commit":"","posture":"readonly","config_path":"/tmp/config.toml","config_hash_sha256":"00","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":7,"audit_file_inode_changed":false}"#;
        assert!(
            !line.contains("tool_matrix"),
            "fixture must be the pre-#632 shape",
        );
        let rec: AuditRecord = serde_json::from_str(line).unwrap();
        let start = process_start_of(&rec).expect("fixture is a process_start");
        assert!(start.tool_matrix.is_empty());
        assert_eq!(start.posture, Some(Posture::Readonly));
    }

    #[test]
    fn process_end_round_trips() {
        let rec = AuditRecord {
            seq: Seq(9999),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::SignalInt,
                total_tool_calls: 42,
                records_lost: 0,
                undrained_dispatches: 0,
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert_eq!(v["reason"], "signal_int");
        assert_eq!(v["total_tool_calls"], 42);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_end_reason_serializes_snake_case() {
        let json = serde_json::to_string(&ProcessEndReason::SignalTerm).unwrap();
        assert_eq!(json, "\"signal_term\"");
    }

    #[test]
    fn auth_record_round_trips_and_uses_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Auth(crate::record::AuthEvent::new(
                crate::record::AuthResult::Success,
                "127.0.0.1".to_string(),
                1143,
                "alice@example.test".to_string(),
                Some("ab".repeat(32)),
                Some(true),
                None,
                None,
            )),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["port"], 1143);
        assert_eq!(v["fingerprint_match"], true);
        assert!(v["error_code"].is_null());
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn auth_result_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::AuthResult::Failure).unwrap(),
            "\"failure\"",
        );
    }

    #[test]
    fn tool_start_round_trips_with_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(10),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolStart(crate::record::ToolStart {
                account: None,
                tool: ToolName::FetchMessage,
                posture_effective: crate::record::PostureEffective::Account(Posture::DraftSafe),
                arguments_redacted: serde_json::json!({
                    "folder": "INBOX",
                    "uid": 12345,
                    "include_html": false,
                }),
                arguments_hash_sha256: "de".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_start");
        assert_eq!(v["tool"], "fetch_message");
        assert_eq!(v["arguments_redacted"]["folder"], "INBOX");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_end_round_trips_with_provenance_and_summary() {
        let rec = AuditRecord {
            seq: Seq(11),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolEnd(crate::record::ToolEnd {
                account: None,
                start_seq: Seq(10),
                tool: ToolName::FetchMessage,
                status: crate::record::ToolStatus::Ok,
                error_code: None,
                duration_ms: 47,
                result_summary: crate::record::ResultSummary {
                    message_ids_returned: vec!["<abc@example>".to_string()],
                    bytes_returned: 4821,
                    truncated: false,
                    security_warnings_emitted: vec![],
                    ..Default::default()
                },
                provenance: crate::record::Provenance {
                    window_seconds: 60,
                    message_ids_recently_read: vec!["<abc@example>".to_string()],
                },
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_end");
        assert_eq!(v["start_seq"], 10);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["result_summary"]["bytes_returned"], 4821);
        assert_eq!(v["provenance"]["window_seconds"], 60);
        // Unpopulated provenance fields are omitted, so a non-artifact tool's
        // tool_end keeps its prior on-disk shape (#316).
        assert!(v["result_summary"].get("artifact_path").is_none());
        assert!(v["result_summary"].get("uids_exported").is_none());
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_end_records_artifact_provenance_and_round_trips() {
        // A write-producing tool's tool_end carries the artifact path/sha/bytes
        // and the exported/failed UID partition durably (#316).
        let rec = AuditRecord {
            seq: Seq(13),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolEnd(crate::record::ToolEnd {
                account: None,
                start_seq: Seq(12),
                tool: ToolName::ExportMessages,
                status: crate::record::ToolStatus::Ok,
                error_code: None,
                duration_ms: 91,
                result_summary: crate::record::ResultSummary {
                    artifact_path: Some("/srv/dl/messages-abc.partial.mbox".to_string()),
                    artifact_sha256: Some("ab".repeat(32)),
                    artifact_bytes: Some(2048),
                    uids_exported: vec![7, 9],
                    uids_failed: vec![8],
                    ..Default::default()
                },
                provenance: crate::record::Provenance {
                    window_seconds: 60,
                    message_ids_recently_read: vec![],
                },
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["result_summary"]["artifact_path"],
            "/srv/dl/messages-abc.partial.mbox"
        );
        assert_eq!(v["result_summary"]["artifact_bytes"], 2048);
        assert_eq!(v["result_summary"]["uids_exported"][0], 7);
        assert_eq!(v["result_summary"]["uids_exported"][1], 9);
        assert_eq!(v["result_summary"]["uids_failed"][0], 8);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn config_event_serializes_as_config_kind() {
        let rec = AuditRecord {
            seq: Seq(3),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Config(crate::record::ConfigEvent {
                path: PathBuf::from("/tmp/config.toml"),
                hash_sha256: "aa".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "config");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::ToolStatus::Error).unwrap(),
            "\"error\"",
        );
    }

    #[test]
    fn tool_status_cancelled_serializes_as_snake_case() {
        let j = serde_json::to_string(&ToolStatus::Cancelled).unwrap();
        assert_eq!(j, "\"cancelled\"");
        let back: ToolStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ToolStatus::Cancelled);
    }
}
