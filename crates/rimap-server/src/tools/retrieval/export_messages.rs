//! `export_messages` tool handler: bulk raw export of multiple UIDs to a
//! single `git am`-able mbox file in the download sandbox.

use std::sync::Arc;

use rimap_imap::types::{FetchSpec, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::retrieval::sandbox;

/// Hard ceiling on the aggregate export size, regardless of the
/// caller-supplied `max_total_bytes`.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// Input for the `export_messages` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ExportMessagesInput {
    /// IMAP folder containing the messages.
    pub folder: String,
    /// UIDs to export, in mbox (patch) order. Non-empty, max 100, de-duped.
    pub uids: Vec<core::num::NonZeroU32>,
    /// UIDVALIDITY observed when the UID list was discovered (e.g. from
    /// `search`). Required: pins mailbox identity across search→export.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub expected_uidvalidity: core::num::NonZeroU32,
    /// Optional destination directory. Must be within the download root.
    pub dest_dir: Option<String>,
    /// Optional advisory basename prefix (sanitized).
    pub filename: Option<String>,
    /// Aggregate byte cap; clamped to `MAX_EXPORT_TOTAL_BYTES`.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub max_total_bytes: Option<u64>,
    /// When true, write the successes to a `.partial.mbox` artifact instead
    /// of failing the whole call. Default false (all-or-nothing).
    pub allow_partial: Option<bool>,
}

/// One successfully exported message.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportedUid {
    pub uid: u32,
    pub size_bytes: usize,
}

/// Reason a requested UID was not exported. Both are determined at the size
/// preflight, before any body fetch — a UID that reaches the body fetch is
/// known-present and in-bounds, and any error there is fatal (never per-UID),
/// so there is no `FetchError` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFailReason {
    NotFound,
    Oversize,
}

/// One requested UID that failed.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FailedUid {
    pub uid: u32,
    pub reason: ExportFailReason,
}

/// Trusted metadata for an `export_messages` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportMessagesMeta {
    /// Folder the messages were exported from.
    pub folder: String,
    /// True iff every requested UID was exported.
    pub complete: bool,
    /// `git am`-ready mbox path. Present only on a complete export;
    /// omitted from the response otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path of a `.partial.mbox` artifact. Present only on a partial
    /// export; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_path: Option<String>,
    /// SHA-256 of the written mbox, hex-encoded.
    pub sha256: String,
    /// Number of messages written to the artifact.
    pub message_count: usize,
    /// Total bytes written.
    pub total_bytes: u64,
    /// UIDVALIDITY the export was pinned to.
    pub uid_validity: u32,
    /// Exported UIDs, in mbox order, with sizes.
    pub succeeded: Vec<ExportedUid>,
    /// Requested UIDs that failed, with reasons.
    pub failed: Vec<FailedUid>,
}

/// Max UIDs per export, shared with the mutation-tool batch cap.
const MAX_EXPORT_UIDS: usize = 100;

/// Validate and normalize the requested UID list: reject empty / over-cap,
/// de-dup preserving first-seen order, and convert to `Uid`.
///
/// # Errors
///
/// `RimapError::Authz { code: InvalidInput }` for an empty list or one
/// exceeding [`MAX_EXPORT_UIDS`].
fn validate_uids(uids: Vec<core::num::NonZeroU32>) -> Result<Vec<Uid>, rimap_core::RimapError> {
    if uids.is_empty() {
        return Err(rimap_core::RimapError::invalid_input(
            "uids must not be empty",
        ));
    }
    if uids.len() > MAX_EXPORT_UIDS {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "uids exceeds the maximum of {MAX_EXPORT_UIDS} per export"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(uids.len());
    for u in uids {
        if seen.insert(u.get()) {
            out.push(Uid::from(u));
        }
    }
    Ok(out)
}

/// Clamp the caller-supplied aggregate byte budget to the hard ceiling.
fn clamp_total_bytes(requested: Option<u64>) -> u64 {
    requested.map_or(MAX_EXPORT_TOTAL_BYTES, |n| n.min(MAX_EXPORT_TOTAL_BYTES))
}

/// Pinned mboxrd separator. `git am`/`mailsplit` use it only as a delimiter
/// and take real authorship from each message's own `From:` header.
const MBOX_SEPARATOR: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

/// Assemble raw RFC822 messages into a single mboxrd byte buffer suitable
/// for `git am`. Each message is preceded by [`MBOX_SEPARATOR`] at column 0;
/// every line matching `^>*From ` is escaped with one extra leading `>`;
/// CRLF is preserved verbatim.
///
/// Callers must pass non-empty message bodies; an empty body would emit a
/// bare separator with no content. Task 7's handler validates this upstream.
fn build_mbox(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for msg in messages {
        // Ensure the previous message ended with a line feed so this
        // separator starts at column 0.
        if let Some(&last) = out.last()
            && last != b'\n'
        {
            out.push(b'\n');
        }
        out.extend_from_slice(MBOX_SEPARATOR);
        escape_from_lines_into(&mut out, msg);
    }
    // Trailing newline for a well-formed final message.
    if let Some(&last) = out.last()
        && last != b'\n'
    {
        out.push(b'\n');
    }
    out
}

/// Append `msg` to `out`, escaping each `^>*From ` line with one extra `>`.
fn escape_from_lines_into(out: &mut Vec<u8>, msg: &[u8]) {
    let mut line_start = 0;
    for i in 0..msg.len() {
        if msg[i] == b'\n' {
            write_mbox_line(out, &msg[line_start..=i]);
            line_start = i + 1;
        }
    }
    if line_start < msg.len() {
        write_mbox_line(out, &msg[line_start..]);
    }
}

/// Append `line` to `out`, prefixing it with `>` when it matches `^>*From `.
fn write_mbox_line(out: &mut Vec<u8>, line: &[u8]) {
    if line_is_from(line) {
        out.push(b'>');
    }
    out.extend_from_slice(line);
}

/// Whether `line` (from column 0) matches `^>*From ` — any run of `>` then
/// the literal `From `.
fn line_is_from(line: &[u8]) -> bool {
    let mut j = 0;
    while j < line.len() && line[j] == b'>' {
        j += 1;
    }
    line[j..].starts_with(b"From ")
}

/// Sanitize the advisory `filename` prefix to a safe single basename, or
/// return the default `"messages"` when absent.
///
/// Uses a conservative **allowlist** grammar — `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
/// — because the prefix ends up in the `path` returned to the agent and the
/// documented flow is `git am <path>`. The allowlist rejects path separators,
/// `..` traversal, shell metacharacters, whitespace, quotes, and all non-ASCII
/// (so bidi / zero-width / tag display-spoofing codepoints cannot appear), and
/// the alphanumeric-first rule rejects leading `.`/`-`.
///
/// # Errors
///
/// `RimapError::Authz { code: InvalidInput }` if the prefix is empty after
/// trimming, longer than 64 bytes, or contains any character outside the
/// grammar.
fn sanitize_filename_prefix(prefix: Option<&str>) -> Result<String, rimap_core::RimapError> {
    let Some(raw) = prefix else {
        return Ok("messages".to_string());
    };
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(rimap_core::RimapError::invalid_input(
            "filename prefix must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} \
             (conservative ASCII basename)",
        ));
    }
    Ok(trimmed.to_string())
}

/// The IMAP operations `export_messages` depends on. The handler calls this
/// trait instead of `account.imap` directly so the orchestration — that every
/// body fetch carries the pinned `expected_uidvalidity`, and that any
/// body-fetch error is fatal-with-no-artifact — is deterministically testable
/// against a hand-written fake without a live server.
pub(crate) trait ExportSource {
    /// Preflight: for each requested uid that exists, the `(uid, RFC822.SIZE)`
    /// pair (size `None` when the server omitted it), plus the folder's
    /// observed UIDVALIDITY (`None` when the server omitted it).
    ///
    /// # Errors
    ///
    /// Propagates IMAP failures (including a UIDVALIDITY mismatch).
    async fn fetch_sizes(
        &self,
        folder: &str,
        uids: &[Uid],
        expected_uidvalidity: u32,
    ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError>;

    /// Fetch one message body, guarded by `expected_uidvalidity`.
    ///
    /// # Errors
    ///
    /// Propagates IMAP failures; the handler treats every error as fatal.
    async fn fetch_one_body(
        &self,
        folder: &str,
        uid: Uid,
        expected_uidvalidity: u32,
    ) -> Result<Vec<u8>, rimap_core::RimapError>;
}

impl ExportSource for AccountState {
    async fn fetch_sizes(
        &self,
        folder: &str,
        uids: &[Uid],
        expected_uidvalidity: u32,
    ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError> {
        let (msgs, uid_validity) = self
            .imap
            .fetch(
                folder,
                uids,
                FetchSpec {
                    size: true,
                    ..FetchSpec::default()
                },
                Some(expected_uidvalidity),
            )
            .await?;
        let sizes = msgs.iter().map(|m| (m.uid.get(), m.size)).collect();
        Ok((sizes, uid_validity))
    }

    async fn fetch_one_body(
        &self,
        folder: &str,
        uid: Uid,
        expected_uidvalidity: u32,
    ) -> Result<Vec<u8>, rimap_core::RimapError> {
        Ok(self
            .imap
            .fetch_body(folder, uid, Some(expected_uidvalidity))
            .await?)
    }
}

/// Execute the `export_messages` tool.
///
/// Validates input, resolves the sandbox destination, then delegates the
/// preflight/fetch/build/write orchestration to [`run_export`] over the
/// account's [`ExportSource`].
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput }` for an empty/over-cap UID
///   list or an unsafe `filename`.
/// - `RimapError::UidValidityChanged` if the folder's UIDVALIDITY no longer
///   matches `expected_uidvalidity`.
/// - `RimapError::Authz { code: InvalidInput }` (all-or-nothing default)
///   listing failed UIDs when `allow_partial` is false and any UID fails.
/// - `RimapError::Imap { ... }` for connection-dropping fetch failures.
/// - `RimapError::Internal` for filesystem/hashing failures.
pub async fn handle(
    account: &AccountState,
    input: ExportMessagesInput,
) -> Result<ToolResponse<ExportMessagesMeta, ()>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let prefix = sanitize_filename_prefix(input.filename.as_deref())?;
    let uids = validate_uids(input.uids)?;
    let budget = clamp_total_bytes(input.max_total_bytes);
    let allow_partial = input.allow_partial.unwrap_or(false);
    let expected = input.expected_uidvalidity.get();
    let per_msg_cap = account.imap.max_fetch_body_bytes();

    let dest =
        sandbox::resolve_dest_dir_async(input.dest_dir, Arc::clone(&account.download_dir)).await?;

    let plan = RunPlan {
        folder: input.folder,
        dest,
        prefix,
        uids,
        expected,
        budget,
        per_msg_cap,
        allow_partial,
    };
    run_export(account, plan).await
}

/// Inputs to [`run_export`], grouped so the orchestrator stays within the
/// positional-parameter limit.
pub(crate) struct RunPlan {
    pub folder: String,
    pub dest: std::path::PathBuf,
    pub prefix: String,
    pub uids: Vec<Uid>,
    pub expected: u32,
    pub budget: u64,
    pub per_msg_cap: u64,
    pub allow_partial: bool,
}

/// The size/identity bounds threaded through the preflight and fetch loop:
/// the pinned UIDVALIDITY, the per-message body cap, and the aggregate byte
/// budget. Grouped so the helpers stay within the positional-parameter limit.
#[derive(Debug, Clone, Copy)]
struct FetchLimits {
    expected: u32,
    per_msg_cap: u64,
    budget: u64,
}

/// Preflight → classify+fetch → frame → write. Generic over [`ExportSource`]
/// so handler wiring is testable against a fake. `dest` is the already-resolved
/// sandbox directory.
///
/// # Errors
///
/// See [`handle`]. Notably: a missing UIDVALIDITY in the preflight, an
/// over-budget eligible-size sum or framed output, an all-or-nothing abort, and
/// any body-fetch error are all returned `Err` before anything is written.
pub(crate) async fn run_export(
    source: &impl ExportSource,
    plan: RunPlan,
) -> Result<ToolResponse<ExportMessagesMeta, ()>, rimap_core::RimapError> {
    let RunPlan {
        folder,
        dest,
        prefix,
        uids,
        expected,
        budget,
        per_msg_cap,
        allow_partial,
    } = plan;

    let limits = FetchLimits {
        expected,
        per_msg_cap,
        budget,
    };

    let size_by_uid = preflight_sizes(source, &folder, &uids, limits).await?;

    let outcomes = fetch_bodies(source, &folder, &uids, &size_by_uid, limits).await?;

    let (complete, bodies, succeeded, failed) = match plan_outcome(outcomes, allow_partial) {
        Outcome::Abort { failed } => {
            let failed_uids: Vec<String> = failed.iter().map(|f| f.uid.to_string()).collect();
            return Err(rimap_core::RimapError::invalid_input(format!(
                "export incomplete (set allow_partial=true to override); failed UIDs: {}",
                failed_uids.join(", ")
            )));
        }
        Outcome::Proceed {
            complete,
            bodies,
            succeeded,
            failed,
        } => (complete, bodies, succeeded, failed),
    };

    let mbox = build_mbox(&bodies);
    let total_bytes = mbox.len() as u64;
    // Authoritative budget check on the *framed* output: mboxrd separators,
    // From-line escaping, and terminal padding add bytes beyond the raw bodies
    // counted during fetch. Reject before writing anything.
    if total_bytes > budget {
        return Err(rimap_core::RimapError::invalid_input(
            "framed mbox exceeds max_total_bytes",
        ));
    }
    let sha256 = sandbox::sha256_hex(&mbox);

    let suffix = if complete { "mbox" } else { "partial.mbox" };
    let token = export_token();
    let filename = format!("{prefix}-{token}.{suffix}");
    let written = sandbox::write_attachment_async(dest, filename, mbox).await?;
    let written = written.to_string_lossy().to_string();

    let (path, partial_path) = if complete {
        (Some(written), None)
    } else {
        (None, Some(written))
    };

    Ok(ToolResponse::meta_only(ExportMessagesMeta {
        folder,
        complete,
        path,
        partial_path,
        sha256,
        message_count: succeeded.len(),
        total_bytes,
        // `expected`, not the preflight-observed value: the guarded fetch
        // fail-closes on any UIDVALIDITY mismatch/omission (preflight rejects
        // None; fetch/fetch_body error on mismatch), so observed == expected is
        // provable whenever we reach the manifest.
        uid_validity: expected,
        succeeded,
        failed,
    }))
}

/// Preflight: fetch reported sizes, reject an absent UIDVALIDITY, and run the
/// advisory eligible-sum budget pre-check. Returns a `uid -> reported size`
/// map (absence from the map means the UID is not present in the folder).
///
/// # Errors
///
/// Propagates IMAP failures; returns `InvalidInput` when the server omits
/// UIDVALIDITY or the eligible reported-size sum exceeds `budget`.
async fn preflight_sizes(
    source: &impl ExportSource,
    folder: &str,
    uids: &[Uid],
    limits: FetchLimits,
) -> Result<std::collections::BTreeMap<u32, Option<u32>>, rimap_core::RimapError> {
    let (sizes, uid_validity_opt) = source.fetch_sizes(folder, uids, limits.expected).await?;
    // The shared guard only *warns* on an omitted UIDVALIDITY; export refuses
    // to run unguarded, so reject an absent value.
    if uid_validity_opt.is_none() {
        return Err(rimap_core::RimapError::invalid_input(
            "server omitted UIDVALIDITY; export_messages requires it to guard the mailbox",
        ));
    }

    let mut size_by_uid: std::collections::BTreeMap<u32, Option<u32>> =
        std::collections::BTreeMap::new();
    for (uid, size) in sizes {
        size_by_uid.insert(uid, size);
    }

    // Advisory aggregate pre-check, summed over ONLY the UIDs that may be
    // written — present and within the per-message cap. Excluding NotFound and
    // known-Oversize UIDs means they cannot block an `allow_partial` export of
    // the writable messages. (A present-but-size-unknown UID counts 0 here; the
    // running actual-bytes check during fetch is its real guard.) The framed
    // size check later is the final authority.
    let eligible_sum: u64 = uids
        .iter()
        .filter_map(|u| match size_by_uid.get(&u.get()) {
            Some(Some(sz)) if u64::from(*sz) <= limits.per_msg_cap => Some(u64::from(*sz)),
            _ => None,
        })
        .sum();
    if eligible_sum > limits.budget {
        return Err(rimap_core::RimapError::invalid_input(
            "export exceeds max_total_bytes",
        ));
    }
    Ok(size_by_uid)
}

/// Classify + fetch in caller order. Missing and known-oversize UIDs are
/// per-UID failures resolved at preflight (no body fetch). `running` is the
/// authoritative bound on *actual* transferred bytes — the reported-size
/// pre-check can be defeated by a server that omits/under-reports RFC822.SIZE,
/// so abort the moment real bytes exceed the budget.
///
/// # Errors
///
/// ANY body-fetch error is fatal — never downgraded to a per-UID failure.
/// Per-UID absence/oversize is already resolved at preflight, so a UID that
/// reaches the body fetch is known-present and in-bounds; an error here
/// (UIDVALIDITY change/omission, `SizeLimit`, `Timeout`, connection loss, or a
/// BODY-stream protocol error) means the session or the returned bytes are
/// untrustworthy. Aborting prevents a corrupt/stale body landing in an
/// artifact. Also returns `InvalidInput` if the running actual-byte total
/// exceeds `budget`.
async fn fetch_bodies(
    source: &impl ExportSource,
    folder: &str,
    uids: &[Uid],
    size_by_uid: &std::collections::BTreeMap<u32, Option<u32>>,
    limits: FetchLimits,
) -> Result<Vec<FetchOutcome>, rimap_core::RimapError> {
    let mut outcomes = Vec::with_capacity(uids.len());
    let mut running: u64 = 0;
    for uid in uids {
        let n = uid.get();
        // Preflight-driven per-UID decision (pure, unit-tested). Skips never
        // attempt a body fetch, so oversize never triggers SizeLimit.
        if let UidPlan::Skip(reason) =
            classify_uid(size_by_uid.get(&n).copied(), limits.per_msg_cap)
        {
            outcomes.push(FetchOutcome {
                uid: n,
                result: Err(reason),
            });
            continue;
        }
        let body = source.fetch_one_body(folder, *uid, limits.expected).await?;
        running = running.saturating_add(body.len() as u64);
        if running > limits.budget {
            return Err(rimap_core::RimapError::invalid_input(
                "export exceeds max_total_bytes",
            ));
        }
        outcomes.push(FetchOutcome {
            uid: n,
            result: Ok(body),
        });
    }
    Ok(outcomes)
}

/// Short token making concurrent exports' filenames distinct. Uses wall-clock
/// nanos plus a process-local counter so two exports in the same instant still
/// differ; `write_attachment`'s de-dup is the correctness backstop.
fn export_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:016x}{seq:04x}")
}

/// Per-UID fetch result fed into [`plan_outcome`].
pub(crate) struct FetchOutcome {
    pub uid: u32,
    pub result: Result<Vec<u8>, ExportFailReason>,
}

/// Decision produced by [`plan_outcome`].
pub(crate) enum Outcome {
    /// Default all-or-nothing path with failures: write nothing, error out.
    Abort { failed: Vec<FailedUid> },
    /// Write the bodies (in order) and report the manifest.
    Proceed {
        complete: bool,
        bodies: Vec<Vec<u8>>,
        succeeded: Vec<ExportedUid>,
        failed: Vec<FailedUid>,
    },
}

/// Partition per-UID outcomes into an export decision. With failures and
/// `allow_partial == false`, returns [`Outcome::Abort`]; otherwise
/// [`Outcome::Proceed`] with `complete == failed.is_empty()`.
fn plan_outcome(outcomes: Vec<FetchOutcome>, allow_partial: bool) -> Outcome {
    let mut bodies = Vec::new();
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for o in outcomes {
        match o.result {
            Ok(body) => {
                succeeded.push(ExportedUid {
                    uid: o.uid,
                    size_bytes: body.len(),
                });
                bodies.push(body);
            }
            Err(reason) => failed.push(FailedUid { uid: o.uid, reason }),
        }
    }
    if !failed.is_empty() && !allow_partial {
        return Outcome::Abort { failed };
    }
    Outcome::Proceed {
        complete: failed.is_empty(),
        bodies,
        succeeded,
        failed,
    }
}

/// What to do with one requested UID, decided from its preflight size entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UidPlan {
    /// Resolved at preflight without a body fetch (`NotFound` / `Oversize`).
    Skip(ExportFailReason),
    /// Present and in-bounds: fetch the body.
    Fetch,
}

/// Classify a UID from its preflight size entry (`None` = absent from the
/// folder; `Some(None)` = present, size unknown; `Some(Some(n))` = present,
/// reported size `n`). Pure, so the security-critical NotFound/Oversize
/// decision is unit-testable without a live IMAP server.
///
/// The `Option<Option<u32>>` signature intentionally encodes three distinct
/// states: absent, present-size-unknown, and present-size-known. A custom enum
/// would be clearer but would require plumbing changes in Task 6's IMAP fetch.
#[expect(
    clippy::option_option,
    reason = "three-state encoding: absent / present-unknown / present-known"
)]
fn classify_uid(reported: Option<Option<u32>>, per_msg_cap: u64) -> UidPlan {
    match reported {
        None => UidPlan::Skip(ExportFailReason::NotFound),
        Some(Some(sz)) if u64::from(sz) > per_msg_cap => UidPlan::Skip(ExportFailReason::Oversize),
        Some(Some(_) | None) => UidPlan::Fetch,
    }
}

#[cfg(test)]
#[expect(
    clippy::panic,
    reason = "tests use panic! for assertion failures in match arms"
)]
mod outcome_tests {
    use super::{ExportFailReason, FetchOutcome, Outcome, plan_outcome};

    fn ok(uid: u32, body: &[u8]) -> FetchOutcome {
        FetchOutcome {
            uid,
            result: Ok(body.to_vec()),
        }
    }
    fn err(uid: u32, reason: ExportFailReason) -> FetchOutcome {
        FetchOutcome {
            uid,
            result: Err(reason),
        }
    }

    #[test]
    fn all_success_is_complete() {
        let out = plan_outcome(vec![ok(1, b"a"), ok(2, b"b")], false);
        match out {
            Outcome::Proceed {
                complete,
                bodies,
                succeeded,
                failed,
            } => {
                assert!(complete);
                assert_eq!(bodies.len(), 2);
                assert_eq!(succeeded.len(), 2);
                assert!(failed.is_empty());
                assert_eq!(succeeded[0].uid, 1);
                assert_eq!(succeeded[1].uid, 2);
                assert_eq!(bodies[0], b"a");
                assert_eq!(bodies[1], b"b");
            }
            Outcome::Abort { .. } => panic!("expected Proceed"),
        }
    }

    #[test]
    fn failure_without_allow_partial_aborts() {
        let out = plan_outcome(vec![ok(1, b"a"), err(2, ExportFailReason::NotFound)], false);
        match out {
            Outcome::Abort { failed } => {
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0].uid, 2);
            }
            Outcome::Proceed { .. } => panic!("expected Abort"),
        }
    }

    #[test]
    fn failure_with_allow_partial_proceeds_incomplete() {
        let out = plan_outcome(vec![ok(1, b"a"), err(2, ExportFailReason::Oversize)], true);
        match out {
            Outcome::Proceed {
                complete,
                bodies,
                succeeded,
                failed,
            } => {
                assert!(!complete);
                assert_eq!(bodies.len(), 1);
                assert_eq!(succeeded.len(), 1);
                assert_eq!(failed.len(), 1);
            }
            Outcome::Abort { .. } => panic!("expected Abort"),
        }
    }

    #[test]
    fn classify_uid_cases() {
        use super::{ExportFailReason, UidPlan, classify_uid};
        assert_eq!(
            classify_uid(None, 100),
            UidPlan::Skip(ExportFailReason::NotFound)
        );
        assert_eq!(
            classify_uid(Some(Some(200)), 100),
            UidPlan::Skip(ExportFailReason::Oversize)
        );
        assert_eq!(classify_uid(Some(Some(50)), 100), UidPlan::Fetch);
        assert_eq!(classify_uid(Some(None), 100), UidPlan::Fetch); // present, size unknown
        // Exact boundary: size == cap is in-bounds (Fetch); one over is Oversize.
        assert_eq!(classify_uid(Some(Some(100)), 100), UidPlan::Fetch);
        assert_eq!(
            classify_uid(Some(Some(101)), 100),
            UidPlan::Skip(ExportFailReason::Oversize)
        );
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod input_tests {
    use super::{MAX_EXPORT_TOTAL_BYTES, clamp_total_bytes, validate_uids};
    use core::num::NonZeroU32;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_uids(Vec::new()).is_err());
    }

    #[test]
    fn rejects_over_100() {
        let v: Vec<NonZeroU32> = (1..=101).map(nz).collect();
        assert!(validate_uids(v).is_err());
    }

    #[test]
    fn accepts_exactly_100() {
        let v: Vec<NonZeroU32> = (1..=100).map(nz).collect();
        assert_eq!(validate_uids(v).unwrap().len(), 100);
    }

    #[test]
    fn dedups_preserving_first_order() {
        let v = vec![nz(3), nz(1), nz(3), nz(2), nz(1)];
        let out = validate_uids(v).unwrap();
        let got: Vec<u32> = out.iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![3, 1, 2]);
    }

    #[test]
    fn clamp_none_is_ceiling() {
        assert_eq!(clamp_total_bytes(None), MAX_EXPORT_TOTAL_BYTES);
    }

    #[test]
    fn clamp_caps_oversized_request() {
        assert_eq!(clamp_total_bytes(Some(u64::MAX)), MAX_EXPORT_TOTAL_BYTES);
        assert_eq!(clamp_total_bytes(Some(1024)), 1024);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod sanitize_tests {
    use super::sanitize_filename_prefix;

    #[test]
    fn default_when_absent() {
        assert_eq!(sanitize_filename_prefix(None).unwrap(), "messages");
    }

    #[test]
    fn accepts_plain_basename() {
        assert_eq!(
            sanitize_filename_prefix(Some("dpdk-series")).unwrap(),
            "dpdk-series"
        );
    }

    #[test]
    fn rejects_everything_outside_the_allowlist() {
        for bad in [
            "../escape",
            "/abs/path",
            "a/b",
            "a\\b",
            "",
            "  ",
            "a\u{0}b",
            "a\nb", // separators/control
            "a;b",
            "a b",
            "a'b",
            "a\"b",
            "a$b",
            "a|b",
            "a&b",
            "a`b", // shell metachars/spaces/quotes
            "-lead",
            ".hidden", // leading dash/dot
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{E0001}b", // bidi / zero-width / tag
        ] {
            assert!(
                sanitize_filename_prefix(Some(bad)).is_err(),
                "should reject {bad:?}"
            );
        }
        // Overlong (> 64 chars) is rejected.
        let long = "a".repeat(65);
        assert!(sanitize_filename_prefix(Some(&long)).is_err());
        // Exactly 64 chars is the accepted boundary.
        let max = "a".repeat(64);
        assert!(sanitize_filename_prefix(Some(&max)).is_ok());
    }

    #[test]
    fn accepts_conservative_ascii_basenames() {
        for ok in ["messages", "dpdk-series", "patch_set.v2", "AB12"] {
            assert!(
                sanitize_filename_prefix(Some(ok)).is_ok(),
                "should accept {ok:?}"
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod build_mbox_tests {
    use super::build_mbox;

    const SEP: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

    #[test]
    fn single_message_gets_separator_and_trailing_newline() {
        let out = build_mbox(&[b"Subject: hi\r\n\r\nbody".to_vec()]);
        assert!(out.starts_with(SEP), "missing leading separator");
        assert!(out.ends_with(b"\n"), "must end with newline");
        assert!(out.ends_with(b"body\n"));
    }

    #[test]
    fn missing_terminal_newline_padded_before_next_separator() {
        // First message has no trailing newline; the second separator must
        // still start at column 0.
        let out = build_mbox(&[
            b"a: 1\r\n\r\nno-newline".to_vec(),
            b"b: 2\r\n\r\nx\n".to_vec(),
        ]);
        let text = String::from_utf8(out).unwrap();
        // Exactly two separators, each at the start of a line.
        let seps: Vec<_> = text.match_indices("From mboxrd@").collect();
        assert_eq!(seps.len(), 2);
        for (idx, _) in &seps {
            assert!(
                *idx == 0 || text.as_bytes()[idx - 1] == b'\n',
                "separator not at col 0"
            );
        }
    }

    #[test]
    fn escapes_every_from_line_including_nested_and_header_position() {
        let msg = b"From the desk of X\r\n>From already escaped\r\nFrom \r\nnormal\n".to_vec();
        let out = build_mbox(&[msg]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(">From the desk of X"));
        assert!(text.contains(">>From already escaped"));
        assert!(text.contains(">From \r\n"));
        assert!(text.contains("\nnormal"));
    }

    #[test]
    fn preserves_crlf_verbatim_in_body() {
        let out = build_mbox(&[b"H: 1\r\n\r\nline1\r\nline2\r\n".to_vec()]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("line1\r\nline2\r\n"));
    }

    #[test]
    fn split_back_round_trips_messages() {
        // Build, then split on separator lines and un-escape; must equal inputs.
        let inputs = vec![
            b"A: 1\r\n\r\nFrom space\r\nbody1\r\n".to_vec(),
            b"B: 2\r\n\r\nbody2\n".to_vec(),
        ];
        let mbox = build_mbox(&inputs);
        let recovered = split_and_unescape(&mbox);
        assert_eq!(recovered.len(), inputs.len());
        // Compare ignoring a single trailing newline build_mbox may add.
        for (got, want) in recovered.iter().zip(inputs.iter()) {
            assert_eq!(trim_one_trailing_nl(got), trim_one_trailing_nl(want));
        }
    }

    fn trim_one_trailing_nl(b: &[u8]) -> &[u8] {
        b.strip_suffix(b"\n").unwrap_or(b)
    }

    // Test-only inverse of build_mbox's framing: split on separator lines,
    // strip one leading '>' from each `^>+From ` line.
    fn split_and_unescape(mbox: &[u8]) -> Vec<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut cur: Option<Vec<u8>> = None;
        for line in split_keep_newlines(mbox) {
            if line == SEP {
                if let Some(c) = cur.take() {
                    parts.push(c);
                }
                cur = Some(Vec::new());
            } else if let Some(c) = cur.as_mut() {
                c.extend_from_slice(&unescape_line(line));
            }
        }
        if let Some(c) = cur.take() {
            parts.push(c);
        }
        parts
    }

    fn unescape_line(line: &[u8]) -> Vec<u8> {
        // If line is `>+From `, drop one leading '>'.
        let mut j = 0;
        while j < line.len() && line[j] == b'>' {
            j += 1;
        }
        if j >= 1 && line[j..].starts_with(b"From ") {
            line[1..].to_vec()
        } else {
            line.to_vec()
        }
    }

    fn split_keep_newlines(b: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..b.len() {
            if b[i] == b'\n' {
                out.push(&b[start..=i]);
                start = i + 1;
            }
        }
        if start < b.len() {
            out.push(&b[start..]);
        }
        out
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod source_seam_tests {
    use super::{ExportSource, RunPlan, run_export};
    use core::num::NonZeroU32;
    use rimap_imap::types::Uid;
    use std::cell::RefCell;
    use std::path::PathBuf;

    fn uid(n: u32) -> Uid {
        Uid::from(NonZeroU32::new(n).unwrap())
    }

    /// A single seeded body for the happy fake.
    struct Seeded {
        uid: u32,
        body: Vec<u8>,
    }

    /// Hand-written fake `ExportSource`. `bodies` seeds the present UIDs (in any
    /// order) with their raw bytes; `uid_validity` is what the preflight
    /// reports; `body_error`, when set, makes EVERY `fetch_one_body` fail with a
    /// freshly-built clone of that error. `seen_expected` records the `expected`
    /// each fetch was called with so tests can assert it never drifts.
    struct FakeSource {
        bodies: Vec<Seeded>,
        uid_validity: Option<u32>,
        body_error: Option<fn() -> rimap_core::RimapError>,
        seen_expected: RefCell<Vec<u32>>,
    }

    impl FakeSource {
        fn happy(bodies: Vec<Seeded>, uid_validity: u32) -> Self {
            Self {
                bodies,
                uid_validity: Some(uid_validity),
                body_error: None,
                seen_expected: RefCell::new(Vec::new()),
            }
        }

        fn failing(uid_validity: u32, body_error: fn() -> rimap_core::RimapError) -> Self {
            Self {
                bodies: vec![Seeded {
                    uid: 1,
                    body: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
                }],
                uid_validity: Some(uid_validity),
                body_error: Some(body_error),
                seen_expected: RefCell::new(Vec::new()),
            }
        }
    }

    impl ExportSource for FakeSource {
        async fn fetch_sizes(
            &self,
            _folder: &str,
            uids: &[Uid],
            _expected: u32,
        ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError> {
            let requested: std::collections::BTreeSet<u32> = uids.iter().map(|u| u.get()).collect();
            let sizes = self
                .bodies
                .iter()
                .filter(|s| requested.contains(&s.uid))
                .map(|s| (s.uid, Some(u32::try_from(s.body.len()).unwrap())))
                .collect();
            Ok((sizes, self.uid_validity))
        }

        async fn fetch_one_body(
            &self,
            _folder: &str,
            uid: Uid,
            expected: u32,
        ) -> Result<Vec<u8>, rimap_core::RimapError> {
            self.seen_expected.borrow_mut().push(expected);
            if let Some(make_err) = self.body_error {
                return Err(make_err());
            }
            let found = self
                .bodies
                .iter()
                .find(|s| s.uid == uid.get())
                .expect("fetch_one_body called for an unseeded uid");
            Ok(found.body.clone())
        }
    }

    fn plan(dest: PathBuf, uids: Vec<Uid>, expected: u32, allow_partial: bool) -> RunPlan {
        RunPlan {
            folder: "INBOX".to_string(),
            dest,
            prefix: "messages".to_string(),
            uids,
            expected,
            budget: super::MAX_EXPORT_TOTAL_BYTES,
            per_msg_cap: 5_242_880,
            allow_partial,
        }
    }

    fn dir_is_empty(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir).expect("read_dir").next().is_none()
    }

    #[tokio::test]
    async fn happy_path_writes_artifact_and_pins_expected_on_every_body() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeSource::happy(
            vec![
                Seeded {
                    uid: 7,
                    body: b"Subject: a\r\n\r\nalpha\r\n".to_vec(),
                },
                Seeded {
                    uid: 9,
                    body: b"Subject: b\r\n\r\nbeta\r\n".to_vec(),
                },
            ],
            4242,
        );
        let resp = run_export(
            &fake,
            plan(tmp.path().to_path_buf(), vec![uid(7), uid(9)], 4242, false),
        )
        .await
        .expect("export should succeed");

        let meta = &resp.meta;
        assert!(meta.complete);
        assert_eq!(meta.message_count, 2);
        assert_eq!(meta.uid_validity, 4242);
        // succeeded preserves caller (mbox) order.
        let order: Vec<u32> = meta.succeeded.iter().map(|s| s.uid).collect();
        assert_eq!(order, vec![7, 9]);
        let path = meta.path.as_deref().expect("complete export has path");
        assert!(meta.partial_path.is_none());
        let on_disk = std::fs::read(path).expect("artifact exists");
        assert_eq!(super::sandbox::sha256_hex(&on_disk), meta.sha256);
        // Every body fetch carried the same pinned UIDVALIDITY.
        assert_eq!(*fake.seen_expected.borrow(), vec![4242, 4242]);
    }

    async fn assert_body_error_aborts_with_no_artifact(make_err: fn() -> rimap_core::RimapError) {
        for allow_partial in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let fake = FakeSource::failing(4242, make_err);
            let result = run_export(
                &fake,
                plan(tmp.path().to_path_buf(), vec![uid(1)], 4242, allow_partial),
            )
            .await;
            assert!(
                result.is_err(),
                "body error must abort (allow_partial={allow_partial})"
            );
            assert!(
                dir_is_empty(tmp.path()),
                "no artifact may be written on a body-fetch error \
                 (allow_partial={allow_partial})"
            );
        }
    }

    #[tokio::test]
    async fn uid_validity_changed_body_error_aborts_no_artifact() {
        assert_body_error_aborts_with_no_artifact(|| {
            rimap_core::RimapError::from(rimap_imap::ImapError::UidValidityChanged {
                folder: "INBOX".to_string(),
                expected: 4242,
                actual: 9999,
            })
        })
        .await;
    }

    #[tokio::test]
    async fn uid_validity_unavailable_body_error_aborts_no_artifact() {
        assert_body_error_aborts_with_no_artifact(|| {
            rimap_core::RimapError::from(rimap_imap::ImapError::UidValidityUnavailable {
                folder: "INBOX".to_string(),
            })
        })
        .await;
    }

    #[tokio::test]
    async fn timeout_body_error_aborts_no_artifact() {
        assert_body_error_aborts_with_no_artifact(|| {
            rimap_core::RimapError::from(rimap_imap::ImapError::Timeout { op: "fetch_body" })
        })
        .await;
    }

    #[tokio::test]
    async fn size_limit_body_error_aborts_no_artifact() {
        assert_body_error_aborts_with_no_artifact(|| {
            rimap_core::RimapError::from(rimap_imap::ImapError::SizeLimit { limit: 1024 })
        })
        .await;
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod git_am_tests {
    use super::build_mbox;
    use std::process::Command;

    fn git(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            // Isolate from host config so commit.gpgsign / global hooks /
            // templates / init.defaultBranch cannot spuriously fail git am.
            // The identity env vars above are load-bearing once global
            // user.name/email is suppressed.
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("git runs")
    }

    /// Emits CRLF (`\r\n`) line endings deliberately, mirroring raw RFC822
    /// bytes; the format string mixes `\r\n` with line-continuation backslashes.
    fn patch(n: u32, body_extra: &str) -> Vec<u8> {
        // A minimal git-format-patch-style message: From/Subject/Date headers,
        // then a unified diff creating file_<n>.txt.
        format!(
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\r\n\
             From: Dev <dev@example.com>\r\n\
             Date: Mon, 1 Jan 2024 0{n}:00:00 +0000\r\n\
             Subject: [PATCH {n}/2] add file {n}{body_extra}\r\n\
             \r\n\
             ---\r\n \
             file_{n}.txt | 1 +\r\n \
             1 file changed, 1 insertion(+)\r\n\
             \r\n\
             diff --git a/file_{n}.txt b/file_{n}.txt\r\n\
             new file mode 100644\r\n\
             index 0000000..0000001\r\n\
             --- /dev/null\r\n\
             +++ b/file_{n}.txt\r\n\
             @@ -0,0 +1 @@\r\n\
             +content {n}\r\n\
             -- \r\n\
             2.40.0\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn git_am_applies_generated_mbox() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        assert!(git(&["init", "-q"], repo).status.success());

        // A spurious `From `-leading line in the message (here in the header
        // region) must be escaped by build_mbox, or git's mbox splitter would
        // wrongly split the series there.
        let mbox = build_mbox(&[patch(1, "\r\nFrom the author: note"), patch(2, "")]);
        let mbox_path = repo.join("series.mbox");
        std::fs::write(&mbox_path, &mbox).unwrap();

        let out = git(&["am", mbox_path.to_str().unwrap()], repo);
        assert!(
            out.status.success(),
            "git am failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        let log = git(&["rev-list", "--count", "HEAD"], repo);
        let count = String::from_utf8_lossy(&log.stdout).trim().to_string();
        assert_eq!(count, "2", "expected 2 commits from a 2-patch series");
        assert!(repo.join("file_1.txt").exists());
        assert!(repo.join("file_2.txt").exists());
    }
}
