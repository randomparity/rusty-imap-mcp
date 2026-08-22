//! `export_messages` tool handler: bulk raw export of multiple UIDs to a
//! single `git am`-able mbox file in the download sandbox.

use std::sync::Arc;

use rimap_imap::types::{FetchSpec, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::retrieval::mbox::build_mbox;
use crate::tools::retrieval::sandbox;

/// Hard ceiling on the aggregate export size, regardless of the
/// caller-supplied `max_total_bytes`.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

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
    /// Aggregate byte cap; clamped to 104857600 (100 MiB).
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
/// `pub(crate)` so the `rimap://docs/workflows` resource's limits table
/// can be pinned against it in `crate::mcp::server`'s tests.
pub(crate) const MAX_EXPORT_UIDS: usize = 100;

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
trait ExportSource {
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

    /// Fetch one message body, guarded by `expected_uidvalidity`, with a
    /// per-call read limit of `body_limit` bytes (the export passes the
    /// remaining aggregate budget so the in-flight body cannot exceed it).
    ///
    /// # Errors
    ///
    /// Propagates IMAP failures; the handler treats every error as fatal.
    async fn fetch_one_body(
        &self,
        folder: &str,
        uid: Uid,
        expected_uidvalidity: u32,
        body_limit: u64,
    ) -> Result<Vec<u8>, rimap_core::RimapError>;
}

// cargo-mutants: best-effort — the stub-return mutants on `fetch_sizes` and
// `fetch_one_body` below survive because this is the real IMAP-backed
// `ExportSource`. The export *logic* is unit-tested against a fake `ExportSource`
// (the trait seam); this impl's `self.imap.fetch*` round trip is covered by the
// over-the-wire harness in issue #520 (export_messages e2e), not a unit test.
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
        body_limit: u64,
    ) -> Result<Vec<u8>, rimap_core::RimapError> {
        Ok(self
            .imap
            .fetch_body_with_limit(folder, uid, Some(expected_uidvalidity), body_limit)
            .await?)
    }
}

/// Execute the `export_messages` tool.
///
/// Validates input, resolves the sandbox destination, then delegates the
/// preflight/fetch/build/write orchestration to `run_export` over the
/// account's `ExportSource`.
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
) -> Result<ToolResponse<ExportMessagesMeta>, rimap_core::RimapError> {
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
struct RunPlan {
    pub folder: String,
    pub dest: sandbox::DestDir,
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
/// All-or-nothing abort error naming the UIDs that cannot be exported. Shared
/// by the preflight short-circuit and the post-fetch [`Outcome::Abort`] path so
/// both report the identical message shape.
fn incomplete_export_error(failed_uids: &[u32]) -> rimap_core::RimapError {
    let mut rendered: Vec<String> = Vec::with_capacity(failed_uids.len());
    for uid in failed_uids {
        rendered.push(uid.to_string());
    }
    rimap_core::RimapError::invalid_input(format!(
        "export incomplete (set allow_partial=true to override); failed UIDs: {}",
        rendered.join(", ")
    ))
}

async fn run_export(
    source: &impl ExportSource,
    plan: RunPlan,
) -> Result<ToolResponse<ExportMessagesMeta>, rimap_core::RimapError> {
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

    // All-or-nothing: if preflight already classifies any requested UID as a
    // failure (NotFound / Oversize), abort before fetching ANY body. Without
    // this, one missing/oversize UID would still pull every other body up to
    // the byte budget only to discard all of them at `plan_outcome`.
    if !allow_partial {
        let mut preflight_failed: Vec<u32> = Vec::new();
        for u in &uids {
            let size = size_by_uid
                .get(&u.get())
                .copied()
                .unwrap_or(PreflightSize::Absent);
            match classify_uid(size, per_msg_cap) {
                UidPlan::Skip(_) => preflight_failed.push(u.get()),
                UidPlan::Fetch => {}
            }
        }
        if !preflight_failed.is_empty() {
            return Err(incomplete_export_error(&preflight_failed));
        }
    }

    let outcomes = fetch_bodies(source, &folder, &uids, &size_by_uid, limits).await?;

    let (complete, bodies, succeeded, failed) = match plan_outcome(outcomes, allow_partial) {
        Outcome::Abort { failed } => {
            let mut failed_uids: Vec<u32> = Vec::with_capacity(failed.len());
            for f in &failed {
                failed_uids.push(f.uid);
            }
            return Err(incomplete_export_error(&failed_uids));
        }
        Outcome::Proceed {
            complete,
            bodies,
            succeeded,
            failed,
        } => (complete, bodies, succeeded, failed),
    };

    // Move `bodies` in: `build_mbox` drains it, so the raw bodies are freed as
    // the framed mbox is built rather than lingering through the write (#318).
    let mbox = build_mbox(bodies);
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

    // Nothing succeeded (only reachable with allow_partial=true and all UIDs
    // failed): report the failures, write no empty artifact.
    let (path, partial_path) = if succeeded.is_empty() {
        (None, None)
    } else {
        let suffix = if complete { "mbox" } else { "partial.mbox" };
        let token = export_token();
        let filename = format!("{prefix}-{token}.{suffix}");
        let written = sandbox::write_attachment_async(dest, filename, mbox).await?;
        let written = written.to_string_lossy().to_string();
        if complete {
            (Some(written), None)
        } else {
            (None, Some(written))
        }
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
/// advisory eligible-sum budget pre-check. Returns a `uid -> ` [`PreflightSize`]
/// map holding only present UIDs (`PresentUnknown` / `Present`); absence from
/// the map means the UID is not present in the folder.
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
) -> Result<std::collections::BTreeMap<u32, PreflightSize>, rimap_core::RimapError> {
    let (sizes, uid_validity_opt) = source.fetch_sizes(folder, uids, limits.expected).await?;
    // The shared guard only *warns* on an omitted UIDVALIDITY; export refuses
    // to run unguarded, so reject an absent value.
    if uid_validity_opt.is_none() {
        return Err(rimap_core::RimapError::invalid_input(
            "server omitted UIDVALIDITY; export_messages requires it to guard the mailbox",
        ));
    }

    let mut size_by_uid: std::collections::BTreeMap<u32, PreflightSize> =
        std::collections::BTreeMap::new();
    for (uid, size) in sizes {
        size_by_uid.insert(
            uid,
            size.map_or(PreflightSize::PresentUnknown, PreflightSize::Present),
        );
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
            Some(&PreflightSize::Present(sz)) if u64::from(sz) <= limits.per_msg_cap => {
                Some(u64::from(sz))
            }
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
    size_by_uid: &std::collections::BTreeMap<u32, PreflightSize>,
    limits: FetchLimits,
) -> Result<Vec<FetchOutcome>, rimap_core::RimapError> {
    let mut outcomes = Vec::with_capacity(uids.len());
    let mut running: u64 = 0;
    for uid in uids {
        let n = uid.get();
        // Preflight-driven per-UID decision (pure, unit-tested). Skips never
        // attempt a body fetch, so oversize never triggers SizeLimit.
        let size = size_by_uid
            .get(&n)
            .copied()
            .unwrap_or(PreflightSize::Absent);
        if let UidPlan::Skip(reason) = classify_uid(size, limits.per_msg_cap) {
            outcomes.push(FetchOutcome {
                uid: n,
                result: Err(reason),
            });
            continue;
        }
        // Cap this body's read at the smaller of the per-message cap and the
        // budget still unspent, so the single in-flight body cannot exceed the
        // remaining budget: `running (raw bytes so far) + in-flight <= budget`
        // pins peak heap to ~`max_total_bytes` (#318). A body that would push
        // past it aborts mid-read with `SizeLimit` (fatal) — the same bound
        // `fetch_message`/`download_attachment` accept per body.
        let body_limit = limits
            .per_msg_cap
            .min(limits.budget.saturating_sub(running));
        let body = source
            .fetch_one_body(folder, *uid, limits.expected, body_limit)
            .await?;
        running = running.saturating_add(body.len() as u64);
        // Defense-in-depth backstop. Unreachable while `body_limit` caps each
        // body to the remaining budget (so `running <= budget` always); kept
        // fail-closed against future changes to the limit computation (#318).
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

#[cfg(test)]
mod token_tests {
    use super::export_token;

    #[test]
    fn export_token_is_nonempty_and_distinct() {
        let a = export_token();
        let b = export_token();
        assert!(!a.is_empty(), "token must not be empty");
        assert_ne!(a, b, "consecutive tokens must differ");
    }
}

/// Per-UID fetch result fed into [`plan_outcome`].
struct FetchOutcome {
    pub uid: u32,
    pub result: Result<Vec<u8>, ExportFailReason>,
}

/// Decision produced by [`plan_outcome`].
enum Outcome {
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
enum UidPlan {
    /// Resolved at preflight without a body fetch (`NotFound` / `Oversize`).
    Skip(ExportFailReason),
    /// Present and in-bounds: fetch the body.
    Fetch,
}

/// A requested UID's preflight size state, resolved before any body fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightSize {
    /// Not present in the folder (the server returned no entry for the UID).
    Absent,
    /// Present, but the server omitted `RFC822.SIZE`.
    PresentUnknown,
    /// Present with a reported `RFC822.SIZE`.
    Present(u32),
}

/// Classify a UID from its preflight [`PreflightSize`]. Pure, so the
/// security-critical NotFound/Oversize decision is unit-testable without a
/// live IMAP server.
fn classify_uid(size: PreflightSize, per_msg_cap: u64) -> UidPlan {
    match size {
        PreflightSize::Absent => UidPlan::Skip(ExportFailReason::NotFound),
        PreflightSize::Present(sz) if u64::from(sz) > per_msg_cap => {
            UidPlan::Skip(ExportFailReason::Oversize)
        }
        PreflightSize::Present(_) | PreflightSize::PresentUnknown => UidPlan::Fetch,
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
        use super::{ExportFailReason, PreflightSize, UidPlan, classify_uid};
        assert_eq!(
            classify_uid(PreflightSize::Absent, 100),
            UidPlan::Skip(ExportFailReason::NotFound)
        );
        assert_eq!(
            classify_uid(PreflightSize::Present(200), 100),
            UidPlan::Skip(ExportFailReason::Oversize)
        );
        assert_eq!(
            classify_uid(PreflightSize::Present(50), 100),
            UidPlan::Fetch
        );
        // present, size unknown
        assert_eq!(
            classify_uid(PreflightSize::PresentUnknown, 100),
            UidPlan::Fetch
        );
        // Exact boundary: size == cap is in-bounds (Fetch); one over is Oversize.
        assert_eq!(
            classify_uid(PreflightSize::Present(100), 100),
            UidPlan::Fetch
        );
        assert_eq!(
            classify_uid(PreflightSize::Present(101), 100),
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
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod source_seam_tests {
    use super::{ExportSource, RunPlan, run_export};
    use core::num::NonZeroU32;
    use rimap_imap::types::Uid;
    use std::cell::RefCell;
    use std::path::Path;

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
        seen_body_limits: RefCell<Vec<u64>>,
    }

    impl FakeSource {
        fn happy(bodies: Vec<Seeded>, uid_validity: u32) -> Self {
            Self {
                bodies,
                uid_validity: Some(uid_validity),
                body_error: None,
                seen_expected: RefCell::new(Vec::new()),
                seen_body_limits: RefCell::new(Vec::new()),
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
                seen_body_limits: RefCell::new(Vec::new()),
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
            body_limit: u64,
        ) -> Result<Vec<u8>, rimap_core::RimapError> {
            self.seen_expected.borrow_mut().push(expected);
            self.seen_body_limits.borrow_mut().push(body_limit);
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

    fn plan(dest_dir: &Path, uids: Vec<Uid>, expected: u32, allow_partial: bool) -> RunPlan {
        let dest = super::sandbox::resolve_dest_dir(None, dest_dir, dest_dir)
            .expect("resolve test dest dir");
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
        let resp = run_export(&fake, plan(tmp.path(), vec![uid(7), uid(9)], 4242, false))
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
            let result =
                run_export(&fake, plan(tmp.path(), vec![uid(1)], 4242, allow_partial)).await;
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

    /// A fake that reports NO UIDs as present (empty size list), simulating
    /// a mailbox where every requested UID is absent.
    struct AllAbsentSource {
        uid_validity: u32,
    }

    impl ExportSource for AllAbsentSource {
        async fn fetch_sizes(
            &self,
            _folder: &str,
            _uids: &[Uid],
            _expected: u32,
        ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError> {
            // Return an empty size list: every requested UID is not present.
            Ok((vec![], Some(self.uid_validity)))
        }

        async fn fetch_one_body(
            &self,
            _folder: &str,
            _uid: Uid,
            _expected: u32,
            _body_limit: u64,
        ) -> Result<Vec<u8>, rimap_core::RimapError> {
            // Should never be called: all UIDs are classified NotFound at preflight.
            panic!("fetch_one_body must not be called when all UIDs are absent");
        }
    }

    #[tokio::test]
    async fn zero_success_partial_writes_no_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = AllAbsentSource { uid_validity: 1234 };

        let result = run_export(
            &fake,
            plan(
                tmp.path(),
                vec![uid(10), uid(20), uid(30)],
                1234,
                true, // allow_partial=true: every-UID-failed is "allowed"
            ),
        )
        .await;

        let resp = result.expect("zero-success partial must return Ok");
        let meta = &resp.meta;

        assert!(
            !meta.complete,
            "complete must be false when nothing succeeded"
        );
        assert!(
            meta.path.is_none(),
            "path must be None (no complete artifact)"
        );
        assert!(
            meta.partial_path.is_none(),
            "partial_path must be None (no empty artifact written)"
        );
        assert_eq!(meta.message_count, 0, "message_count must be 0");
        assert_eq!(meta.total_bytes, 0, "total_bytes must be 0");
        assert_eq!(meta.failed.len(), 3, "all 3 UIDs must appear in failed");
        for f in &meta.failed {
            assert_eq!(
                f.reason,
                super::ExportFailReason::NotFound,
                "uid {} must be NotFound",
                f.uid
            );
        }
        let failed_uids: Vec<u32> = meta.failed.iter().map(|f| f.uid).collect();
        assert!(
            failed_uids.contains(&10) && failed_uids.contains(&20) && failed_uids.contains(&30),
            "failed list must include all requested UIDs: {failed_uids:?}"
        );

        // No artifact may be written.
        assert!(
            dir_is_empty(tmp.path()),
            "dest dir must be empty — no 0-byte artifact written"
        );
    }

    /// Reports a set of present UIDs at preflight but panics if any body fetch
    /// is attempted — used to prove the all-or-nothing short-circuit aborts
    /// BEFORE `fetch_one_body` when preflight already found a failed UID.
    struct PreflightFailNoFetchSource {
        present: Vec<(u32, u32)>,
        uid_validity: u32,
    }

    impl ExportSource for PreflightFailNoFetchSource {
        async fn fetch_sizes(
            &self,
            _folder: &str,
            uids: &[Uid],
            _expected: u32,
        ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError> {
            let requested: std::collections::BTreeSet<u32> = uids.iter().map(|u| u.get()).collect();
            let sizes = self
                .present
                .iter()
                .filter(|(u, _)| requested.contains(u))
                .map(|(u, sz)| (*u, Some(*sz)))
                .collect();
            Ok((sizes, Some(self.uid_validity)))
        }

        async fn fetch_one_body(
            &self,
            _folder: &str,
            _uid: Uid,
            _expected: u32,
            _body_limit: u64,
        ) -> Result<Vec<u8>, rimap_core::RimapError> {
            panic!(
                "fetch_one_body must not run: allow_partial=false and preflight \
                 already found a failed UID"
            );
        }
    }

    #[tokio::test]
    async fn all_or_nothing_aborts_before_any_body_fetch_on_preflight_failure() {
        let tmp = tempfile::tempdir().unwrap();
        // UID 7 is present; UID 8 is absent → NotFound at preflight. With
        // allow_partial=false the export must abort before fetching UID 7's
        // body (the fake panics if it does).
        let fake = PreflightFailNoFetchSource {
            present: vec![(7, 20)],
            uid_validity: 4242,
        };
        let result = run_export(&fake, plan(tmp.path(), vec![uid(7), uid(8)], 4242, false)).await;

        let err = result.expect_err("missing UID + allow_partial=false must abort");
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(
            err.to_string().contains("export incomplete"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains('8'),
            "error must name the missing UID 8: {err}"
        );
        assert!(
            dir_is_empty(tmp.path()),
            "no artifact may be written on abort"
        );
    }

    #[tokio::test]
    async fn body_limit_clamps_to_remaining_budget() {
        // Budget tighter than per_msg_cap: each body's read limit is the
        // budget still unspent, shrinking as bytes are fetched. (The framed
        // mbox then overflows the tiny budget so the call errors — here we
        // assert the limits threaded into each fetch, the #318 plumbing.)
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeSource::happy(
            vec![
                Seeded {
                    uid: 1,
                    body: vec![b'a'; 10],
                },
                Seeded {
                    uid: 2,
                    body: vec![b'b'; 4],
                },
            ],
            7,
        );
        let dest =
            super::sandbox::resolve_dest_dir(None, tmp.path(), tmp.path()).expect("resolve dest");
        let plan = RunPlan {
            folder: "INBOX".to_string(),
            dest,
            prefix: "messages".to_string(),
            uids: vec![uid(1), uid(2)],
            expected: 7,
            // eligible_sum = 10 + 4 = 14 <= 15 passes preflight; per_msg_cap is
            // larger than the budget, so the remaining budget gates the limit.
            budget: 15,
            per_msg_cap: 80,
            allow_partial: false,
        };
        let _ = run_export(&fake, plan).await;
        // First fetch: min(80, 15 - 0) = 15. Second: min(80, 15 - 10) = 5.
        assert_eq!(*fake.seen_body_limits.borrow(), vec![15, 5]);
    }

    /// Reports a tiny `RFC822.SIZE` but returns a far larger body, and honors
    /// the per-call `body_limit` exactly as the real IMAP read does (aborting
    /// with `SizeLimit` when the body would exceed it). Models the STRIDE-D
    /// hostile-server under-reporting #318 targets.
    struct UnderReportSource {
        uid_validity: u32,
        reported: u32,
        body: Vec<u8>,
    }

    impl ExportSource for UnderReportSource {
        async fn fetch_sizes(
            &self,
            _folder: &str,
            uids: &[Uid],
            _expected: u32,
        ) -> Result<(Vec<(u32, Option<u32>)>, Option<u32>), rimap_core::RimapError> {
            let sizes = uids
                .iter()
                .map(|u| (u.get(), Some(self.reported)))
                .collect();
            Ok((sizes, Some(self.uid_validity)))
        }

        async fn fetch_one_body(
            &self,
            _folder: &str,
            _uid: Uid,
            _expected: u32,
            body_limit: u64,
        ) -> Result<Vec<u8>, rimap_core::RimapError> {
            if self.body.len() as u64 > body_limit {
                return Err(rimap_core::RimapError::from(
                    rimap_imap::ImapError::SizeLimit { limit: body_limit },
                ));
            }
            Ok(self.body.clone())
        }
    }

    #[tokio::test]
    async fn under_reported_body_exceeding_remaining_budget_aborts_no_artifact() {
        // The server claims 1 byte (passes the eligible-sum preflight) but the
        // body is 100 bytes. The read limit = min(80, 50 - 0) = 50 < 100, so
        // the in-flight read aborts with SizeLimit before buffering it — peak
        // stays bounded and no artifact is written.
        let tmp = tempfile::tempdir().unwrap();
        let fake = UnderReportSource {
            uid_validity: 9,
            reported: 1,
            body: vec![b'x'; 100],
        };
        let dest =
            super::sandbox::resolve_dest_dir(None, tmp.path(), tmp.path()).expect("resolve dest");
        let plan = RunPlan {
            folder: "INBOX".to_string(),
            dest,
            prefix: "messages".to_string(),
            uids: vec![uid(1)],
            expected: 9,
            budget: 50,
            per_msg_cap: 80,
            allow_partial: false,
        };
        let err = run_export(&fake, plan)
            .await
            .expect_err("under-reported oversize body must abort");
        assert_eq!(err.code(), rimap_core::ErrorCode::AttachmentTooLarge);
        assert!(
            dir_is_empty(tmp.path()),
            "no artifact may be written on abort"
        );
    }
}
