//! In-memory ring buffer of recently-read Message-IDs. Fed by `fetch_message`
//! and `search` result paths (Sprint 5 wires the feeders). Every `tool_end`
//! snapshots the current contents into [`crate::record::Provenance`].
//!
//! Entries older than `window_seconds` are evicted on every push and on every
//! snapshot. This is a pure-Rust in-memory structure — no I/O, no locking
//! beyond what the caller holds.
//!
//! Duplicate Message-IDs are permitted: if the same ID is recorded twice it
//! will appear twice in the snapshot. Deduplication, if desired, is the
//! caller's responsibility.
//!
//! Callers MUST lossy-decode non-UTF-8 input before calling `record`;
//! `String` cannot represent non-UTF-8 bytes. Per-entry length is capped at
//! `MAX_MESSAGE_ID_LEN` bytes (truncated with a `…[truncated]` suffix);
//! entry count is capped at `MAX_BUFFER_ENTRIES` (oldest evicted).
// ProvenanceBuffer is unwired scaffolding: the fetch_message / search
// feeders that populate it land in a future sprint (see the module doc).
// It is exercised only by this module's own tests, so the `expect` is
// scoped to non-test builds — when the feeders are wired, the expectation
// becomes unfulfilled and prompts its removal.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "feeders wired in a future sprint; see module doc")
)]

use std::collections::VecDeque;

use time::OffsetDateTime;
use unicode_segmentation::UnicodeSegmentation;

/// Maximum byte length of a Message-ID stored in the buffer. Values longer
/// than this are truncated with [`TRUNCATED_SUFFIX`] appended. The cap is
/// RFC 5322 line length.
const MAX_MESSAGE_ID_LEN: usize = 998;

/// Hard cap on entry count. When the buffer is at capacity, the oldest entry
/// is evicted regardless of the time window.
const MAX_BUFFER_ENTRIES: usize = 1024;

/// Marker appended to a Message-ID whose original byte length exceeded
/// [`MAX_MESSAGE_ID_LEN`]. Tests assert against this exact string.
const TRUNCATED_SUFFIX: &str = "\u{2026}[truncated]";

/// Ring buffer of observed Message-IDs with timestamps. Not thread-safe on
/// its own; the caller holds a `Mutex<ProvenanceBuffer>` if needed.
#[derive(Debug, Clone)]
pub(crate) struct ProvenanceBuffer {
    window: std::time::Duration,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    message_id: String,
    seen_at: OffsetDateTime,
}

impl ProvenanceBuffer {
    /// Construct an empty buffer with a retention window in seconds.
    #[must_use]
    pub fn new(window_seconds: u32) -> Self {
        Self {
            window: std::time::Duration::from_secs(u64::from(window_seconds)),
            entries: VecDeque::new(),
        }
    }

    /// Record that a Message-ID was read now. Evicts stale entries before
    /// inserting. Values longer than `MAX_MESSAGE_ID_LEN` bytes are truncated
    /// with a `…[truncated]` suffix. When the buffer is at `MAX_BUFFER_ENTRIES`
    /// capacity, the oldest entry is evicted regardless of the time window.
    pub fn record(&mut self, message_id: impl Into<String>) {
        self.record_at(message_id, OffsetDateTime::now_utc());
    }

    /// Variant taking an explicit clock so eviction can be asserted
    /// deterministically. Applies the same length cap and count cap as
    /// [`record`](Self::record). Crate-private; tests inside `rimap-audit`
    /// see it via `pub(crate)`.
    pub(crate) fn record_at(&mut self, message_id: impl Into<String>, now: OffsetDateTime) {
        self.evict_before(now);

        let mut message_id = message_id.into();
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            truncate_at_grapheme_boundary(&mut message_id, MAX_MESSAGE_ID_LEN);
            message_id.push_str(TRUNCATED_SUFFIX);
        }

        if self.entries.len() >= MAX_BUFFER_ENTRIES {
            self.entries.pop_front();
        }

        self.entries.push_back(Entry {
            message_id,
            seen_at: now,
        });
    }

    /// Return a `Vec<String>` of current entries, oldest-first. Evicts stale
    /// entries before snapshotting.
    #[must_use]
    pub fn snapshot(&mut self) -> Vec<String> {
        self.evict_before(OffsetDateTime::now_utc());
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Test-only snapshot with explicit clock. Crate-private; integration
    /// tests do not need this seam.
    #[cfg(test)]
    pub(crate) fn snapshot_at(&mut self, now: OffsetDateTime) -> Vec<String> {
        self.evict_before(now);
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Returns the number of entries currently buffered, including any
    /// stale entries that have not yet been evicted. `record*` and
    /// `snapshot*` evict before they act; `len` does not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict entries whose `seen_at` is strictly older than `now - window`.
    /// An entry timestamped exactly at the cutoff is retained.
    fn evict_before(&mut self, now: OffsetDateTime) {
        let cutoff = now - self.window;
        while let Some(front) = self.entries.front() {
            if front.seen_at < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Truncate `s` in-place to the largest prefix that ends at a grapheme
/// cluster boundary and has byte length <= `max_bytes`.
///
/// This is a module-local copy of `rimap_content::unicode::truncate_graphemes_in_place`
/// (the canonical reference). It is duplicated here to avoid pulling the
/// full `rimap-content` API surface (mail-parser, scraper, ammonia, idna)
/// into `rimap-audit` for one helper.
fn truncate_at_grapheme_boundary(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut cut = 0;
    for (idx, cluster) in s.grapheme_indices(true) {
        if idx + cluster.len() > max_bytes {
            break;
        }
        cut = idx + cluster.len();
    }
    s.truncate(cut);
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use time::OffsetDateTime;

    use super::TRUNCATED_SUFFIX;
    use crate::writer::provenance::ProvenanceBuffer;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000 + secs).unwrap()
    }

    #[test]
    fn records_preserve_insertion_order() {
        let mut b = ProvenanceBuffer::new(60);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(1));
        b.record_at("<c@x>", at(2));
        let snap = b.snapshot_at(at(3));
        assert_eq!(snap, vec!["<a@x>", "<b@x>", "<c@x>"]);
    }

    #[test]
    fn entries_older_than_window_are_evicted_on_snapshot() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(5));
        b.record_at("<c@x>", at(15));
        let snap = b.snapshot_at(at(15));
        assert_eq!(snap, vec!["<b@x>", "<c@x>"]);
    }

    #[test]
    fn eviction_runs_before_new_inserts() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(100));
        assert_eq!(b.len(), 1);
        assert_eq!(b.snapshot_at(at(100)), vec!["<b@x>"]);
    }

    #[test]
    fn empty_buffer_snapshots_to_empty_vec() {
        let mut b = ProvenanceBuffer::new(60);
        assert!(b.is_empty());
        let snap = b.snapshot_at(at(0));
        assert!(snap.is_empty());
    }

    #[test]
    fn window_of_zero_drops_everything_immediately() {
        let mut b = ProvenanceBuffer::new(0);
        b.record_at("<a@x>", at(0));
        assert_eq!(b.snapshot_at(at(1)), Vec::<String>::new());
    }

    #[test]
    fn oversize_message_id_is_truncated_with_suffix() {
        let mut b = ProvenanceBuffer::new(60);
        let huge = "x".repeat(2000);
        b.record_at(huge, at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        let stored = &snap[0];
        assert!(stored.ends_with(TRUNCATED_SUFFIX));
        assert!(stored.len() < 2000);
    }

    #[test]
    fn oversize_multibyte_message_id_truncates_at_grapheme_boundary() {
        // Regression: a Message-ID that exceeds MAX_MESSAGE_ID_LEN with
        // a multi-byte grapheme cluster straddling the cap byte must
        // not panic and must yield a valid UTF-8 prefix + the
        // "…[truncated]" suffix.
        //
        // Construction: 997 ASCII 'a' + 'é' (2 bytes) + 100 'b'.
        // MAX_MESSAGE_ID_LEN is 998, so the cap lands inside 'é'; the
        // cluster must be dropped entirely, leaving exactly 997 'a's
        // plus the suffix.
        let mut b = ProvenanceBuffer::new(60);
        let mut huge = "a".repeat(997);
        huge.push('é');
        huge.push_str(&"b".repeat(100));
        b.record_at(huge, at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        let stored = &snap[0];
        assert!(
            stored.ends_with(TRUNCATED_SUFFIX),
            "missing truncation suffix in {stored:?}"
        );
        let prefix_len = stored.len() - TRUNCATED_SUFFIX.len();
        assert_eq!(prefix_len, 997, "expected 997-byte prefix in {stored:?}");
    }

    #[test]
    fn count_cap_evicts_oldest_beyond_max_entries() {
        // Window is huge so time eviction isn't in play.
        let mut b = ProvenanceBuffer::new(3600);
        for i in 0..2000_u64 {
            b.record_at(format!("<id-{i}@x>"), at(i64::try_from(i).unwrap()));
        }
        let snap = b.snapshot_at(at(2000));
        // Capped at MAX_BUFFER_ENTRIES = 1024.
        assert_eq!(snap.len(), 1024);
        // Oldest (id-0) is gone; newest (id-1999) is present.
        assert!(!snap.iter().any(|s| s == "<id-0@x>"));
        assert!(snap.iter().any(|s| s == "<id-1999@x>"));
    }

    #[test]
    fn message_id_at_exactly_max_len_is_not_truncated() {
        // Pin `> with >=` at the length-cap branch in `record_at`. With `>`,
        // a Message-ID of exactly MAX_MESSAGE_ID_LEN bytes is stored as-is.
        // With `>=`, it would be truncated and gain the `…[truncated]`
        // suffix, ballooning past the 998-byte cap.
        let mut b = ProvenanceBuffer::new(60);
        let exact = "x".repeat(super::MAX_MESSAGE_ID_LEN);
        b.record_at(exact.clone(), at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0], exact,
            "ID at exactly the cap must be stored verbatim",
        );
        assert!(
            !snap[0].ends_with(TRUNCATED_SUFFIX),
            "ID at exactly the cap must not gain the truncation suffix",
        );
    }

    #[test]
    fn record_observably_appends_to_buffer() {
        // Pin `record with ()` mutation: calling `record` must observably
        // change `len` (it is the only public path to push entries). The
        // `()` stub would leave the buffer empty.
        let mut b = ProvenanceBuffer::new(60);
        assert_eq!(b.len(), 0);
        b.record("<a@x>");
        assert_eq!(b.len(), 1);
        b.record("<b@x>");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn snapshot_returns_actual_recorded_ids() {
        // Pin `snapshot -> Vec<String>` stub mutations (vec![],
        // vec![String::new()], vec!["xyzzy".into()]): the production
        // entry point is `snapshot()` (wall-clock-now), not the
        // test-only `snapshot_at`. Use a long window so the
        // implicit `now` cannot trigger eviction, then assert the
        // returned vec equals the recorded IDs in order.
        let mut b = ProvenanceBuffer::new(3600);
        b.record("<one@x>");
        b.record("<two@x>");
        b.record("<three@x>");
        let snap = b.snapshot();
        assert_eq!(snap, vec!["<one@x>", "<two@x>", "<three@x>"]);
    }

    #[test]
    fn len_returns_actual_entry_count() {
        // Pin `len -> usize with 1`: an empty buffer must report 0, and a
        // 3-element buffer must report 3 — neither matches the constant 1.
        let mut b = ProvenanceBuffer::new(60);
        assert_eq!(b.len(), 0);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(0));
        b.record_at("<c@x>", at(0));
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn is_empty_distinguishes_empty_from_populated() {
        // Pin `is_empty -> bool with true`: a populated buffer must report
        // false; the constant `true` mutation would lie.
        let mut b = ProvenanceBuffer::new(60);
        assert!(b.is_empty());
        b.record_at("<a@x>", at(0));
        assert!(
            !b.is_empty(),
            "is_empty must return false after a record() call",
        );
    }

    #[test]
    fn truncate_at_grapheme_boundary_fills_to_exact_max_bytes_for_ascii() {
        // Pin both mutations on the inner truncation helper:
        //   * `idx + cluster.len() > max_bytes` -> `>=` would break one
        //     cluster early, leaving 997 bytes instead of 998.
        //   * `idx + cluster.len() > max_bytes` -> `idx * cluster.len() > ...`
        //     with `cluster.len() == 1` would never break, leaving the
        //     full 999 bytes (and the call site would still append the
        //     suffix because the outer `len() > MAX` test fired).
        //
        // We feed an ASCII string of length MAX+1 so the helper definitely
        // truncates, and assert the resulting prefix is exactly
        // MAX_MESSAGE_ID_LEN bytes.
        let mut b = ProvenanceBuffer::new(60);
        let oversized = "x".repeat(super::MAX_MESSAGE_ID_LEN + 1);
        b.record_at(oversized, at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        let stored = &snap[0];
        assert!(
            stored.ends_with(TRUNCATED_SUFFIX),
            "oversize ID must gain the truncation suffix",
        );
        let prefix_len = stored.len() - TRUNCATED_SUFFIX.len();
        assert_eq!(
            prefix_len,
            super::MAX_MESSAGE_ID_LEN,
            "ASCII oversize prefix must fill the byte cap exactly",
        );
    }
}
