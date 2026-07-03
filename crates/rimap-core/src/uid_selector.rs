//! [`UidSelector`] — the single-or-batch UID target shape.
//!
//! # Wire shapes
//!
//! ```text
//! {"uid": 42}        -> UidSelector::Single
//! {"uids": [1,2,3]}  -> UidSelector::Batch
//! ```
//!
//! # Why a manual `Deserialize`
//!
//! `#[serde(untagged)]` + `#[serde(flatten)]` silently picks the first
//! matching variant on ambiguous payloads (both `uid` and `uids` present) and
//! collapses errors to "did not match any variant". We deserialize into a
//! neutral two-key shape and disambiguate explicitly so both "both present"
//! and "neither present" produce actionable errors.

use core::num::NonZeroU32;

use schemars::JsonSchema;
use serde::de::{Error as DeError, Unexpected};
use serde::{Deserialize, Deserializer, Serialize};

/// Maximum number of UIDs accepted in a single batch request.
pub const MAX_BATCH_UIDS: usize = 100;

/// Targets exactly one message (`{"uid": N}`) or a batch (`{"uids": [...]}`).
///
/// Encodes the "exactly one of uid OR uids" invariant at the type level —
/// ambiguous or empty payloads are rejected at deserialize time rather than
/// caught by runtime validation in every handler.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(untagged)]
#[non_exhaustive]
pub enum UidSelector {
    /// Single-message target.
    Single {
        /// Non-zero message UID.
        uid: NonZeroU32,
    },
    /// Batch target (1 to 100 uids).
    Batch {
        /// Non-empty, bounded batch of UIDs.
        uids: BoundedUids,
    },
}

impl UidSelector {
    /// Consume the selector and yield the underlying UIDs in declaration order.
    #[must_use]
    pub fn into_uids(self) -> Vec<NonZeroU32> {
        match self {
            Self::Single { uid } => vec![uid],
            Self::Batch { uids } => uids.0,
        }
    }
}

/// Non-empty list of UIDs, capped at 100 entries.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct BoundedUids(Vec<NonZeroU32>);

impl BoundedUids {
    /// View the underlying UIDs.
    #[must_use]
    pub fn as_slice(&self) -> &[NonZeroU32] {
        &self.0
    }
}

impl TryFrom<Vec<NonZeroU32>> for BoundedUids {
    type Error = String;

    fn try_from(value: Vec<NonZeroU32>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("uids batch must not be empty".to_string());
        }
        if value.len() > MAX_BATCH_UIDS {
            return Err(format!(
                "uids batch size {} exceeds maximum of {MAX_BATCH_UIDS}",
                value.len()
            ));
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for BoundedUids {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Vec::<NonZeroU32>::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct UidSelectorWire {
    #[serde(default)]
    uid: Option<NonZeroU32>,
    #[serde(default)]
    uids: Option<BoundedUids>,
}

impl<'de> Deserialize<'de> for UidSelector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = UidSelectorWire::deserialize(deserializer)?;
        match (wire.uid, wire.uids) {
            (Some(uid), None) => Ok(Self::Single { uid }),
            (None, Some(uids)) => Ok(Self::Batch { uids }),
            (Some(_), Some(_)) => Err(D::Error::invalid_value(
                Unexpected::Other("both `uid` and `uids`"),
                &"exactly one of `uid` or `uids`",
            )),
            (None, None) => Err(D::Error::invalid_value(
                Unexpected::Other("neither `uid` nor `uids`"),
                &"exactly one of `uid` or `uids`",
            )),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<UidSelector, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn single_uid(sel: &UidSelector) -> Option<u32> {
        if let UidSelector::Single { uid } = sel {
            Some(uid.get())
        } else {
            None
        }
    }

    fn batch_uids(sel: &UidSelector) -> Option<Vec<u32>> {
        if let UidSelector::Batch { uids } = sel {
            Some(uids.as_slice().iter().map(|u| u.get()).collect())
        } else {
            None
        }
    }

    #[test]
    fn deserializes_single_shape() {
        let sel = parse(r#"{"uid": 42}"#).unwrap();
        assert_eq!(single_uid(&sel), Some(42));
    }

    #[test]
    fn deserializes_batch_shape() {
        let sel = parse(r#"{"uids": [1, 2, 3]}"#).unwrap();
        assert_eq!(batch_uids(&sel), Some(vec![1, 2, 3]));
    }

    #[test]
    fn rejects_both_present() {
        let err = parse(r#"{"uid": 1, "uids": [2]}"#).unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn rejects_neither_present() {
        let err = parse("{}").unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn rejects_empty_batch() {
        let err = parse(r#"{"uids": []}"#).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn rejects_oversized_batch() {
        let uids: Vec<u32> = (1..=101).collect();
        let json = serde_json::to_string(&serde_json::json!({"uids": uids})).unwrap();
        let err = parse(&json).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn rejects_zero_uid() {
        let err = parse(r#"{"uid": 0}"#).unwrap_err();
        // NonZeroU32 rejects 0 with its own message.
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_zero_in_batch() {
        let err = parse(r#"{"uids": [1, 0, 2]}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}"
        );
    }

    #[test]
    fn into_uids_single() {
        let sel = parse(r#"{"uid": 7}"#).unwrap();
        let got: Vec<u32> = sel.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![7]);
    }

    #[test]
    fn into_uids_batch() {
        let sel = parse(r#"{"uids": [10, 11]}"#).unwrap();
        let got: Vec<u32> = sel.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![10, 11]);
    }

    #[test]
    fn flattens_into_parent_struct() {
        #[derive(Debug, Deserialize)]
        struct Parent {
            folder: String,
            #[serde(flatten)]
            target: UidSelector,
        }

        let p: Parent = serde_json::from_str(r#"{"folder": "INBOX", "uid": 42}"#).unwrap();
        assert_eq!(p.folder, "INBOX");
        matches!(p.target, UidSelector::Single { .. });

        let p: Parent = serde_json::from_str(r#"{"folder": "INBOX", "uids": [1, 2]}"#).unwrap();
        assert_eq!(p.folder, "INBOX");
        matches!(p.target, UidSelector::Batch { .. });

        let err = serde_json::from_str::<Parent>(r#"{"folder": "INBOX"}"#).unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");

        let err = serde_json::from_str::<Parent>(r#"{"folder": "INBOX", "uid": 1, "uids": [2]}"#)
            .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }
}
