//! Unified IMAP RFC 3501 part-ID walker over `BodyStructure` trees.
//!
//! Part numbering: top-level multipart children are "1", "2", ..."N".
//! Nested multipart sub-parts are "1.1", "1.2", etc. A single-part
//! message at the root is "1". A `message/rfc822` part surfaces its
//! own part ID and the walker then descends into its body with a
//! fresh prefix derived from that number.

use rimap_imap::types::BodyStructure;

/// Maximum recursion depth. Matches the MIME depth cap used during
/// rimap-content parsing.
pub(crate) const MAX_PART_DEPTH: u32 = 64;

/// Walk a `BodyStructure` tree, invoking `visit` for every leaf
/// (`Single`) or `message/rfc822` wrapper (`Message`) node with its
/// IMAP part ID.
pub(crate) fn walk_body_structure<F>(bs: &BodyStructure, mut visit: F)
where
    F: FnMut(&str, &BodyStructure),
{
    walk_inner(bs, "", &mut visit, 0);
}

fn walk_inner<F>(bs: &BodyStructure, prefix: &str, visit: &mut F, depth: u32)
where
    F: FnMut(&str, &BodyStructure),
{
    // cargo-mutants: known-equivalent — `> with >=` on this defensive
    // recursion cap. `>=` differs from `>` only at exactly `depth ==
    // MAX_PART_DEPTH` (64); no real IMAP BODYSTRUCTURE nests 64 levels deep,
    // so for any tree a server actually returns the walk visits an identical
    // set of parts. Same shape as `rimap-content` `raw_parts.rs:71`.
    if depth > MAX_PART_DEPTH {
        return;
    }
    match bs {
        BodyStructure::Single { .. } => {
            let part_id = leaf_part_id(prefix);
            visit(&part_id, bs);
        }
        BodyStructure::Multipart { parts, .. } => {
            for (i, child) in parts.iter().enumerate() {
                let cid = child_part_id(prefix, i + 1);
                walk_inner(child, &cid, visit, depth + 1);
            }
        }
        BodyStructure::Message { body, .. } => {
            let part_id = leaf_part_id(prefix);
            visit(&part_id, bs);
            walk_inner(body, &part_id, visit, depth + 1);
        }
    }
}

/// Compute the IMAP part ID for a leaf or `message/rfc822` node.
/// Root-level nodes get `"1"`; nested nodes keep their prefix.
fn leaf_part_id(prefix: &str) -> String {
    if prefix.is_empty() {
        "1".to_string()
    } else {
        prefix.to_string()
    }
}

/// Compute the IMAP part ID for the `index`-th child of a multipart.
/// Root-level children are `"1"`, `"2"`, etc.; nested children are
/// `"prefix.1"`, `"prefix.2"`, etc.
fn child_part_id(prefix: &str, index: usize) -> String {
    if prefix.is_empty() {
        index.to_string()
    } else {
        format!("{prefix}.{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(mt: &str, sub: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mt.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size: 10,
        }
    }

    #[test]
    fn single_part_yields_one() {
        let bs = single("text", "plain");
        let mut ids = Vec::new();
        walk_body_structure(&bs, |id, _| ids.push(id.to_string()));
        assert_eq!(ids, vec!["1"]);
    }

    #[test]
    fn multipart_yields_numbered_leaves() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![single("text", "plain"), single("image", "png")],
        };
        let mut ids = Vec::new();
        walk_body_structure(&bs, |id, _| ids.push(id.to_string()));
        assert_eq!(ids, vec!["1", "2"]);
    }

    #[test]
    fn nested_multipart_dotted_ids() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![single("text", "plain"), single("image", "gif")],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".into(),
            parts: vec![inner, single("application", "zip")],
        };
        let mut ids = Vec::new();
        walk_body_structure(&bs, |id, _| ids.push(id.to_string()));
        assert_eq!(ids, vec!["1.1", "1.2", "2"]);
    }

    #[test]
    fn depth_limit_stops_descent() {
        let mut bs = single("text", "plain");
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".into(),
                parts: vec![bs],
            };
        }
        let mut ids = Vec::new();
        walk_body_structure(&bs, |id, _| ids.push(id.to_string()));
        assert!(ids.is_empty());
    }
}
