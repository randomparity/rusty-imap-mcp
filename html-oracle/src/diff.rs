//! Two-tier equivalence rule. reference_only = ref - prod - allowlist. Empty =>
//! Match. Non-empty with an explaining warning => Soft. Non-empty with none =>
//! Hard (silent drop = bug).

use std::collections::BTreeSet;

use rimap_content::test_support::HtmlResult;
use rimap_core::warning::WarningCode;

use crate::norm;
use crate::reference::ReferenceExtract;

/// Warning codes that legitimately explain dropped/removed text.
pub const DROP_EXPLAINING: &[WarningCode] = &[
    WarningCode::HtmlHiddenContentDetected,
    WarningCode::HtmlScriptStripped,
    WarningCode::HtmlStyleStripped,
    WarningCode::HtmlRemoteImageStripped,
    WarningCode::HtmlLinkTextHrefMismatch,
    WarningCode::HtmlAnchorUnparsableHref,
];

#[derive(Debug)]
pub enum Verdict {
    Match,
    Soft { reference_only: BTreeSet<String> },
    Hard { reference_only: BTreeSet<String> },
}

#[derive(Debug)]
pub struct Divergence {
    pub verdict: Verdict,
    pub production_only: BTreeSet<String>,
}

fn has_explaining_warning(prod: &HtmlResult) -> bool {
    prod.warnings
        .iter()
        .any(|w| DROP_EXPLAINING.contains(&w.code))
}

pub fn classify(
    prod: &HtmlResult,
    refx: &ReferenceExtract,
    allow_tokens: &BTreeSet<String>,
) -> Divergence {
    let prod_tokens = norm::tokenize(&prod.body_text);
    let prod_href_ids = norm::href_identities(prod.anchor_hrefs.iter());

    let mut reference_only: BTreeSet<String> = BTreeSet::new();
    for t in &refx.text_tokens {
        if !prod_tokens.contains(t) && !allow_tokens.contains(t) {
            reference_only.insert(t.clone());
        }
    }
    for h in &refx.href_ids {
        if !prod_href_ids.contains(h) && !allow_tokens.contains(h) {
            reference_only.insert(h.clone());
        }
    }

    let mut production_only: BTreeSet<String> = BTreeSet::new();
    for t in &prod_tokens {
        if !refx.text_tokens.contains(t) {
            production_only.insert(t.clone());
        }
    }

    let verdict = if reference_only.is_empty() {
        Verdict::Match
    } else if has_explaining_warning(prod) {
        Verdict::Soft { reference_only }
    } else {
        Verdict::Hard { reference_only }
    };
    Divergence {
        verdict,
        production_only,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use rimap_content::test_support::sanitize_html;

    fn refx(tokens: &[&str]) -> ReferenceExtract {
        ReferenceExtract {
            text_tokens: tokens.iter().map(|s| s.to_string()).collect(),
            href_ids: BTreeSet::new(),
        }
    }

    #[test]
    fn silent_drop_is_hard() {
        // Production result with a token the reference sees but production
        // dropped, and NO explaining warning.
        let prod = sanitize_html(b"<p>keep</p>", Some("utf-8")).unwrap();
        let r = refx(&["keep", "ghost"]);
        let d = classify(&prod, &r, &BTreeSet::new());
        assert!(matches!(d.verdict, Verdict::Hard { .. }), "{:?}", d.verdict);
    }

    #[test]
    fn explained_drop_is_soft() {
        // display:none hidden text => HtmlHiddenContentDetected fires.
        let prod = sanitize_html(
            br#"<p>keep</p><div style="display:none">secret</div>"#,
            Some("utf-8"),
        )
        .unwrap();
        let r = refx(&["keep", "secret"]);
        let d = classify(&prod, &r, &BTreeSet::new());
        assert!(matches!(d.verdict, Verdict::Soft { .. }), "{:?}", d.verdict);
    }

    #[test]
    fn allowlisted_token_suppressed() {
        let prod = sanitize_html(b"<p>keep</p>", Some("utf-8")).unwrap();
        let r = refx(&["keep", "ghost"]);
        let mut allow = BTreeSet::new();
        allow.insert("ghost".to_string());
        let d = classify(&prod, &r, &allow);
        assert!(matches!(d.verdict, Verdict::Match), "{:?}", d.verdict);
    }
}
