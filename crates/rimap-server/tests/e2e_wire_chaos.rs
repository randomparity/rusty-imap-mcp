//! Network-chaos wire-driven e2e (#522). Interposes Toxiproxy between the
//! `rusty-imap-mcp` binary and the Dovecot fixture to exercise degraded-but-alive
//! network conditions — delayed greeting, mid-FETCH stall, RST during STARTTLS,
//! byte-trickle — asserting the typed `ERR_*` wire code, the audit record, and
//! post-fault recovery with no wedged session/breaker.
//!
//! Nightly-only: gated behind `RIMAP_CHAOS=1` so the suite silent-skips on PR CI
//! (which sweeps `binary(/e2e/)` under `RIMAP_REQUIRE_DOCKER=1` but never sets
//! `RIMAP_CHAOS`). See
//! `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md`.

#[path = "support/chaos/mod.rs"]
mod chaos;

// PERMANENT dead-code link. Each e2e binary compiles support/chaos
// independently, so every public accessor a given commit boundary does not yet
// call appears dead under -D warnings. Referencing them here counts as "use".
// Mirrors e2e_wire_fault_injection.rs::force_use_for_dead_code_link. Keep this
// permanently — some accessors (fingerprint) are first called only in later
// scenarios, so removing the link would re-break lint.
#[expect(
    dead_code,
    reason = "cross-boundary dead-code link for support/chaos items"
)]
fn force_use_for_dead_code_link() {
    let _ = chaos::ChaosHarness::try_start;
    let _ = chaos::ChaosHarness::imaps_port;
    let _ = chaos::ChaosHarness::starttls_port;
    let _ = chaos::ChaosHarness::fingerprint;
    let _ = chaos::ChaosHarness::toxics;
    let _ = chaos::ToxiproxyControl::add_toxic;
    let _ = chaos::ToxiproxyControl::reset;
    let _: fn() -> _ = || chaos::ChaosSkip::Disabled;
    let _: fn() -> _ = || chaos::ChaosSkip::DockerUnavailable;
}

// Temporary Task-2 harness self-test: validates the chaos stack comes up,
// readiness (fingerprint + control API + proxies) passes, and a toxic can be
// added and cleared. Removed in Task 4 once real scenarios exercise the harness.
#[test]
fn chaos_harness_selftest() {
    let Ok(h) = chaos::ChaosHarness::try_start() else {
        return;
    };
    assert!(h.imaps_port() != 0 && h.starttls_port() != 0);
    assert_eq!(h.fingerprint().to_hex().len(), 64);
    h.toxics().add_toxic(
        "imaps",
        &serde_json::json!({ "type": "latency", "attributes": { "latency": 1 } }),
    );
    h.toxics().reset();
}
