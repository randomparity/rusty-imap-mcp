//! Network-chaos e2e support: a Toxiproxy-in-path Dovecot harness (#522).
pub mod harness;

pub use harness::{ChaosHarness, ChaosSkip, ToxiproxyControl};
