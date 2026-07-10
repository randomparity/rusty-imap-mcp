//! Differential HTML→text sanitizer oracle. See
//! `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.

mod allowlist;
mod diff;
mod norm;
mod reference;

fn main() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}
