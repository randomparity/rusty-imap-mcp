//! Library crate for the rusty-imap-mcp binary.
//!
//! The modules are exposed with `#[doc(hidden)] pub` so that the
//! binary entry point (`main.rs`) and integration tests in
//! `tests/` can reach internal types, without advertising a stable
//! library API. External consumers should not depend on this
//! surface — it is an implementation detail.

#![deny(missing_docs)]

#[doc(hidden)]
pub mod boot;
#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod mcp;
#[doc(hidden)]
pub mod tools;

#[cfg(test)]
mod test_support;
