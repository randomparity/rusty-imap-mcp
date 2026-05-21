#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_content::output::SecurityWarning;

fuzz_target!(|data: &[u8]| {
    // Exercise the pre-parser scrubber for panics on adversarial input.
    // The harness deliberately does not assert structural invariants on
    // the output: the scrubber's RFC 2047 grammar handling (logical-header
    // splitting, fold continuation, multi-byte boundary tracking) is
    // richer than what a stateless byte scan in the harness can faithfully
    // replicate, and a simplified scan over-fires on inputs the scrubber
    // correctly classifies as non-smuggling. content_mime exercises the
    // same code path through `parse_message` for end-to-end behaviour.
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let _ = rimap_content::test_support::scrub_header_smuggling(data, &mut warnings);
});
