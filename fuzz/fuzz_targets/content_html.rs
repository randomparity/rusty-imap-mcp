#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // sanitize_html(raw: &[u8], charset: Option<&str>) -> Result<HtmlResult, ContentError>
    //
    // The fuzzer drives both arguments. The first byte (modulo a small
    // table) selects a charset label so the input space includes
    // realistic charset routing; the rest is the body.
    if data.is_empty() {
        return;
    }
    let charset = match data[0] % 5 {
        0 => None,
        1 => Some("utf-8"),
        2 => Some("iso-8859-1"),
        3 => Some("windows-1252"),
        _ => Some("us-ascii"),
    };
    let body = &data[1..];
    let _ = rimap_content::test_support::sanitize_html(body, charset);
});
