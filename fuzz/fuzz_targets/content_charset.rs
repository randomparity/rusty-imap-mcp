#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Wire format: first byte = label length L (0..=63), next L bytes = label
    // (UTF-8 if valid, otherwise None), remainder = bytes to decode.
    if data.is_empty() {
        return;
    }
    let label_len = (data[0] & 0x3f) as usize;
    if 1 + label_len > data.len() {
        return;
    }
    let label_bytes = &data[1..1 + label_len];
    let body = &data[1 + label_len..];

    let label = std::str::from_utf8(label_bytes).ok();
    let _ = rimap_content::decode(body, label);
});
