#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_server::mcp::wire_validator::__fuzz_validate as validate;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate(s);
    }
});
