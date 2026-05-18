#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_server::mcp::fuzz_oracle::{
    FuzzOutcome, check_error_envelope_valid, check_rmcp_accepts, fuzz_validate,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    match fuzz_validate(s) {
        FuzzOutcome::Skip => {}
        FuzzOutcome::Forward => {
            if let Err(rmcp_err) = check_rmcp_accepts(s) {
                panic!(
                    "validator FORWARDED an envelope rmcp rejects: \
                     input={s:?} rmcp_err={rmcp_err}"
                );
            }
        }
        FuzzOutcome::Reject(synthesized) => {
            if let Err(schema_err) = check_error_envelope_valid(&synthesized) {
                panic!(
                    "validator synthesized a schema-INVALID error envelope: \
                     input={s:?} synthesized={synthesized:?} schema_err={schema_err}"
                );
            }
        }
    }
});
