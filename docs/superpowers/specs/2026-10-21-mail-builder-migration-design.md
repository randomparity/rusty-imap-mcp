# Mail-builder 1.0 and attachment filename decoding

## Problem and authority

The dependency repair request selects #879 (filename decoding) and #880
(mail-builder 1.0 with outbound snapshots); #875 is the bare-bump duplicate.
This change integrates that existing migration with current main and the selected
Rust dependency updates. The caller fixed the full-spec assessment denominator at
800 non-lock source lines, based on the existing roughly 804-line candidate diff.
The implementation is one tightly coupled integration unit. Its transient execution
plan stays in the private dependency-evaluation reports.

## Scope

Preserve current Rust versions, MSRV 1.88, release targets, main's final-basename
spoof detection (#883), posture and account boundaries, and outgoing Bcc privacy.
Decode BODYSTRUCTURE Content-Type name and Content-Disposition filename using
mail-parser's existing MIME semantics; disposition filename takes precedence.
Reuse the existing sanitizer and attach warnings to the attachment index.
Keep the existing bounded-header policy before allocating synthesized header bytes.
Pin mail-builder 1.0's existing serialization through reviewed outbound snapshots.
Do not add runtime features, dependencies beyond the selected migration, config,
interfaces beyond #879's existing helper, or unrelated refactors.

## Success

1. RFC 2231 single/continued values and RFC 2047 names decode consistently with
   the full-message path for the named cases; absent names remain absent.
2. Header-smuggling parameters are dropped with warnings; synthesized headers
   cannot grow beyond MAX_HEADER_BYTES, including escaping and fixed framing.
3. Existing Unicode, basename, and double-extension defenses remain active.
4. Plain, long Unicode, folded-recipient, multipart attachment, and forwarded
   outbound bytes match inspected snapshots. CR and LF must pair in both directions.
5. Current selected-set dependency repairs and lockfile parity remain intact;
   full local CI, required container arms, and the changed server fuzz lock build pass.

## Failure model

Actors are email agents composing mail and IMAP servers returning untrusted MIME
parameters on supported developer/release platforms. Assets are header integrity,
bounded synthesized memory, filename provenance and warning fidelity, envelope-only
Bcc recipients, and byte-preserving base64 wrapping of forwarded originals.
Invalid parameter names or CR/LF/NUL values are omitted with the existing warning.
Excess synthesized bytes withhold the filename and warn; no partial name is emitted.
The input BODYSTRUCTURE vectors are already allocated by transport; this helper
bounds additional serialization allocation, not transport's own storage.
Existing malformed MIME precedence follows mail-parser; a new MIME policy is outside
scope. Cross-platform runtime proof remains CI's responsibility; local proof is arm64.

## Validation

Focused-test: filename params tests cover precedence, absent/empty values, RFC 2231,
RFC 2047, quoting, controls, and bounded append behavior. Add a pre-fix assertion
that oversized quoted values do not grow the synthesized buffer. Replace a timing
assertion with that deterministic resource contract; run the test red then green.
Focused-test: normalizer rejects standalone CR and standalone LF (controlled bad
input before repair), and accepts CRLF; run outbound_bytes_snapshots red then green.
Focused-test: existing filename spoof corpus and sanitizer tests protect #883;
run the content crate tests and inspect any snapshots instead of blind acceptance.
Focused-test: outbound snapshots and existing compose/Bcc/forward tests protect
wire contracts; run message_builder and wire functional suites in full CI.
Structural checks: regenerate tool schemas and tools reference before CI; inspect
changes, preserve lock parity, run actionlint and zizmor for combined workflows.
Run just ci with mandatory Docker and chaos enabled, Node 22, and record fresh JUnit
counts plus exit codes. Confirm the built production binary derives from the current
HEAD before functional testing. Build server fuzz targets optimized with nightly,
ASAN and four jobs; no fuzz campaign or unrelated content rebuild is required.

## Integration and rollback

Apply #879 before #880, retain their history, and resolve stale manifest conflict
by keeping current audited Rust repairs plus mail-builder 1.0. No external writes.
Each repair gets a conventional commit and configured hooks. Revert the integration
commits to roll back; no persisted format or deployment transition is introduced.
