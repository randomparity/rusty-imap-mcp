# Advisory dependency remediation

## Problem

The workspace advisory gate reports nine findings in ammonia, rustls,
rustls-webpki, and webpki-roots. The separate HTML oracle graph also resolves
an affected ammonia version.

## Scope

Use compatible patched releases: workspace ammonia 4.1.8, rustls 0.23.46,
rustls-webpki 0.103.16, and webpki-roots 1.0.10; preserve the oracle
ammonia 4.2 line with 4.2.4. Raise direct minimum requirements and update
affected tracked lockfiles. Remove the stale windows-sys 0.52 deny skip
already documented as unnecessary. Preserve feature selections and MSRV.

### Failure model

- Prevent: affected versions in the committed root and oracle graphs.
- Detect: fuzz/probe lock drift through existing parity checks.
- Preserve: sanitizer snapshots, TLS pinning, and transport behavior.
- Accept: a future upstream advisory can require another dependency update.

## Success

Root and oracle advisory checks pass without new exceptions. Existing
functional, security corpus, snapshot, and MSRV checks remain green.
No public API, configuration, or protocol changes are required.

## Validation

- focused-test: `just deny` and `just oracle-deny`; expected red is the
  reproduced advisory failure, expected green is zero advisory findings.
- focused-test: `just check-fuzz-lock-parity` and
  `just check-compiler-probe-locks` verify derived dependency graphs.
- Regression: `RIMAP_REQUIRE_DOCKER=1 just ci`, including sanitizer corpus,
  wire/SMTP fixtures, MSRV, and oracle checks. Review any snapshot diff
  rather than accepting it. Rebuild excluded fuzz targets after realignment.
