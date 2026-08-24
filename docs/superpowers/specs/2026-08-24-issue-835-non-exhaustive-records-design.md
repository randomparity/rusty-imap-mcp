# Published data records become non-exhaustive — design

Issue: [#835](https://github.com/randomparity/rusty-imap-mcp/issues/835).
Verified on `main` at `b708b96b5d3095f06b34b61a8ac065687cd1f016`.
Decision: [ADR-0026](../../ADR/0026-published-data-records-non-exhaustive.md).

## Frozen scope

- **Scope identity:** issue #835, annotation token `q835-d8f3faa3`.
- **Outcome:** before v0.2.0, field additions stop being silent breaking
  changes for every remaining public data-record struct in published library
  crates.
- **Sources:** issue #835; completed precedents #665, #706, #707, #715, and
  #716; the operator's interactive decisions to exclude unpublished
  `rimap-server` tool records and to repair two EOF-normalization findings
  emitted by the current `just hooks` artifact.
- **Exclusions:** `rimap-server` tool `*Meta` and `*Input` records; opaque
  structs whose externally visible API does not expose data fields; runtime,
  serialization, wire-format, dependency, persistence, concurrency,
  authentication, and migration changes.
- **Permitted surface:** qualifying definitions in `rimap-imap`,
  `rimap-content`, `rimap-config`, `rimap-authz`, `rimap-smtp`, and
  `rimap-core`; compile-forced callers and destructures; minimal constructors;
  focused contract tests and doctests; generated schemas only if changed;
  `CHANGELOG.md`; and EOF-only repairs to `crates/rimap-server/Cargo.toml` and
  `docs/ADR/0025-pre-init-single-envelope-validator-interception.md`.
- **Ambiguities:** none.
- **Interaction:** interactive.

## Problem

A public Rust struct with public fields is exhaustive unless marked
`#[non_exhaustive]`. Adding a field to such a struct breaks downstream struct
literals and exhaustive destructures. The workspace's `cargo semver-checks`
baseline is v0.1.0 while the manifests are already 0.2.0-dev, so the current
major-version transition permits and therefore does not diagnose these breaks.
The attribute is itself breaking, making the unreleased v0.2.0 window the only
point where the policy can be completed without consuming another major
version.

The earlier changes applied this policy to `rimap-config`, `rimap-audit`, and
`AuthEvent`. Issue #835 identifies the remaining published-crate gap but gives
an illustrative rather than exhaustive type list. An AST inventory at the
verified base found 57 `pub struct` definitions with at least one externally
public field in the six permitted crates; 30 already carry the attribute and
27 do not.

## Decision

Apply `#[non_exhaustive]` to every one of the 27 missing public-field record
structs. The inventory boundary is structural and reviewable: the struct is
public, at least one field is public outside its defining crate, and the value
represents configuration, input, output, captured data, or a structured error.
A public type with only private or restricted fields is opaque rather than a
public data record and stays outside this change.

### Complete inventory

| Crate | Missing records at the verified base |
|---|---|
| `rimap-authz` | `BreakerConfig` |
| `rimap-config` | `ResolutionPolicy` |
| `rimap-content` | `HtmlResult`, `OutboundHtml`, `RawPart`, `ThreadingHeaders`, `FilterResult` |
| `rimap-core` | `FolderNameError`, `ToolAnnotationHints` |
| `rimap-imap` | `ConnectionConfig`, `DeleteOutcome`, `SearchOutcome`, `TlsConfigBundle`, `Folder`, `StatusItems`, `FolderStatus`, `SelectedFolder`, `MoveResult`, `AppendResult`, `Envelope`, `Address`, `HeaderSearch`, `StructuredQuery`, `FetchSpec`, `FetchedMessage` |
| `rimap-smtp` | `SendEnvelope`, feature-gated `CapturedSend` |

`FolderNameError` is included because it is a structured public error value
with a public field, matching the already non-exhaustive
`InvalidAccountName`. Feature-gated `CapturedSend` is included because
`test-support` is a published feature and its public API is still downstream
API.

### Construction cutover

`#[non_exhaustive]` rejects every cross-crate struct expression, including
functional-update syntax (`..base`), with E0639. It does not prevent public
field reads or assignment after construction.

For each compiler-reported cross-crate construction site:

1. Use an existing constructor when one already expresses the required fields.
2. Otherwise use `Default::default()` followed by field assignment when the
   type already has a meaningful `Default`.
3. Add a constructor only when an existing workspace caller cannot construct
   the value through either route. The constructor takes exactly the fields
   with no meaningful default and initializes the remainder exactly as the
   defining crate already does.
4. Do not add `Default` merely to make the cutover convenient. In particular,
   required identity, host, credential-policy, or message-address fields must
   not gain invented empty defaults.

Types produced only by their defining crate gain no speculative constructor.
Cross-crate destructures add `..` and keep their existing behavior.

### Compile contract

Each changed type receives a concise `compile_fail,E0639` doctest that attempts
a downstream struct expression using the type's actual public surface. Before
the attribute, the doctest must fail because the expression compiles; after the
attribute, it passes because rustc rejects the expression. The snippets must
not depend on a missing import, private field, unavailable `Default`, or any
other failure mode.

Because stable rustdoc does not validate the error-code suffix, a focused
cross-crate integration probe also checks `error[E0639]` for representative
plain-literal and functional-update forms across the changed crate families.
The probe follows `rimap-audit/tests/non_exhaustive_e0639.rs`: a temporary
crate depends on local path crates and the test inspects `cargo check` stderr.
It does not test source text.

## Runtime and data behavior

The attribute changes compile-time downstream construction and destructuring
only. It does not alter layout guarantees, serde output, MCP tool schemas,
network behavior, validation, authorization, or error mapping. Constructor and
caller rewrites must produce field-for-field equivalent values. Existing
behavior tests remain the primary proof; constructor-specific tests compare
against the defining crate's existing production construction path where a
new constructor is required.

Generated tool schemas are regenerated only if `just regen-tool-schemas`
produces a diff. An attribute-only schema diff would be unexpected and must be
diagnosed rather than accepted blindly.

## Failure handling

The first complete compile after adding the attributes is the authoritative
inventory of cross-crate fallout. E0639 sites are migrated; other compiler
errors are diagnosed independently rather than assumed to be fallout.
Guardrail failures are corrected only from their current failure artifact.
The implementation does not suppress lints, semver checks, schema drift, or
doctest failures.

## Verification

1. Add the compile-fail contract before attributes and run focused doctests;
   observe failure because the struct expressions still compile.
2. Add attributes and migrate compiler-reported callsites; rerun focused crate
   doctests and tests.
3. Run the representative E0639 integration probe and focused behavior tests
   for every crate that gained a constructor or caller rewrite.
4. Run `just regen-tool-schemas` and inspect whether any generated file moved.
5. Run `just semver-checks`; expected result is green but vacuous for the
   already-declared 0.2.0-dev major transition, so it is a gate rather than
   evidence that the API did not break.
6. Run `just ci` in the background to completion.

## Acceptance criteria

- All 27 inventory entries carry `#[non_exhaustive]`.
- Every cross-crate construction and destructuring site compiles through the
  established constructor/default-plus-assignment/rest-pattern idiom.
- New constructors exist only for compiler-proven callers without an existing
  construction route and preserve the prior field values.
- Focused doctests fail before the attributes and pass after them; the
  representative integration probe observes E0639 specifically.
- Runtime behavior, serialized output, and generated tool schemas do not drift.
- `CHANGELOG.md` explains the breaking construction change and the supported
  downstream idiom.
- `just semver-checks` and `just ci` pass.

## Durable execution context

- Branch: `feat/non-exhaustive-records-835`
- Base branch: `main`
- Guardrails: focused crate doctests/tests during TDD; `just
  regen-tool-schemas`; `just semver-checks`; final `just ci`.
- Open findings: none at design authoring.
- Review deferrals: none at design authoring.
