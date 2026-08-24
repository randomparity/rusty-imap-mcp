# ADR-0026: Published data records are non-exhaustive

**Status:** Accepted · 2026-08-24 · issue [#835](https://github.com/randomparity/rusty-imap-mcp/issues/835)

## Context

Public Rust structs with public fields permit downstream struct literals and
exhaustive destructuring. Adding a field is therefore a source-breaking change
unless the struct is marked `#[non_exhaustive]`. The workspace is already on the
unreleased 0.2.0-dev major transition, so applying the attribute now consumes no
additional version break; after v0.2.0 it would require another major version.

Issues #665, #706, #707, #715, and #716 established the repository convention
for config and audit records. Issue #835 found the remaining gap across six
published library crates. Its named examples are illustrative: an AST inventory
at `b708b96b5d3095f06b34b61a8ac065687cd1f016` found 57 public structs with at
least one externally public field, 30 already non-exhaustive and 27 still
exhaustive.

## Decision

Every public struct in a published library crate that exposes at least one
public data field is `#[non_exhaustive]`. The rule includes configuration,
input, output, captured-test data, and structured error records. It excludes
opaque structs whose fields are private or restricted and the unpublished
`rimap-server` tool-record surface.

Retrofits use the existing construction path first. A new constructor is added
only when a current cross-crate caller has neither a suitable constructor nor a
meaningful `Default`; it takes exactly the fields without meaningful defaults.
Downstream mutation after construction and destructuring with `..` remain
supported. Each retrofitted type carries a downstream compile-fail contract,
with representative integration coverage checking rustc E0639 specifically.

## Consequences

- Existing downstream struct expressions and exhaustive destructures break at
  compile time and must move to constructors or `Default` plus assignment, and
  to rest patterns respectively.
- Future field additions to covered structs are source-compatible for
  downstream consumers.
- Types produced only inside their defining crate may intentionally become
  externally non-constructible; no speculative constructor is added.
- The attribute does not change serde output, MCP schemas, runtime behavior, or
  network behavior.
- Feature-gated published APIs, including `rimap-smtp/test-support`, follow the
  same rule.
- New published public-field record structs are born non-exhaustive rather than
  retrofitted later.

## Considered & rejected

- **Limit the sweep to the examples named in issue #835.** verified:
  `ast-grep run -p 'pub struct $S { $$$FIELDS }' -l rust --json=compact` over
  the six published crate `src` trees at
  `b708b96b5d3095f06b34b61a8ac065687cd1f016`, followed by checking externally
  public fields and preceding attributes, found 27 missing records, including
  `AppendResult`, `ConnectionConfig`, and `FilterResult` outside the issue's
  explicit examples. An example-only sweep would leave the stated “every”
  criterion false.
- **Mark every public struct mechanically.** judgment: this would change opaque
  clients, state holders, and private-field error wrappers whose fields do not
  expose a data-record construction contract; the public-field boundary is
  narrower and directly tied to the failure being prevented.
- **Add `Default` or builders to every covered type.** verified: completed
  issues #665 and #706 established that `#[non_exhaustive]` rejects
  functional-update syntax too, and that constructors are added only for
  actual callers. Blanket defaults would invent invalid values for required
  fields, while blanket builders would add API with no consumer.
- **Wait until after v0.2.0.** verified: `crates/rimap-audit/tests/non_exhaustive_e0639.rs`
  compiles downstream probes and observes rustc E0639 for the attribute itself;
  applying the policy after the current unreleased major transition would
  consume another breaking release.
- **Include unpublished `rimap-server` tool records.** judgment: the operator
  explicitly excluded that separate internal/schema surface; compiler-forced
  server callsites remain in scope, but schema-facing tool records do not.
