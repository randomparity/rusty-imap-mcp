# ADR-0026: Published data records are non-exhaustive

**Status:** Accepted · 2026-08-24 · issue [#835](https://github.com/randomparity/rusty-imap-mcp/issues/835)

## Context

Public Rust named-field structs with public fields permit downstream struct
literals and exhaustive destructuring. Adding a field is therefore a
source-breaking change
unless the struct is marked `#[non_exhaustive]`. v0.2.0 is already released,
and the workspace is on the unreleased 0.3.0-dev pre-1.0 breaking-version
transition. Applying the attribute before v0.3.0 consumes no additional
breaking release; after that release it would require the next minor line.

Issues #665, #706, #707, #715, and #716 established the repository convention
for config and audit records. Issue #835 found the remaining gap across six
published library crates. Its named examples are illustrative. Two AST
inventories at `b708b96b5d3095f06b34b61a8ac065687cd1f016` found 58 public
named-field structs with at least one externally public field: 57 non-generic
candidates and generic `CircuitBreaker<C>`. The latter is a state holder whose
public clock is a test seam, not a data record. The remaining 57 qualifying
records divide into 30 already non-exhaustive and 27 still exhaustive.

## Decision

Every public named-field record struct in the six issue #835 library crates
that exposes at least one public data field is `#[non_exhaustive]`. The rule
includes configuration, input, output, captured-test data, and structured
error records. It excludes tuple newtypes and tuple error wrappers, whose
single positional field is the type's identity rather than an extensible
record contract; opaque structs whose fields are private or restricted; and,
by explicit operator decision, the separate public tool-record surface in the
published `rimap-server` crate.

Retrofits use the existing construction path first. A new constructor is added
only when a current cross-crate caller has neither a suitable constructor nor a
meaningful `Default`; it takes exactly the fields without meaningful defaults.
Downstream mutation after construction and destructuring with `..` remain
supported. Focused downstream compile-fail contracts cover the relevant
literal and functional-update forms, with representative integration coverage
checking rustc E0639 specifically.

## Consequences

- Existing downstream struct expressions and exhaustive destructures break at
  compile time and must move to constructors or `Default` plus assignment, and
  to rest patterns respectively.
- An otherwise-compatible public field addition no longer breaks downstream
  code solely because struct literals or exhaustive destructures omit it.
  Auto-trait, derive, serde, schema, and runtime compatibility remain separate
  review obligations.
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
  brace-form AST queries for non-generic and generic public structs over the
  six published crate `src` trees at
  `b708b96b5d3095f06b34b61a8ac065687cd1f016`, followed by checking externally
  public fields, preceding attributes, and the data-record boundary, found 27
  missing records. They include `AppendResult`, `ConnectionConfig`, and
  `FilterResult` outside the issue's explicit examples. The only other raw
  public-field candidate is generic `CircuitBreaker<C>`, classified as a state
  holder because its public clock is a test seam. An example-only sweep would
  leave the stated “every record” criterion false.
- **Mark every public struct mechanically.** judgment: this would change opaque
  clients, state holders, and private-field error wrappers whose fields do not
  expose a data-record construction contract; the public-field boundary is
  narrower and directly tied to the failure being prevented.
- **Include public tuple newtypes and tuple error wrappers.** judgment:
  `Host(pub String)`, `Username(pub String)`, `ParseErrorCodeError(pub String)`,
  and `UnknownPosture(pub String)` expose one positional value as the type's
  identity. Adding another position would change that identity rather than
  extend a named data record; making their constructors inaccessible would
  impose migration cost without protecting the field-addition contract this
  decision governs.
- **Add `Default` or builders to every covered type.** verified: completed
  issues #665 and #706 established that `#[non_exhaustive]` rejects
  functional-update syntax too, and that constructors are added only for
  actual callers. Blanket defaults would invent invalid values for required
  fields, while blanket builders would add API with no consumer.
- **Leave the remaining records exhaustive permanently.** judgment: this would
  avoid certain downstream migration in 0.3.0 but preserve the exact
  field-addition break that the frozen issue outcome requires this sweep to
  remove; partial adoption would also leave the published API policy
  inconsistent across equivalent records.
- **Wait until after v0.3.0.** verified:
  `crates/rimap-audit/tests/non_exhaustive_e0639.rs` compiles downstream probes
  and observes rustc E0639 for the attribute itself; applying the policy after
  the current unreleased breaking-version transition would consume the next
  minor line.
- **Include published `rimap-server` tool records.** judgment: the operator
  explicitly excluded that separate internal/schema surface; compiler-forced
  server callsites remain in scope, but schema-facing tool records do not.
