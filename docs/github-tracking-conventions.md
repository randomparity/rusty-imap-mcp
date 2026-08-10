# GitHub tracking conventions

This file records the label taxonomy and workflow conventions used by automated
tooling (`/campaign`, `/recover-orphans`, `/work-issue`, `/ship-pr`) in this
repository. Agents and humans must follow these conventions consistently so the
tooling can make correct inferences about issue state.

## `status:` labels are for active work only

The `status:` label set tracks *in-flight* work:

| label | meaning |
|---|---|
| `status:needs-triage` | Filed, not yet reviewed |
| `status:ready` | Triaged, prioritised, waiting to be picked up |
| `status:in-progress` | Actively being implemented |
| `status:in-review` | PR open, under review |
| `status:awaiting-merge` | PR approved and green, waiting for merge |
| `status:blocked` | Blocked on an external dependency or decision |
| `status:needs-human` | Pipeline cannot proceed without operator input |

There is no `status:done` label. **Absence of a `status:` label on a closed
issue is the terminal state.**

## Strip `status:*` on close — absence means done

**Convention (option 2):** when an issue is closed (merged, resolved, or
won't-fix), remove **all** `status:*` labels from it. A closed issue with no
`status:` label is unambiguously finished.

Rationale:
- A lingering `status:blocked` on a closed-and-merged issue is actively
  misleading — any query for blocked work will surface it as a false positive.
- A lingering `status:awaiting-merge` is noise; the issue is closed, it merged.
- Absence is a clean terminal signal. No backfill, no extra label, no ambiguity.

**Workflow for closers (human or agent):**

1. Merge or close the issue.
2. Remove all `status:*` labels: `gh issue edit <N> --remove-label "status:<x>"`.

Example one-liner (from the worktree root, with `$N` set to the issue number):

```bash
gh issue edit "$N" --remove-label "status:awaiting-merge"
# or for multiple labels:
for label in status:awaiting-merge status:in-review status:in-progress; do
  gh issue edit "$N" --remove-label "$label" 2>/dev/null || true
done
```

## Closed-state is authoritative

`status:` labels are meaningless once an issue is closed. **Tooling must treat
closed issues as already done regardless of any lingering `status:` label.**

Specifically:
- `/recover-orphans`: skip closed issues entirely when scanning for stale
  in-flight labels; do not re-adopt a closed issue because it carries
  `status:in-progress`.
- `/campaign`: a closed issue is done — do not re-queue it.
- Any query for "stuck" or "blocked" work must filter on `--state open`.

## Background

This convention was chosen in issue #774 after surveying 60 closed issues and
finding ~50 % carried lingering labels spanning four different `status:` values
(`awaiting-merge`, `in-review`, `ready`, `needs-triage`). The inconsistency
made it impossible to infer intent from the label alone, and a false
`status:blocked` on a merged issue (#716) was the concrete harm. Option 2
("strip on close") was selected as the cleanest fit for automated tooling and
the least ambiguous signal.
