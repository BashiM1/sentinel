# ADR-003 — Concrete before abstract: no Detector interface in M0

**Status:** Accepted, 2026-05-21.

## Context

Sentinel scans inference endpoints. The scanner is Garak today;
the README mentions GPU-waste detection and other future detectors.
The natural Go idiom is to define a `Detector` interface upfront and
hide each scanner behind it:

```go
type Detector interface {
    BuildJob(scan *GovernanceScan) *batchv1.Job
    ParseOutput(raw []byte) ([]Finding, error)
}
```

Interfaces are easy. The trap is what they obscure: the cost of an
interface is the *next* implementation, not the first. The second
detector forces you to discover where the abstraction leaks (Garak
emits JSONL with a specific schema; a different detector probably
emits something else; the "Detector" interface ends up either too
narrow or too generic).

The first detector also acts as the reference shape. Trying to design
an interface against zero implementations produces an interface that
serves no implementation.

## Decision

`internal/detector/garak/` exposes two free functions — `BuildGarakJob`
and `ParseGarakOutput` — called directly from the reconciler. No
`Detector` interface. No registry. No plugin system.

When a second detector lands, *that* is when the interface gets
extracted: design it against two concrete implementations, fit the
abstraction to what is actually shared.

Same rule applies to `internal/remediation/annotate/` — one function,
`Apply`, called directly. No `Remediator` interface.

## Consequences

**Positive.** Zero abstraction overhead in M0. The Garak code reads
top to bottom; following a call from the reconciler is one jump.
Refactoring later is a renamed-receiver job, not a redesign.

**Negative.** When the second scanner does arrive, there is a
mechanical extraction step. That step is bounded — a few hours, not
days — and benefits from having the first implementation as the
reference.

**Audit trail.** This rule is enforced project-wide in CLAUDE.md
("CONCRETE before abstract") and the project memory. Code reviewers
should reject interface introductions that have no second
implementation in flight.

## Related

- CLAUDE.md "Architecture rules — do not violate", rule #2
- `pkg/audit/` is the one place we *did* define an interface upfront
  (`Backend`), because three backends — local, GCS, S3 — are already
  on the roadmap. ADR-0004 (forthcoming if/when GCS lands) will
  document that choice.
