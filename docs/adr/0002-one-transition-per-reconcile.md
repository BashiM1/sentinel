# ADR-002 — One phase transition per Reconcile call

**Status:** Accepted, 2026-05-22.

## Context

In an early Prompt-2 design sketch the state machine could have collapsed
trivially-determined phases into one Reconcile pass — e.g., once a
human's approval is observed, jump straight from `AwaitingApproval`
through `Approved` into `Remediating`, since the latter is mechanically
determined by the former.

Compressing transitions is tempting: fewer reconciles, faster end-to-end,
less code.

The audit chain (`pkg/audit/`) writes one HMAC-linked entry per
reconcile. If two transitions land in one pass, the chain either:

1. Collapses them into a single entry — losing one transition's
   evidence.
2. Forces the audit layer to inspect controller-internal state to
   split them post-hoc — coupling two layers that should stay
   independent.

## Decision

`internal/controller/governancescan_controller.go`'s `advance()` switch
performs **exactly one phase transition per Reconcile invocation**,
always — even when the next phase is trivially derivable. The reconcile
returns `ctrl.Result{Requeue: true}` (or `RequeueAfter`) so the next
step happens in its own pass.

Auto-approve (`spec.approval.required=false`) collapses
`FindingsDetected → Approved` into one transition — that *is* still
one transition, with `system:auto` recorded as the principal.

## Consequences

**Positive.** The audit chain's entry boundary equals the reconcile
boundary — the natural seam for tamper-evident per-transition records.
Tests can assert one transition per `drive()` call. Each transition is
independently retriable.

**Negative.** A full happy-path lifecycle is 7 reconciles. Marginally
more apiserver round-trips than a collapsed implementation. The cost is
real in extreme-throughput scenarios; for the governance-workflow use
case it is irrelevant.

**Locked in by tests.** The happy-path test in
`internal/controller/governancescan_controller_test.go` explicitly
asserts that `Approved → Remediating` and `Remediating → Completed`
are reached via separate `drive()` calls.

## Related

- [ADR-0001 — Single CRD governs the whole lifecycle](0001-single-crd.md)
- `docs/battle-scars.md` scar 07 — the original capture of this rule
- `feedback_one_transition_per_reconcile.md` (project memory) — carries
  this rule across sessions
