# ADR-001 — Single CRD governs the whole lifecycle

**Status:** Accepted, 2026-05-21.

## Context

The natural Kubernetes idiom for a multi-step workflow is multiple CRDs:
a `ScanPolicy` to declare intent, a `ScanResult` to hold findings, an
`ApprovalRequest` to gate execution, an `AuditRecord` to track decisions.
Each CRD has its own controller, its own RBAC, its own lifecycle. The
pattern composes well in theory.

In practice, for a single-team M0 implementation, it fragments. Each
CRD adds RBAC surface area, status-update fan-out, and a join key that
the controllers have to keep consistent. The Separation of Duties roles
we *do* care about (scanner, approver, executor, policy-admin, auditor)
are not the same dimensions as the workflow steps.

## Decision

Sentinel uses one CRD — `GovernanceScan` — that carries the full
lifecycle in its `spec` and `status`. The state machine
(`Pending → Scanning → FindingsDetected → AwaitingApproval → Approved →
Remediating → Completed`, with `Failed` as a terminal) lives in
`status.phase`. Findings, the approval decision, and the audit-chain
head all live on the same resource.

Separation of Duties is enforced at the **RBAC verb** layer
(`status/patch` for the approver, `deployments/scale` for the executor)
rather than by resource shape. See `config/rbac/*_clusterrole.yaml`.

## Consequences

**Positive.** One reconciler. One watch. One `kubectl get` for the
whole scan picture. Audit-chain entries (ADR-002) align with a single
resource's lifecycle. RBAC review is concentrated.

**Negative.** Approvers patching `status.approval` need verb-level
restriction (`patch` only, not `update`) to prevent overwriting prior
status fields — handled in `config/rbac/approver_clusterrole.yaml`.
Some readers expect a separate `ApprovalRequest` and may search for
one before finding the truth on the scan's status.

**Reversal cost.** Splitting later is moderate work: introduce the new
CRD, dual-write status during a migration window, deprecate the old
field. Not free, but not painful enough to block this decision.

## Related

- [ADR-0002 — One transition per Reconcile](0002-one-transition-per-reconcile.md)
- CLAUDE.md "Architecture rules — do not violate", rule #1
