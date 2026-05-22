# Scope

What Sentinel is and is not. Read before contributing or evaluating.

## What it is

A Kubernetes operator that manages a governance lifecycle for AI inference
workloads. One CRD (`GovernanceScan`) carries the full state machine in
its `spec` and `status`. The operator:

1. Watches `GovernanceScan` resources and scans the registered inference
   endpoint with Garak.
2. Records findings (OWASP LLM Top 10 mapping; severity from per-probe
   attacker success rate).
3. Blocks remediation behind a binary `kubectl patch`-driven human
   approval — no web UI, no webhook in M0.
4. On approval, annotates the target Deployment with scan metadata and,
   for critical findings, scales it to zero.
5. Writes every state transition into an HMAC-SHA256-chained, tamper-
   evident audit log on the local filesystem.

This is a **reference implementation**. The Kubernetes layer of a three-
project pattern; the cloud-layer siblings are
[`cost-gate`](https://github.com/BashiM1/cost-gate) (GCP) and
[`finops-agentic-remediation`](https://github.com/BashiM1/finops-agentic-remediation)
(AWS).

## What it is not

- **Not a scanner.** Garak does the scanning. Sentinel orchestrates,
  approves, audits.
- **Not a multi-cluster operator.** M0 runs one controller against one
  cluster. Multi-cluster federation is Phase 2.
- **Not a web product.** The approval surface is `kubectl patch`
  exclusively. A Slack DecisionSurface adapter is shelved for Phase 2.
- **Not a policy engine.** Approval is **binary** (approve-all /
  reject-all). Per-finding granularity is shelved for Phase 2.
- **Not a remediation framework.** Two remediation actions only —
  annotate the workload and (for critical findings) scale to zero.
  No autonomous sophistication, no DAG engine, no embedded scripting.
- **Not production-certified.** Control families align with audit
  expectations by design intent, not by audit certification. See the
  TODO(security) markers in `cmd/main.go` and
  `internal/controller/governancescan_controller.go` for the work
  required to promote a deployment.

## What's complete (M0, closed 2026-05-22)

- GovernanceScan CRD with the eight-phase state machine.
- Reconciler with Kubernetes-Job-based scanning lifecycle, owner-ref
  cleanup, finalizer, restart resilience.
- `kubectl`-driven binary approval gate. `hack/approve.sh`,
  `hack/reject.sh`.
- Annotate + scale-to-zero remediation handler.
- HMAC-chained audit trail (`pkg/audit/`) with local filesystem backend.
- `sentinelctl verify` offline chain-integrity CLI.
- Five Separation-of-Duties ClusterRoles.
- Helm chart bundling everything.
- envtest and unit tests across all components; one e2e test driving
  the full lifecycle via envtest.

## What's not complete

- **Garak runtime verified against a real cluster** (M1, in progress).
  The Garak image, CLI flags, and `report.jsonl` schema are best-guess
  values gated behind `TODO(verify)` markers in
  `internal/detector/garak/`. The end-to-end install on kind succeeds,
  but the scan Job currently fails with `ImagePullBackOff` until M1
  ships a working image.
- HMAC key delivery via Kubernetes Secret rather than env var.
- Admission webhook validating the approver identity against the
  apiserver's user-info (the M0 implementation trusts the self-reported
  `status.approval.approver` string).
- GCS / S3 Object Lock audit backends.
- Metrics endpoint with cert-manager-provisioned TLS.

## Boundary with companion projects

- `cost-gate` and `finops-agentic-remediation` implement the same
  detect → assess → approve → execute → audit pattern at the cloud
  layer (GCP and AWS respectively). Sentinel brings the pattern into
  Kubernetes.
- The three projects share **no code**. They share an architectural
  pattern, a Slack workspace (in the finops sibling), and the same
  author. There is no runtime cross-call between Sentinel and the
  cloud-layer siblings.
