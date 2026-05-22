# Sentinel

Kubernetes operator for governing AI inference workloads.

Sentinel scans inference endpoints, gates remediation behind human approval, and records every state transition in an HMAC-chained audit log.

Read [`SCOPE.md`](SCOPE.md) first. For hard-won lessons from the build, see [`docs/battle-scars.md`](docs/battle-scars.md).

## Lifecycle

A single CRD (`GovernanceScan`) carries the full governance lifecycle:

```
Pending → Scanning → FindingsDetected → AwaitingApproval
                                            ├─ approved → Approved → Remediating → Completed
                                            └─ rejected ─────────────────────────→ Completed
```

The operator:

- launches a Kubernetes Job running Garak against a target inference endpoint
- parses findings into OWASP LLM Top 10 categories
- pauses for a human approval decision
- annotates or quarantines the workload
- appends every transition to a tamper-evident audit chain

No web UI. No embedded policy DSL. No hidden automation.

## Architecture

| Component | Responsibility |
| --- | --- |
| `GovernanceScan` CRD (`api/v1alpha1/`) | Desired state + lifecycle status |
| Reconciler (`internal/controller/`) | One transition per reconcile loop ([ADR-0002](docs/adr/0002-one-transition-per-reconcile.md)) |
| Garak detector (`internal/detector/garak/`) | Job construction + finding parse |
| Remediation (`internal/remediation/annotate/`) | Annotation + scale-to-zero |
| Audit chain (`pkg/audit/`) | HMAC-SHA256 chain, zero K8s dependencies |
| `sentinelctl verify` (`cmd/sentinelctl/`) | Offline chain integrity check |
| Helm chart (`helm/sentinel/`) | CRD, controller, SoD RBAC, audit wiring |

One controller. One reconciler. One audit chain.

## Quick start

Tested on kind 1.35, Helm 3.x. The scan Job will `ImagePullBackOff` until M1 ships a verified Garak image.

```bash
# Build and load
docker build -t sentinel-controller:latest .
kind load docker-image sentinel-controller:latest --name <your-cluster>

# Install
helm install sentinel ./helm/sentinel \
  -n sentinel-system --create-namespace

# Apply a scan
kubectl apply -f config/samples/sentinel_v1alpha1_governancescan.yaml

# Approve or reject
./hack/approve.sh example-scan
./hack/reject.sh  example-scan

# Verify audit chain offline
go run ./cmd/sentinelctl verify \
  --path /tmp/sentinel-audit \
  --scan example-scan \
  --namespace default \
  --key sentinel-dev-key
```

## Status

**M0 complete (2026-05-22).** CRD, reconciler, approval gate, remediation handler, HMAC audit chain, offline verifier, SoD RBAC, Helm chart, envtest + e2e. Full closure record in [`docs/m0-closure.md`](docs/m0-closure.md).

**M1 (in progress).** Verify Garak against a real runtime. The operator works end-to-end; only the scanner image is unverified.

## Design constraints

Sentinel is intentionally narrow.

It is a Kubernetes operator, a governance lifecycle, and a reference implementation.

It is not a scanner, a web platform, a multi-cluster control plane, or a general remediation framework.

See [`SCOPE.md`](SCOPE.md) for boundaries and non-goals.

## Documentation

- [`SCOPE.md`](SCOPE.md) — what this system is and is not
- [`docs/battle-scars.md`](docs/battle-scars.md) — hard-won lessons with evidence
- [`docs/m0-closure.md`](docs/m0-closure.md) — end-to-end verification record
- [`docs/architecture.mermaid`](docs/architecture.mermaid) — component diagram
- ADRs: [single CRD](docs/adr/0001-single-crd.md), [one transition per reconcile](docs/adr/0002-one-transition-per-reconcile.md), [concrete before abstract](docs/adr/0003-concrete-before-abstract.md)

## Related projects

- [`cost-gate`](https://github.com/BashiM1/cost-gate) — GCP governance sibling
- [`finops-agentic-remediation`](https://github.com/BashiM1/finops-agentic-remediation) — AWS governance sibling

The projects share a pattern, not code.

## License

Apache License 2.0. See [LICENSE](LICENSE).