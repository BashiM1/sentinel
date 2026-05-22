# Sentinel

Kubernetes operator for AI workload governance. Scans inference endpoints, gates remediation behind human approval, and writes HMAC-chained tamper-evident audit logs.

For what this system is and is not, read [`SCOPE.md`](./SCOPE.md) first.
For hard-won lessons from the build, see [`docs/battle-scars.md`](./docs/battle-scars.md).
For end-to-end verification of the M0 install, see [`docs/m0-closure.md`](./docs/m0-closure.md).

## Architecture

One CRD (`GovernanceScan`) carries the full lifecycle in its `spec` and `status`. One controller. One reconciler. No web server, no webhook. See [`docs/architecture.mermaid`](./docs/architecture.mermaid) for the component-level flow.

| Component | Role |
|---|---|
| `cmd/main.go` | Operator entrypoint. Wires the audit backend (`SENTINEL_AUDIT_PATH`, `SENTINEL_AUDIT_KEY`) and starts the controller-runtime manager. |
| `internal/controller/governancescan_controller.go` | Reconciler. State machine `advance()` performs exactly one phase transition per Reconcile call (see [ADR-0002](./docs/adr/0002-one-transition-per-reconcile.md)). |
| `internal/detector/garak/` | `BuildGarakJob` constructs the scanner Job; `ParseGarakOutput` parses `report.jsonl` into Findings with OWASP-LLM-Top-10 mapping. Two free functions, no Detector interface ([ADR-0003](./docs/adr/0003-concrete-before-abstract.md)). |
| `internal/remediation/annotate/` | `Apply` annotates the target Deployment and, on critical findings, scales it to zero. Idempotent. |
| `pkg/audit/` | Zero-Kubernetes-dependency audit subsystem. HMAC-SHA256 chain, local-filesystem `Backend`. Importable by any Go program. |
| `cmd/sentinelctl/` | Offline CLI. One subcommand: `verify`. Exit `0` intact, `1` broken, `2` usage. |
| `helm/sentinel/` | Chart bundling the CRD, the controller Deployment with audit env wiring and an emptyDir audit volume, the controller's manager RBAC, and the five SoD ClusterRoles. |

## Lifecycle

```
""  ──►  Pending  ──►  Scanning  ──►  FindingsDetected  ──►  AwaitingApproval
                                                                    │
                                                                (approved)
                                                                    ▼
            Completed  ◄──  Remediating  ◄──  Approved  ◄───────────┤
            ▲                                                       │
            └──── (rejected; remediation skipped) ───────────────────┘

            Failed  ◄──  (any phase: Job failure, missing target, parse error)
```

The full approval-required happy path is seven Reconcile passes and seven audit entries:

1. **`""` → `Pending`.** Controller observed the CR. Audit event `ScanRegistered`.
2. **`Pending` → `Scanning`.** Owned Job created with the Garak image. Owner reference + label `sentinel.io/governancescan=<name>` for restart resilience. Audit event `ScanStarted`.
3. **`Scanning` → `FindingsDetected`.** Job complete; logs parsed; severity counts in the audit `Detail`. Audit event `FindingsDetected`.
4. **`FindingsDetected` → `AwaitingApproval`.** Reconciler returns `ctrl.Result{RequeueAfter: 30s}` as a safety net on top of the watch. Audit event `ApprovalRequested`.
5. **`AwaitingApproval` → `Approved`.** Triggered by an external `kubectl patch ... --subresource status -p '{"status":{"approval":{"decision":"approved","approver":"..."}}}'`. Audit event `ApprovalDecision` with the approver as principal.
6. **`Approved` → `Remediating`.** Audit event `RemediationStarted` with the planned action.
7. **`Remediating` → `Completed`.** `annotate.Apply` runs during this transition. Critical findings cause `Spec.Replicas = 0` + quarantine annotations. Audit event `RemediationCompleted`.

Rejection (`AwaitingApproval` → `Completed` with `Approved=False`) is **not** a failure — it's a legitimate human decision. The audit chain records it; remediation is skipped.

## Separation of Duties

The Helm chart installs five unbound ClusterRoles. Cluster admins bind them to the appropriate users, teams, or ServiceAccounts ([`config/rbac/`](./config/rbac/)).

| Role                    | Verbs on `GovernanceScan` | Other verbs                                        |
|-------------------------|---------------------------|----------------------------------------------------|
| `sentinel-scanner`      | `get,list,watch` + `status/patch,update` | `batch/jobs: create,get,list,watch,delete`         |
| `sentinel-approver`     | `get,list,watch` + `status/patch` only   | none — `patch` not `update` prevents overwriting prior status |
| `sentinel-executor`     | `get,list,watch` + `status/patch,update` | `apps/deployments: get,patch,update` + `deployments/scale: patch,update` |
| `sentinel-policy-admin` | `create,update,patch,delete,get,list,watch` | none — full CRUD on policy, nothing on status / Jobs / workloads |
| `sentinel-auditor`      | `get,list,watch` (read-only)             | `batch/jobs: get,list,watch`                       |

## Security Properties

- **HMAC-SHA256-chained audit trail** ([`pkg/audit/audit.go:ComputeHash`](./pkg/audit/audit.go)). Every state transition is an entry; each hashes the previous entry's hash with a key held only by the controller. `VerifyChain` reports the first broken index on tampering or deletion (`pkg/audit/local_test.go` covers tampered, deleted, and out-of-order cases). Known design limit: fields are concatenated without delimiters — bounded by the secret key but flagged as `SECURITY:` in code.
- **Verb-level RBAC for approvals.** The `sentinel-approver` role can `patch` `status` but not `update`, so an approver cannot overwrite prior status fields (findings, audit references, condition history). See [`config/rbac/approver_clusterrole.yaml`](./config/rbac/approver_clusterrole.yaml).
- **Restart-resilient discovery.** Owned Jobs are found via owner-UID-verified label lookup (`sentinel.io/governancescan=<name>`) in `internal/controller/job.go:findOwnedJob`. A controller restart re-attaches to in-flight Jobs without in-memory state.
- **Finalizer-gated deletion.** `sentinel.io/governancescan` runs `Background`-propagation Job deletion before removing itself, so the audit chain entry for the scan's deletion always precedes the parent CR's actual removal.
- **One transition per Reconcile.** The audit-chain entry boundary equals the reconcile boundary. Two transitions cannot collapse into a single chain entry. Locked in by tests asserting separate `drive()` calls for `Approved → Remediating` and `Remediating → Completed` ([ADR-0002](./docs/adr/0002-one-transition-per-reconcile.md)).
- **Distroless controller image.** `Dockerfile` final stage is `gcr.io/distroless/static:nonroot`. Deployment runs with `runAsNonRoot`, dropped capabilities, read-only root filesystem.
- **No long-lived credentials.** The chart wires `SENTINEL_AUDIT_KEY` from a Helm value for local kind testing only; production uses a mounted Kubernetes Secret, flagged with `TODO(security)` in [`cmd/main.go`](./cmd/main.go) and [`internal/controller/governancescan_controller.go`'s `checkApproval`](./internal/controller/governancescan_controller.go).

## Quick Start

Tested against kind 1.35 and helm 3.x. The Garak scanner image is currently a placeholder; the operator will install and reconcile correctly, but the scan Job itself will fail with `ImagePullBackOff` until the M1 image swap lands.

```bash
# Build the controller image and load it into kind.
docker build -t sentinel-controller:latest .
kind load docker-image sentinel-controller:latest --name <your-cluster>

# Install via Helm.
helm install sentinel ./helm/sentinel -n sentinel-system --create-namespace
kubectl wait --for=condition=Available --timeout=120s \
  deployment/sentinel-controller -n sentinel-system

# Apply a sample GovernanceScan.
kubectl apply -f config/samples/sentinel_v1alpha1_governancescan.yaml
kubectl get governancescans

# Approve or reject (binary, kubectl-only).
./hack/approve.sh example-scan
./hack/reject.sh  example-scan
```

A full reference run of these steps, including the controller log output and what `ImagePullBackOff` looks like in M0, is in [`docs/m0-closure.md`](./docs/m0-closure.md).

## Verifying an audit chain offline

```bash
go run ./cmd/sentinelctl verify \
  --path /tmp/sentinel-audit \
  --scan example-scan \
  --namespace default \
  --key sentinel-dev-key

# → Chain integrity: OK (7 entries, 0 breaks)
```

`sentinelctl` has zero Kubernetes dependencies. Copy a chain out of the cluster (`kubectl cp` or `kubectl debug` against the controller pod's `/tmp/sentinel-audit` emptyDir), hand it to an auditor with the key, run `verify`. The auditor never needs cluster access.

## Tests

```bash
make test                          # unit + envtest, excludes /e2e
go test ./pkg/audit/...            # audit subsystem, no envtest
go test ./cmd/sentinelctl/...      # CLI
go test ./test/e2e/...             # audit-lifecycle e2e via envtest
```

The Makefile's `make test` excludes `test/e2e/` by path; the audit-lifecycle e2e test lives there without the `e2e` build tag and runs via `go test ./test/e2e/...`. The other files in that directory (`e2e_suite_test.go`, `e2e_test.go`) carry `//go:build e2e` because they require a live kind cluster + cert-manager.

There is no automated integration suite beyond envtest. End-to-end validation against a real cluster is in [`docs/m0-closure.md`](./docs/m0-closure.md).

## Documentation

- [`SCOPE.md`](./SCOPE.md) — what this system is and is not. Read first.
- [`docs/architecture.mermaid`](./docs/architecture.mermaid) — component diagram.
- [`docs/m0-closure.md`](./docs/m0-closure.md) — end-to-end verification log from the first kind install.
- [`docs/battle-scars.md`](./docs/battle-scars.md) — hard-won lessons with raw evidence in [`docs/battle-scars/evidence/`](./docs/battle-scars/evidence/).
- [`CHANGELOG.md`](./CHANGELOG.md) — release notes.
- [`helm/sentinel/values.yaml`](./helm/sentinel/values.yaml) — chart configuration reference.

### Architecture Decision Records

- [`0001-single-crd.md`](./docs/adr/0001-single-crd.md) — why one CRD carries the whole lifecycle instead of separate `ScanPolicy`/`ApprovalRequest`/`AuditRecord` resources.
- [`0002-one-transition-per-reconcile.md`](./docs/adr/0002-one-transition-per-reconcile.md) — why phase transitions never bundle, even when the next phase is trivially determined.
- [`0003-concrete-before-abstract.md`](./docs/adr/0003-concrete-before-abstract.md) — why there is no `Detector` interface in M0.

## Repository Layout

```
sentinel/
  api/v1alpha1/             CRD type definitions
  cmd/                      Operator entrypoint
  cmd/sentinelctl/          Audit-chain verify CLI
  internal/
    controller/             Reconciliation loop
    detector/garak/         Garak Job creation and output parsing
    remediation/annotate/   Remediation handlers
  pkg/
    audit/                  Standalone audit trail (HMAC chain + backends)
  helm/sentinel/            Helm chart
  hack/                     hack/approve.sh, hack/reject.sh
  docs/                     ADRs, battle scars, closure records, architecture diagram
  config/                   Kubebuilder manifests, RBAC, samples
  test/e2e/                 audit_lifecycle_test.go (envtest, no build tag)
```

## Related Projects

- **[`cost-gate`](https://github.com/BashiM1/cost-gate)** — GCP sibling. FastAPI on Cloud Run that ingests Terraform plans and emits `CostGateThresholdExceeded` events.
- **[`finops-agentic-remediation`](https://github.com/BashiM1/finops-agentic-remediation)** — AWS sibling. Pulumi + Lambda + Bedrock + Slack + S3 Object Lock implementation of the same detect → assess → approve → execute → audit pattern.

The three repos share **no code**. They share the architectural pattern and the author. Sentinel brings the pattern into Kubernetes; the cloud-layer siblings implement it against GCP and AWS respectively. There is no runtime cross-call between Sentinel and the cloud-layer siblings.

## Status

**M0 (Foundation): closed 2026-05-22.** All M0 deliverables landed; end-to-end install verified on local kind. See [`docs/m0-closure.md`](./docs/m0-closure.md).

**M1 (Garak runtime verification): in progress.** The placeholder `ghcr.io/nvidia/garak:latest` image returns 403 on pull. M1 either builds `deploy/garak/Dockerfile` on `python:3.11-slim + pip install garak` or sources a working community image. Then each `TODO(verify)` in `internal/detector/garak/job.go` (CLI flags, `rest.json` schema) and `parser.go` (report field names) is reconciled against actual Garak output. The operator works end-to-end; only the scanner image is unverified.

This is a **reference implementation**. The control families are designed to map to audit expectations — alignment is by design intent, not by audit certification. See [`SCOPE.md`](./SCOPE.md) for what would be required to promote a deployment to production.

## License

Apache License 2.0. See the headers on every source file and the LICENSE section below.

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
