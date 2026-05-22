# Sentinel — Project Context for Claude Code

## What this is

A Kubernetes operator built with Kubebuilder (Go) that manages a governance
lifecycle for AI workloads. One CRD (GovernanceScan). The operator scans
explicitly registered inference endpoints, gates remediation behind human
approval, and writes a tamper-evident audit trail.

This is a reference implementation of a governance lifecycle pattern, not a
product. The same detect-assess-approve-execute-audit pattern is implemented
at the cloud layer in two companion projects:

- cost-gate (GCP, FastAPI, Cloud Run, OIDC federation)
- finops-agentic-remediation (AWS, Pulumi, Bedrock, S3 Object Lock)

Sentinel brings that pattern into Kubernetes.

## Who I am

First-time Go developer. First Kubernetes operator. I understand the
architecture deeply but I am learning Go and controller-runtime as I build.
Explain non-obvious Go patterns when you use them. Do not simplify the
architecture to accommodate my Go inexperience — write idiomatic,
production-quality Go and I will learn from it.

## Development environment

- OS: Ubuntu 24.04
- Go: 1.23.9
- Docker: installed and running
- Cluster: kind (local, name: sentinel-dev)
- Cloud: none. All development is local. I handle cloud deployment manually
  in a separate terminal. You never run gcloud, gsutil, or any cloud CLI.
- Editor: VS Code
- RAM: 16GB (12GB operational)
- Disk: tight — do not create unnecessary files or large test fixtures

## Battle scars

Hard-won lessons live in `docs/battle-scars.md` with raw evidence under
`docs/battle-scars/evidence/`. **Capture habit: evidence first, fix
second.** When a test fails confusingly or a tool surprises you, copy
the terminal output into a numbered evidence file *before* you start
editing code, then add the entry. The format is fixed (Date/What/Why/
Fix/Lesson/Evidence) — see existing entries.

## Current state

Milestone: M0 (Foundation) — **CLOSED 2026-05-22.** First end-to-end install on kind verified; see `docs/m0-closure.md`.

## On `continue` (session resume)

Read [project-resume-2026-05-22 memory](../../.claude-sentinel-home/.claude/projects/-home-bashm1-Development-Personal-sentinel/memory/project_resume_2026_05_22.md) first — it has the full resume protocol. Short version:

1. **Confirm git state** with `git log --oneline -5` and `git tag`. Report one sentence. The M0 commit may or may not have landed overnight; staging is still intact either way and that is *not* a blocker for the work below.
2. **Do the offline M1 prep autonomously** (no network, no irreversible action, no clarifying questions):
   - Create `deploy/garak/Dockerfile` — `python:3.11-slim` + `pip install garak` skeleton with a `TODO(network)` header explaining the sandbox PyPI block.
   - Create `deploy/garak/README.md` — operator-facing build / push / `kind load` / chart-override instructions.
   - Create `docs/m1-todo-verify-checklist.md` — every `TODO(verify)` from `internal/detector/garak/job.go` and `parser.go` as a checklist with the verification command.
   - Run `make test` only if any code under test was touched.
3. **Update this Current state block** to reflect M1 prep done and the next blocker (the user building/pushing the actual Garak image).
4. **Stop and report.** Do not attempt `docker build` of the Garak image, do not delete the kind cluster, do not touch `README.md` or git staging. Those are the user's calls.

End-of-day cluster state (kind `sentinel-dev`): `sentinel-system/sentinel-controller` Running; `default/example-scan` in `Phase=Scanning` with the scan Job in `ImagePullBackOff` (expected — that's the placeholder image M1 will fix).

Open M1 question (still active, escalating): the Garak image and CLI assumptions need manual verification — the code compiles and unit-tests pass against the assumed schema, but real-cluster behaviour is unverified. See "Things to verify" below.

### Things to verify before relying on the Garak Job
1. `internal/detector/garak/job.go` — `GarakImage` is `ghcr.io/nvidia/garak:latest` as a best-guess placeholder. NVIDIA may not publish an official image; you may need to build one (suggested: `deploy/garak/Dockerfile` on `python:3.11-slim` with `pip install garak`).
2. `internal/detector/garak/job.go` — `scanScript` uses `--model_type rest --generator_option_file ... --probes ... --report_prefix ...`. Confirm each flag against `garak --help` on the installed version. Older/newer Garak versions have used `--config`, `--probe_tags`, `--report_dir`.
3. `internal/detector/garak/job.go` — the inline `rest.json` schema (`uri`, `method`, `req_template_json_object`, `response_json_field`) is taken from circa-early-2026 Garak docs. Newer versions may rename fields.
4. `internal/detector/garak/parser.go` — `garakReportEntry` assumes fields `entry_type=eval`, `probe`, `passed`, `failed`. Run a real Garak report and confirm these field names.

### Completed
- 2026-05-21 Kubebuilder scaffold (`kubebuilder init` + `create api`) — domain sentinel.io, module github.com/BashiM1/sentinel.
- 2026-05-21 GovernanceScan v1alpha1 types defined (spec: Target/Scanner/Approval/Audit; status: Phase/Conditions/LastScanTime/Findings/FindingsCount/Approval/AuditRef). Phase enum constants exposed. `make manifests`, `make generate`, `make build` all green. Sample CR at `config/samples/sentinel_v1alpha1_governancescan.yaml`.
- 2026-05-21 Reconciler state machine implemented. Eight phases (Pending → Scanning → FindingsDetected → AwaitingApproval → Approved → Remediating → Completed; Failed on rejection). Exactly one phase transition per Reconcile call, with immediate requeue between transitions so each is independently auditable when pkg/audit/ lands in Prompt 7. Conditions: `Ready`, `ScanComplete`, `Approved`. Events emitted at every transition via EventRecorder. Findings were hardcoded in `internal/controller/findings.go` and pluggable via a `FindingsFn` field on the reconciler (replaced in Prompt 3 — see below). ApprovalConfig.Required is `*bool` to survive apiserver defaulting. envtest suite covered happy paths, rejection, idempotency, FindingsFn injection, and missing-CR.
- 2026-05-22 Real Kubernetes Job lifecycle. Pending now ensures an owned scan Job exists (busybox placeholder — the Garak image is Prompt 4) before transitioning to Scanning. Scanning polls Job status via owner-ref + label lookup, parses pod-log output as JSON, and advances to FindingsDetected on success or Failed on Job failure or output parse errors. Job naming `{scan}-scan-{8-char-rand}`, TTLSecondsAfterFinished=3600, BackoffLimit=2, RestartPolicy=Never, emptyDir at /output. Finalizer (`sentinel.io/governancescan`) added in its own reconcile pass; on delete it lists owned Jobs (via label, UID-verified) and deletes them with Background propagation before removing itself. Restart resilience comes from `Owns(&batchv1.Job{})` + UID-filtered List, with no in-memory state. Test injection point is now `ResultsReaderFn func(ctx, *batchv1.Job) ([]byte, error)`; default is `readJobLogs` against `Clientset`. envtest suite (12 specs) covers Job creation, dedupe, success/failure paths, output-read error, finalizer cleanup, restart resilience, full approval/auto-approve/rejection flows, idempotency, and missing-CR. 75.4% controller-package coverage (drop from 91.7% is the untestable-in-envtest `readJobLogs` path and a few fallback branches that need a real cluster).
- 2026-05-22 Garak integration. New package `internal/detector/garak/` with `BuildGarakJob(scan, extraLabels)` and `ParseGarakOutput(raw)` — two free functions, no Detector interface (per CLAUDE.md's CONCRETE-before-abstract rule). Reconciler now calls these directly; busybox `buildScanJob` and the old `parseFindings` are deleted. `LabelGovernanceScan` stays in the controller package and is passed into the builder via `extraLabels`, so future scanners don't need to import controller internals. Probe→OWASP mapping is substring/case-insensitive: promptinject/dan/jailbreak→LLM01, leakplay/snowball/xss→LLM02, encoding→LLM05, continuation→LLM06; everything else→`UNMAPPED` (sentinel category, not fabricated). Severity from attacker success rate: `>0.50` critical, `>0.25` high, `>0.10` medium, else low. Findings sorted by ID for deterministic output across reconciles. `parser_test.go` covers: normal multi-probe parse, empty input, malformed-JSON lines skipped silently, UNMAPPED for unknown probes, multi-line aggregation per probe, field population spot-check, probe→OWASP table, severity threshold boundaries. Image, CLI flags, and report schema are best-guess and gated behind `TODO(verify)` markers — see "Things to verify before relying on the Garak Job" above. controller-pkg coverage 75.3%, garak-pkg 82.4%.
- 2026-05-22 Approval gate + remediation. New package `internal/remediation/annotate/` with `Apply(ctx, c, scan)` (also no interface) and sentinel `ErrTargetNotFound`. Target Deployment lookup parses `Spec.Target.Service` as shortname / `name.ns` / FQDN, defaulting namespace to the scan's. Always-annotations: `last-scan-time` (RFC3339 UTC), `scan-result=Completed`, `approved-by`, `findings-count`. Critical findings additionally set `quarantined=true`, `quarantine-reason`, and scale `Spec.Replicas=0`. Apply is idempotent (re-running sets the same annotations/replicas). Reconciler calls `annotate.Apply` during the Remediating → Completed transition (not during Approved → Remediating) so the audit chain entry for that pass captures the act of doing the work — per battle scar 07. Behavioural change worth flagging: **rejection now resolves to Completed (not Failed)** with `Approved=False`/`Ready=True`/Reason=Rejected. The audit trail keeps rejection distinguishable from successful remediation via the condition, but the overall outcome of "human resolved the scan by deciding not to act" is no longer treated as a failure. Approval poll uses a 30s `RequeueAfter` safety net on top of the watch on GovernanceScan. Self-reported approver string in `.status.approval.approver` is the M0 trust model; a TODO in `checkApproval` documents the production path (admission webhook against real user-info). Helper scripts `hack/approve.sh` and `hack/reject.sh` take the kubeconfig context as the approver string. envtest suite expanded with `rejection path` (Completed + Deployment untouched), `remediation: missing target Deployment` (→ Failed with `not found` in Ready condition), and the existing happy-path tests now also assert annotations + scale-to-zero. annotate-pkg coverage 91.4%; controller still 75.5%.
- 2026-05-22 Audit subsystem. New package `pkg/audit/` with zero Kubernetes dependencies (stdlib + `github.com/google/uuid` only), importable by any Go program. `AuditEntry` struct + `Backend` interface (`Append`/`List`/`Verify`) — the interface is justified upfront because three backends (local, GCS, S3) are already on the roadmap. `ComputeHash` is HMAC-SHA256 over a plain field concatenation (with a `SECURITY:` comment noting the boundary-confusion weakness; the MVP keeps the simple concat to match spec and the risk is bounded by the secret HMAC key). `VerifyChain` checks per-entry hash integrity first, then chain-link continuity, so tampered entries report at their own index and deleted entries report at the slot they used to occupy. `LocalBackend` writes `{basePath}/{namespace}/{scanName}/{ts}-{id}.json` via temp-file-rename for atomicity; List sorts by filename (lex == chronological because timestamps are UTC RFC3339Nano) then by Timestamp for defence in depth; an absent chain returns `(nil, nil)` not an error. 18 tests across `audit_test.go` and `local_test.go` — including a known-value hash check that locks the exact algorithm and field order, so an accidental format change breaks loudly. 83.6% coverage.
- 2026-05-22 Audit wired into reconciler + `sentinelctl verify` CLI + e2e. `Backend.Append` now returns `(AuditEntry, error)` — a minor divergence from the Prompt 6 strict signature, motivated by the need to populate `Status.AuditRef` from the persisted Hash without re-listing. Reconciler holds an `Audit audit.Backend` field (nilable, so existing controller-only tests need no change) and emits one audit entry per phase transition via `transitionAudit(scan, from, to)`. Audit append happens BEFORE the status update so that an audit-write failure aborts the reconcile cleanly; the trade-off is that an audit-success + status-update-failure produces a duplicate audit entry on retry (chain still verifies; duplicates are operationally visible). One extra event beyond the user's literal list: `ScanRegistered` on `""→Pending`, which makes the happy-path chain length 7 as expected. Audit backend is configured via env vars `SENTINEL_AUDIT_PATH` (default `/tmp/sentinel-audit`) and `SENTINEL_AUDIT_KEY` (default `sentinel-dev-key`); a `TODO(security)` in `cmd/main.go` documents the production hardening path (mount a Kubernetes Secret as a file). `cmd/sentinelctl/main.go` ships one subcommand `verify` using stdlib `flag` (no new deps); exits 0 on intact, 1 on broken, 2 on usage/IO errors. `test/e2e/audit_lifecycle_test.go` drives the full happy path under envtest (no e2e build tag, so it runs via `go test ./test/e2e/...`; `make test` keeps the `grep -v /e2e` exclusion so this file is intentionally not in the default suite). CHANGELOG.md drafted from the user's verbatim list. Coverage: controller 62.4% (dropped from 75.5% as audit dispatcher added paths), audit 83.0%, sentinelctl 84.2%.
- 2026-05-22 **M0 closed.** Five SoD ClusterRoles landed at `config/rbac/{scanner,approver,executor,policyadmin,auditor}_clusterrole.yaml` (kustomization updated). Helm chart at `helm/sentinel/` covers: CRD (in `templates/crds/`), controller Deployment with `SENTINEL_AUDIT_PATH`/`SENTINEL_AUDIT_KEY` env wiring and an `emptyDir` audit volume, controller manager ClusterRole + binding, and the five SoD ClusterRoles. Distroless image, read-only root, non-root user, dropped capabilities. Metrics are disabled by default (no TLS certs in the baseline chart). `helm template` renders cleanly: 6 ClusterRoles + 1 ClusterRoleBinding + 1 CRD + 1 SA + 1 Deployment. Verified end-to-end on kind `sentinel-dev`: `docker build && kind load && helm install` succeeded; controller pod went `Running` in under 5s, picked up the sample CR, advanced it `""→Pending→Scanning`, created the scan Job with the (placeholder) Garak image, and emitted `JobCreated`+`ScanStarted` events. Scan Job hits expected `ImagePullBackOff` because `ghcr.io/nvidia/garak:latest` is still gated behind `TODO(verify)` — the controller did everything M0 promised; only the scanner image remains. Full verification log preserved in `docs/m0-closure.md`.

### In progress
- (nothing yet)

### Known issues
- go.mod has `go 1.25.7` (set by kubebuilder v4.14.0); local `go` is 1.23.9 and the toolchain auto-downloads 1.25.x on build via `GOTOOLCHAIN=auto`. Builds work but the env mismatch is worth knowing about.
- `make test` exits non-zero on this dev box even when all specs pass. Root cause: the auto-downloaded 1.25.x toolchain at `~/.claude-sentinel-home/go/pkg/mod/golang.org/toolchain@*/pkg/tool/linux_amd64/` ships only 7 of ~15 standard tools (missing `covdata`, `addr2line`, `buildid`, `doc`, `fix`, `nm`, `objdump`, etc.). The Makefile's `-coverprofile cover.out` invokes `covdata`, which fails. Workaround until a complete Go 1.25 SDK is installed (`go install golang.org/dl/go1.25.10@latest && ~/go/bin/go1.25.10 download`): run `KUBEBUILDER_ASSETS=$(pwd)/bin/k8s/1.35.0-linux-amd64 go test ./internal/controller/...` directly. Tests themselves pass cleanly (verified 2026-05-21 at 91.7% controller coverage).

### Shelved (Phase 2, post-MVP)
- Battle-scars tagging and cross-project queryability (a dashboard view over `docs/battle-scars.md` across this and the two companion projects). Noted 2026-05-22 — the room is empty; fill it with entries first, decorate later.
- GPU waste detector
- Slack DecisionSurface adapter
- GCS audit backend
- S3 Object Lock audit backend
- Webhook approval UI
- Per-finding granular approval
- Prometheus/OTEL metrics
- Multi-cluster support
- Sigstore/cosign attestations

## Architecture rules — do not violate

1. ONE CRD only: GovernanceScan. No ScanPolicy, no ApprovalRequest, no
   AuditRecord, no RemediationPlan. Everything lives in spec and status
   of this one resource.

2. CONCRETE before abstract. Do not define interfaces before a concrete
   implementation exists. Build Garak Job creation directly in the
   reconciler. Extract interfaces only when a second implementation
   creates real duplication pain.

3. State machine phases: Pending, Scanning, FindingsDetected,
   AwaitingApproval, Approved, Remediating, Completed, Failed.
   Transitions are deterministic. No DAG engine. No workflow DSL.
   No dynamic workflow graphs. No embedded scripting.

4. Approval is BINARY for MVP: approve-all or reject-all via kubectl
   patch. No per-finding granularity. No web UI. No webhook.

5. Remediation is TWO ACTIONS only: annotate the workload with scan
   metadata, or scale the Deployment to zero (for critical findings).
   No autonomous remediation sophistication.

6. Audit entries are HMAC-chained (each entry hashes the previous).
   Local filesystem backend only for MVP. GCS and S3 backends are
   Phase 2.

7. No premature plugin systems, event buses, factories, registries,
   or generalized orchestration frameworks.

## Reconciliation rules

- Reconcile functions must be idempotent. Running reconcile twice on the
  same cluster state must produce the same result.
- Reconcile functions must derive desired actions from observed cluster
  state, not from assumptions about call order.
- Never assume a reconcile call is the first or only call.
- Status updates must tolerate optimistic concurrency conflicts
  (use retry on conflict).
- Owned resources (Jobs) must be discoverable after controller restart
  via owner references. Do not rely on in-memory state.

## Separation of Duties — five ClusterRoles

- sentinel-scanner: read scan targets, create/update scan results
- sentinel-approver: read findings, create approval decisions
- sentinel-executor: read approved decisions, execute remediations
- sentinel-policy-admin: create/update/delete scan policies
- sentinel-auditor: read-only on all governance resources and audit log

## File structure

```
sentinel/
  api/v1alpha1/             CRD type definitions
  cmd/                      Operator entrypoint
  cmd/sentinelctl/          CLI tool (audit verify)
  internal/
    controller/             Reconciliation loop
    detector/garak/         Garak Job creation and output parsing
    remediation/annotate/   Remediation handlers
  pkg/
    audit/                  Standalone audit trail (HMAC chain + backends)
  helm/sentinel/            Helm chart
  hack/                     Helper scripts (approve.sh, reject.sh)
  docs/adr/                 Architectural Decision Records
  config/                   Kubebuilder manifests, RBAC, samples
  test/e2e/                 End-to-end tests
```

## Testing rules

- Use envtest for controller tests.
- Unit tests for every non-trivial function.
- Test file goes next to the file it tests (Go convention).
- Tests call Reconcile() directly and assert on resulting state.
- Tests NEVER use time.Sleep or polling loops to wait for state changes.
- Each test drives the state machine by calling Reconcile() repeatedly
  and checking Status after each call.
- Timing-based assertions cause flaky tests. Do not write them.

## Things you must NOT do

- Do not run gcloud, gsutil, or any cloud CLI commands.
- Do not create GKE clusters or cloud resources.
- Do not add dependencies without explaining why they are needed.
- Do not create interfaces before concrete implementations exist.
- Do not add features not described in the current milestone.
- Do not use third-party web frameworks. net/http + html/template only.
- Do not add JavaScript to any component.
- Do not write tests that depend on timing or sleep.
- Do not create more than one CRD.
- Do not build workflow engines, DAG systems, or plugin registries.
- Do not flatten architecture or avoid idiomatic Go patterns because
  I am a beginner. Write production-quality code. I will learn from it.
