# Changelog

## [Unreleased]

### Added
- GovernanceScan CRD with lifecycle state machine (Pending, Scanning,
  FindingsDetected, AwaitingApproval, Approved, Remediating, Completed,
  Failed)
- Reconciler with Kubernetes Job-based scanning lifecycle
- Garak scanner integration with OWASP LLM Top 10 mapping
- kubectl-driven binary approval (approve-all / reject-all)
- Remediation: workload annotation and scale-to-zero quarantine
- HMAC-chained tamper-evident audit trail (pkg/audit/)
- Local filesystem audit backend
- sentinelctl verify command for audit chain integrity
- Five Separation of Duties ClusterRoles (config/rbac/, also bundled in
  the Helm chart)
- Finalizer-based cleanup of owned Jobs
- envtest and unit test coverage for all components
- Sample CRs in config/samples/
- Helper scripts: hack/approve.sh, hack/reject.sh
- Helm chart (helm/sentinel/) covering the CRD, the controller
  Deployment with audit env wiring + emptyDir audit volume, the
  controller's manager ClusterRole + binding, and the five SoD
  ClusterRoles
- Battle-scars log (docs/battle-scars.md) capturing hard-won lessons
  with raw evidence under docs/battle-scars/evidence/
- M0 end-to-end verification record (docs/m0-closure.md) showing first
  successful real-cluster install on kind
