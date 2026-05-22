/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
	"github.com/BashiM1/sentinel/internal/detector/garak"
	"github.com/BashiM1/sentinel/internal/remediation/annotate"
	"github.com/BashiM1/sentinel/pkg/audit"
)

// Condition types exposed on GovernanceScan.Status.Conditions.
const (
	ConditionScanComplete = "ScanComplete"
	ConditionApproved     = "Approved"
	ConditionReady        = "Ready"
)

// Event reasons. Kept short and stable so that consumers (alerts, dashboards,
// audit pipeline) can match on them.
const (
	EventScanStarted        = "ScanStarted"
	EventJobCreated         = "JobCreated"
	EventFindingsDetected   = "FindingsDetected"
	EventAwaitingApproval   = "AwaitingApproval"
	EventAutoApproved       = "AutoApproved"
	EventApprovalGranted    = "ApprovalGranted"
	EventApprovalRejected   = "ApprovalRejected"
	EventRemediationStarted = "RemediationStarted"
	EventScanCompleted      = "ScanCompleted"
	EventScanFailed         = "ScanFailed"
)

// FinalizerName guards Job cleanup on GovernanceScan deletion. Cascade
// garbage collection via owner references would clean up the Jobs even
// without a finalizer, but the explicit cleanup also lets future audit-trail
// entries record the deletion event (Prompt 7) before the parent resource is
// gone.
const FinalizerName = "sentinel.io/governancescan"

// jobPollInterval is how often we re-reconcile while waiting on a running
// scan Job. The Watch on owned Jobs (set up in SetupWithManager) will usually
// wake us sooner — this is the safety-net cadence in case a Watch event is
// dropped or the Job's status never changes (e.g., stuck Pod).
const jobPollInterval = 10 * time.Second

// approvalPollInterval is how often we re-reconcile while waiting for a
// human to patch .status.approval. The Watch on GovernanceScan will wake
// us as soon as the patch lands; this is the safety-net cadence for the
// case where the patch happens against an apiserver whose watch event
// somehow misses our cache (rare, but cheap insurance).
const approvalPollInterval = 30 * time.Second

// ResultsReader retrieves the raw scanner output for a Job. The default
// implementation reads pod logs via the clientset, but tests inject their
// own implementation because envtest does not run pods.
type ResultsReader func(ctx context.Context, job *batchv1.Job) ([]byte, error)

// GovernanceScanReconciler reconciles a GovernanceScan object.
type GovernanceScanReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// Clientset is the typed Kubernetes client used to fetch pod logs. It is
	// optional only if ResultsReaderFn is set; production code must wire it.
	Clientset kubernetes.Interface

	// ResultsReaderFn overrides log reading. Defaults to readJobLogs against
	// Clientset. Tests inject a closure that returns synthetic JSON.
	ResultsReaderFn ResultsReader

	// Audit is the audit-trail backend. Nilable: existing controller-only
	// tests don't need to wire it. When non-nil, every phase transition
	// produces an audit entry and Status.AuditRef is bumped to the
	// entry's Hash.
	Audit audit.Backend
}

// +kubebuilder:rbac:groups=sentinel.sentinel.io,resources=governancescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sentinel.sentinel.io,resources=governancescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sentinel.sentinel.io,resources=governancescans/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch

// Reconcile advances the GovernanceScan state machine by at most one phase
// per invocation. Finalizer management runs first so deletion can drive the
// resource to terminal state even when the spec is in an unusual phase.
func (r *GovernanceScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("governancescan", req.NamespacedName)

	var scan sentinelv1alpha1.GovernanceScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion path. We never run the state machine on a deleting object —
	// it would race with the cascade GC for the Job, and the audit trail
	// (Prompt 7) needs the cleanup to be the last action recorded.
	if !scan.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &scan)
	}

	// Ensure the finalizer is set before doing any work. This is a metadata
	// mutation (a spec write, not a status write) so it must be its own
	// reconcile pass to keep the audit chain's status-only entries coherent.
	if !controllerutil.ContainsFinalizer(&scan, FinalizerName) {
		controllerutil.AddFinalizer(&scan, FinalizerName)
		if err := r.Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if isTerminal(scan.Status.Phase) {
		return ctrl.Result{}, nil
	}

	originalPhase := scan.Status.Phase
	result, err := r.advance(ctx, &scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Skip the Status().Update when phase did not change. Every transition
	// in advance() that mutates conditions also moves the phase, so phase
	// equality is a sufficient proxy for "nothing changed". This guard is
	// what keeps idempotency intact even with RequeueAfter set (the
	// approval poll requeues every 30s without writing status).
	if scan.Status.Phase == originalPhase {
		return result, nil
	}

	// Phase transition occurred. Append the audit entry FIRST, then
	// update status. Order matters:
	//
	//   - On audit failure we have not touched the apiserver; the next
	//     reconcile sees the old phase and replays the transition.
	//   - On audit success + status-update failure we have an audit
	//     entry but no status update; the next reconcile will replay
	//     and produce a duplicate audit entry. Duplicates do not break
	//     chain verification (each links correctly) and are operationally
	//     visible as "two entries for one transition" — preferable to
	//     missing entries.
	if err := r.auditTransition(ctx, &scan, originalPhase); err != nil {
		return ctrl.Result{}, fmt.Errorf("audit transition %s->%s: %w", originalPhase, scan.Status.Phase, err)
	}

	if err := r.Status().Update(ctx, &scan); err != nil {
		log.V(1).Info("status update failed, will requeue", "error", err.Error())
		return ctrl.Result{}, err
	}
	return result, nil
}

// auditTransition appends one audit entry describing the just-completed
// phase transition and updates Status.AuditRef. If r.Audit is nil the
// call is a no-op so the existing controller-only tests can construct
// the reconciler without an audit backend.
func (r *GovernanceScanReconciler) auditTransition(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan, fromPhase string) error {
	if r.Audit == nil {
		return nil
	}
	event, principal, detail := transitionAudit(scan, fromPhase, scan.Status.Phase)
	persisted, err := r.Audit.Append(ctx, audit.AuditEntry{
		ScanName:  scan.Name,
		Namespace: scan.Namespace,
		Event:     event,
		Principal: principal,
		Detail:    detail,
	})
	if err != nil {
		return err
	}
	scan.Status.AuditRef = persisted.Hash
	return nil
}

// transitionAudit maps a (from, to) phase pair to the audit entry
// fields. Each transition has exactly one mapping, matching the
// one-transition-per-Reconcile rule recorded in battle scar 07. New
// transitions require a new case here — silently falling through to
// the default writes an "UnknownTransition" entry which surfaces in
// audit listings.
func transitionAudit(scan *sentinelv1alpha1.GovernanceScan, from, to string) (event, principal, detail string) {
	const controller = "sentinel-controller"
	switch {
	case from == "" && to == sentinelv1alpha1.PhasePending:
		// Initial observation. Prompt 7's spec lists the explicit
		// transitions starting at Pending->Scanning, but the e2e
		// expectation of 7 entries for the full happy-path includes
		// this one; "ScanRegistered" makes the audit chain start at
		// the apiserver-observed CR rather than mid-flight.
		return "ScanRegistered", controller, "GovernanceScan observed; lifecycle starts"

	case from == sentinelv1alpha1.PhasePending && to == sentinelv1alpha1.PhaseScanning:
		return "ScanStarted", controller,
			fmt.Sprintf("scan started against %s:%d", scan.Spec.Target.Service, scan.Spec.Target.Port)

	case from == sentinelv1alpha1.PhaseScanning && to == sentinelv1alpha1.PhaseFindingsDetected:
		return "FindingsDetected", controller, describeFindings(scan.Status.Findings)

	case from == sentinelv1alpha1.PhaseFindingsDetected && to == sentinelv1alpha1.PhaseAwaitingApproval:
		return "ApprovalRequested", controller, "awaiting human approval (patch .status.approval)"

	case from == sentinelv1alpha1.PhaseFindingsDetected && to == sentinelv1alpha1.PhaseApproved:
		// Auto-approve path (spec.approval.required=false).
		return "ApprovalDecision", "system:auto", "Approved"

	case from == sentinelv1alpha1.PhaseAwaitingApproval && to == sentinelv1alpha1.PhaseApproved:
		return "ApprovalDecision", approverOf(scan), "Approved"

	case from == sentinelv1alpha1.PhaseAwaitingApproval && to == sentinelv1alpha1.PhaseCompleted:
		// Rejection path. Captured here, not under Failed, because the
		// scan resolved successfully — a human said no.
		return "ApprovalDecision", approverOf(scan), "Rejected"

	case from == sentinelv1alpha1.PhaseApproved && to == sentinelv1alpha1.PhaseRemediating:
		return "RemediationStarted", controller, remediationDetail(scan)

	case from == sentinelv1alpha1.PhaseRemediating && to == sentinelv1alpha1.PhaseCompleted:
		return "RemediationCompleted", controller,
			fmt.Sprintf("remediation applied to %s", scan.Spec.Target.Service)

	case to == sentinelv1alpha1.PhaseFailed:
		return "ScanFailed", controller, failureMessage(scan)
	}

	return "UnknownTransition", controller, fmt.Sprintf("from=%s to=%s", from, to)
}

func approverOf(scan *sentinelv1alpha1.GovernanceScan) string {
	if scan.Status.Approval == nil {
		return "<unknown>"
	}
	return scan.Status.Approval.Approver
}

func failureMessage(scan *sentinelv1alpha1.GovernanceScan) string {
	if cond := meta.FindStatusCondition(scan.Status.Conditions, ConditionReady); cond != nil && cond.Message != "" {
		return cond.Message
	}
	return "unspecified failure"
}

func describeFindings(findings []sentinelv1alpha1.Finding) string {
	var c, h, m, l int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			c++
		case "high":
			h++
		case "medium":
			m++
		case "low":
			l++
		}
	}
	return fmt.Sprintf("%d findings (%d critical, %d high, %d medium, %d low)", len(findings), c, h, m, l)
}

func remediationDetail(scan *sentinelv1alpha1.GovernanceScan) string {
	hasCritical := false
	for _, f := range scan.Status.Findings {
		if f.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	if hasCritical {
		return fmt.Sprintf("annotate %s and scale to zero (critical findings present)", scan.Spec.Target.Service)
	}
	return fmt.Sprintf("annotate %s (no critical findings)", scan.Spec.Target.Service)
}

func isTerminal(phase string) bool {
	return phase == sentinelv1alpha1.PhaseCompleted || phase == sentinelv1alpha1.PhaseFailed
}

// finalize handles the deletion path. It deletes any owned Jobs (Background
// propagation so Pods clean up async) and then removes the finalizer.
func (r *GovernanceScanReconciler) finalize(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(scan, FinalizerName) {
		return ctrl.Result{}, nil
	}

	var jobs batchv1.JobList
	if err := r.List(ctx, &jobs,
		client.InNamespace(scan.Namespace),
		client.MatchingLabels{LabelGovernanceScan: scan.Name},
	); err != nil {
		return ctrl.Result{}, err
	}

	propagation := metav1.DeletePropagationBackground
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if !ownedBy(job, scan) {
			continue
		}
		if err := r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	controllerutil.RemoveFinalizer(scan, FinalizerName)
	if err := r.Update(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func ownedBy(job *batchv1.Job, scan *sentinelv1alpha1.GovernanceScan) bool {
	for _, owner := range job.OwnerReferences {
		if owner.UID == scan.UID {
			return true
		}
	}
	return false
}

// advance mutates scan.Status to reflect the next phase. Returns the
// reconcile Result. requeue=true (or RequeueAfter>0) means another reconcile
// should run; result.Requeue=false and RequeueAfter=0 means we're blocked on
// external input (approval) or have reached a terminal phase.
func (r *GovernanceScanReconciler) advance(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan) (ctrl.Result, error) {
	switch scan.Status.Phase {
	case "":
		r.toPending(scan)
		return ctrl.Result{Requeue: true}, nil
	case sentinelv1alpha1.PhasePending:
		return r.handlePending(ctx, scan)
	case sentinelv1alpha1.PhaseScanning:
		return r.handleScanning(ctx, scan)
	case sentinelv1alpha1.PhaseFindingsDetected:
		return r.fromFindingsDetected(scan), nil
	case sentinelv1alpha1.PhaseAwaitingApproval:
		return r.checkApproval(scan), nil
	case sentinelv1alpha1.PhaseApproved:
		r.toRemediating(scan)
		return ctrl.Result{Requeue: true}, nil
	case sentinelv1alpha1.PhaseRemediating:
		return r.handleRemediating(ctx, scan)
	default:
		return ctrl.Result{}, fmt.Errorf("unknown phase %q", scan.Status.Phase)
	}
}

func (r *GovernanceScanReconciler) toPending(scan *sentinelv1alpha1.GovernanceScan) {
	scan.Status.Phase = sentinelv1alpha1.PhasePending
	setCondition(scan, ConditionReady, metav1.ConditionFalse, "Pending", "scan not yet started")
	setCondition(scan, ConditionScanComplete, metav1.ConditionFalse, "Pending", "scan not yet started")
	setCondition(scan, ConditionApproved, metav1.ConditionUnknown, "Pending", "no approval decision recorded")
}

// handlePending ensures an owned scan Job exists, then transitions to
// Scanning. Job creation is idempotent: if a Job is already present (e.g.,
// because the controller crashed between Job creation and status update),
// we adopt it without creating a duplicate.
func (r *GovernanceScanReconciler) handlePending(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan) (ctrl.Result, error) {
	job, err := findOwnedJob(ctx, r.Client, scan)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("look up existing scan Job: %w", err)
	}

	if job == nil {
		job = garak.BuildGarakJob(scan, map[string]string{LabelGovernanceScan: scan.Name})
		if err := controllerutil.SetControllerReference(scan, job, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("set owner reference on scan Job: %w", err)
		}
		if err := r.Create(ctx, job); err != nil {
			// AlreadyExists means a parallel reconcile beat us to it — fine,
			// the next pass will discover it via findOwnedJob.
			if apierrors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, fmt.Errorf("create scan Job: %w", err)
		}
		r.event(scan, corev1.EventTypeNormal, EventJobCreated,
			fmt.Sprintf("created scan Job %s/%s", job.Namespace, job.Name))
	}

	now := metav1.Now()
	scan.Status.Phase = sentinelv1alpha1.PhaseScanning
	scan.Status.LastScanTime = &now
	setCondition(scan, ConditionScanComplete, metav1.ConditionFalse, "Scanning",
		fmt.Sprintf("scanner Job %s running against %s:%d", job.Name, scan.Spec.Target.Service, scan.Spec.Target.Port))
	r.event(scan, corev1.EventTypeNormal, EventScanStarted,
		fmt.Sprintf("started scan of %s:%d", scan.Spec.Target.Service, scan.Spec.Target.Port))

	return ctrl.Result{RequeueAfter: jobPollInterval}, nil
}

// handleScanning polls the owned Job. Three branches: succeeded → parse and
// move to FindingsDetected; failed → move to Failed; running → requeue
// after jobPollInterval (the Watch on owned Jobs will usually wake us sooner).
func (r *GovernanceScanReconciler) handleScanning(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan) (ctrl.Result, error) {
	job, err := findOwnedJob(ctx, r.Client, scan)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("look up scan Job: %w", err)
	}
	if job == nil {
		// The Job vanished out from under us. Could be that an operator
		// hand-deleted it. Treat as a scan failure rather than silently
		// recreating, because re-creating would mask a problem.
		r.toFailed(scan, "scan Job disappeared while in Scanning phase")
		return ctrl.Result{}, nil
	}

	switch {
	case jobSucceeded(job):
		raw, err := r.results(ctx, job)
		if err != nil {
			r.toFailed(scan, fmt.Sprintf("read scan Job output: %v", err))
			return ctrl.Result{}, nil
		}
		findings, err := garak.ParseGarakOutput(raw)
		if err != nil {
			r.toFailed(scan, fmt.Sprintf("parse scan Job output: %v", err))
			return ctrl.Result{}, nil
		}
		r.toFindingsDetected(scan, findings)
		return ctrl.Result{Requeue: true}, nil

	case jobFailed(job):
		r.toFailed(scan, fmt.Sprintf("scan Job failed: %s", jobFailureReason(job)))
		return ctrl.Result{}, nil

	default:
		return ctrl.Result{RequeueAfter: jobPollInterval}, nil
	}
}

func (r *GovernanceScanReconciler) toFindingsDetected(scan *sentinelv1alpha1.GovernanceScan, findings []sentinelv1alpha1.Finding) {
	scan.Status.Findings = findings
	scan.Status.FindingsCount = int32(len(findings))
	scan.Status.Phase = sentinelv1alpha1.PhaseFindingsDetected
	setCondition(scan, ConditionScanComplete, metav1.ConditionTrue, "FindingsDetected",
		fmt.Sprintf("scan produced %d finding(s)", len(findings)))
	r.event(scan, corev1.EventTypeNormal, EventFindingsDetected,
		fmt.Sprintf("scan produced %d finding(s)", len(findings)))
}

func (r *GovernanceScanReconciler) toFailed(scan *sentinelv1alpha1.GovernanceScan, reason string) {
	scan.Status.Phase = sentinelv1alpha1.PhaseFailed
	setCondition(scan, ConditionReady, metav1.ConditionFalse, "Failed", reason)
	setCondition(scan, ConditionScanComplete, metav1.ConditionFalse, "Failed", reason)
	r.event(scan, corev1.EventTypeWarning, EventScanFailed, reason)
}

func (r *GovernanceScanReconciler) fromFindingsDetected(scan *sentinelv1alpha1.GovernanceScan) ctrl.Result {
	if scan.Spec.Approval.IsRequired() {
		scan.Status.Phase = sentinelv1alpha1.PhaseAwaitingApproval
		setCondition(scan, ConditionApproved, metav1.ConditionUnknown, "AwaitingApproval",
			"waiting for human approval decision (patch .status.approval to proceed)")
		r.event(scan, corev1.EventTypeNormal, EventAwaitingApproval,
			"awaiting human approval — patch .status.approval to proceed")
		return ctrl.Result{RequeueAfter: approvalPollInterval}
	}
	now := metav1.Now()
	scan.Status.Approval = &sentinelv1alpha1.ApprovalStatus{
		Decision:  sentinelv1alpha1.DecisionApproved,
		Approver:  "system:auto",
		Timestamp: now,
	}
	scan.Status.Phase = sentinelv1alpha1.PhaseApproved
	setCondition(scan, ConditionApproved, metav1.ConditionTrue, "AutoApproved",
		"spec.approval.required=false; remediation auto-approved")
	r.event(scan, corev1.EventTypeNormal, EventAutoApproved,
		"spec.approval.required=false; remediation auto-approved")
	return ctrl.Result{Requeue: true}
}

func (r *GovernanceScanReconciler) checkApproval(scan *sentinelv1alpha1.GovernanceScan) ctrl.Result {
	if scan.Status.Approval == nil {
		// Still waiting. The Watch on GovernanceScan will normally wake us
		// when the human patches .status.approval; the RequeueAfter is a
		// safety net for the case where the watch event is missed.
		//
		// TODO(security): production should validate the approver against
		// the Kubernetes user info carried on the patch request (via an
		// admission webhook), not trust the self-reported `approver`
		// string in .status.approval. This MVP self-reports.
		return ctrl.Result{RequeueAfter: approvalPollInterval}
	}
	switch scan.Status.Approval.Decision {
	case sentinelv1alpha1.DecisionApproved:
		scan.Status.Phase = sentinelv1alpha1.PhaseApproved
		setCondition(scan, ConditionApproved, metav1.ConditionTrue, "Approved",
			fmt.Sprintf("approved by %s", scan.Status.Approval.Approver))
		r.event(scan, corev1.EventTypeNormal, EventApprovalGranted,
			fmt.Sprintf("approved by %s", scan.Status.Approval.Approver))
		return ctrl.Result{Requeue: true}
	case sentinelv1alpha1.DecisionRejected:
		// Rejection is a legitimate human decision, not a system failure.
		// The scan reaches Completed with Approved=False so downstream
		// systems can tell rejection from successful remediation, but the
		// overall outcome is "we ran a scan and a human resolved it".
		scan.Status.Phase = sentinelv1alpha1.PhaseCompleted
		setCondition(scan, ConditionApproved, metav1.ConditionFalse, "Rejected",
			fmt.Sprintf("rejected by %s", scan.Status.Approval.Approver))
		setCondition(scan, ConditionReady, metav1.ConditionTrue, "Rejected",
			"scan rejected; remediation skipped per human decision")
		r.event(scan, corev1.EventTypeWarning, EventApprovalRejected,
			fmt.Sprintf("rejected by %s — remediation skipped", scan.Status.Approval.Approver))
		return ctrl.Result{}
	default:
		// Unrecognised decision: treat as still pending. The CRD enum
		// validation already rejects this at the apiserver, so this is
		// defence in depth.
		return ctrl.Result{RequeueAfter: approvalPollInterval}
	}
}

func (r *GovernanceScanReconciler) toRemediating(scan *sentinelv1alpha1.GovernanceScan) {
	scan.Status.Phase = sentinelv1alpha1.PhaseRemediating
	r.event(scan, corev1.EventTypeNormal, EventRemediationStarted,
		"remediation started (annotate workload + scale-to-zero for critical findings)")
}

// handleRemediating runs the annotate remediation handler and advances the
// state machine based on the outcome. The work happens during this
// transition (not during Approved → Remediating) so the audit-chain entry
// for the Remediating → Completed transition captures the act of doing
// the work — see docs/battle-scars.md scar 07 for the rationale.
func (r *GovernanceScanReconciler) handleRemediating(ctx context.Context, scan *sentinelv1alpha1.GovernanceScan) (ctrl.Result, error) {
	err := annotate.Apply(ctx, r.Client, scan)
	switch {
	case errors.Is(err, annotate.ErrTargetNotFound):
		r.toFailed(scan, fmt.Sprintf("remediation target Deployment not found for service %q", scan.Spec.Target.Service))
		return ctrl.Result{}, nil
	case err != nil:
		// Transient error — let controller-runtime retry with backoff.
		// Phase stays Remediating; annotate.Apply is idempotent.
		return ctrl.Result{}, fmt.Errorf("apply remediation: %w", err)
	}
	r.toCompleted(scan)
	return ctrl.Result{}, nil
}

func (r *GovernanceScanReconciler) toCompleted(scan *sentinelv1alpha1.GovernanceScan) {
	scan.Status.Phase = sentinelv1alpha1.PhaseCompleted
	setCondition(scan, ConditionReady, metav1.ConditionTrue, "Completed",
		"scan and remediation complete")
	r.event(scan, corev1.EventTypeNormal, EventScanCompleted,
		"scan and remediation complete")
}

// results returns the raw scanner output bytes. Tests inject ResultsReaderFn;
// production uses the default pod-log reader, which requires Clientset.
func (r *GovernanceScanReconciler) results(ctx context.Context, job *batchv1.Job) ([]byte, error) {
	if r.ResultsReaderFn != nil {
		return r.ResultsReaderFn(ctx, job)
	}
	if r.Clientset == nil {
		return nil, fmt.Errorf("reconciler has no ResultsReaderFn and no Clientset")
	}
	return readJobLogs(ctx, r.Clientset, job)
}

func (r *GovernanceScanReconciler) event(scan *sentinelv1alpha1.GovernanceScan, eventType, reason, message string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Event(scan, eventType, reason, message)
}

func setCondition(scan *sentinelv1alpha1.GovernanceScan, t string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&scan.Status.Conditions, metav1.Condition{
		Type:               t,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: scan.Generation,
	})
}

// SetupWithManager wires the controller to watch GovernanceScans and any
// Jobs they own. The Owns(&batchv1.Job{}) call is what lets us discover
// existing Jobs after a controller restart — the manager indexes them by
// owner reference and re-queues the parent GovernanceScan when Job status
// changes, so we never rely on in-memory state.
func (r *GovernanceScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sentinelv1alpha1.GovernanceScan{}).
		Owns(&batchv1.Job{}).
		Named("governancescan").
		Complete(r)
}
