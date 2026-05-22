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

// This file deliberately has no `//go:build e2e` tag so it runs as part
// of the default `go test ./...`. The other files in this directory
// (e2e_suite_test.go, e2e_test.go) are guarded by `//go:build e2e`
// because they require a live kind cluster + CertManager; this test
// uses envtest and is self-contained.

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
	"github.com/BashiM1/sentinel/internal/controller"
	"github.com/BashiM1/sentinel/pkg/audit"
)

const sampleScanJSON = `{"entry_type": "eval", "probe": "promptinject.HijackHateHumans", "passed": 5, "failed": 95}`

// TestAuditLifecycle_HappyPath drives a GovernanceScan through every phase
// in the approval-required happy path and asserts the audit chain has
// exactly the expected events, in order, intact under verification.
func TestAuditLifecycle_HappyPath(t *testing.T) {
	ctx := context.Background()

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	if dir := findEnvtestBinaryDir(); dir != "" {
		env.BinaryAssetsDirectory = dir
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("envtest start: %v (ensure KUBEBUILDER_ASSETS is set or bin/k8s/* exists)", err)
	}
	t.Cleanup(func() {
		// envtest.Stop can be flaky on a contended host; one retry.
		if err := env.Stop(); err != nil {
			_ = env.Stop()
		}
	})

	s := scheme.Scheme
	if err := sentinelv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	k8sClient, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	auditDir := t.TempDir()
	auditKey := []byte("e2e-audit-key")
	backend, err := audit.NewLocalBackend(auditDir, auditKey)
	if err != nil {
		t.Fatalf("audit backend: %v", err)
	}

	r := &controller.GovernanceScanReconciler{
		Client: k8sClient,
		Scheme: s,
		Audit:  backend,
		ResultsReaderFn: func(_ context.Context, _ *batchv1.Job) ([]byte, error) {
			return []byte(sampleScanJSON), nil
		},
	}

	scanName := "audit-lifecycle"
	ns := "default"
	key := types.NamespacedName{Name: scanName, Namespace: ns}

	required := true
	scan := &sentinelv1alpha1.GovernanceScan{
		ObjectMeta: metav1.ObjectMeta{Name: scanName, Namespace: ns},
		Spec: sentinelv1alpha1.GovernanceScanSpec{
			Target: sentinelv1alpha1.ScanTarget{
				Service: "llm-service",
				Port:    8080,
			},
			Scanner:  sentinelv1alpha1.ScannerConfig{Type: "garak", Profile: "owasp-llm-top10"},
			Approval: sentinelv1alpha1.ApprovalConfig{Required: &required},
			Audit:    sentinelv1alpha1.AuditConfig{Backend: "local", Path: "/tmp/sentinel-audit"},
		},
	}
	if err := k8sClient.Create(ctx, scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	// Seed the target Deployment so remediation succeeds.
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-service", Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(3)),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "llm-service"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "llm-service"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "x", Image: "scratch"}},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, dep); err != nil {
		t.Fatalf("create deployment: %v", err)
	}

	reconcileOnce := func(label string) {
		if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile [%s]: %v", label, err)
		}
	}

	// Pass 1: add finalizer.
	reconcileOnce("finalizer")
	// Pass 2: "" -> Pending  (audit entry 1: ScanRegistered).
	reconcileOnce("registered")
	// Pass 3: Pending -> Scanning (audit entry 2: ScanStarted; Job created).
	reconcileOnce("scanning")

	// Mark the Job complete (envtest substitute for the Job controller).
	var jobs batchv1.JobList
	if err := k8sClient.List(ctx, &jobs, client.InNamespace(ns)); err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("expected exactly 1 scan Job, got %d", len(jobs.Items))
	}
	markJobComplete(t, ctx, k8sClient, &jobs.Items[0])

	// Pass 4: Scanning -> FindingsDetected  (audit entry 3).
	reconcileOnce("findings")
	// Pass 5: FindingsDetected -> AwaitingApproval (audit entry 4).
	reconcileOnce("awaiting")

	// Patch the approval as a human would via `kubectl patch ... --subresource status`.
	var refetched sentinelv1alpha1.GovernanceScan
	if err := k8sClient.Get(ctx, key, &refetched); err != nil {
		t.Fatalf("get scan: %v", err)
	}
	refetched.Status.Approval = &sentinelv1alpha1.ApprovalStatus{
		Decision:  sentinelv1alpha1.DecisionApproved,
		Approver:  "alice@example.test",
		Timestamp: metav1.Now(),
	}
	if err := k8sClient.Status().Update(ctx, &refetched); err != nil {
		t.Fatalf("patch approval: %v", err)
	}

	// Pass 6: AwaitingApproval -> Approved (audit entry 5: ApprovalDecision).
	reconcileOnce("approved")
	// Pass 7: Approved -> Remediating (audit entry 6: RemediationStarted).
	reconcileOnce("remediating")
	// Pass 8: Remediating -> Completed (audit entry 7: RemediationCompleted).
	reconcileOnce("completed")

	// Confirm terminal state on the CR.
	var final sentinelv1alpha1.GovernanceScan
	if err := k8sClient.Get(ctx, key, &final); err != nil {
		t.Fatalf("get final: %v", err)
	}
	if final.Status.Phase != sentinelv1alpha1.PhaseCompleted {
		t.Fatalf("final phase: want Completed, got %q", final.Status.Phase)
	}
	if final.Status.AuditRef == "" {
		t.Error("Status.AuditRef should be populated after the chain wrote its last entry")
	}

	// Verify the chain.
	verifyResult, err := backend.Verify(ctx, scanName, ns)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verifyResult.Intact {
		t.Fatalf("chain reported not intact: %+v", verifyResult)
	}
	if verifyResult.EntryCount != 7 {
		t.Fatalf("entry count: want 7, got %d", verifyResult.EntryCount)
	}

	// Check the event sequence.
	entries, err := backend.List(ctx, scanName, ns)
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	wantEvents := []string{
		"ScanRegistered",
		"ScanStarted",
		"FindingsDetected",
		"ApprovalRequested",
		"ApprovalDecision",
		"RemediationStarted",
		"RemediationCompleted",
	}
	if len(entries) != len(wantEvents) {
		t.Fatalf("entries: want %d, got %d", len(wantEvents), len(entries))
	}
	for i, want := range wantEvents {
		if entries[i].Event != want {
			t.Errorf("entry %d Event: want %q, got %q", i, want, entries[i].Event)
		}
	}

	// AuditRef on the final CR should equal the last entry's Hash.
	if final.Status.AuditRef != entries[len(entries)-1].Hash {
		t.Errorf("Status.AuditRef mismatch:\n  want: %s\n  got:  %s",
			entries[len(entries)-1].Hash, final.Status.AuditRef)
	}

	// Approver on the ApprovalDecision entry must be the patched human, not the controller.
	if entries[4].Principal != "alice@example.test" {
		t.Errorf("ApprovalDecision Principal: want alice@example.test, got %q", entries[4].Principal)
	}
}

// markJobComplete sets the conditions the K8s 1.31+ apiserver requires
// for a Complete=True transition. Mirrors the helper in
// internal/controller/governancescan_controller_test.go; duplicated
// here to keep this e2e file self-contained.
func markJobComplete(t *testing.T, ctx context.Context, c client.Client, job *batchv1.Job) {
	t.Helper()
	now := metav1.Now()
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now
	job.Status.Succeeded = 1
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastProbeTime: now, LastTransitionTime: now, Reason: "Succeeded"},
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastProbeTime: now, LastTransitionTime: now, Reason: "JobComplete"},
	}
	if err := c.Status().Update(ctx, job); err != nil {
		t.Fatalf("update job status: %v", err)
	}
}

func findEnvtestBinaryDir() string {
	base := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(base, e.Name())
		}
	}
	return ""
}
