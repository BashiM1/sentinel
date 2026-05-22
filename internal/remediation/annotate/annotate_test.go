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

package annotate

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := appsv1.AddToScheme(s); err != nil {
		t.Fatalf("register appsv1: %v", err)
	}
	if err := sentinelv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("register sentinelv1alpha1: %v", err)
	}
	return s
}

func sampleScan() *sentinelv1alpha1.GovernanceScan {
	now := metav1.NewTime(time.Date(2026, 5, 22, 9, 30, 0, 0, time.UTC))
	return &sentinelv1alpha1.GovernanceScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-1", Namespace: "default"},
		Spec: sentinelv1alpha1.GovernanceScanSpec{
			Target: sentinelv1alpha1.ScanTarget{
				Service: "llm-service",
				Port:    8080,
			},
		},
		Status: sentinelv1alpha1.GovernanceScanStatus{
			LastScanTime:  &now,
			FindingsCount: 1,
			Approval: &sentinelv1alpha1.ApprovalStatus{
				Decision:  sentinelv1alpha1.DecisionApproved,
				Approver:  "alice@example.test",
				Timestamp: now,
			},
			Findings: []sentinelv1alpha1.Finding{
				{ID: "garak:test.X", Category: "LLM01", Severity: "medium", Description: "x"},
			},
		},
	}
}

func deployment(name, namespace string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       appsv1.DeploymentSpec{Replicas: ptr.To(replicas)},
	}
}

func TestApply_AlwaysAnnotates(t *testing.T) {
	ctx := context.Background()
	scan := sampleScan()
	dep := deployment("llm-service", "default", 3)

	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(dep).
		Build()

	if err := Apply(ctx, c, scan); err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	var got appsv1.Deployment
	if err := c.Get(ctx, types.NamespacedName{Name: "llm-service", Namespace: "default"}, &got); err != nil {
		t.Fatalf("get deployment after Apply: %v", err)
	}

	wantAnnotations := map[string]string{
		AnnotationLastScanTime:  "2026-05-22T09:30:00Z",
		AnnotationScanResult:    sentinelv1alpha1.PhaseCompleted,
		AnnotationApprovedBy:    "alice@example.test",
		AnnotationFindingsCount: "1",
	}
	for k, want := range wantAnnotations {
		if got.Annotations[k] != want {
			t.Errorf("annotation %q: want %q, got %q", k, want, got.Annotations[k])
		}
	}

	// Non-critical findings: no quarantine annotations and replicas untouched.
	if _, ok := got.Annotations[AnnotationQuarantined]; ok {
		t.Errorf("non-critical scan should not set %s", AnnotationQuarantined)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 3 {
		t.Errorf("non-critical scan should not change replicas; got %v", got.Spec.Replicas)
	}
}

func TestApply_CriticalScalesToZero(t *testing.T) {
	ctx := context.Background()
	scan := sampleScan()
	scan.Status.Findings = append(scan.Status.Findings, sentinelv1alpha1.Finding{
		ID: "garak:promptinject.Crit", Category: "LLM01", Severity: "critical",
	})
	scan.Status.FindingsCount = int32(len(scan.Status.Findings))

	dep := deployment("llm-service", "default", 5)
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(dep).
		Build()

	if err := Apply(ctx, c, scan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var got appsv1.Deployment
	_ = c.Get(ctx, types.NamespacedName{Name: "llm-service", Namespace: "default"}, &got)

	if got.Spec.Replicas == nil || *got.Spec.Replicas != 0 {
		t.Errorf("critical finding should scale to zero; got %v", got.Spec.Replicas)
	}
	if got.Annotations[AnnotationQuarantined] != "true" {
		t.Errorf("%s should be \"true\"; got %q", AnnotationQuarantined, got.Annotations[AnnotationQuarantined])
	}
	if got.Annotations[AnnotationQuarantineReason] != QuarantineReasonCritical {
		t.Errorf("%s mismatch: got %q", AnnotationQuarantineReason, got.Annotations[AnnotationQuarantineReason])
	}
}

func TestApply_TargetNotFound(t *testing.T) {
	ctx := context.Background()
	scan := sampleScan()
	// No Deployment seeded into the fake client.
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	err := Apply(ctx, c, scan)
	if !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("expected ErrTargetNotFound, got %v", err)
	}
	// The error message should name the namespace/name pair we looked up
	// so the operator can grep their cluster.
	if err.Error() == "" || !contains(err.Error(), "default/llm-service") {
		t.Errorf("error message should include default/llm-service; got %q", err.Error())
	}
}

func TestApply_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	scan := sampleScan()
	scan.Status.Findings[0].Severity = "critical"
	scan.Status.FindingsCount = 1

	dep := deployment("llm-service", "default", 3)
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(dep).
		Build()

	// Two passes should leave the Deployment in the same state.
	if err := Apply(ctx, c, scan); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	var afterFirst appsv1.Deployment
	_ = c.Get(ctx, types.NamespacedName{Name: "llm-service", Namespace: "default"}, &afterFirst)

	if err := Apply(ctx, c, scan); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	var afterSecond appsv1.Deployment
	_ = c.Get(ctx, types.NamespacedName{Name: "llm-service", Namespace: "default"}, &afterSecond)

	// Replicas and the quarantine annotations are the load-bearing ones.
	if *afterFirst.Spec.Replicas != *afterSecond.Spec.Replicas {
		t.Errorf("replicas differ between passes")
	}
	for _, k := range []string{AnnotationQuarantined, AnnotationQuarantineReason, AnnotationLastScanTime} {
		if afterFirst.Annotations[k] != afterSecond.Annotations[k] {
			t.Errorf("annotation %q differs between passes", k)
		}
	}
}

func TestApply_EmptyTargetService(t *testing.T) {
	ctx := context.Background()
	scan := sampleScan()
	scan.Spec.Target.Service = ""
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	err := Apply(ctx, c, scan)
	if err == nil {
		t.Fatal("expected an error for empty target.service")
	}
	if errors.Is(err, ErrTargetNotFound) {
		t.Errorf("empty service should not surface as ErrTargetNotFound (it never even attempts a lookup); got %v", err)
	}
}

func TestParseServiceFQDN(t *testing.T) {
	cases := []struct {
		in        string
		defaultNS string
		wantName  string
		wantNS    string
	}{
		{"llm-service", "default", "llm-service", "default"},
		{"llm-service.ml", "default", "llm-service", "ml"},
		{"llm-service.ml.svc.cluster.local", "default", "llm-service", "ml"},
		{"", "default", "", "default"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			name, ns := parseServiceFQDN(c.in, c.defaultNS)
			if name != c.wantName || ns != c.wantNS {
				t.Errorf("parseServiceFQDN(%q, %q) = (%q, %q), want (%q, %q)",
					c.in, c.defaultNS, name, ns, c.wantName, c.wantNS)
			}
		})
	}
}

// Restricted strings.Contains substitute so the test file doesn't import
// strings just for one call. (Saves a line.)
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Compile-time check that fake.ClientBuilder still produces something
// satisfying client.Client; protects against a controller-runtime upgrade
// silently changing the Builder's return type.
var _ client.Client = fake.NewClientBuilder().Build()
