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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
	"github.com/BashiM1/sentinel/internal/detector/garak"
	"github.com/BashiM1/sentinel/internal/remediation/annotate"
)

// scanFixture builds a GovernanceScan with sensible defaults. Each test
// overrides the unique fields.
type scanFixture struct {
	name             string
	approvalRequired bool
}

func (f scanFixture) build() *sentinelv1alpha1.GovernanceScan {
	required := f.approvalRequired
	return &sentinelv1alpha1.GovernanceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.name,
			Namespace: "default",
		},
		Spec: sentinelv1alpha1.GovernanceScanSpec{
			Target: sentinelv1alpha1.ScanTarget{
				// Shortname (no FQDN) so the remediation handler looks
				// up the Deployment in the scan's own namespace
				// ("default"). The sample CR at
				// config/samples/sentinel_v1alpha1_governancescan.yaml
				// uses the FQDN form to document that it works; tests
				// favour the shortname for setup simplicity.
				Service: "llm-service",
				Port:    8080,
			},
			Scanner: sentinelv1alpha1.ScannerConfig{
				Type:    "garak",
				Profile: "owasp-llm-top10",
			},
			Approval: sentinelv1alpha1.ApprovalConfig{
				Required: &required,
			},
			Audit: sentinelv1alpha1.AuditConfig{
				Backend: "local",
				Path:    "/tmp/sentinel-audit",
			},
		},
	}
}

// drive calls Reconcile once and refetches the resource. Tests that expect
// the resource to be gone (e.g., after finalizer removes finalizer) use
// driveExpectGone instead.
func drive(
	ctx context.Context,
	r *GovernanceScanReconciler,
	key types.NamespacedName,
) (reconcile.Result, *sentinelv1alpha1.GovernanceScan) {
	GinkgoHelper()
	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	Expect(err).NotTo(HaveOccurred())

	var refetched sentinelv1alpha1.GovernanceScan
	Expect(k8sClient.Get(ctx, key, &refetched)).To(Succeed())
	return res, &refetched
}

// driveExpectGone calls Reconcile once and asserts the resource is no longer
// in the apiserver afterwards (the finalizer-removal completes deletion).
func driveExpectGone(ctx context.Context, r *GovernanceScanReconciler, key types.NamespacedName) reconcile.Result {
	GinkgoHelper()
	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.Get(ctx, key, &sentinelv1alpha1.GovernanceScan{})
	Expect(apierrors.IsNotFound(err)).To(BeTrue(), "expected GovernanceScan to be gone after finalizer removal")
	return res
}

// driveToScanning runs the finalizer pass, the empty→Pending transition, and
// the Pending→Scanning transition. Returns the scan so callers can pass its
// UID into listOwnedJobs.
func driveToScanning(ctx context.Context, r *GovernanceScanReconciler, key types.NamespacedName) *sentinelv1alpha1.GovernanceScan {
	GinkgoHelper()
	drive(ctx, r, key) // finalizer add
	drive(ctx, r, key) // "" -> Pending
	_, scan := drive(ctx, r, key)
	Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseScanning))
	return scan
}

// listOwnedJobs returns Jobs owned by the scan with the given UID. Matching
// by UID (not just label) mirrors the production findOwnedJob and protects
// against label leftovers from a sibling It under the same Context — those
// reuse the scan name but get a fresh UID per Create.
func listOwnedJobs(ctx context.Context, scanUID types.UID, namespace string) []batchv1.Job {
	GinkgoHelper()
	var all batchv1.JobList
	Expect(k8sClient.List(ctx, &all, client.InNamespace(namespace))).To(Succeed())
	var owned []batchv1.Job
	for _, j := range all.Items {
		for _, owner := range j.OwnerReferences {
			if owner.UID == scanUID {
				owned = append(owned, j)
				break
			}
		}
	}
	return owned
}

// listJobsByLabel is the label-only lookup used by cleanup. We cannot use UID
// after the CR is gone because UIDs aren't retained.
func listJobsByLabel(ctx context.Context, scanName, namespace string) []batchv1.Job {
	GinkgoHelper()
	var jobs batchv1.JobList
	Expect(k8sClient.List(ctx, &jobs,
		client.InNamespace(namespace),
		client.MatchingLabels{LabelGovernanceScan: scanName},
	)).To(Succeed())
	return jobs.Items
}

// markJobComplete sets the Complete condition on a Job. envtest runs a real
// apiserver and K8s 1.31+ rejects a Complete=True condition unless
// SuccessCriteriaMet=True is set first and StartTime/CompletionTime are
// populated — replicate that here so the status update is accepted.
func markJobComplete(ctx context.Context, job *batchv1.Job) {
	GinkgoHelper()
	now := metav1.Now()
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now
	job.Status.Succeeded = 1
	job.Status.Conditions = []batchv1.JobCondition{
		{
			Type:               batchv1.JobSuccessCriteriaMet,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             "Succeeded",
		},
		{
			Type:               batchv1.JobComplete,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             "JobComplete",
		},
	}
	Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())
}

// markJobFailed analogously needs FailureTarget before Failed and a StartTime.
func markJobFailed(ctx context.Context, job *batchv1.Job, reason, message string) {
	GinkgoHelper()
	now := metav1.Now()
	job.Status.StartTime = &now
	job.Status.Failed = 1
	job.Status.Conditions = []batchv1.JobCondition{
		{
			Type:               batchv1.JobFailureTarget,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             reason,
			Message:            message,
		},
		{
			Type:               batchv1.JobFailed,
			Status:             corev1.ConditionTrue,
			LastProbeTime:      now,
			LastTransitionTime: now,
			Reason:             reason,
			Message:            message,
		},
	}
	Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())
}

// makeTargetDeployment seeds a Deployment that matches scanFixture's default
// target service name. Tests that exercise the remediation path call this in
// BeforeEach; tests that should hit the "missing target" branch skip it.
// Returned so individual tests can refetch and assert annotations.
func makeTargetDeployment(ctx context.Context, name, namespace string, replicas int32) *appsv1.Deployment {
	GinkgoHelper()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "x", Image: "scratch"}},
				},
			},
		},
	}
	Expect(k8sClient.Create(ctx, dep)).To(Succeed())
	return dep
}

func refetchDeployment(ctx context.Context, name, namespace string) *appsv1.Deployment {
	GinkgoHelper()
	var dep appsv1.Deployment
	Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &dep)).To(Succeed())
	return &dep
}

// deleteDeployment removes a Deployment if it exists. Cleanup-only.
func deleteDeployment(ctx context.Context, name, namespace string) {
	GinkgoHelper()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	if err := k8sClient.Delete(ctx, dep); err != nil && !apierrors.IsNotFound(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}

// fakeResults returns a ResultsReader that ignores the Job and returns the
// supplied JSON. Most happy-path tests inject one of these.
func fakeResults(payload string) ResultsReader {
	return func(_ context.Context, _ *batchv1.Job) ([]byte, error) {
		return []byte(payload), nil
	}
}

// fakeResultsError returns a ResultsReader that always errors. Used to
// exercise the "scan job output unreadable" branch.
func fakeResultsError(msg string) ResultsReader {
	return func(_ context.Context, _ *batchv1.Job) ([]byte, error) {
		return nil, fmt.Errorf("%s", msg)
	}
}

// sampleScanJSON is a one-line Garak-shaped report fixture. It produces a
// single finding when parsed by garak.ParseGarakOutput (probe promptinject.*
// maps to LLM01; 95/100 success rate maps to critical).
const sampleScanJSON = `{"entry_type": "eval", "probe": "promptinject.HijackHateHumans", "passed": 5, "failed": 95}`

func drainEvents(rec *record.FakeRecorder) []string {
	out := []string{}
	for {
		select {
		case ev := <-rec.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func conditionStatus(scan *sentinelv1alpha1.GovernanceScan, t string) metav1.ConditionStatus {
	c := meta.FindStatusCondition(scan.Status.Conditions, t)
	if c == nil {
		return metav1.ConditionStatus("<missing>")
	}
	return c.Status
}

func conditionReason(scan *sentinelv1alpha1.GovernanceScan, t string) string {
	c := meta.FindStatusCondition(scan.Status.Conditions, t)
	if c == nil {
		return "<missing>"
	}
	return c.Reason
}

var _ = Describe("GovernanceScan controller", func() {
	var (
		ctx      context.Context
		r        *GovernanceScanReconciler
		recorder *record.FakeRecorder
	)

	BeforeEach(func() {
		ctx = context.Background()
		recorder = record.NewFakeRecorder(64)
		r = &GovernanceScanReconciler{
			Client:          k8sClient,
			Scheme:          k8sClient.Scheme(),
			Recorder:        recorder,
			ResultsReaderFn: fakeResults(sampleScanJSON),
		}
	})

	cleanup := func(name string) {
		scan := &sentinelv1alpha1.GovernanceScan{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}}
		// First strip the finalizer so the apiserver actually removes the CR
		// even if the test exited mid-flow. We then issue the delete and
		// also clean up any owned Jobs that might still be hanging around.
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, scan); err == nil {
			if controllerutil.RemoveFinalizer(scan, FinalizerName) {
				_ = k8sClient.Update(ctx, scan)
			}
			_ = k8sClient.Delete(ctx, scan)
		}
		bg := metav1.DeletePropagationBackground
		for _, j := range listJobsByLabel(ctx, name, "default") {
			job := j
			_ = k8sClient.Delete(ctx, &job, &client.DeleteOptions{PropagationPolicy: &bg})
		}
		// Verify the next test starts from a clean slate — any leftover Job
		// would cause UID-filtered lookups in the next It to misbehave.
		Expect(listJobsByLabel(ctx, name, "default")).To(BeEmpty())
		// Delete any target Deployment a remediation test created; safe to
		// call even when no Deployment exists.
		deleteDeployment(ctx, "llm-service", "default")
	}

	Context("Job lifecycle", func() {
		Context("creates a scan Job when transitioning to Scanning", func() {
			const name = "lifecycle-create"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			AfterEach(func() { cleanup(name) })

			It("adds finalizer, creates exactly one Job with the right metadata, and transitions to Scanning", func() {
				By("Reconcile 1: finalizer is added; no phase change yet")
				_, scan := drive(ctx, r, key)
				Expect(scan.Finalizers).To(ContainElement(FinalizerName))
				Expect(scan.Status.Phase).To(BeEmpty())

				By("Reconcile 2: empty -> Pending; still no Job")
				_, scan = drive(ctx, r, key)
				Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhasePending))
				Expect(listOwnedJobs(ctx, scan.UID, "default")).To(BeEmpty())

				By("Reconcile 3: Pending -> Scanning; Job is created")
				res, scan := drive(ctx, r, key)
				Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseScanning))
				Expect(scan.Status.LastScanTime).NotTo(BeNil())
				Expect(res.RequeueAfter).To(Equal(jobPollInterval),
					"Scanning phase should requeue after the job-poll interval")

				jobs := listOwnedJobs(ctx, scan.UID, "default")
				Expect(jobs).To(HaveLen(1))
				job := jobs[0]
				Expect(job.Name).To(HavePrefix(name + "-scan-"))
				Expect(job.Labels[LabelGovernanceScan]).To(Equal(name))
				Expect(job.OwnerReferences).To(HaveLen(1))
				Expect(job.OwnerReferences[0].UID).To(Equal(scan.UID))
				Expect(job.OwnerReferences[0].Controller).NotTo(BeNil())
				Expect(*job.OwnerReferences[0].Controller).To(BeTrue())
				Expect(job.Spec.BackoffLimit).NotTo(BeNil())
				Expect(*job.Spec.BackoffLimit).To(Equal(int32(2)))
				Expect(job.Spec.TTLSecondsAfterFinished).NotTo(BeNil())
				Expect(*job.Spec.TTLSecondsAfterFinished).To(Equal(int32(3600)))
				Expect(job.Spec.Template.Spec.RestartPolicy).To(Equal(corev1.RestartPolicyNever))
				Expect(job.Spec.Template.Spec.Volumes).To(HaveLen(1))
				Expect(job.Spec.Template.Spec.Volumes[0].EmptyDir).NotTo(BeNil())
				Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))
				// Image is verified via the garak package constant (subject
				// to TODO(verify) until the Garak image is confirmed).
				Expect(job.Spec.Template.Spec.Containers[0].Image).To(Equal(garak.GarakImage))
				Expect(job.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(1))
				Expect(job.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(garak.OutputDir))
				// Resource requests from the design spec.
				reqs := job.Spec.Template.Spec.Containers[0].Resources.Requests
				Expect(reqs.Memory().String()).To(Equal("512Mi"))
				Expect(reqs.Cpu().String()).To(Equal("500m"))
			})
		})

		Context("does not create a duplicate Job on re-reconcile", func() {
			const name = "lifecycle-dedupe"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			AfterEach(func() { cleanup(name) })

			It("reconciling Scanning multiple times keeps the original Job", func() {
				scan := driveToScanning(ctx, r, key)
				originalJobs := listOwnedJobs(ctx, scan.UID, "default")
				Expect(originalJobs).To(HaveLen(1))
				originalName := originalJobs[0].Name

				By("Three extra reconciles while Job has not completed")
				for i := 0; i < 3; i++ {
					_, scan := drive(ctx, r, key)
					Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseScanning))
				}
				jobs := listOwnedJobs(ctx, scan.UID, "default")
				Expect(jobs).To(HaveLen(1))
				Expect(jobs[0].Name).To(Equal(originalName))
			})
		})

		Context("Job success path", func() {
			const name = "lifecycle-success"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			AfterEach(func() { cleanup(name) })

			It("parses findings from Job output and transitions to FindingsDetected", func() {
				scan := driveToScanning(ctx, r, key)
				jobs := listOwnedJobs(ctx, scan.UID, "default")
				job := &jobs[0]

				By("Marking the Job Succeeded externally (envtest substitute for Job controller)")
				markJobComplete(ctx, job)

				By("Next reconcile parses output and advances")
				_, scan = drive(ctx, r, key)
				Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFindingsDetected))
				Expect(scan.Status.Findings).To(HaveLen(1))
				Expect(scan.Status.Findings[0].ID).To(Equal("garak:promptinject.HijackHateHumans"))
				Expect(scan.Status.Findings[0].Category).To(Equal("LLM01"))
				Expect(scan.Status.Findings[0].Severity).To(Equal("critical"))
				Expect(scan.Status.FindingsCount).To(BeNumerically("==", 1))
				Expect(conditionStatus(scan, ConditionScanComplete)).To(Equal(metav1.ConditionTrue))
			})

			It("transitions to Failed if reading Job output errors", func() {
				r.ResultsReaderFn = fakeResultsError("simulated log read failure")
				scan := driveToScanning(ctx, r, key)
				jobs := listOwnedJobs(ctx, scan.UID, "default")
				markJobComplete(ctx, &jobs[0])

				_, scan = drive(ctx, r, key)
				Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFailed))
				Expect(conditionReason(scan, ConditionScanComplete)).To(Equal("Failed"))
			})
		})

		Context("Job failure path", func() {
			const name = "lifecycle-failure"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			AfterEach(func() { cleanup(name) })

			It("transitions to Failed and records the Job failure reason in the condition message", func() {
				scan := driveToScanning(ctx, r, key)
				jobs := listOwnedJobs(ctx, scan.UID, "default")

				markJobFailed(ctx, &jobs[0], "BackoffLimitExceeded", "Job has reached the specified backoff limit")

				_, scan = drive(ctx, r, key)
				Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFailed))
				readyCond := meta.FindStatusCondition(scan.Status.Conditions, ConditionReady)
				Expect(readyCond).NotTo(BeNil())
				Expect(readyCond.Status).To(Equal(metav1.ConditionFalse))
				Expect(readyCond.Message).To(ContainSubstring("BackoffLimitExceeded"))
				Expect(readyCond.Message).To(ContainSubstring("backoff limit"))

				By("Failed is terminal: subsequent reconciles are no-ops")
				beforeRV := scan.ResourceVersion
				_, scan = drive(ctx, r, key)
				Expect(scan.ResourceVersion).To(Equal(beforeRV))
			})
		})

		Context("finalizer cleanup on deletion", func() {
			const name = "lifecycle-delete"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			// No AfterEach cleanup — the test itself removes the CR.

			It("deletes the owned Job and lets the apiserver complete the GovernanceScan deletion", func() {
				scan := driveToScanning(ctx, r, key)
				Expect(listOwnedJobs(ctx, scan.UID, "default")).To(HaveLen(1))

				By("Issuing a delete on the GovernanceScan")
				Expect(k8sClient.Delete(ctx, scan)).To(Succeed())

				By("Verifying the CR is still present (finalizer is gating deletion)")
				Expect(k8sClient.Get(ctx, key, scan)).To(Succeed())
				Expect(scan.DeletionTimestamp).NotTo(BeNil())

				By("Reconcile runs finalize, deletes the Job, removes the finalizer, and the apiserver completes deletion")
				driveExpectGone(ctx, r, key)
				Expect(listOwnedJobs(ctx, scan.UID, "default")).To(BeEmpty())
			})
		})

		Context("restart resilience", func() {
			const name = "lifecycle-restart"
			key := types.NamespacedName{Name: name, Namespace: "default"}

			BeforeEach(func() {
				Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			})
			AfterEach(func() { cleanup(name) })

			It("a fresh reconciler instance discovers the existing Job and does not create a duplicate", func() {
				scan := driveToScanning(ctx, r, key)
				originalJobs := listOwnedJobs(ctx, scan.UID, "default")
				Expect(originalJobs).To(HaveLen(1))
				originalName := originalJobs[0].Name

				By("Spinning up a new reconciler instance (simulates a controller restart)")
				freshRecorder := record.NewFakeRecorder(32)
				fresh := &GovernanceScanReconciler{
					Client:          k8sClient,
					Scheme:          k8sClient.Scheme(),
					Recorder:        freshRecorder,
					ResultsReaderFn: fakeResults(sampleScanJSON),
				}

				By("Reconciling several times against the fresh instance")
				for i := 0; i < 3; i++ {
					_, refetched := drive(ctx, fresh, key)
					Expect(refetched.Status.Phase).To(Equal(sentinelv1alpha1.PhaseScanning))
				}

				jobs := listOwnedJobs(ctx, scan.UID, "default")
				Expect(jobs).To(HaveLen(1))
				Expect(jobs[0].Name).To(Equal(originalName))

				By("The fresh instance can also advance the state machine once the Job succeeds")
				markJobComplete(ctx, &jobs[0])
				_, refetched := drive(ctx, fresh, key)
				Expect(refetched.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFindingsDetected))
			})
		})
	})

	Context("full happy path (approval required)", func() {
		const name = "happy-approval"
		key := types.NamespacedName{Name: name, Namespace: "default"}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			// sampleScanJSON produces a critical finding, so remediation
			// will scale this Deployment to zero. Start at 3 replicas so
			// the test can verify the scale-down explicitly.
			makeTargetDeployment(ctx, "llm-service", "default", 3)
		})
		AfterEach(func() { cleanup(name) })

		It("walks every phase with one transition per Reconcile pass and remediates the target", func() {
			scan := driveToScanning(ctx, r, key)
			jobs := listOwnedJobs(ctx, scan.UID, "default")
			markJobComplete(ctx, &jobs[0])

			By("Scanning -> FindingsDetected")
			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFindingsDetected))

			By("FindingsDetected -> AwaitingApproval (with 30s safety-net requeue)")
			res, scan := drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseAwaitingApproval))
			Expect(res.Requeue).To(BeFalse())
			Expect(res.RequeueAfter).To(Equal(approvalPollInterval))

			By("Patching approval and reconciling")
			scan.Status.Approval = &sentinelv1alpha1.ApprovalStatus{
				Decision:  sentinelv1alpha1.DecisionApproved,
				Approver:  "alice@example.test",
				Timestamp: metav1.Now(),
			}
			Expect(k8sClient.Status().Update(ctx, scan)).To(Succeed())

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseApproved))

			By("Approved and Remediating each get their own Reconcile pass")
			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseRemediating))

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseCompleted))
			Expect(conditionStatus(scan, ConditionReady)).To(Equal(metav1.ConditionTrue))

			By("Target Deployment has all annotations")
			dep := refetchDeployment(ctx, "llm-service", "default")
			Expect(dep.Annotations[annotate.AnnotationScanResult]).To(Equal(sentinelv1alpha1.PhaseCompleted))
			Expect(dep.Annotations[annotate.AnnotationApprovedBy]).To(Equal("alice@example.test"))
			Expect(dep.Annotations[annotate.AnnotationFindingsCount]).To(Equal("1"))
			Expect(dep.Annotations[annotate.AnnotationLastScanTime]).NotTo(BeEmpty())

			By("Critical findings caused scale-to-zero + quarantine annotations")
			Expect(dep.Spec.Replicas).NotTo(BeNil())
			Expect(*dep.Spec.Replicas).To(BeNumerically("==", 0))
			Expect(dep.Annotations[annotate.AnnotationQuarantined]).To(Equal("true"))
			Expect(dep.Annotations[annotate.AnnotationQuarantineReason]).To(Equal(annotate.QuarantineReasonCritical))

			By("Terminal phase: subsequent reconciles do not bump resourceVersion")
			beforeRV := scan.ResourceVersion
			_, scan = drive(ctx, r, key)
			Expect(scan.ResourceVersion).To(Equal(beforeRV))

			By("All expected events emitted in order")
			events := drainEvents(recorder)
			expectedReasons := []string{
				EventJobCreated,
				EventScanStarted,
				EventFindingsDetected,
				EventAwaitingApproval,
				EventApprovalGranted,
				EventRemediationStarted,
				EventScanCompleted,
			}
			Expect(events).To(HaveLen(len(expectedReasons)))
			for i, want := range expectedReasons {
				Expect(events[i]).To(ContainSubstring(want), "event %d", i)
			}
		})
	})

	Context("full happy path (auto-approve)", func() {
		const name = "happy-auto"
		key := types.NamespacedName{Name: name, Namespace: "default"}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: false}.build())).To(Succeed())
			makeTargetDeployment(ctx, "llm-service", "default", 2)
		})
		AfterEach(func() { cleanup(name) })

		It("skips AwaitingApproval, records system:auto approval, and remediates", func() {
			scan := driveToScanning(ctx, r, key)
			jobs := listOwnedJobs(ctx, scan.UID, "default")
			markJobComplete(ctx, &jobs[0])

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFindingsDetected))

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseApproved))
			Expect(scan.Status.Approval).NotTo(BeNil())
			Expect(scan.Status.Approval.Approver).To(Equal("system:auto"))
			Expect(conditionReason(scan, ConditionApproved)).To(Equal("AutoApproved"))

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseRemediating))
			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseCompleted))

			By("Deployment was annotated with the auto-approver")
			dep := refetchDeployment(ctx, "llm-service", "default")
			Expect(dep.Annotations[annotate.AnnotationApprovedBy]).To(Equal("system:auto"))
		})
	})

	Context("rejection path", func() {
		const name = "rejection"
		key := types.NamespacedName{Name: name, Namespace: "default"}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
			// Deployment exists, but rejection skips remediation entirely
			// — so it should remain untouched at the end of the test.
			makeTargetDeployment(ctx, "llm-service", "default", 4)
		})
		AfterEach(func() { cleanup(name) })

		It("AwaitingApproval -> Completed when decision=rejected; remediation skipped", func() {
			scan := driveToScanning(ctx, r, key)
			jobs := listOwnedJobs(ctx, scan.UID, "default")
			markJobComplete(ctx, &jobs[0])

			drive(ctx, r, key) // Scanning -> FindingsDetected
			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseAwaitingApproval))

			scan.Status.Approval = &sentinelv1alpha1.ApprovalStatus{
				Decision:  sentinelv1alpha1.DecisionRejected,
				Approver:  "bob@example.test",
				Timestamp: metav1.Now(),
			}
			Expect(k8sClient.Status().Update(ctx, scan)).To(Succeed())

			res, scan := drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseCompleted),
				"rejection should reach Completed (not Failed) — it's a legitimate human decision")
			Expect(res.Requeue).To(BeFalse())
			Expect(res.RequeueAfter).To(BeZero())
			Expect(conditionStatus(scan, ConditionApproved)).To(Equal(metav1.ConditionFalse))
			Expect(conditionReason(scan, ConditionApproved)).To(Equal("Rejected"))
			Expect(conditionStatus(scan, ConditionReady)).To(Equal(metav1.ConditionTrue),
				"a rejected-but-resolved scan is Ready=True; the audit trail records Approved=False")

			By("The target Deployment is untouched — remediation was skipped")
			dep := refetchDeployment(ctx, "llm-service", "default")
			Expect(*dep.Spec.Replicas).To(BeNumerically("==", 4),
				"rejection should not scale the Deployment")
			Expect(dep.Annotations).NotTo(HaveKey(annotate.AnnotationScanResult),
				"rejection should not stamp scan-result annotations")
			Expect(dep.Annotations).NotTo(HaveKey(annotate.AnnotationQuarantined))

			By("Failed-style assertions removed: rejection is not a failure")
			beforeRV := scan.ResourceVersion
			_, scan = drive(ctx, r, key)
			Expect(scan.ResourceVersion).To(Equal(beforeRV),
				"Completed is terminal — re-reconciles must not bump resourceVersion")
		})
	})

	Context("remediation: missing target Deployment", func() {
		const name = "missing-target"
		key := types.NamespacedName{Name: name, Namespace: "default"}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: false}.build())).To(Succeed())
			// No target Deployment created — annotate.Apply should
			// return ErrTargetNotFound and drive the scan to Failed.
		})
		AfterEach(func() { cleanup(name) })

		It("transitions to Failed when no matching Deployment exists", func() {
			scan := driveToScanning(ctx, r, key)
			jobs := listOwnedJobs(ctx, scan.UID, "default")
			markJobComplete(ctx, &jobs[0])

			drive(ctx, r, key) // Scanning -> FindingsDetected
			drive(ctx, r, key) // -> Approved (auto)
			drive(ctx, r, key) // -> Remediating

			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseFailed))
			Expect(conditionStatus(scan, ConditionReady)).To(Equal(metav1.ConditionFalse))
			readyCond := meta.FindStatusCondition(scan.Status.Conditions, ConditionReady)
			Expect(readyCond).NotTo(BeNil())
			Expect(readyCond.Message).To(ContainSubstring("not found"))
		})
	})

	Context("idempotency at blocked state", func() {
		const name = "idempotent"
		key := types.NamespacedName{Name: name, Namespace: "default"}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, scanFixture{name: name, approvalRequired: true}.build())).To(Succeed())
		})
		AfterEach(func() { cleanup(name) })

		It("reconcile at AwaitingApproval is a no-op when no decision recorded", func() {
			scan := driveToScanning(ctx, r, key)
			jobs := listOwnedJobs(ctx, scan.UID, "default")
			markJobComplete(ctx, &jobs[0])

			drive(ctx, r, key) // -> FindingsDetected
			_, scan = drive(ctx, r, key)
			Expect(scan.Status.Phase).To(Equal(sentinelv1alpha1.PhaseAwaitingApproval))
			frozenRV := scan.ResourceVersion

			for i := 0; i < 3; i++ {
				_, scan = drive(ctx, r, key)
				Expect(scan.ResourceVersion).To(Equal(frozenRV),
					"reconcile pass %d should not have written status while blocked", i+1)
			}
		})
	})

	Context("missing resource", func() {
		It("returns no error and no requeue when the CR is gone", func() {
			res, err := r.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "never-existed", Namespace: "default"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Requeue).To(BeFalse())
			Expect(res.RequeueAfter).To(BeZero())
		})
	})
})
