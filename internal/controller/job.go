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
	"io"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
)

// LabelGovernanceScan tags every Job spawned by the operator with the name of
// the GovernanceScan that owns it. The label lets the reconciler list owned
// Jobs cheaply (instead of scanning every Job in the namespace) while the
// owner reference remains the authoritative source of truth — see
// findOwnedJob for the cross-check.
//
// Defined in this package (the reader) rather than in internal/detector/garak
// (the writer) so that swapping in a second scanner later doesn't require
// the controller to know about scanner-specific packages. The garak Job
// builder receives the label via its extraLabels parameter.
const LabelGovernanceScan = "sentinel.io/governancescan"

// findOwnedJob returns the Job spawned for this scan, or nil if none exists.
// It filters by label first (cheap server-side selector) then double-checks
// the owner UID, so a stray Job that happens to share the label but was not
// created by this CR is ignored.
func findOwnedJob(ctx context.Context, c client.Client, scan *sentinelv1alpha1.GovernanceScan) (*batchv1.Job, error) {
	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs,
		client.InNamespace(scan.Namespace),
		client.MatchingLabels{LabelGovernanceScan: scan.Name},
	); err != nil {
		return nil, err
	}
	for i := range jobs.Items {
		job := &jobs.Items[i]
		for _, owner := range job.OwnerReferences {
			if owner.UID == scan.UID {
				return job, nil
			}
		}
	}
	return nil, nil
}

// jobSucceeded reports whether a Job has reached the Complete condition. We
// trust the condition over `.status.succeeded` count to stay consistent with
// the apiserver's semantics during Job retries.
func jobSucceeded(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// jobFailed reports whether a Job has exhausted its backoff and given up.
// JobFailureTarget signals an upcoming failure but is not yet terminal, so we
// look at JobFailed only.
func jobFailed(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// jobFailureReason renders the JobFailed condition's reason/message for
// inclusion in Status.Conditions on the GovernanceScan. Returns "unknown" if
// no JobFailed condition is present.
func jobFailureReason(job *batchv1.Job) string {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			if c.Reason == "" && c.Message == "" {
				return "JobFailed"
			}
			if c.Message == "" {
				return c.Reason
			}
			return fmt.Sprintf("%s: %s", c.Reason, c.Message)
		}
	}
	return "unknown"
}

// readJobLogs is the default ResultsReader. It locates the Pod that ran the
// Job via the standard `batch.kubernetes.io/job-name` label, picks the first
// Succeeded Pod, and returns its logs. envtest does not run Pods so tests
// must inject a ResultsReader override; this function is exercised only
// against a real cluster.
func readJobLogs(ctx context.Context, clientset kubernetes.Interface, job *batchv1.Job) ([]byte, error) {
	pods, err := clientset.CoreV1().Pods(job.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("batch.kubernetes.io/job-name=%s", job.Name),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods for job %s: %w", job.Name, err)
	}
	var target *corev1.Pod
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodSucceeded {
			target = &pods.Items[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no Succeeded pod found for job %s", job.Name)
	}
	stream, err := clientset.CoreV1().Pods(target.Namespace).
		GetLogs(target.Name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream logs for pod %s: %w", target.Name, err)
	}
	defer stream.Close()
	return io.ReadAll(stream)
}
