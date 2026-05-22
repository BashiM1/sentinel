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

// Package annotate is the single remediation handler shipped in M0.
// "Annotate" is the primary action; scale-to-zero is a conditional add-on
// triggered by critical findings. The package is named for the always-on
// behaviour, not the conditional one. If a second remediation handler is
// ever added, extract a Remediator interface then — not before.
package annotate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
)

// Annotation keys written onto the target Deployment by Apply.
const (
	AnnotationLastScanTime     = "sentinel.io/last-scan-time"
	AnnotationScanResult       = "sentinel.io/scan-result"
	AnnotationApprovedBy       = "sentinel.io/approved-by"
	AnnotationFindingsCount    = "sentinel.io/findings-count"
	AnnotationQuarantined      = "sentinel.io/quarantined"
	AnnotationQuarantineReason = "sentinel.io/quarantine-reason"

	// QuarantineReasonCritical is the value written into
	// AnnotationQuarantineReason when scale-to-zero is triggered by a
	// critical finding.
	QuarantineReasonCritical = "Critical findings detected"
)

// ErrTargetNotFound is the sentinel returned by Apply when the target
// Deployment does not exist. The reconciler uses errors.Is to distinguish
// this (terminal — Phase=Failed) from transient errors (returned to
// controller-runtime for retry with backoff).
var ErrTargetNotFound = errors.New("target Deployment not found")

// Apply runs the remediation defined by the M0 spec:
//
//  1. Look up the target Deployment matching scan.Spec.Target.Service.
//  2. Always write four "what happened" annotations onto it.
//  3. If any finding has severity "critical", scale Replicas to 0 and
//     add two "quarantine" annotations.
//
// The function is idempotent: re-running it sets the same annotation
// values and scales to the same replica count, so a transient apiserver
// failure that triggers a controller-runtime retry will not double-scale
// or skip annotations.
func Apply(ctx context.Context, c client.Client, scan *sentinelv1alpha1.GovernanceScan) error {
	name, namespace := parseServiceFQDN(scan.Spec.Target.Service, scan.Namespace)
	if name == "" {
		return fmt.Errorf("scan.spec.target.service is empty; cannot identify a target Deployment")
	}

	var dep appsv1.Deployment
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(ctx, key, &dep); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%w: %s/%s", ErrTargetNotFound, namespace, name)
		}
		return fmt.Errorf("get target Deployment %s: %w", key, err)
	}

	if dep.Annotations == nil {
		dep.Annotations = map[string]string{}
	}

	// Always-on annotations. LastScanTime may be nil if a future flow
	// reaches Remediating without a populated timestamp; emit the empty
	// string rather than panicking, and write the actual key/value the
	// reconciler set on the GovernanceScan.
	if scan.Status.LastScanTime != nil {
		dep.Annotations[AnnotationLastScanTime] = scan.Status.LastScanTime.UTC().Format("2006-01-02T15:04:05Z")
	} else {
		dep.Annotations[AnnotationLastScanTime] = ""
	}
	// Apply is only called on the approval path, after the reconciler has
	// decided the scan will reach Completed. Encoding "Completed" rather
	// than scan.Status.Phase (which is "Remediating" at the moment Apply
	// runs) keeps the annotation meaningful from the workload owner's
	// point of view.
	dep.Annotations[AnnotationScanResult] = sentinelv1alpha1.PhaseCompleted
	if scan.Status.Approval != nil {
		dep.Annotations[AnnotationApprovedBy] = scan.Status.Approval.Approver
	}
	dep.Annotations[AnnotationFindingsCount] = strconv.FormatInt(int64(scan.Status.FindingsCount), 10)

	// Conditional quarantine.
	if hasCritical(scan.Status.Findings) {
		dep.Spec.Replicas = ptr.To(int32(0))
		dep.Annotations[AnnotationQuarantined] = "true"
		dep.Annotations[AnnotationQuarantineReason] = QuarantineReasonCritical
	}

	if err := c.Update(ctx, &dep); err != nil {
		return fmt.Errorf("update target Deployment %s: %w", key, err)
	}
	return nil
}

func hasCritical(findings []sentinelv1alpha1.Finding) bool {
	for _, f := range findings {
		if f.Severity == "critical" {
			return true
		}
	}
	return false
}

// parseServiceFQDN extracts the Deployment name and namespace from a Kubernetes
// service reference. Three input shapes are supported:
//
//   - "llm-service"                          (short name; uses defaultNamespace)
//   - "llm-service.ml"                       (namespaced shortcut)
//   - "llm-service.ml.svc.cluster.local"     (full FQDN)
//
// The convention assumes the Deployment shares its name with the Service,
// which is the most common pattern. If your setup uses a different
// convention (e.g. Service selectors pointing at differently-named
// Deployments), this is where to add support.
func parseServiceFQDN(service, defaultNamespace string) (name, namespace string) {
	parts := strings.SplitN(service, ".", 3)
	name = parts[0]
	if len(parts) >= 2 && parts[1] != "" {
		namespace = parts[1]
	} else {
		namespace = defaultNamespace
	}
	return
}
