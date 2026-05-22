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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase values for GovernanceScanStatus.Phase. The reconciler advances a
// GovernanceScan through these states deterministically.
const (
	PhasePending          = "Pending"
	PhaseScanning         = "Scanning"
	PhaseFindingsDetected = "FindingsDetected"
	PhaseAwaitingApproval = "AwaitingApproval"
	PhaseApproved         = "Approved"
	PhaseRemediating      = "Remediating"
	PhaseCompleted        = "Completed"
	PhaseFailed           = "Failed"
)

// Approval decisions recorded on GovernanceScanStatus.Approval.
const (
	DecisionApproved = "approved"
	DecisionRejected = "rejected"
)

// ScanTarget identifies the inference endpoint to scan. The endpoint must
// already exist in the cluster and be reachable from the scanner Job's pod.
type ScanTarget struct {
	// service is the cluster-internal DNS name of the target Service (for
	// example, llm-service.ml.svc.cluster.local).
	// +required
	Service string `json:"service"`

	// port is the TCP port on the target Service.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ScannerConfig selects which scanner runs and how often.
type ScannerConfig struct {
	// type names the scanner implementation. Only "garak" is supported in M0.
	// +kubebuilder:default=garak
	// +optional
	Type string `json:"type,omitempty"`

	// schedule, if set, runs the scanner on a cron schedule. Leaving this
	// empty means the scan runs once when the resource is reconciled.
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// profile names a scanner-specific configuration bundle (for example,
	// "owasp-llm-top10" for Garak).
	// +optional
	Profile string `json:"profile,omitempty"`
}

// ApprovalConfig controls whether remediation requires a human decision.
type ApprovalConfig struct {
	// required gates remediation behind an approval decision when true.
	// Defaults to true at the apiserver via the kubebuilder default marker.
	// The pointer type matters: a plain `bool` with `omitempty` would erase
	// an explicit `false` on the wire, which the apiserver would then re-
	// default back to `true`. Pointer + omitempty lets callers express "I
	// explicitly mean false" by setting the value, distinct from "I did
	// not specify it" by leaving it nil.
	// +kubebuilder:default=true
	// +optional
	Required *bool `json:"required,omitempty"`
}

// IsRequired reports whether approval is required for this scan. Unset means
// required (matches the kubebuilder default), so the reconciler can call this
// method on a freshly-fetched object without worrying about the pointer.
func (a ApprovalConfig) IsRequired() bool {
	if a.Required == nil {
		return true
	}
	return *a.Required
}

// AuditConfig selects the backend that receives HMAC-chained audit entries.
type AuditConfig struct {
	// backend names the audit sink. Only "local" (filesystem) is supported
	// in M0. GCS and S3 backends are Phase 2.
	// +kubebuilder:validation:Enum=local
	// +kubebuilder:default=local
	// +optional
	Backend string `json:"backend,omitempty"`

	// path is the on-disk location for the local backend. Required when
	// backend is "local".
	// +optional
	Path string `json:"path,omitempty"`
}

// GovernanceScanSpec is the desired state of a governance scan.
type GovernanceScanSpec struct {
	// +required
	Target ScanTarget `json:"target"`

	// +required
	Scanner ScannerConfig `json:"scanner"`

	// +optional
	Approval ApprovalConfig `json:"approval,omitempty"`

	// +required
	Audit AuditConfig `json:"audit"`
}

// Finding is a single issue produced by the scanner. The ID is stable for
// a given Category+Description combination so that re-scans can correlate.
type Finding struct {
	// +required
	ID string `json:"id"`

	// category is the taxonomy bucket (for example, "LLM01" for the OWASP
	// LLM Top 10 category for prompt injection).
	// +required
	Category string `json:"category"`

	// +kubebuilder:validation:Enum=critical;high;medium;low
	// +required
	Severity string `json:"severity"`

	// +required
	Description string `json:"description"`
}

// ApprovalStatus records the decision that gates remediation. Binary in M0:
// approve-all or reject-all. Per-finding granularity is Phase 2.
type ApprovalStatus struct {
	// +kubebuilder:validation:Enum=approved;rejected
	// +required
	Decision string `json:"decision"`

	// +required
	Approver string `json:"approver"`

	// +required
	Timestamp metav1.Time `json:"timestamp"`
}

// GovernanceScanStatus is the observed state of a governance scan.
type GovernanceScanStatus struct {
	// phase is the current point in the scan lifecycle. The reconciler is
	// the sole writer of this field.
	// +kubebuilder:validation:Enum=Pending;Scanning;FindingsDetected;AwaitingApproval;Approved;Remediating;Completed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// findingsCount mirrors len(Findings). It exists so the additionalPrinterColumn
	// "Findings" can render a scalar count without clients having to evaluate the
	// array length. The reconciler is the sole writer and must keep it in sync.
	// +optional
	FindingsCount int32 `json:"findingsCount,omitempty"`

	// +optional
	Approval *ApprovalStatus `json:"approval,omitempty"`

	// auditRef is the hash of the most recent audit entry for this scan.
	// Combined with the audit chain it lets verifiers prove that no entries
	// referencing this scan have been tampered with.
	// +optional
	AuditRef string `json:"auditRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Findings",type=integer,JSONPath=`.status.findingsCount`
// +kubebuilder:printcolumn:name="LastScan",type=date,JSONPath=`.status.lastScanTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GovernanceScan is the Schema for the governancescans API.
type GovernanceScan struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GovernanceScanSpec `json:"spec"`

	// +optional
	Status GovernanceScanStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GovernanceScanList contains a list of GovernanceScan.
type GovernanceScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GovernanceScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GovernanceScan{}, &GovernanceScanList{})
}
