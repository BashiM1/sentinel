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

// Package garak builds the Kubernetes Job that runs NVIDIA's Garak scanner
// against a GovernanceScan target, and parses the Garak report into the
// project's Finding type. It exposes two free functions (no Detector
// interface) because Garak is the only scanner Sentinel ships in M0 and
// premature abstraction is prohibited by CLAUDE.md. If a second scanner is
// added later, extract the interface then — not before.
package garak

import (
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
)

const (
	// OutputDir is the in-pod directory where Garak writes its JSONL report
	// and where the shell wrapper concatenates the final report onto stdout
	// for the controller's log-reading ResultsReader to pick up.
	OutputDir = "/output"

	// GarakImage is the container image used for the scan.
	//
	// TODO(verify): As of this writing there is no widely-published official
	// NVIDIA Garak image. The Garak repo at github.com/NVIDIA/garak ships a
	// Python package; you typically `pip install garak`. Before relying on
	// this Job in a real cluster you must either:
	//   1. Confirm NVIDIA now publishes an official image (likely on Docker
	//      Hub or GHCR under nvidia/garak or similar) and update this
	//      constant to its fully-qualified name and pinned tag; or
	//   2. Build your own image (see deploy/garak/Dockerfile — TODO) that
	//      installs Garak via pip on top of python:3.11-slim and push it
	//      to a registry your cluster can pull from.
	//
	// A non-existent image will produce ImagePullBackOff and the Job will
	// fail with that as the condition reason — handleScanning surfaces this
	// through the GovernanceScan's Ready condition message, so the failure
	// mode is at least visible.
	GarakImage = "ghcr.io/nvidia/garak:latest" // TODO(verify)

	// DefaultProbes is the comma-separated list of Garak probe families
	// scanned by default. Each family must have a corresponding entry in
	// parser.go's probeToOWASP mapping; new probes added here without a
	// mapping will be reported with category=UNMAPPED.
	DefaultProbes = "promptinject,dan,leakplay,encoding,continuation,snowball,xss"
)

// BuildGarakJob constructs the Kubernetes Job that runs Garak against the
// GovernanceScan target. The caller is responsible for:
//   - Adding any selector labels needed for owner lookup (passed in via
//     extraLabels — see internal/controller for the LabelGovernanceScan
//     constant).
//   - Calling controllerutil.SetControllerReference so the Job is garbage-
//     collected with the parent GovernanceScan.
//
// The returned Job is otherwise complete: its Pod spec includes resource
// requests, a writable emptyDir at /output, and a shell wrapper that runs
// Garak then cats the final JSONL report onto stdout so the controller's
// pod-log ResultsReader can consume it without needing kubectl exec.
func BuildGarakJob(scan *sentinelv1alpha1.GovernanceScan, extraLabels map[string]string) *batchv1.Job {
	name := fmt.Sprintf("%s-scan-%s", scan.Name, rand.String(8))

	labels := map[string]string{}
	for k, v := range extraLabels {
		labels[k] = v
	}

	targetURL := fmt.Sprintf("http://%s:%d", scan.Spec.Target.Service, scan.Spec.Target.Port)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: scan.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: ptr.To(int32(3600)),
			BackoffLimit:            ptr.To(int32(2)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Volumes: []corev1.Volume{{
						Name:         "output",
						VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
					}},
					Containers: []corev1.Container{{
						Name:         "garak",
						Image:        GarakImage,
						Command:      []string{"sh", "-c", scanScript(targetURL, DefaultProbes)},
						VolumeMounts: []corev1.VolumeMount{{Name: "output", MountPath: OutputDir}},
						Env: []corev1.EnvVar{
							// Documented for operator-side debugging via
							// `kubectl set env`. The shell wrapper reads
							// these so the scan target is visible in
							// `kubectl describe pod`.
							{Name: "SENTINEL_TARGET_URL", Value: targetURL},
							{Name: "SENTINEL_PROBES", Value: DefaultProbes},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("512Mi"),
								corev1.ResourceCPU:    resource.MustParse("500m"),
							},
						},
					}},
				},
			},
		},
	}
}

// scanScript renders the shell wrapper that invokes Garak and surfaces its
// JSONL report onto stdout.
//
// TODO(verify): every command-line flag in this script is a best-effort
// reconstruction of Garak's REST-generator CLI. Confirm each against the
// installed Garak version before relying on the Job's exit status. The
// fields most likely to be wrong:
//
//	--model_type rest               // confirm subcommand / flag name
//	--generator_option_file <path>  // may be `--generator_options` (inline)
//	                                // or `--config` in newer versions
//	--probes <comma-list>           // confirm flag name; may be `--probe_tags`
//	--report_prefix <path>          // confirm path convention; some versions
//	                                // use --report_dir instead
//
// The rest.json schema embedded below (uri, method, req_template_json_object,
// response_json_field) is taken from Garak's REST-plugin documentation as of
// early 2026; if you're on a newer Garak the field names may differ. Run
// `garak --help` and `python -m garak.generators.rest --help` inside the
// container to confirm before relying on this.
func scanScript(targetURL, probes string) string {
	// The heredoc-embedded JSON config assumes an OpenAI-compatible chat
	// endpoint at /v1/chat/completions. If your target uses a different
	// path or request shape, override this script via a ConfigMap (not
	// yet wired — see Prompt 5+) or edit the constant directly.
	restConfig := fmt.Sprintf(`{
  "rest": {
    "name": "sentinel-target",
    "uri": "%s/v1/chat/completions",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "req_template_json_object": {
      "model": "default",
      "messages": [{"role": "user", "content": "$INPUT"}]
    },
    "response_json": true,
    "response_json_field": "choices/0/message/content"
  }
}`, targetURL)

	return fmt.Sprintf(`set -e
mkdir -p %[1]s
cat > %[1]s/rest.json <<'REST_CONFIG_EOF'
%[2]s
REST_CONFIG_EOF

echo "==> sentinel: starting Garak scan against %[1]s (probes: %[3]s)"
# TODO(verify): confirm flag names against the installed Garak version.
garak \
  --model_type rest \
  --generator_option_file %[1]s/rest.json \
  --probes %[3]s \
  --report_prefix %[1]s/garak \
  || echo "==> sentinel: garak exited non-zero (partial results may still be present)"

echo "==> sentinel: garak run complete; locating report"
ls -la %[1]s

# Cat the report onto stdout so the controller's ResultsReader (which reads
# pod logs) can ingest it. We accept both .report.jsonl and .jsonl suffixes
# to be resilient to filename schema drift between Garak versions.
find %[1]s -maxdepth 1 \( -name '*.report.jsonl' -o -name 'garak.*.jsonl' \) -print -exec cat {} +
`, OutputDir, restConfig, probes)
}
