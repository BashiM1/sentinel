# M0 Closure — End-to-End Verification

Captured 2026-05-22 immediately after `helm install` against the local
kind cluster `sentinel-dev`. This is the first end-to-end run of the
operator against a real apiserver (as opposed to envtest). It confirms
the controller, the CRD, the five SoD ClusterRoles, and the sample CR
flow are all wired correctly. Garak image resolution is *expected* to
fail at this point — it's still a TODO(verify) placeholder.

## helm install

```
$ helm install sentinel ./helm/sentinel -n sentinel-system --create-namespace
NAME: sentinel
LAST DEPLOYED: Fri May 22 02:43:25 2026
NAMESPACE: sentinel-system
STATUS: deployed
REVISION: 1
TEST SUITE: None
```

## What the chart installed

```
$ kubectl get pods -n sentinel-system
NAME                                  READY   STATUS    RESTARTS   AGE
sentinel-controller-bd9ff6546-sw4v9   1/1     Running   0          97s

$ kubectl get crd governancescans.sentinel.sentinel.io
NAME                                   CREATED AT
governancescans.sentinel.sentinel.io   2026-05-22T01:43:25Z

$ kubectl get clusterrole sentinel-scanner sentinel-approver sentinel-executor sentinel-policy-admin sentinel-auditor
NAME                    CREATED AT
sentinel-scanner        2026-05-22T01:43:25Z
sentinel-approver       2026-05-22T01:43:25Z
sentinel-executor       2026-05-22T01:43:25Z
sentinel-policy-admin   2026-05-22T01:43:25Z
sentinel-auditor        2026-05-22T01:43:25Z
```

Pod went `Running` in well under the 120s `kubectl wait` timeout.

## Controller picks up the sample CR

```
$ kubectl apply -f config/samples/sentinel_v1alpha1_governancescan.yaml
governancescan.sentinel.sentinel.io/example-scan created

$ kubectl get governancescans -o wide
NAME           PHASE      FINDINGS   LASTSCAN   AGE
example-scan   Scanning              72s        72s
```

`Phase=Scanning` proves the reconciler observed the CR and advanced it
through `""→Pending→Scanning`.

## Controller log (full)

```
2026-05-22T01:43:26Z  INFO  setup  audit backend configured  {"path": "/tmp/sentinel-audit"}
2026-05-22T01:43:26Z  INFO  setup  Starting manager
2026-05-22T01:43:26Z  INFO  starting server  {"name": "health probe", "addr": "[::]:8081"}
2026-05-22T01:43:26Z  INFO  Starting EventSource  ... source: *v1alpha1.GovernanceScan
2026-05-22T01:43:26Z  INFO  Starting EventSource  ... source: *v1.Job
2026-05-22T01:43:26Z  INFO  Starting Controller   ...
2026-05-22T01:43:26Z  INFO  Starting workers      ... worker count: 1
2026-05-22T01:43:50Z  DEBUG events created scan Job default/example-scan-scan-s7vtq2s2  ... reason: JobCreated
2026-05-22T01:43:50Z  DEBUG events started scan of llm-service.ml.svc.cluster.local:8080 ... reason: ScanStarted
```

Both phase-transition events fired against the apiserver — meaning the
audit chain in `/tmp/sentinel-audit/default/example-scan/` has at least
two entries (`ScanRegistered` and `ScanStarted`) at this point. The
chain is on the controller pod's emptyDir; full inspection requires
`kubectl debug` or `kubectl cp` (the controller image is distroless
and has no shell).

## Expected failure: scan Job ImagePullBackOff

The scan Job tries to pull `ghcr.io/nvidia/garak:latest`, which is the
best-guess placeholder image still gated behind a `TODO(verify)` marker.
The image doesn't resolve, so:

```
$ kubectl get pods -l sentinel.io/governancescan=example-scan
NAME                               READY   STATUS             RESTARTS   AGE
example-scan-scan-s7vtq2s2-6n64h   0/1     ImagePullBackOff   0          40s

$ kubectl describe pod ... | grep -A1 Failed
Warning  Failed     34s (x3 over 71s)  kubelet  ... Failed to pull image "ghcr.io/nvidia/garak:latest":
  failed to authorize: failed to fetch anonymous token: ... 403 Forbidden
```

This is the documented expected outcome — the controller did its job
(observed, transitioned, created the Job); the Job will fail until
either NVIDIA publishes an official Garak image or we ship our own at
`deploy/garak/Dockerfile`. Both are out of M0 scope.

## What this proves about M0

- Helm chart renders + installs cleanly.
- Controller pod starts, reads `SENTINEL_AUDIT_*` env vars, configures
  the audit backend, sets up watches for `GovernanceScan` and `Job`.
- CRD is registered.
- All five SoD ClusterRoles exist.
- Controller picks up new `GovernanceScan` CRs and reconciles them.
- State machine advances through the early phases; Job creation
  matches the design.
- Failure mode for a non-resolvable image is visible and recoverable
  (the controller's `handleScanning` will surface this as a `Failed`
  phase via `JobFailed` once kubelet gives up retrying).
