# Sentinel — Battle Scars

Hard-won lessons that should not bite us again. Each entry follows a fixed
four-line format and links to raw evidence under `battle-scars/evidence/`.

**Capture habit: evidence first, fix second.** When something bites, save
the terminal output (or quoted directive, or screenshot) before you start
fixing. Retroactive reconstruction loses fidelity; the moment you start
editing code the original error message gets buried in scroll-back.

Format per entry:

- **Date / session** — when it happened
- **What happened** — concrete observable
- **Why** — root cause, in one or two sentences
- **Fix** — what we changed (file/symbol or commit)
- **Lesson** — what to do differently next time
- **Evidence** — link to the raw artifact

---

## 01 — Kubebuilder v4.14 hard-pins `go 1.25.7` into go.mod

- **Date / session:** 2026-05-21 — Prompt 1 (M0 scaffold)
- **What happened:** Local Go was 1.23.9. `kubebuilder init` succeeded but wrote `go 1.25.7` into `go.mod`. Subsequent `kubebuilder create api` triggered `go: switching to go1.25.10` and auto-downloaded a toolchain into the module cache — a silent and surprising side-effect.
- **Why:** Kubebuilder v4.14.0 (released April 2026) targets Go ≥ 1.25 features. The `go` directive in `go.mod` is the apiserver of toolchain selection; with `GOTOOLCHAIN=auto` (Go 1.21+ default), any build will fetch the matching toolchain regardless of what `go version` reports.
- **Fix:** Accepted the directive as-is; documented the mismatch in CLAUDE.md "Known issues". No code change.
- **Lesson:** Run `head go.mod` immediately after `kubebuilder init` and reconcile the `go` directive against the installed toolchain before you write any code. If the local Go is below the directive, expect transparent toolchain downloads into `$GOMODCACHE/golang.org/toolchain@*` and budget time for that on slow links.
- **Evidence:** [`battle-scars/evidence/01-kubebuilder-go-mod-1257.txt`](battle-scars/evidence/01-kubebuilder-go-mod-1257.txt)

---

## 02 — Auto-downloaded Go toolchain is partial (missing `covdata`)

- **Date / session:** 2026-05-22 — Prompt 2 (state machine tests)
- **What happened:** `make test` exited non-zero even though every Ginkgo spec passed. Output included `go: no such tool "covdata"` for three packages with no test files, and the coverage profile was never written.
- **Why:** The auto-downloaded toolchain at `~/.claude-sentinel-home/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.*.linux-amd64/pkg/tool/linux_amd64/` ships only 7 of the ~15 standard tools — missing `covdata`, `addr2line`, `buildid`, `doc`, `fix`, `nm`, `objdump`, `pack`, `pprof`, `test2json`, `trace`. `go test -coverprofile` invokes `covdata` to merge coverage data from packages without tests; the missing binary fails the merge step but the tests themselves complete first.
- **Fix:** Documented in CLAUDE.md "Known issues" with a workaround invocation (`KUBEBUILDER_ASSETS=… go test ./internal/controller/...`). The proper fix is `go install golang.org/dl/go1.25.10@latest && ~/go/bin/go1.25.10 download` to get a full SDK — but that is an operator action, not a code change.
- **Lesson:** When `make test` exits non-zero, read the *content* of the output rather than the exit code. If the failures all reference toolchain tools, you have a partial-toolchain problem, not a test problem. Re-run with plain `go test ./<pkg>/...` to confirm the specs pass before chasing fictional test bugs.
- **Evidence:** [`battle-scars/evidence/02-covdata-missing.txt`](battle-scars/evidence/02-covdata-missing.txt)

---

## 03 — `bool` + `omitempty` + `kubebuilder:default=true` silently re-defaults `false`

- **Date / session:** 2026-05-22 — Prompt 2 (state machine tests)
- **What happened:** The "approval not required" test expected `Phase=Approved` after the auto-approve transition but saw `Phase=AwaitingApproval`. The field `ApprovalConfig.Required bool` with `json:"required,omitempty"` was the culprit — when set to `false` in Go, JSON marshalling omitted the field, the apiserver applied the `default=true` defaulting, and the round-tripped object came back as `Required=true`.
- **Why:** `omitempty` drops zero values on serialise. The Kubernetes apiserver applies defaulting only to fields absent from the submitted object. The two interact to make explicit `false` indistinguishable from "unset" on the wire, and explicit `false` loses every time.
- **Fix:** Changed `Required` to `*bool` (api/v1alpha1/governancescan_types.go) with a `IsRequired()` helper that treats nil as `true`. The pointer-with-omitempty lets `false` survive the round-trip.
- **Lesson:** Any boolean field with a default of `true` in a CRD must be `*bool`, not `bool`. Same applies for any field where "zero value" and "unset" need to be distinguishable — strings with required=true defaulting, numeric thresholds, etc. The convention is consistent across Kubernetes core types; copy them.
- **Evidence:** [`battle-scars/evidence/03-bool-default-shadowing.txt`](battle-scars/evidence/03-bool-default-shadowing.txt)

---

## 04 — K8s 1.31+ enforces strict Job status validation in envtest

- **Date / session:** 2026-05-22 — Prompt 3 (Job lifecycle tests)
- **What happened:** Eight tests failed with HTTP 422 when calling `k8sClient.Status().Update(ctx, job)` to simulate Job completion. Error: "Job.batch is invalid: [status.completionTime: Required value, status.conditions: Invalid value: cannot set Complete=True condition without the SuccessCriteriaMet=true condition, status.startTime: Required value]".
- **Why:** Kubernetes 1.31 hardened Job status validation. To set `Complete=True` the apiserver now requires `SuccessCriteriaMet=True` to precede it *and* `StartTime`/`CompletionTime` to be populated. Symmetrically, `Failed=True` requires `FailureTarget=True` and `StartTime`. envtest runs a real apiserver, so it enforces all of this — there is no test-mode bypass.
- **Fix:** Rewrote `markJobComplete` and `markJobFailed` in `governancescan_controller_test.go` to set the prerequisite condition and timestamps before the terminal condition.
- **Lesson:** When envtest rejects a `Status().Update`, read the full 422 — it lists every missing/invalid field. Don't simplify mock Job statuses; mirror the apiserver's full state machine. Same enforcement applies to other resources that gained transition-condition validation in recent K8s versions (Pod, etc.).
- **Evidence:** [`battle-scars/evidence/04-job-status-validation-1-31.txt`](battle-scars/evidence/04-job-status-validation-1-31.txt)

---

## 05 — Sibling `It`-blocks under one `Context` leak Job state across tests

- **Date / session:** 2026-05-22 — Prompt 3 (Job lifecycle tests)
- **What happened:** One test passed under `go test ./...` and failed under `make test` (which adds `-coverprofile`). The failing assertion expected `Phase=Failed` but saw `Phase=Scanning`. Two sibling `It`-blocks in the same `Context` shared the CR name `lifecycle-success`; the `listOwnedJobs` helper filtered by label only, so when the second test's `markJobComplete` operated on `jobs[0]` it sometimes marked the *previous* test's leftover Job, while the actual current Job stayed in-flight.
- **Why:** Two layered issues: (1) coverage instrumentation perturbs goroutine scheduling enough to expose the race; (2) the test helper used the label `sentinel.io/governancescan=<name>` as its only filter, but the label is reused across CRs that share a name (which sibling Its do because they share a `Context`-scoped constant). Owner UIDs differ across CRs even when names collide, and the production `findOwnedJob` already filtered by UID for this exact reason.
- **Fix:** `listOwnedJobs(ctx, scanUID, namespace)` in `governancescan_controller_test.go` now mirrors production: list jobs, filter by owner UID. The label-only lookup remains as `listJobsByLabel`, used only by cleanup (where UID is no longer available). Cleanup additionally uses `DeletePropagationBackground` and asserts `BeEmpty()` to fail fast if a leftover survives.
- **Lesson:** Whatever filter the production code uses to identify "owned" resources, tests must use the same. Label-only filtering is fine when label values are unique; the moment two test CRs share a name across an apiserver, you need UID. If a test passes under one runner and fails under another, suspect ordering/state-leakage before suspecting code under test.
- **Evidence:** [`battle-scars/evidence/05-sibling-it-job-state-leak.txt`](battle-scars/evidence/05-sibling-it-job-state-leak.txt)

---

## 06 — Garak terminology inversion: `passed` = model held, `failed` = breach

- **Date / session:** 2026-05-22 — Prompt 4 (Garak parser)
- **What happened:** When writing `ParseGarakOutput`, the intuitive read of the eval entry `{"passed": 5, "failed": 95}` would have been "95 attempts failed (model held)" — i.e., the model is mostly safe. The real semantic is the opposite: `passed` means the model successfully resisted the attack; `failed` means the attacker bypassed safety. A 95-failed probe is *bad* news, not good news.
- **Why:** Garak's terminology is from the probe's point of view, not the model's. The probe "passes" when it doesn't succeed in compromising the model and "fails" when it doesn't compromise — wait, no, the other way: the probe passes when it doesn't elicit unsafe output, fails when it does. Honestly this is exactly why this is in the battle scars file: even writing the explanation, I have to slow down and check direction. The terminology is genuinely confusing.
- **Fix:** Header comment in `internal/detector/garak/parser.go` calls this out at the top of the file, and `ParseGarakOutput` derives `successRate = failed / total` with a comment naming it as "the attacker's success rate".
- **Lesson:** When parsing third-party security tool output, write the terminology mapping at the top of the parser before writing any logic. Severity direction bugs in a security tool are hard to spot in code review because the variable names look fine — the inversion lives in the domain, not the code.
- **Evidence:** [`battle-scars/evidence/06-garak-terminology.txt`](battle-scars/evidence/06-garak-terminology.txt) (no terminal output — domain-derived from Garak docs)

---

## 09 — Sandbox can't reach the user's SSH agent or `~/.ssh/config`

- **Date / session:** 2026-05-22 — M0 push attempt
- **What happened:** Tried `git fetch origin` after setting the remote URL to `git@github.com-personal:BashiM1/sentinel.git`. Got `git@github.com: Permission denied (publickey)`. The error reports the *bare* host (`github.com`) because ssh couldn't resolve the `github.com-personal` alias.
- **Why:** The sandbox runs with `HOME=/home/bashm1/.claude-sentinel-home/`. The user's real ssh config and keys live in `/home/bashm1/.ssh/`. Ssh reads the empty config in the fake home, can't find the alias, falls back to bare `github.com` with no identity. Separately, `SSH_AUTH_SOCK` from the user's terminal isn't inherited, so `ssh-add -l` returns "Could not open a connection".
- **Fix:** No code change. The user runs `git push` from their real terminal where their agent and config are live. From inside the sandbox I can edit local state and `git remote set-url` but I cannot do anything that talks to a private remote over SSH.
- **Lesson:** Before promising to run any `git push` / `git fetch` / `git pull` / `gh clone` against a private remote, check `ssh-add -l` and the existence of `~/.ssh/config`. If either is missing, surface the limit *before* the user is waiting on a network operation that won't happen.
- **Evidence:** [`battle-scars/evidence/09-sandbox-ssh-isolation.txt`](battle-scars/evidence/09-sandbox-ssh-isolation.txt)

---

## 08 — `go get` DNS-times-out in this sandbox; check `go.sum` first

- **Date / session:** 2026-05-22 — Prompt 6 (audit subsystem)
- **What happened:** Ran `go get github.com/google/uuid` to add a dep the user asked for. Failed with `dial tcp: lookup proxy.golang.org on 127.0.0.53:53: read udp ...: i/o timeout` — the sandbox has no outbound DNS to the Go proxy.
- **Why:** The dev environment runs without internet access to public package proxies. Even though Go's defaults assume `GOPROXY=https://proxy.golang.org,direct`, the network layer blocks it.
- **Fix:** Checked `go.sum` first — `google/uuid v1.6.0` was already an indirect transitive dep (pulled in by client-go or controller-runtime). Just imported it and ran `go mod tidy` afterwards to promote it to a direct require. No network round-trip needed.
- **Lesson:** Before running `go get` in this sandbox, `grep <pkg> go.sum`. If it's already there, the module cache has it — just import and `go mod tidy`. Reserve `go get` for genuinely-new deps and expect those to fail (would need either a registered private mirror or to drop the requirement). Same pattern applies to any other tool that does proxy round-trips by default (npm, pip, cargo).
- **Evidence:** [`battle-scars/evidence/08-go-get-dns-timeout-sandbox.txt`](battle-scars/evidence/08-go-get-dns-timeout-sandbox.txt)

---

## 07 — One phase transition per Reconcile, always

- **Date / session:** 2026-05-22 — Prompt 2 (state machine design)
- **What happened:** While designing the state machine I considered collapsing two trivially-determined transitions (Approved → Remediating → Completed) into one Reconcile pass. The user vetoed: "one phase transition per Reconcile call, always. Approved and Remediating are separate phases, each written in their own Reconcile pass with an immediate requeue between them. This makes every transition independently auditable when we wire `pkg/audit/` in Prompt 7."
- **Why:** Prompt 7 will add HMAC-chained audit entries, one per reconcile. If two transitions land in one pass they either collapse into a single chain entry (loses one transition's evidence) or force the audit layer to inspect controller state to split them (couples layers that should stay independent). One-transition-per-Reconcile keeps the chain-entry boundary identical to the reconcile boundary, which is the natural seam.
- **Fix:** The `advance()` switch in `governancescan_controller.go` is structured so every arm mutates exactly one phase. The happy-path test asserts that `Approved → Remediating` and `Remediating → Completed` are separate reconcile calls. Memory `feedback_one_transition_per_reconcile.md` carries the rule across sessions.
- **Lesson:** Architectural rules that are easy to "optimise away" need their *reason* recorded somewhere durable, not just the rule. The temptation to bundle "obvious" transitions is real and the audit-chain rationale is the only thing that makes the cost of bundling visible.
- **Evidence:** [`battle-scars/evidence/07-one-transition-per-reconcile.txt`](battle-scars/evidence/07-one-transition-per-reconcile.txt) (no terminal output — quoted user directive)
