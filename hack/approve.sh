#!/bin/bash
# approve.sh — approve a GovernanceScan that is in AwaitingApproval phase.
# Usage: approve.sh <scan-name>
#
# The approver is taken from `kubectl config current-context` for now. See the
# TODO in checkApproval (internal/controller/governancescan_controller.go) for
# the production hardening path (admission webhook that validates against the
# real user-info on the request).
set -euo pipefail

SCAN=${1:?Usage: approve.sh <scan-name>}
APPROVER=$(kubectl config current-context)
kubectl patch governancescan "$SCAN" --type merge \
  --subresource status \
  -p "{\"status\":{\"approval\":{\"decision\":\"approved\",\"approver\":\"$APPROVER\"}}}"
