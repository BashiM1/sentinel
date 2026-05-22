#!/bin/bash
# reject.sh — reject a GovernanceScan in AwaitingApproval. The scan ends in
# Completed with Approved=False; no remediation runs. The rejection is the
# auditable record of the human decision.
# Usage: reject.sh <scan-name>
set -euo pipefail

SCAN=${1:?Usage: reject.sh <scan-name>}
APPROVER=$(kubectl config current-context)
kubectl patch governancescan "$SCAN" --type merge \
  --subresource status \
  -p "{\"status\":{\"approval\":{\"decision\":\"rejected\",\"approver\":\"$APPROVER\"}}}"
