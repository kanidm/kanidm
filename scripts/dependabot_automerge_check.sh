#!/bin/bash

if [ -z "$1" ]; then
    echo "Specify the PR URL"
    exit 1
fi

PR_URL="$1"

# are we good?
CONCLUSIONS="$(gh pr status --json statusCheckRollup | jq '.currentBranch | .[] | .[] | select(.conclusion != "SUCCESS") | select(.conclusion != "NEUTRAL")| {status: .status, workfFlowName: .workFlowName, conclusion: .conclusion}')"
# check approval
APPROVED="$(gh pr status --json reviewDecision -q .currentBranch.reviewDecision)"

# sets the upstream metadata for `gh pr status`
gh pr checkout "$PR_URL"
if [ "${APPROVED}" != "APPROVED" ]; then
    echo "PR not approved!"
    exit 1
fi

if [ "$(echo "${CONCLUSIONS}" | wc -l)" -eq 0 ]; then
    gh pr review --approve "$PR_URL"
else
    echo "Already running or failed: ${CONCLUSIONS}";
fi
