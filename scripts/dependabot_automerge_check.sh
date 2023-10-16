#!/bin/bash

if [ -z "$1" ]; then
    echo "Specify the PR URL"
    exit 1
fi

PR_URL="$1"

# sets the upstream metadata for `gh pr status`
gh pr checkout "$PR_URL"


# are we good?
echo "Checking Conclusions"
CONCLUSIONS="$(gh pr status --json statusCheckRollup | jq '.currentBranch | .[] | .[] | select(.conclusion != "SUCCESS") | select(.conclusion != "NEUTRAL")| {status: .status, workfFlowName: .workFlowName, conclusion: .conclusion}')"



if [ "$(echo "${CONCLUSIONS}" | wc -l)" -eq 0 ]; then
    gh pr review --approve "$PR_URL"
else
    echo "Already running or failed: ${CONCLUSIONS}";
fi

if [ "${APPROVED}" != "APPROVED" ]; then
    echo "PR isn't approved!"
    exit 0
fi

# check approval
echo "Checking if already approved...."
APPROVED="$(gh pr status --json reviewDecision -q .currentBranch.reviewDecision)"