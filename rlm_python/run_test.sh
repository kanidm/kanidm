#!/bin/bash

# set -e

TEST_RADIUS_USER="test_radius_user"
RADIUS_GROUP="radius_access_allowed"

#shellcheck disable=SC2162
read -p "Enter idm_admin password: " KANIDM_PASSWORD

export KANIDM_PASSWORD
cargo run --bin kanidm login --name idm_admin
unset KANIDM_PASSWORD

GROUP_CREATE_OUTPUT="$(KANIDM_NAME=idm_admin cargo run --bin kanidm group create "${RADIUS_GROUP}" 2>&1)"
GROUP_CREATE_RESULT="$(echo "${GROUP_CREATE_OUTPUT}" | grep -c -E '(Successfully created|AttrUnique)')"

if [ "${GROUP_CREATE_RESULT}" -eq 1 ]; then
    echo "Group ${RADIUS_GROUP} created"
else
    echo "Something failed during group creation"
    exit 1
fi


echo "Creating RADIUS test user ${TEST_RADIUS_USER}"
USER_CREATE_OUTPUT="$(KANIDM_NAME=idm_admin cargo run --bin kanidm service-account create "${TEST_RADIUS_USER}" "${TEST_RADIUS_USER}")"

USER_CREATE_RESULT="$(echo "${USER_CREATE_OUTPUT}" | grep -c -E '(Successfully created|AttrUnique)')"
if [ "${USER_CREATE_RESULT}" -eq 1 ]; then
    echo "User ${TEST_RADIUS_USER} created"
else
    echo "Something failed during service account creation"
    exit 1
fi


echo "Creating API Token..."
TOKEN_EXPIRY="$(date -v+1H +%Y-%m-%dT%H:%M:%S+10:00)"

RADIUS_TOKEN_RESULT="$(KANIDM_NAME=idm_admin cargo run --bin kanidm service-account api-token generate \
    "${TEST_RADIUS_USER}" radius "${TOKEN_EXPIRY}" \
    -o json)"
RADIUS_TOKEN="$(echo "${RADIUS_TOKEN_RESULT}" | grep result | jq -r .result)"

if [ -z "${RADIUS_TOKEN}" ]; then
    echo "Couldn't find RADIUS token in output"
    echo "${RADIUS_TOKEN_RESULT}"
    exit 1
fi

echo "Updating secret in config file"
sed -i '' -e "s/^secret.*/secret = \"${RADIUS_TOKEN}\"/" ~/.config/kanidm
