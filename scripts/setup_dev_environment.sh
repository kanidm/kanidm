#!/bin/bash

# run this, it'll set up a bunch of default stuff
# - reset the admin and idm_admin users
# - set up a test user
# - set up a test group
# - set up a test oauth2 rp (https://kanidm.com)
# - prompt to reset testuser's creds online

set -e

# if they passed --help then output the help
if [ "${1}" == "--help" ]; then
    echo "Usage: $0 [--remove-db]"
    echo "  --remove-db: remove the existing DB before running"
    exit 0
fi

# if --remove-db is in the command line args then remove the DB
if [ -z "${REMOVE_TEST_DB}" ]; then
    if [ "${1}" == "--remove-db" ]; then
        REMOVE_TEST_DB=1
    else
        REMOVE_TEST_DB=0
    fi
fi


if [ ! -f run_insecure_dev_server.sh ]; then
    echo "Please run from the server/daemon dir!"
    exit 1
fi

# wait for them to shut down the server if it's running...
while true
do
    if [ "$(pgrep kanidmd | wc -l )" -eq 0 ]; then
        break
    fi
    echo "Stop the kanidmd server first please!"
    sleep 1
done

# defaults
KANIDM_CONFIG="../../examples/insecure_server.toml"
KANIDM_URL="$(rg origin "${KANIDM_CONFIG}" | awk '{print $NF}' | tr -d '"')"
KANIDM_CA_PATH="/tmp/kanidm/ca.pem"

# needed for the CLI tools to do their thing
export KANIDM_URL
export KANIDM_CA_PATH
export KANIDM_CONFIG

# string things
TEST_USER_NAME="testuser"
TEST_USER_DISPLAY="Test Crab"
TEST_GROUP="test_users"
OAUTH2_RP_ID="test_oauth2"
OAUTH2_RP_DISPLAY="test_oauth2"

# commands to run things
KANIDM="cargo run --manifest-path ../../Cargo.toml --bin kanidm -- "
KANIDMD="cargo run -p daemon --bin kanidmd -- "

if [ "${REMOVE_TEST_DB}" -eq 1 ]; then
    echo "Removing the existing DB!"
    rm /tmp/kanidm/kanidm.db || true
fi

echo "Reset the admin user"
ADMIN_PASS=$(${KANIDMD} recover-account admin -o json 2>&1 | rg recovery | rg result | jq -r .result )
echo "admin pass: '${ADMIN_PASS}'"
echo "Reset the idm_admin user"
IDM_ADMIN_PASS=$(${KANIDMD} recover-account idm_admin -o json 2>&1 | rg recovery | rg result | jq -r .result)
echo "idm_admin pass: '${IDM_ADMIN_PASS}'"

while true
do
    echo "Waiting for you to start the server... testing ${KANIDM_URL}"
    curl --cacert "${KANIDM_CA_PATH}" -fs "${KANIDM_URL}" > /dev/null && break
    sleep 2
done

echo "login with admin"
${KANIDM} login -D admin --password "${ADMIN_PASS}"
echo "login with idm_admin"
${KANIDM} login -D idm_admin --password "${IDM_ADMIN_PASS}"

# create group test_users
${KANIDM} group create "${TEST_GROUP}" -D idm_admin

# create testuser (person)
${KANIDM} person create "${TEST_USER_NAME}" "${TEST_USER_DISPLAY}" -D idm_admin

echo "Adding ${TEST_USER_NAME} to ${TEST_GROUP}"
${KANIDM} group add-members "${TEST_GROUP}" "${TEST_USER_NAME}" -D idm_admin

echo "Enable experimental UI for admin idm_admin ${TEST_USER_NAME}"
${KANIDM} group add-members  idm_ui_enable_experimental_features admin idm_admin "${TEST_USER_NAME}"

# create oauth2 rp
echo "Creating the OAuth2 RP"
${KANIDM} system oauth2 create "${OAUTH2_RP_ID}" "${OAUTH2_RP_DISPLAY}" "https://kanidm.com" -D admin

echo "Creating the OAuth2 RP Scope Map"
${KANIDM} system oauth2 update-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" openid -D admin
echo "Creating the OAuth2 RP Supplemental Scope Map"
${KANIDM} system oauth2 update-sup-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" admin -D admin
echo "Creating the OAuth2 RP Secondary Supplemental Crab-baite Scope Map.... wait, no that's not a thing."


# config auth2
echo "Pulling secret for the OAuth2 RP"
${KANIDM} system oauth2 show-basic-secret -o json "${OAUTH2_RP_ID}" -D admin

echo "Creating cred reset link for ${TEST_USER_NAME}"
${KANIDM} person credential create-reset-token "${TEST_USER_NAME}" -D idm_admin

echo "Done!"

echo "###################################"
echo "admin password:     ${ADMIN_PASS}"
echo "idm_admin password: ${IDM_ADMIN_PASS}"
echo "UI URL:             ${KANIDM_URL}"
echo "###################################"
