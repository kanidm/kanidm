#!/bin/bash

# run this, it'll set up a bunch of default stuff
# - reset the admin and idm_admin users
# - set up a test user
# - set up a test group
# - set up a test oauth2 rp (https://kanidm.com)
# - prompt to reset testuser's creds online

set -e

if [ -n "${BUILD_MODE}" ]; then
    BUILD_MODE="--${BUILD_MODE}"
else
    BUILD_MODE=""
fi

# if they passed --help then output the help
if [ "${1}" == "--help" ]; then
    echo "Usage: $0 [--remove-db]"
    echo "  --remove-db: remove the existing DB before running"
    echo "  Env vars:"
    echo " BUILD_MODE - default=debug, set to 'release' to build binaries in release mode"
    exit 0
fi
if [ ! -f run_insecure_dev_server.sh ]; then
    if [ "$(basename "$(pwd)")" == "kanidm" ]; then
        cd server/daemon || exit 1
    else
        echo "Please run from the server/daemon dir, I can't tell where you are..."
        exit 1
    fi
fi


# if --remove-db is in the command line args then remove the DB
if [ -z "${REMOVE_TEST_DB}" ]; then
    if [ "${1}" == "--remove-db" ]; then
        REMOVE_TEST_DB=1
    else
        REMOVE_TEST_DB=0
    fi
fi


# defaults
KANIDM_CONFIG_FILE="../../examples/insecure_server.toml"
KANIDM_URL="$(rg origin "${KANIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
KANIDM_CA_PATH="/tmp/kanidm/ca.pem"

# wait for them to shut down the server if it's running...
while true; do
    if [ "$(pgrep kanidmd | wc -l)" -eq 1 ]; then
        break
    fi
    echo "Start the kanidmd server first please!"

    while true; do
        echo "Waiting for you to start the server... testing ${KANIDM_URL}"
        curl --cacert "${KANIDM_CA_PATH}" -fs "${KANIDM_URL}" >/dev/null && break
        sleep 2
    done
done

# needed for the CLI tools to do their thing
export KANIDM_URL
export KANIDM_CA_PATH
export KANIDM_CONFIG_FILE

# string things
TEST_USER_NAME="testuser"
TEST_USER_DISPLAY="Test Crab"
TEST_GROUP="test_users"
OAUTH2_RP_ID="test_oauth2"
OAUTH2_RP_DISPLAY="test_oauth2"

# commands to run things
KANIDM="cargo run ${BUILD_MODE} --manifest-path ../../Cargo.toml --bin kanidm -- "
KANIDMD="cargo run ${BUILD_MODE} -p daemon --bin kanidmd -- "

if [ "${REMOVE_TEST_DB}" -eq 1 ]; then
    echo "Removing the existing DB!"
    rm /tmp/kanidm/kanidm.db || true
fi

echo "Resetting the admin user..."
${KANIDMD} recover-account admin -o json 2>&1
ADMIN_PASS_STR="$(${KANIDMD} recover-account admin -o json 2>&1)"
ADMIN_PASS=$(echo "${ADMIN_PASS_STR}" | rg password | jq -r .password)
if [ -z "${ADMIN_PASS}" ] || [ "${ADMIN_PASS}" == "null " ]; then
    echo "Failed to reset admin password!"
    echo "${ADMIN_PASS_STR}"
    exit 1
fi

echo "admin pass: '${ADMIN_PASS}'"
echo "Resetting the idm_admin user..."
IDM_ADMIN_PASS=$(${KANIDMD} recover-account idm_admin -o json 2>&1 | rg password | jq -r .password)
if [ -z "${IDM_ADMIN_PASS}" ] || [ "${IDM_ADMIN_PASS}" == "null " ]; then
    echo "Failed to reset admin password!"
    exit 1
fi
echo "idm_admin pass: '${IDM_ADMIN_PASS}'"

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
${KANIDM} group add-members idm_ui_enable_experimental_features admin idm_admin "${TEST_USER_NAME}" -D idm_admin

# create oauth2 rp for kanidm.com
echo "Creating the kanidm.com OAuth2 RP"
${KANIDM} system oauth2 create "kanidm_com" "Kanidm.com" "https://kanidm.com" -D admin
echo "Creating the kanidm.com OAuth2 RP Scope Map"
${KANIDM} system oauth2 update-scope-map "kanidm_com" "${TEST_GROUP}" openid -D admin
echo "Creating the kanidm.com OAuth2 RP Supplemental Scope Map"
${KANIDM} system oauth2 update-sup-scope-map "kanidm_com" "${TEST_GROUP}" admin -D admin


# create oauth2 rp for localhost:10443 - for oauth2 proxy testing
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP"
${KANIDM} system oauth2 create "${OAUTH2_RP_ID}" "${OAUTH2_RP_DISPLAY}" "https://localhost:10443" -D admin
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP Scope Map - Group ${TEST_GROUP}"
${KANIDM} system oauth2 update-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" openid -D admin
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP Supplemental Scope Map"
${KANIDM} system oauth2 update-sup-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" admin -D admin

echo "Creating the OAuth2 RP Secondary Supplemental Crab-baite Scope Map.... wait, no that's not a thing."

echo "Checking the OAuth2 RP Exists"
${KANIDM} system oauth2 list -D admin | rg -A10 "${OAUTH2_RP_ID}"

# config auth2
echo "Pulling secret for the ${OAUTH2_RP_ID} OAuth2 RP"
OAUTH2_SECRET="$(${KANIDM} system oauth2 show-basic-secret -o json "${OAUTH2_RP_ID}" -D admin)"
echo "${OAUTH2_SECRET}"

echo "Creating cred reset link for ${TEST_USER_NAME}"
${KANIDM} person credential create-reset-token "${TEST_USER_NAME}" -D idm_admin

echo "Done!"

echo "###################################"
echo "admin password:     ${ADMIN_PASS}"
echo "idm_admin password: ${IDM_ADMIN_PASS}"
echo "UI URL:             ${KANIDM_URL}"
echo "OAuth2 RP ID:       ${OAUTH2_RP_ID}"
echo "OAuth2 Secret:      $(echo "${OAUTH2_SECRET}" | jq  -r .secret)"
echo "###################################"
