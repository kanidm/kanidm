#!/bin/bash

# this script runs the server in release mode and tries to set up a dev environment, which catches failures between the
# server and CLI, and ensures clap/etc rules actually work
#
# you really really really really don't want to run this when an environment you like exists, it'll mess it up

set -e

WAIT_TIMER=5


echo "Building release binaries..."
cargo build --release --bin kanidm --bin kanidmd

if [ -d '.git' ]; then
    echo "You're in the root dir, let's move you!"
    CURRENT_DIR="$(pwd)"
    cd server/daemon/ || exit 1
fi


if [ ! -f "run_insecure_dev_server.sh" ]; then
    echo "I'm not sure where you are, please run this from the root of the repository or the server/daemon directory"
    exit 1
fi

export KANIDM_CONFIG="../../examples/insecure_server.toml"

mkdir -p /tmp/kanidm/client_ca

echo "Generating certificates..."
cargo run --bin kanidmd --release cert-generate

echo "Making sure it runs with the DB..."
cargo run --bin kanidmd --release recover-account idm_admin -o json

echo "Running the server..."
cargo run --bin kanidmd --release server  &
KANIDMD_PID=$!
echo "Kanidm PID: ${KANIDMD_PID}"


if [ "$(jobs -p | wc -l)" -eq 0 ]; then
    echo "Kanidmd failed to start!"
    exit 1
fi

ATTEMPT=0

KANIDM_CONFIG_FILE="../../examples/insecure_server.toml"
KANIDM_URL="$(rg origin "${KANIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
KANIDM_CA_PATH="/tmp/kanidm/ca.pem"

export KANIDM_CONFIG_FILE
export KANIDM_URL
export KANIDM_CA_PATH

while true; do
    echo "Waiting for the server to start... testing ${KANIDM_URL}"
    curl --cacert "${KANIDM_CA_PATH}" -fs "${KANIDM_URL}/status" >/dev/null && break
    sleep 2
    ATTEMPT="$((ATTEMPT + 1))"
    if [ "${ATTEMPT}" -gt 3 ]; then
        echo "Kanidmd failed to start!"
        exit 1
    fi
done

../../scripts/setup_dev_environment.sh


if [ -n "$CURRENT_DIR" ]; then
    cd "$CURRENT_DIR" || exit 1
fi

echo "Running the OpenAPI schema checks"

bash -c ./scripts/openapi_tests/check_openapi_spec.sh || exit 1

echo "Waiting ${WAIT_TIMER} seconds and terminating Kanidmd"
sleep "${WAIT_TIMER}"
if [ "$(pgrep kanidmd | wc -l)" -gt 0 ]; then
    kill $(pgrep kanidmd)
fi



while true; do
    echo "Waiting for the server to start... testing ${KANIDM_URL}"
    curl --cacert "${KANIDM_CA_PATH}" -fs "${KANIDM_URL}/status" >/dev/null && break
    sleep 2
    ATTEMPT="$((ATTEMPT + 1))"
    if [ "${ATTEMPT}" -gt 3 ]; then
        echo "Kanidmd failed to start!"
        exit 1
    fi
done

KANIDM="cargo run ${BUILD_MODE} --manifest-path ../../Cargo.toml --bin kanidm -- "

# now we start checking things again
${KANIDM} person create testuser2 testuser2

${KANIDM} group get idm_all_persons --output json
${KANIDM} group get idm_all_persons --output json  | jq .dynmember | grep -c testuser2 || exit 1