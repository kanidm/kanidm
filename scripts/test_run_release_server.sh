#!/bin/bash

# this script runs the server in release mode and tries to set up a dev environment, which catches failures between the
# server and CLI, and ensures clap/etc rules actually work
#
# you really really really really don't want to run this when an environment you like exists, it'll mess it up

set -e

WAIT_TIMER=5
if [ -z "${BUILD_MODE}" ]; then
    BUILD_MODE="--profile dev"
fi

export KANIDM_CONFIG="./server/daemon/insecure_server.toml"

mkdir -p /tmp/kanidm/client_ca

echo "Building release binaries..."
# shellcheck disable=SC2086
cargo build --locked $BUILD_MODE || {
    echo "Failed to build release binaries, please check the output above."
    exit 1
}

echo "Generating certificates..."
# shellcheck disable=SC2086
cargo run --bin kanidmd $BUILD_MODE cert-generate

echo "Making sure it runs with the DB..."
# shellcheck disable=SC2086
cargo run --bin kanidmd $BUILD_MODE scripting recover-account idm_admin

echo "Running the server..."
# shellcheck disable=SC2086
cargo run --bin kanidmd $BUILD_MODE server  &
KANIDMD_PID=$!
echo "Kanidm PID: ${KANIDMD_PID}"

if [ "$(jobs -p | wc -l)" -eq 0 ]; then
    echo "Kanidmd failed to start!"
    exit 1
fi

ATTEMPT=0

KANIDM_CONFIG_FILE="./insecure_server.toml"
if [ -f "${KANIDM_CONFIG_FILE}" ]; then
    echo "Found config file ${KANIDM_CONFIG_FILE}"
else
    echo "Config file ${KANIDM_CONFIG_FILE} not found!"
    exit 1
fi
KANIDM_URL="$(grep -E '^origin.*https' "${KANIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
KANIDM_CA_PATH="/tmp/kanidm/ca.pem"

while true; do
    echo "Waiting for the server to start... testing url '${KANIDM_URL}'"
    curl --cacert "${KANIDM_CA_PATH}" -f "${KANIDM_URL}/status" >/dev/null && break
    sleep 2
    ATTEMPT="$((ATTEMPT + 1))"
    if [ "${ATTEMPT}" -gt 3 ]; then
        echo "Kanidmd failed to start!"
        exit 1
    fi
done

BUILD_MODE=$BUILD_MODE ./scripts/setup_dev_environment.sh || kill -9 "${KANIDMD_PID}"

echo "Running the OpenAPI schema checks"

bash -c ./scripts/openapi_tests/check_openapi_spec.sh || exit 1

echo "Waiting ${WAIT_TIMER} seconds and terminating Kanidmd"
sleep "${WAIT_TIMER}"
if [ "$(pgrep kanidmd | wc -l)" -gt 0 ]; then
    kill $(pgrep kanidmd)
fi
