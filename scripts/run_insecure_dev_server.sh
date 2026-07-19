#!/bin/sh

set -e

# This script based on the developer readme and allows you to run a test server.

if [ -z "$KANI_CARGO_OPTS" ]; then
    KANI_CARGO_OPTS="--profile dev"
fi

# also where the files are stored
if [ -z "$KANI_TMP" ]; then
    KANI_TMP=/tmp/kanidm/
fi

if [ ! -d "${KANI_TMP}" ]; then
    echo "Creating temp kanidm dir: ${KANI_TMP}"
    mkdir -p "${KANI_TMP}"
fi

mkdir -p "${KANI_TMP}"/client_ca

CONFIG_FILE=${CONFIG_FILE:="./scripts/insecure_server.toml"}

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Couldn't find configuration file at ${CONFIG_FILE}, please ensure you're running this script from the project root directory."
    exit 1
fi

if [ -n "${1}" ]; then
    COMMAND=$*
    #shellcheck disable=SC2086
    cargo run ${KANI_CARGO_OPTS} --bin kanidmd -- ${COMMAND} -c "${CONFIG_FILE}"
else
    #shellcheck disable=SC2086
    cargo run ${KANI_CARGO_OPTS} --bin kanidmd -- cert-generate -c "${CONFIG_FILE}"
    #shellcheck disable=SC2086
    cargo run ${KANI_CARGO_OPTS} --bin kanidmd -- server -c "${CONFIG_FILE}"
fi
