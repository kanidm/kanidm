#!/bin/bash

# This script based on the developer readme and allows you to run a test server.

if [ -z "$KANI_TMP" ]; then
    KANI_TMP=/tmp/kanidm
fi

CONFIG_FILE="../../examples/insecure_server.toml"

if [ ! -f "${CONFIG_FILE}" ]; then
    SCRIPT_DIR="$(dirname -a "$0")"
    echo "Couldn't find configuration file at ${CONFIG_FILE}, please ensure you're running this script from its base directory (${SCRIPT_DIR})."
    exit 1
fi
if [ ! -f "${KANI_TMP}/chain.pem" ]; then
    echo "Couldn't find certificate at /tmp/kanidm/chain.pem, quitting"
    exit 1
fi
if [ ! -f "${KANI_TMP}/key.pem" ]; then
    echo "Couldn't find key file at /tmp/kanidm/key.pem, quitting"
    exit 1
fi

COMMAND="server"
if [ -n "${1}" ]; then
    COMMAND=$*
fi

#shellcheck disable=SC2086
cargo run --bin kanidmd -- ${COMMAND} -c "${CONFIG_FILE}"
