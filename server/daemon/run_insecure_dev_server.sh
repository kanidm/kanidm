#!/bin/bash

# This script based on the developer readme and allows you to run a test server.

if [ -z "$KANI_CARGO_OPTS" ]; then
    KANI_CARGO_OPTS=""
fi

CONFIG_FILE="../../examples/insecure_server.toml"

if [ ! -f "${CONFIG_FILE}" ]; then
    SCRIPT_DIR="$(dirname -a "$0")"
    echo "Couldn't find configuration file at ${CONFIG_FILE}, please ensure you're running this script from its base directory (${SCRIPT_DIR})."
    exit 1
fi

#shellcheck disable=SC2086
cargo run ${KANI_CARGO_OPTS} --bin kanidmd -- cert-generate -c "${CONFIG_FILE}"

COMMAND="server"
if [ -n "${1}" ]; then
    COMMAND=$*
fi

#shellcheck disable=SC2086
cargo run ${KANI_CARGO_OPTS} --bin kanidmd -- ${COMMAND} -c "${CONFIG_FILE}"
