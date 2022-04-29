#!/bin/bash

# This script based on the developer readme and allows you to run a test server.


CONFIG_FILE="../../examples/insecure_server.toml"

if [ ! -f "${CONFIG_FILE}" ]; then
    SCRIPT_DIR="$(dirname -a "$0")"
    echo "Couldn't find configuration file at ${CONFIG_FILE}, please ensure you're running this script from its base directory (${SCRIPT_DIR})."
    exit 1
fi
if [ ! -f "/tmp/kanidm/chain.pem" ]; then
    echo "Couldn't find certificate at /tmp/kanidm/chain.pem, quitting"
    exit 1
fi
if [ ! -f "/tmp/kanidm/key.pem" ]; then
    echo "Couldn't find key file at /tmp/kanidm/key.pem, quitting"
    exit 1
fi

cargo run --bin kanidmd server -c "${CONFIG_FILE}"
