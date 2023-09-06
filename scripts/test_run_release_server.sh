#!/bin/bash

set -e

WAIT_TIMER=30

terminate_crab () {
    echo "Waiting ${WAIT_TIMER} seconds and terminating Kanidmd"
    sleep "${WAIT_TIMER}"
    killall kanidmd
}


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

mkdir -p /tmp/kanidm/

cargo run --bin kanidmd cert-generate --config ../../examples/insecure_server.toml


cargo run --bin kanidmd server --config ../../examples/insecure_server.toml &

sleep 5

../../scripts/setup_dev_environment.sh

terminate_crab &

fg

if [ -n "$CURRENT_DIR" ]; then
    cd "$CURRENT_DIR"
fi
