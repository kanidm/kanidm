#!/bin/bash

set -e

terminate_crab () {
    echo "Waiting 10 seconds and terminating Kanidmd"
    sleep 10
    killall kanidmd
}

if [ -d '.git' ]; then
    echo "You're in the root dir, let's move you!"
    CURRENT_DIR="$(pwd)"
    cd server/daemon/ || exit 1
fi

if [ ! -f "run_insecure_dev_server.sh" ]; then
    echo "I'm not sure where you are, please run this from the root of the repository or the server/daemon directory"
    exit 1
fi

cargo build --release --bin kanidmd

cargo run --bin kanidmd cert-generate --config ../../examples/insecure_server.toml

terminate_crab &

cargo run --bin kanidmd server --config ../../examples/insecure_server.toml

if [ -n "$CURRENT_DIR" ]; then
    cd "$CURRENT_DIR"
fi
