#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 target_os"
    if [ -d ./platform ]; then
        echo "Options:"
        find platform/crossbuild -type d -maxdepth 1 -mindepth 1 | awk -F'/' '{print $NF}' | sort
    fi
    exit 1
fi

if [ ! -d "platform/crossbuild/$1" ]; then
    echo "Could not find platform/crossbuild/$1"
    exit 1
fi

echo "Building to ./target/$1"
rm -rf "./target/$1"
mkdir -p "./target/$1"

CROSS_CONFIG="platform/crossbuild/${1}/Cross.toml" \
    cross build --target aarch64-unknown-linux-gnu \
        --bin kanidm_unixd \
        --bin kanidm_unixd_tasks \
        --bin kanidm_ssh_authorizedkeys \
        --bin kanidm-unix \
        --release

mv ./target/aarch64-unknown-linux-gnu/release/kanidm* "./target/$1/"
rm "./target/$1/*.d"