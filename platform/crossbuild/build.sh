#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 target_os"
    if [ -d ./platform ]; then
        echo "Options:"
        find platform/crossbuild -maxdepth 1 -mindepth 1 -type d | awk -F'/' '{print $NF}' | sort
    fi
    exit 1
fi

if [ ! -d "platform/crossbuild/$1" ]; then
    echo "Could not find platform/crossbuild/$1"
    exit 1
fi

# Find the target rust architecture
TRIPLET=$(echo $1 | cut -d \- -f 3-)
echo "Crossbuilding for: $TRIPLET"

CROSS_CONFIG="platform/crossbuild/${1}/Cross.toml" \
    cross build --target aarch64-unknown-linux-gnu \
        --bin kanidm_unixd \
        --bin kanidm_unixd_tasks \
        --bin kanidm_ssh_authorizedkeys \
        --bin kanidm-unix \
        --release
CROSS_CONFIG="platform/crossbuild/${1}/Cross.toml" \
    cross build --target aarch64-unknown-linux-gnu \
        -p pam_kanidm \
        -p nss_kanidm \
        --release

TRIPLET=$(echo $1 | cut -d \- -f 3-)

echo "Build artefacts for ${TRIPLET}:"
find "./target/${TRIPLET}/release/" -maxdepth 1 \
    -type f -not -name '*.d' \
    -name '*kanidm*'
