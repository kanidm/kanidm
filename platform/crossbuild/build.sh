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

TARGET_DIR="./target/$1"

echo "Recreating then building to ${TARGET_DIR}"
rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"

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

find "./target/aarch64-unknown-linux-gnu/release/" -maxdepth 1 \
    -type f -not -name '*.d' \
    -name 'kanidm*' \
    -exec mv "{}" "${TARGET_DIR}/" \;

find "./target/aarch64-unknown-linux-gnu/release/" -maxdepth 1 \
    -name '*kanidm*.so' \
    -exec mv "{}" "${TARGET_DIR}/" \;
# find "${TARGET_DIR}" -name '*.d' -delete

echo "Contents of ${TARGET_DIR}"
find "${TARGET_DIR}" -type f
