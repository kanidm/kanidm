#!/usr/bin/env bash

set -eux

TOPDIR=$(git rev-parse --show-toplevel)
CURDIR=$(readlink -f $(dirname -- "$0"))

CACHE_DIR=${CACHE_DIR:-$(readlink -f $CURDIR/cache)}

if [[ -e ~/.cargo/registry && ! -e $CACHE_DIR/cargo/registry ]]; then
    rsync -a ~/.cargo/registry $CACHE_DIR/cargo/
    rsync -a ~/.cargo/git $CACHE_DIR/cargo/
fi

mkdir -p $TARGET_DIR

podman run --rm -it \
    -v $CACHE_DIR/cargo/:/cargo  \
    -v $CACHE_DIR/rustup/:/rustup  \
    -v $CACHE_DIR/dnf:/var/cache/dnf \
    -v $TOPDIR:/src \
    -v $TARGET_DIR:/src/target \
    -e KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE} \
    $IMAGE_NAME "$@"
