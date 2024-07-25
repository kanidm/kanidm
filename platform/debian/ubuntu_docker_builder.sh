#!/usr/bin/env bash

# Starts a ubuntu docker container with the source code mounted

if [ -z "${KANIDM_CONTAINER}" ]; then
    KANIDM_CONTAINER="ubuntu:latest"
fi

if [ "$(basename "$(pwd)")" != "kanidm" ]; then
    echo "Please run this from the root dir of the repo"
    exit 1
fi

echo "Starting base ubuntu container"
echo "Repository is in ~/kanidm/"

# shellcheck disable=SC2068
# shellcheck disable=SC2086
docker run --rm -it $KANIDM_BUILDER_OPTIONS \
    -e "INSTALL_RUST=1" \
    -e "PACKAGING=1" \
    -e "TZ=UTC" \
    -v "$(pwd):/root/kanidm/" \
    --workdir "/root/kanidm/" \
    --entrypoint "/root/kanidm/platform/debian/interactive_entrypoint.sh" \
    "${KANIDM_CONTAINER}" $@
