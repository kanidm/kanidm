#!/bin/bash

set -e

cleanup() {
    echo "Cleaning up ${1}"
    rm -rf "$1"
}

if [ -f openapi.json ]; then
    rm openapi.json
fi
WORKDIR="$(mktemp -d)"
echo "Trying to pull openapi.json to ${WORKDIR}"
curl -sfk https://localhost:8443/docs/v1/openapi.json > "${WORKDIR}/openapi.json" || echo "Failed download"

if [ ! -f "${WORKDIR}/openapi.json" ]; then
    echo "Failed to download openapi.json"
    cleanup "${WORKDIR}"
    exit 1
fi

# if  "${WORKDIR}/openapi.json" is empty, exit
if [ ! -s "${WORKDIR}/openapi.json" ]; then
    echo "openapi.json is empty, cleaning up and exiting"
    cleanup "${WORKDIR}"
    exit 1
fi

docker run \
    --mount "type=bind,src=${WORKDIR}/openapi.json,target=/openapi.json" \
    --rm pythonopenapi/openapi-spec-validator /openapi.json && \
    echo "openapi-spec-validator passed"


docker run --rm -it \
    --mount "type=bind,src=${WORKDIR},target=/spec" \
    openapitools/openapi-generator-cli generate \
    -i /spec/openapi.json -g rust

cleanup "${WORKDIR}"
