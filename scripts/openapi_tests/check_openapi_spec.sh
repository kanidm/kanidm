#!/bin/bash

set -e

if [ -f openapi.json ]; then
    rm openapi.json
fi
WORKDIR="$(mktemp -d)"
echo "Saving openapi.json to ${WORKDIR}"

curl -sfk https://localhost:8443/docs/v1/openapi.json > "${WORKDIR}/openapi.json" && \
docker run \
    --mount "type=bind,src=${WORKDIR}/openapi.json,target=/openapi.json" \
    --rm pythonopenapi/openapi-spec-validator /openapi.json && rm -rf "${WORKDIR}"
