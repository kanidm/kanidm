#!/bin/bash

if [ -z "${IMAGE}" ]; then
    IMAGE="kanidm/radius:devel"
fi
echo "Running docker container: ${IMAGE}"

if [ -z "${CONFIG_FILE}" ]; then
    CONFIG_FILE="$(pwd)/../examples/kanidm"
fi
echo "Using config file: ${CONFIG_FILE}"

if [ ! -d "/tmp/kanidm/" ]; then
	echo "Can't find /tmp/kanidm - you might need to run insecure_generate_certs.sh"
fi

echo "Starting the dev container..."
#shellcheck disable=SC2068
docker run --rm -it \
    --network host \
    --name radiusd \
    -v /tmp/kanidm/:/etc/raddb/certs/ \
    -v "${CONFIG_FILE}:/data/kanidm" \
    ${IMAGE} $@
