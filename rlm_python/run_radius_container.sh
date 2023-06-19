#!/bin/bash
set -x


if [ -z "${IMAGE}" ]; then
    IMAGE="kanidm/radius:devel"
fi
echo "Running docker container: ${IMAGE}"

if [ ! -z "${IMAGE_ARCH}" ]; then
    IMAGE_ARCH="--platform ${IMAGE_ARCH}"
fi

if [ -z "${CONFIG_FILE}" ]; then
    CONFIG_FILE="$(pwd)/../examples/kanidm"
fi
echo "Using config file: ${CONFIG_FILE}"

if [ ! -d "/tmp/kanidm/" ]; then
	echo "Can't find /tmp/kanidm - you may need to run run_insecure_dev_server"
fi

echo "Starting the dev container..."
#shellcheck disable=SC2068
docker run --rm -it \
    ${IMAGE_ARCH} \
    --network host \
    --name radiusd \
    -v /tmp/kanidm/:/data/ \
    -v /tmp/kanidm/:/tmp/kanidm/ \
    -v /tmp/kanidm/:/certs/ \
    -v "${CONFIG_FILE}:/data/kanidm" \
    "${IMAGE}" $@
