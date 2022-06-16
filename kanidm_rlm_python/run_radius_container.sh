#!/bin/bash

if [ ! -d "/tmp/kanidm/" ]; then
	echo "Can't find /tmp/kanidm - you might need to run insecure_generate_certs.sh"
fi

echo "Starting the dev container..."
#shellcheck disable=SC2068
docker run --rm -it \
    --network host \
    --name radiusd \
    -v /tmp/kanidm/dh.pem:/etc/raddb/certs/dh.pem \
    -v /tmp/kanidm/ca.pem:/etc/raddb/certs/ca.pem \
    -v /tmp/kanidm/cert.pem:/etc/raddb/certs/cert.pem \
    -v /tmp/kanidm/chain.pem:/etc/raddb/certs/server.pem \
    -v /tmp/kanidm/key.pem:/etc/raddb/certs/key.pem \
    -v "${HOME}/.config/kanidm:/data/kanidm" \
    kanidm/radius:devel $@
