#!/bin/bash

if [ ! -d "/tmp/kanidm/" ]; then
	echo "Can't find /tmp/kanidm - you might need to run insecure_generate_certs.sh"
fi

echo "Starting the dev container..."
#shellcheck disable=SC2068
docker run --rm -it --name kanidm_radius \
    -v /tmp/kanidm/chain.pem:/etc/raddb/certs/chain.pem \
    -v /tmp/kanidm/key.pem:/etc/raddb/certs/key.pem \
    -v /tmp/kanidm/ca.pem:/etc/raddb/certs/ca.pem \
    -v "${HOME}/.config/kanidm_radius.ini:/data/config.ini" \
    -v "${HOME}/.config/kanidm:/etc/kanidm/config" \
    --user root -v /tmp/kanidm/dh.pem:/etc/raddb/certs/dh.pem \
    kanidm/radius:devel $@
