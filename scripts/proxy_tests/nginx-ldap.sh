#!/bin/bash

# enable proxy-v1 and then run the server locally and then run this container, which exposes nginx with ldap proxying to kanidm on port 4636 - connecting to localhost:3636

docker run --network host \
    --rm \
    --mount "type=bind,source=/tmp/kanidm,target=/kanidm_certs" \
    --mount "type=bind,source=$(pwd)/nginx-kanidm-ldap.conf,target=/etc/nginx/nginx.conf" \
    --name nginx-proxy-test \
    nginx:latest