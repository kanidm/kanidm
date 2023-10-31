#!/bin/bash

docker run \
    docker.io/grafana/loki:2.9.2 \
    -config.file=/etc/loki/local-config.yaml \
    -target=all
