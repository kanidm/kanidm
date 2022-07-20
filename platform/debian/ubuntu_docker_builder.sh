#!/usr/bin/env bash

# Starts a ubuntu docker container with the source code mounted

if [ "$(basename "$(pwd)")" != "kanidm" ]; then
    echo "Please run this from the root dir of the repo"
    exit 1
fi

echo "Starting base ubuntu container"
echo "Repository is in ~/kanidm/"
docker run --rm -it \
    -v "$(pwd):/root/kanidm/" \
    --workdir "/root/kanidm/" \
    ubuntu:latest "$@"
