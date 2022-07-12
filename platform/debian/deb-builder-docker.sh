#!/usr/bin/env bash

if [ "$(basename $(pwd))" != "kanidm" ]; then
    echo "Please run this from the root dir of the repo"
    exit 1
fi

echo "Starting base ubuntu container"
echo "Repository is in ~/kanidm/"
docker run --rm -it \
    -v "$(pwd):/root/kanidm/" \
    ubuntu:latest
