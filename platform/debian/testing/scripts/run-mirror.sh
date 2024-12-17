#!/bin/bash

set -eu

MIRROR_PORT="${MIRROR_PORT:-31625}"

zip=$(readlink -f ${1?})

mkdir -p snapshot && cd snapshot
unzip -o "$zip"

python3 -m http.server -b 127.0.0.1 "$MIRROR_PORT" -d .
