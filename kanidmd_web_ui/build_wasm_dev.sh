#!/bin/sh

RUSTFLAGS="${RUSTFLAGS} --cfg debug "  BUILD_FLAGS="--dev" ./build_wasm.sh
