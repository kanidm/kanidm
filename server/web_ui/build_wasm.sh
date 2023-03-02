#!/bin/sh

# This builds the assets for the Web UI, defaulting to a release build.

if [ ! -f build_wasm.sh ]; then
    echo "Please run from the crate directory. (server/web_ui)"
    exit 1
fi

if [ -z "${BUILD_FLAGS}" ]; then
    BUILD_FLAGS="--release --no-typescript"
fi

if [ -z "$(which rsync)" ]; then
    echo "Cannot find rsync which is needed to move things around, quitting!"
    exit 1
fi

if [ "$(find ./pkg/ -name 'kanidmd*' | wc -l)" -gt 0 ]; then
    echo "Cleaning up"
    rm pkg/kanidmd*
fi

# we can disable this since we want it to expand
# shellcheck disable=SC2086
wasm-pack build ${BUILD_FLAGS} --target web || exit 1

touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    rsync --delete-after -r --copy-links -v ./src/img/ ./pkg/img/ && \
    rsync --delete-after -r --copy-links -v ./src/external/ ./pkg/external/ && \
    cp ../../README.md ./pkg/
    cp ../../LICENSE.md ./pkg/
    cp ./src/style.css ./pkg/style.css && \
    cp ./src/wasmloader.js ./pkg/wasmloader.js && \
    rm ./pkg/.gitignore
