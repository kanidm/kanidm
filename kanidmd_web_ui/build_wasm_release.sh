#!/bin/sh

if [ -z "${BUILD_FLAGS}" ]; then
    BUILD_FLAGS="--release"
fi

wasm-pack build ${BUILD_FLAGS} --target web || exit 1

touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    rsync --delete-after -r --copy-links -v ./src/img/ ./pkg/img/ && \
    rsync --delete-after -r --copy-links -v ./src/external/ ./pkg/external/ && \
    cp ./src/style.css ./pkg/style.css && \
    cp ./src/wasmloader.js ./pkg/wasmloader.js && \
    rm ./pkg/.gitignore
