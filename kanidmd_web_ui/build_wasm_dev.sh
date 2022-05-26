#!/bin/sh
wasm-pack build --dev --target web && \
    touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    cp ./src/style.css ./pkg/style.css && \
    cp ./src/wasmloader.js ./pkg/wasmloader.js && \
    cp ./src/favicon.svg ./pkg/favicon.svg && \
    cp -a ./src/external ./pkg/external && \
    rm ./pkg/.gitignore

