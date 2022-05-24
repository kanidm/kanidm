#!/bin/sh
wasm-pack build --dev --target web && \
    cp ./src/style.css ./pkg/style.css && \
    cp ./src/wasmloader.js ./pkg/wasmloader.js && \
    cp ./src/favicon.svg ./pkg/favicon.svg && \
    cp -a ./src/external ./pkg/external && \
    rm ./pkg/.gitignore

