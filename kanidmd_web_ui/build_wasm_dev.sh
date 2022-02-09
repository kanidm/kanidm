#!/bin/sh
wasm-pack build --dev --target web && \
    cp ./src/style.css ./pkg/style.css && \
    cp -a ./src/external ./pkg/external && \
    rm ./pkg/.gitignore

