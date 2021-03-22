#!/bin/sh
wasm-pack build --no-typescript --release --target web && \
    rollup ./src/main.js --format iife --file ./pkg/bundle.js && \
    rm ./pkg/.gitignore
