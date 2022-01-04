#!/bin/sh
wasm-pack build --dev --target web && \
    rollup ./src/main.js --format iife --file ./pkg/bundle.js && \
    cp ./src/style.css ./pkg/style.css && \
    cp -a ./src/external ./pkg/external && \
    rm ./pkg/.gitignore
    

