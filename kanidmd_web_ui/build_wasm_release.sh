#!/bin/sh
wasm-pack build --release --target web || exit 1

touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    cp -R ./src/img ./pkg/ &&
    cp ./src/style.css ./pkg/style.css && \
    cp ./src/wasmloader.js ./pkg/wasmloader.js && \
    rm ./pkg/.gitignore


