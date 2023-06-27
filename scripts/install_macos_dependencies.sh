#!/bin/bash

set -e

ERROR=0
if [ -z "$(which cargo)" ]; then
    echo "You don't have cargo / rust installed!"
    echo "Go to <https://www.rust-lang.org/tools/install> for instructions!"
    ERROR=1
fi

if [ -z "$(which wasm-pack)" ]; then
    echo "You don't have wasm-pack installed! Installing it now..."
    cargo install wasm-pack
fi

if [ $ERROR -eq 1 ]; then
    exit 1
fi
