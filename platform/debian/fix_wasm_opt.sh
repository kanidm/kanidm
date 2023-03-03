#!/bin/bash

# This is a hack to work around the fact that wasm-opt isn't available on
# Linux + aarch64

if [ "$(uname -m)" = "aarch64" ] && [ "$(uname -s)" = "Linux" ]; then
    echo "#####################################"
    echo "      WASM-OPT NOT AVAILABLE"
    echo ""
    echo "        Large WASM ahead."
    echo "#####################################"

    if [ "$(grep -oE 'wasm-opt.*' server/web_ui/Cargo.toml | awk '{print $NF}')" != "false" ]; then
        echo "Updating server/web_ui/Cargo.toml to disable wasm-opt"
        cat >> server/web_ui/Cargo.toml <<-EOM
[package.metadata.wasm-pack.profile.release]
wasm-opt = false
EOM
    fi
fi

