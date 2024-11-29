#!/bin/bash

set -e

echo "Installing rust stable toolchain"
rustup update
rustup default stable
rustup component add rustfmt clippy

echo "Installing packages"
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    cmake \
    libtss2-dev \
    tpm-udev \
    jq \
    libpam0g-dev \
    libssl-dev \
    libudev-dev \
    pkg-config \
    ripgrep

export PATH="$HOME/.cargo/bin:$PATH"

cargo install \
    sccache


# stupid permissions issues
sudo chown vscode ~/ -R
sudo chgrp vscode ~/ -R

# shellcheck disable=SC1091
source scripts/devcontainer_poststart.sh

cargo install
    cargo-audit \
    mdbook-mermaid \
    mdbook
cargo install mdbook-alerts --version 0.6.4
cargo install deno --locked


echo "Done!"