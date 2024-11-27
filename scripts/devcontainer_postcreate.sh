#!/bin/bash

set -e

echo "Installing all the things"

rustup update
rustup default stable
rustup component add rustfmt clippy

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
cargo install sccache cargo-audit mdbook-mermaid mdbook
cargo install mdbook-alerts --version 0.6.4
cargo install deno --locked


echo "Done!"