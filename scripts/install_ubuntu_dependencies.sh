#!/bin/bash

set -e

if [ "$(whoami)" == "root" ]; then
    SUDOCMD=""
else
    SUDOCMD="sudo "
fi

${SUDOCMD} apt-get update &&
${SUDOCMD} apt-get install -y \
    libpam0g-dev \
    libudev-dev \
    libssl-dev \
    pkg-config \
    curl \
    rsync \
    git \
    cmake \
    build-essential \
    jq \
    tpm-udev

if [ -z "${PACKAGING}" ]; then
    PACKAGING=0
fi

if [ "${PACKAGING}" -eq 1 ]; then
    # Install packages needed for cargo-deb to build healthy debs for any supported target
    # This works in Debian, but not in Ubuntu because they do multiarch weird.
    # It would be too invasive to config a daily driver Ubuntu install for multiarch,
    # so instead we don't, and just warn.
    source /etc/os-release
    if [[ "$ID" == "ubuntu" ]]; then
      2>&1 echo "You're running Ubuntu, so we're skipping enabling multiarch for you because it would be too invasive. You won't be able to build valid debs for other than your native architecture."
    ${SUDOCMD} apt-get install -y \
    	libpam0g \
    	libssl3
    elif [[ "$ID" == "debian" ]]; then
    ${SUDOCMD} dpkg --add-architecture arm64 && ${SUDOCMD} apt-get update
    ${SUDOCMD} apt-get install -y \
    	libpam0g:{amd64,arm64} \
    	libssl3:{amd64,arm64}
    fi
    export INSTALL_RUST=1
fi

if [ -z "$(which cargo)" ]; then
    if [ -f "$HOME/.cargo/env" ]; then
        #shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    elif [ "${INSTALL_RUST}" == "1" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        #shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    else
        echo "#############################################################"
        echo "Couldn't find rust and you didn't say to install it..."
        echo "#############################################################"
    fi

fi

ERROR=0
if [ -z "$(which cargo)" ]; then
    echo "You don't have cargo / rust installed!"
    echo "Go to <https://www.rust-lang.org/tools/install> for instructions!"
    echo ""
    echo "Or run this script with INSTALL_RUST=1 to install it for you."
    ERROR=1
fi

if [ $ERROR -eq 0 ] && [ -z "$(which wasm-pack)" ]; then
    echo "You don't have wasm-pack installed! Installing it now..."
    cargo install wasm-pack
fi
if [ $ERROR -eq 0 ] && [ -z "$(which wasm-bindgen)" ]; then
    echo "You don't have wasm-bindgen installed! Installing it now..."
    cargo install -f wasm-bindgen-cli
fi
if [ $ERROR -eq 0 ] && [ -z "$(which cross)" ]; then
    echo "You don't have cargo-deb installed! Installing it now..."
    cargo install -f cross
fi
if [ $ERROR -eq 0 ] && [ -z "$(which cargo-deb)" ]; then
    echo "You don't have cargo-deb installed! Installing it now..."
    cargo install -f cargo-deb
fi


if [ $ERROR -eq 1 ]; then
    exit 1
fi

echo "Woo, all ready to go!"

#shellcheck disable=SC2016
echo 'You might need to load the env:  source "$HOME/.cargo/env"'
