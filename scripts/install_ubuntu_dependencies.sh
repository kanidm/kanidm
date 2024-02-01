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
    build-essential \
    jq

if [ -z "${PACKAGING}" ]; then
    PACKAGING=0
fi

if [ "${PACKAGING}" -eq 1 ]; then
    ${SUDOCMD} apt-get install -y \
        devscripts \
        fakeroot \
        dh-make \
        debmake
fi

if [ "${PACKAGING}" -eq 1 ]; then
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


if [ $ERROR -eq 1 ]; then
    exit 1
fi

echo "Woo, all ready to go!"

#shellcheck disable=SC2016
echo 'You might need to load the env:  source "$HOME/.cargo/env"'
