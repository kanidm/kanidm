#!/bin/bash

export PATH="$HOME/.cargo/bin:$PATH"
SCCACHE_SERVER_UDS="/tmp/sccache.sock" sccache --start-server


export RUSTC_WRAPPER="sccache"
export CC="sccache /usr/bin/clang"