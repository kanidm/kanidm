#!/bin/bash

if [ "$(uname -m)" == "x86_64" ]; \
    then export RUSTFLAGS='-Ctarget-cpu=haswell'; \
fi; \
if [ "$(uname -m)" == "aarch64" ]; \
    then export RUSTFLAGS=''; \
fi; \
if [ "${SCCACHE_REDIS}" != "" ]; \
    then \
        export CC="/usr/bin/sccache /usr/bin/clang" && \
        export RUSTC_WRAPPER=sccache && \
        sccache --start-server; \
    else \
        export CC="/usr/bin/clang"; \
fi; \
export RUSTC_BOOTSTRAP=1 && \
echo $RUSTC_BOOTSTRAP && \
echo $RUSTC_WRAPPER && \
echo $RUSTFLAGS && \
echo $CC && \
cargo build \
    --offline \
    --features=concread/simd_support,libsqlite3-sys/bundled \
    --release; \
if [ "${SCCACHE_REDIS}" != "" ]; \
    then sccache -s; \
fi; \

