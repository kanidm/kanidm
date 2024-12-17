FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --assume-yes --no-install-recommends \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    clang lld
    #pkg-config

ENV CROSS_TOOLCHAIN_PREFIX=aarch64-linux-gnu-
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$CROSS_TOOLCHAIN_PREFIX"gcc \
    AR_aarch64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"ar \
    CC_aarch64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"gcc \
    CXX_aarch64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"g++ \
    RUST_TEST_THREADS=1 \
    PKG_CONFIG_PATH="/usr/lib/aarch64-linux-gnu/pkgconfig/" \
    PKG_CONFIG_ALLOW_CROSS="1"
