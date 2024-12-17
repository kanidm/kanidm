FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --assume-yes --no-install-recommends \
    g++ \
    libc6-dev-amd64-cross \
    clang lld

ENV CROSS_TOOLCHAIN_PREFIX=x86_64-linux-gnu-
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CROSS_TOOLCHAIN_PREFIX"gcc \
    AR_x86_64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"ar \
    CC_x86_64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"gcc \
    CXX_x86_64_unknown_linux_gnu="$CROSS_TOOLCHAIN_PREFIX"g++ \
    RUST_TEST_THREADS=1 \
    PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig/" \
    PKG_CONFIG_ALLOW_CROSS="1"
