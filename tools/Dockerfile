ARG RUST_VERSION=1.84

FROM --platform=$BUILDPLATFORM docker.io/tonistiigi/xx AS xx
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS base
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS toolchain

# Prevent deletion of apt cache
RUN rm -f /etc/apt/apt.conf.d/docker-clean

# Match Rustc version as close as possible
# rustc -vV
ARG LLVM_VERSION=19
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

# Install repo tools
# Line one: compiler tools
# Line two: curl, for downloading binaries
# Line three: for xx-verify
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
apt-get update && apt-get install -y \
    clang-${LLVM_VERSION} lld-${LLVM_VERSION} pkg-config make perl jq \
    curl git \
    file \
    libssl-dev
# libssl is needed in the host architecture due to an issue with the headers

# Create symlinks for LLVM tools
RUN <<EOF
    # clang
    ln -s /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang
    ln -s "/usr/bin/clang++-${LLVM_VERSION}" "/usr/bin/clang++"
    # lld
    ln -s /usr/bin/ld64.lld-${LLVM_VERSION} /usr/bin/ld64.lld
    ln -s /usr/bin/ld.lld-${LLVM_VERSION} /usr/bin/ld.lld
    ln -s /usr/bin/lld-${LLVM_VERSION} /usr/bin/lld
    ln -s /usr/bin/lld-link-${LLVM_VERSION} /usr/bin/lld-link
    ln -s /usr/bin/wasm-ld-${LLVM_VERSION} /usr/bin/wasm-ld
EOF

# Developer tool versions
# renovate: datasource=github-releases depName=cargo-bins/cargo-binstall
ENV BINSTALL_VERSION=1.10.21
# renovate: datasource=github-releases depName=psastras/sbom-rs
ENV CARGO_SBOM_VERSION=0.9.1
# renovate: datasource=crate depName=lddtree
ENV LDDTREE_VERSION=0.3.7

# Install unpackaged tools
RUN <<EOF
    curl --retry 5 -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
    cargo binstall --no-confirm cargo-sbom --version $CARGO_SBOM_VERSION
    cargo binstall --no-confirm lddtree --version $LDDTREE_VERSION
EOF

# Set up xx (cross-compilation scripts)
COPY --from=xx / /
ARG TARGETPLATFORM

# Install libraries linked by the binary
# xx-* are xx-specific meta-packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
xx-apt-get install -y \
    xx-c-essentials xx-cxx-essentials pkg-config \
    libsqlite3-dev libssl-dev libudev-dev


# Set up Rust toolchain
WORKDIR /app
COPY ./rust-toolchain.toml .
RUN rustc --version \
    && rustup target add $(xx-cargo --print-target-triple)

# Build binary
# We disable incremental compilation to save disk space, as it only produces a minimal speedup for this case.
RUN echo "CARGO_INCREMENTAL=0" >> /etc/environment

# Configure pkg-config
RUN <<EOF
    echo "PKG_CONFIG_LIBDIR=/usr/lib/$(xx-info)/pkgconfig" >> /etc/environment
    echo "PKG_CONFIG=/usr/bin/$(xx-info)-pkg-config" >> /etc/environment
    echo "PKG_CONFIG_ALLOW_CROSS=true" >> /etc/environment
EOF

# Configure cc to use clang version
RUN <<EOF
    echo "CC=clang" >> /etc/environment
    echo "CXX=clang++" >> /etc/environment
EOF

# Cross-language LTO
RUN <<EOF
    echo "CFLAGS=-flto" >> /etc/environment
    echo "CXXFLAGS=-flto" >> /etc/environment
    # Linker is set to target-compatible clang by xx
    echo "RUSTFLAGS='-Clinker-plugin-lto -Clink-arg=-fuse-ld=lld'" >> /etc/environment
EOF

# Apply CPU-specific optimizations if TARGET_CPU is provided
ARG TARGET_CPU=
RUN <<EOF
  set -o allexport
  . /etc/environment
  if [ -n "${TARGET_CPU}" ]; then
    echo "CFLAGS='${CFLAGS} -march=${TARGET_CPU}'" >> /etc/environment
    echo "CXXFLAGS='${CXXFLAGS} -march=${TARGET_CPU}'" >> /etc/environment
    echo "RUSTFLAGS='${RUSTFLAGS} -C target-cpu=${TARGET_CPU}'" >> /etc/environment
  fi
EOF

# Prepare output directories
RUN mkdir /out

FROM toolchain AS builder

ARG TARGETPLATFORM

ARG KANIDM_FEATURES=""
ARG KANIDM_BUILD_PROFILE=""
ARG KANIDM_BUILD_OPTIONS=""

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}

# Verify environment configuration
RUN cat /etc/environment
RUN xx-cargo --print-target-triple

# Get source
COPY . .

# Build the binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target \
    /bin/bash <<EOF
    set -o allexport
    . /etc/environment
    PACKAGES_LIST=("kanidm_tools" "kanidm-ipa-sync" "kanidm-ldap-sync")
    TARGET_DIR=(\$(cargo metadata --no-deps --format-version 1 | \
            jq -r ".target_directory"))
    mkdir /out/sbin
    for PACKAGE in "\${PACKAGES_LIST[@]}"; do
        xx-cargo build --locked --release \
            -p \$PACKAGE ${KANIDM_BUILD_OPTIONS} \
            --features="${KANIDM_FEATURES}";
        BINARIES=(\$(cargo metadata --no-deps --format-version 1 | \
            jq -r ".packages[] | select(.name == \"\$PACKAGE\") | .targets[] | select( .kind | map(. == \"bin\") | any ) | .name"))
        for BINARY in "\${BINARIES[@]}"; do
            echo \$BINARY
            xx-verify \$TARGET_DIR/$(xx-cargo   --print-target-triple)/release/\$BINARY
            cp \$TARGET_DIR/$(xx-cargo --print-target-triple)/release/\$BINARY /out/sbin/\$BINARY
        done
    done
EOF

# Generate Software Bill of Materials (SBOM)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    bash <<EOF
    mkdir /out/sbom
    typeset -A PACKAGES
    for BINARY in /out/sbin/*; do
        BINARY_BASE=\$(basename \${BINARY})
        package=\$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[] | select(.targets[] | select( .kind | map(. == \"bin\") | any ) | .name == \"\$BINARY_BASE\") | .name")
        if [ -z "\$package" ]; then
            continue
        fi
        PACKAGES[\$package]=1
    done
    for PACKAGE in \$(echo \${!PACKAGES[@]}); do
        echo \$PACKAGE
        cargo sbom --cargo-package \$PACKAGE > /out/sbom/\$PACKAGE.spdx.json
    done
EOF

# Extract dynamically linked dependencies
RUN <<EOF
    mkdir /out/libs
    mkdir /out/libs-root
    for BINARY in /out/sbin/*; do
        lddtree "$BINARY" | awk '{print $(NF-0) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {}
    done
EOF

# For runtime server
RUN mkdir /etc/kanidm && \
    touch /etc/kanidm/config

FROM toolchain as fido-builder

ARG TARGETPLATFORM

ARG KANIDM_FEATURES=""
ARG KANIDM_BUILD_PROFILE=""
ARG KANIDM_BUILD_OPTIONS=""

# Set the build profile
ENV KANIDM_BUILD_PROFILE=${KANIDM_BUILD_PROFILE:-container_generic}

# Verify environment configuration
RUN cat /etc/environment
RUN xx-cargo --print-target-triple

# Get source
RUN git init && \
    git remote add origin https://github.com/kanidm/webauthn-rs.git && \
    git fetch origin 66a3d9903b31fa5a67fc00dd65ba8f55695df183 && \
    git reset --hard FETCH_HEAD

# Build the binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target,id=/fido/target \
    bash <<EOF
    set -o allexport
    . /etc/environment
    TARGET_DIR=(\$(cargo metadata --no-deps --format-version 1 | \
            jq -r ".target_directory"))
    mkdir /out/sbin
    PACKAGE=fido-mds-tool
    # The lock file in this repo is not complete
    xx-cargo build --release \
        -p \$PACKAGE;
    BINARIES=(\$(cargo metadata --no-deps --format-version 1 | \
        jq -r ".packages[] | select(.name == \"\$PACKAGE\") | .targets[] | select( .kind | map(. == \"bin\") | any ) | .name"))
    for BINARY in "\${BINARIES[@]}"; do
        echo \$BINARY
        xx-verify \$TARGET_DIR/$(xx-cargo   --print-target-triple)/release/\$BINARY
        cp \$TARGET_DIR/$(xx-cargo --print-target-triple)/release/\$BINARY /out/sbin/\$BINARY
    done
EOF

# Generate Software Bill of Materials (SBOM)# Generate Software Bill of Materials (SBOM)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    bash <<EOF
    mkdir /out/sbom
    typeset -A PACKAGES
    for BINARY in /out/sbin/*; do
        BINARY_BASE=\$(basename \${BINARY})
        package=\$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[] | select(.targets[] | select( .kind | map(. == \"bin\") | any ) | .name == \"\$BINARY_BASE\") | .name")
        echo \$BINARY \$package
        if [ -z "\$package" ]; then
            continue
        fi
        PACKAGES[\$package]=1
    done
    for PACKAGE in \$(echo \${!PACKAGES[@]}); do
        echo \$PACKAGE
        cargo sbom --cargo-package \$PACKAGE > /out/sbom/\$PACKAGE.spdx.json
    done
EOF

# Extract dynamically linked dependencies
RUN <<EOF
    mkdir /out/libs
    mkdir /out/libs-root
    for BINARY in /out/sbin/*; do
        lddtree "$BINARY" | awk '{print $(NF-0) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {}
    done
EOF

FROM scratch

WORKDIR /

# Copy root certs for tls into image
# You can also mount the certs from the host
# --volume /etc/ssl/certs:/etc/ssl/certs:ro
COPY --from=base /etc/ssl/certs /etc/ssl/certs

# Copy our build
COPY --from=builder --chmod=0755 /out/sbin/ /sbin/
COPY --from=fido-builder --chmod=0755 /out/sbin/ /sbin/

# Copy SBOM
COPY --from=builder /out/sbom/ /sbom/
COPY --from=fido-builder /out/sbom/ /sbom/


# Copy dynamic libraries to root
COPY --from=builder /out/libs-root/ /
COPY --from=builder /out/libs/ /usr/lib/

COPY --from=fido-builder /out/libs/ /usr/lib/

# Inform linker where to find libraries
ENV LD_LIBRARY_PATH=/usr/lib

ENV RUST_BACKTRACE=1

COPY --from=builder /etc/kanidm/ /etc/kanidm/

CMD [ "/sbin/kanidm", "-h" ]