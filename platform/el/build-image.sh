#!/usr/bin/env bash
# Should have probably been just a Dockerfile ...

set -uex

CURDIR=$(readlink -f $(dirname -- "$0"))
CACHE_DIR=${CACHE_DIR:-$(readlink -f $CURDIR/cache)}

BASE_IMAGE=${BASE_IMAGE:-almalinux:9}
IMAGE_NAME=${IMAGE_NAME:-kanidm-builder-el9}
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-stable}

OS_PACKAGES=(
    openssl-devel
    systemd-devel
    sqlite-devel
    openssl-devel
    pam-devel
    clang
    which
    git
    rpm-build
    systemd-rpm-macros
    rsync
    perl-core
)

c=$(buildah from $BASE_IMAGE)

# Install a rust toolchain
export CARGO_HOME=$CACHE_DIR/cargo
export RUSTUP_HOME=$CACHE_DIR/rustup
export RUSTUP_INIT_SKIP_PATH_CHECK=yes

mkdir -p $CARGO_HOME $RUSTUP_HOME

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o $CACHE_DIR/rustup-init.sh
sh $CACHE_DIR/rustup-init.sh -y --no-modify-path --default-toolchain=$RUST_TOOLCHAIN

# Install system dependencies
mkdir -p $CACHE_DIR/dnf
buildah run -v $CACHE_DIR/dnf:/var/cache/dnf "$c" -- dnf --setopt=keepcache=True install -y "${OS_PACKAGES[@]}"

cat > $CACHE_DIR/rustenv.sh <<'EOF'
export CARGO_HOME=/cargo
export RUSTUP_HOME=/rustup
export CC=/usr/bin/clang
export PATH="/cargo/bin:$PATH"
EOF
buildah copy --chmod 0755 $c $CACHE_DIR/rustenv.sh /etc/profile.d/rustenv.sh

buildah config \
    --workingdir=/src \
    --volume=/src \
    --volume=/cargo \
    --volume=/rustup \
    $c

buildah commit --rm $c $IMAGE_NAME
