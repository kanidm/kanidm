#!/usr/bin/env bash

echo "Updating local packages"
apt-get update

echo "Installing build dependencies"
apt-get install -y \
          libpam0g-dev \
          libudev-dev \
          libssl-dev \
          libsqlite3-dev \
          pkg-config \
          make \
          devscripts \
          fakeroot \
          dh-make \
          debmake

echo "Installing rustup"

if [ "$(which cargo | wc -l)" -ne 1 ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > "$TMPDIR/rustup.sh"
    chmod +x "${TMPDIR}/rustup.sh"
    "${TMPDIR}/rustup.sh" -y
fi

# shellcheck disable=SC1091
source "$HOME/.cargo/env"
echo "Done installing rustup!"
