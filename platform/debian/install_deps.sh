#!/usr/bin/env bash

echo "Updating local packages"
sudo apt-get update

echo "Installing build dependencies"
sudo apt-get install -y \
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

if [ -d "$HOME/.cargo/" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

if [ "$(which cargo | wc -l)" -ne 1 ]; then
    echo "Installing rust"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > "$TMPDIR/rustup.sh"
    chmod +x "${TMPDIR}/rustup.sh"
    "${TMPDIR}/rustup.sh" -y
    echo "Done installing rust!"
else
    echo "rust already installed!"
fi

if  [ "$1" == "kanidmd" ] && [ "$(which wasm-pack | wc -l)" -eq 0 ]; then
	echo "Installing wasm-pack"
	echo "Downloading script to ~/install-wasm-pack"
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf > "${HOME}/install-wasm-pack"
	chmod +x "${HOME}/install-wasm-pack"
    sudo "${HOME}/install-wasm-pack"
    rm "${HOME}/install-wasm-pack"
else
    echo "wasm-pack already installed"
fi