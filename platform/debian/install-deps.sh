#/usr/bin/env bash

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

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > $TMPDIR/rustup.sh
chmod +x $TMPDIR/rustup.sh
$TMPDIR/rustup.sh -y

exit 1

echo "Done installing rustup!"
