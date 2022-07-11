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
          cargo \
          make \
          devscripts \
          fakeroot \
          dh-make \
          debmake
