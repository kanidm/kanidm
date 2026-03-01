#!/bin/bash

CURRDIR="$(pwd)"

mkdir -p /tmp/freeradius-src mkdir -p /usr/include/freeradius-devel/
curl -fsSL https://github.com/FreeRADIUS/freeradius-server/archive/refs/tags/release_3_2_8.tar.gz | tar -xz -C /tmp/freeradius-src
mv /tmp/freeradius-src/freeradius-server-release{*,}
cd /tmp/freeradius-src/freeradius-server-release || { echo "Failed to change directory to /tmp/freeradius-src/freeradius-server-release"; exit 1; }
./configure --with-openssl=no > /tmp/freeradius_configure.log 2>&1
make > /tmp/freeradius_make.log 2>&1
mkdir -p /usr/include/freeradius/
cp -R ./src/include/* /usr/include/freeradius/
cp -R ./src/include/* /usr/include/freeradius-devel/

if [ "${DEBUG:-0}" -eq 1 ]; then
    echo "######################"
    echo "Looking at /usr/include/freeradius-devel/"
    ls -lah /usr/include/freeradius-devel/
    echo "######################"
    echo "Configure log"
    echo "######################"
    cat /tmp/freeradius_configure.log
    echo "######################"
    echo "Freeradius make log:"
    echo "######################"
    cat /tmp/freeradius_make.log
    echo "######################"
fi

echo "Done! Moving back to $CURRDIR"
cd "$CURRDIR" || exit 0