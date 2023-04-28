#!/usr/bin/env bash

set -uex

CURDIR="$(readlink -f $(dirname -- "$0"))"
TOPDIR="$(git rev-parse --show-toplevel)"

VERSION=$(grep -m1 -F 'version = ' $TOPDIR/Cargo.toml | cut -d'"' -f2)
VERSION=$(echo $VERSION | sed 's/-/~/g')
COMMIT=$(git rev-parse --short HEAD)

rm -rf /src/target/.rpmbuild/
mkdir -p /src/target/.rpmbuild/{RPMS,BUILDROOT,BUILD,SOURCES}

(
    cd $TOPDIR
    rpmbuild --build-in-place -bb "$CURDIR/kanidm.spec" \
        -D "_version ${VERSION}.${COMMIT}" \
        -D "_release ${RELEASE:-0}" \
        -D "_topdir /src/target/.rpmbuild" \
        -D "_sourcedir /src/platform/el"
)

mkdir -p /src/target/release/rpms
find /src/target/.rpmbuild/RPMS/ -iname '*.rpm' -exec cp -v '{}' /src/target/release/rpms \;
