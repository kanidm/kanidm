#!/usr/bin/bash

# you can skip the dependency install by setting the env var SKIP_DEPS=1

set -e

if [ -z $1 ]; then
    PACKAGE="kanidm"
else
    PACKAGE="$1"
fi


echo "Building ${PACKAGE}"


if [ "$(whoami)" != "root" ]; then
    SUDO="sudo "
else
    SUDO=""
fi
if [ -n "${GITHUB_WORKSPACE}" ]; then
    SOURCE_DIR="${GITHUB_WORKSPACE}"
else
    SOURCE_DIR="$HOME/kanidm"
fi
BUILD_DIR="$HOME/build"
PACKAGE_DIR="${BUILD_DIR}/kanidm"
BINARY_DIR="${PACKAGE_DIR}/usr/local/bin"


if [ -z "${SKIP_DEPS}" ]; then

    ${SUDO}./platform/debian/install-deps.sh
fi


# if we can't find cargo then need to update the path
if [ "$(which cargo | wc -l)" -eq 0 ]; then
    if [  -z "$(echo $PATH | grep -o '.cargo/bin')" ]; then
        echo "Updating path to include local cargo dir"
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
fi

# this assumes the versions are in lock-step, which is fine at the moment.s
KANIDM_VERSION="$(grep -ioE 'version.*' kanidm_tools/Cargo.toml | head -n1 | awk '{print $NF}' | tr -d '"')"

# if we're in a github action, then it's easy to get the commit
if [ -n "${GITHUB_SHA}" ]; then
    GIT_HEAD="${GITHUB_SHA}"
else
    GIT_HEAD="$(git rev-parse HEAD)"
fi

GIT_COMMIT="${GIT_HEAD:0:7}"
# DATESTR="$(date +%Y%m%d%H%M)"

# PACKAGE_VERSION="${KANIDM_VERSION}-${DATESTR}-${GIT_COMMIT}"
PACKAGE_VERSION="${KANIDM_VERSION}-${GIT_COMMIT}"
echo "Package Version: ${PACKAGE_VERSION}"

# echo "Building kanidm"
# make local/kanidm

echo "Updating package dir"
rm -rf "${BUILD_DIR}/*"

# where the binary will go
# mkdir -p "${BINARY_DIR}"
# just debian things
# mkdir -p "${PACKAGE_DIR}/DEBIAN"
# cp platform/debian/kanidm/* "${PACKAGE_DIR}/DEBIAN"
# chmod 555 ${PACKAGE_DIR}/DEBIAN/*
echo "Setting permissions on debian scripts"
find "${SOURCE_DIR}/platform/debian" -name 'pre*' -ls -exec chmod 555 "{}" \;
find "${SOURCE_DIR}/platform/debian" -name 'rules' -ls -exec chmod 555 "{}" \;

echo "Copying source files to ${BUILD_DIR}"
rsync -a \
    --exclude .git \
    --exclude target \
    --exclude kanidm_book \
    --exclude artwork \
    --exclude pykanidm \
    --exclude designs \
    --exclude project_docs \
    "${SOURCE_DIR}" \
    "${BUILD_DIR}/"



echo "Copying the debian-specific build files"
cd "${BUILD_DIR}/kanidm"
rm -rf debian && mkdir -p debian
cp -R platform/debian/packaging/* debian/

if [ -d "platform/debian/${PACKAGE}/" ]; then
    echo "Copying debian-specific files for ${PACKAGE}"
    cp platform/debian/${PACKAGE}/* debian/
else
    echo "No package-specific files were found"
fi

echo "Updating changelog"

sed -E \
    "s/#DATE#/$(date -R)/" \
    platform/debian/packaging/templates/changelog  | \
    sed -E "s/#VERSION#/${PACKAGE_VERSION}/" | \
    sed -E "s/#GIT_COMMIT#/${GIT_COMMIT}/" | \
    sed -E "s/#PACKAGE#/${PACKAGE}/" > debian/changelog

echo "Running clean"
# debian/rules clean

echo "Running build"
debian/rules build

echo "Packaging ${PACKAGE}"
debian/rules binary
