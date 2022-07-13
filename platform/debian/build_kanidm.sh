#!/usr/bin/bash

# you can skip the dependency install by setting the env var SKIP_DEPS=1

set -e

if [ -z "$1" ]; then
    PACKAGE="kanidm"
else
    PACKAGE="$1"
fi

if [ ! -d "./platform/debian/${PACKAGE}" ]; then
    echo "Can't find packaging files for ${PACKAGE}"
    exit 1
fi

echo "Building ${PACKAGE}"

# gotta do the sudo thing in github actions, or... in general
if [ "$(whoami)" != "root" ]; then
    SUDO="sudo "
else
    SUDO=""
fi
if [ -n "${GITHUB_WORKSPACE}" ]; then
    SOURCE_DIR="${GITHUB_WORKSPACE}"
else
    SOURCE_DIR="${HOME}/kanidm"
fi
BUILD_DIR="$HOME/build"

if [ -z "${SKIP_DEPS}" ]; then
    if [ "$(which sudo | wc -l)" -eq 0 ]; then
        apt-get update && apt-get -y install sudo
    fi
    "${SUDO}./platform/debian/install_deps.sh"
else
    echo "SKIP_DEPS configured, skipping install of rust and packages"
fi

#shellcheck disable=SC1091
source "$HOME/.cargo/env"

# if we can't find cargo then need to update the path
if [ "$(which cargo | wc -l)" -eq 0 ]; then
    if echo "$PATH" | grep -q '.cargo/bin'; then
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

# we only want the short commit
GIT_COMMIT="${GIT_HEAD:0:7}"
DATESTR="$(date +%Y%m%d%H%M)"

PACKAGE_VERSION="${KANIDM_VERSION}-${DATESTR}${GIT_COMMIT}"
echo "Package Version: ${PACKAGE_VERSION}"

echo "Updating package dir"
rm -rf "${BUILD_DIR:?}/*"

echo "Copying source files to ${BUILD_DIR}"
rsync -a \
    --exclude target \
    "${SOURCE_DIR}" \
    "${BUILD_DIR}/"

echo "Copying the debian-specific build files"
cd "${BUILD_DIR}/kanidm"
rm -rf debian && mkdir -p debian
cp -R platform/debian/packaging/* debian/

if [ -d "platform/debian/${PACKAGE}/" ]; then
    echo "Copying debian-specific files for ${PACKAGE}"
    # shellcheck disable=SC2086
    cp platform/debian/${PACKAGE}/* debian/
else
    echo "No package-specific files were found"
fi

echo "Setting permissions on debian scripts"
find "./debian/" -name 'pre*' -ls -exec chmod 755 "{}" \;
find "./debian/" -name 'rules' -ls -exec chmod 755 "{}" \;


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
fakeroot debian/rules binary

echo "Moving debs to target/"
find ../ -maxdepth 1 -name '*.deb' -exec mv "{}" "${SOURCE_DIR}/target/" \;

echo "Done, packages:"
find "${SOURCE_DIR}/target/" -maxdepth 1 -name '*.deb'
