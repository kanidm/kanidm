#!/usr/bin/bash

# you can skip the dependency install by setting the env var SKIP_DEPS=1

set -e

if [ -z "${ARCH}" ]; then
    ARCH="$(dpkg --print-architecture)"
fi

if [ "${ARCH}" != "$(dpkg --print-architecture)" ]; then
    echo "${ARCH} != $(dpkg --print-architecture), cross-compiling!"
    export PKG_CONFIG_ALLOW_CROSS=1
else
    echo "Building for ${ARCH}"
fi


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


SOURCE_DIR="$(cargo metadata --format-version 1 | jq -r .workspace_root)"

echo "Source dir ${SOURCE_DIR}"

if [ ! -d "${SOURCE_DIR}" ]; then
    echo "Can't find source dir ${SOURCE_DIR}!"
    exit 1
fi

BUILD_DIR="$(mktemp -d)"

if [ -z "${SKIP_DEPS}" ]; then
    PACKAGING=1 ./scripts/install_ubuntu_dependencies.sh
else
    echo "SKIP_DEPS configured, skipping install of rust and packages"
fi

if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
else
    echo "Couldn't find cargo env in ${HOME}/.cargo/env that seems weird?"
fi

# if we can't find cargo then need to update the path
if [ "$(which cargo | wc -l)" -eq 0 ]; then
    if echo "$PATH" | grep -q '.cargo/bin'; then
        echo "Updating path to include local cargo dir"
        export PATH="$HOME/.cargo/bin:$PATH"
        if [ "$(which cargo | wc -l)" -eq 0 ]; then
            echo "Still couldn't find cargo, bailing!"
            exit 1
        fi
    fi
fi

# this assumes the versions are in lock-step, which is fine at the moment.
KANIDM_VERSION="$(grep -ioE 'version.*' Cargo.toml | head -n1 | awk '{print $NF}' | tr -d '"')"

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

echo "Copying source files from ${SOURCE_DIR} to ${BUILD_DIR}"
rsync -a \
    --exclude target \
    "${SOURCE_DIR}/" \
    "${BUILD_DIR}/"

echo "Copying the debian-specific build files"
cd "${BUILD_DIR}"
pwd
ls -la
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
mkdir -p "${SOURCE_DIR}/target/"
find ../ -maxdepth 1 -name '*.deb' -exec mv "{}" "${SOURCE_DIR}/target/" \;

echo "Done, packages:"
find "${SOURCE_DIR}/target/" -maxdepth 1 -name '*.deb'
