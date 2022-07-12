#!/usr/bin/bash

# you can skip the dependency install by setting the env var SKIP_DEPS=1

set -e

if [ -z $1 ]; then
    PACKAGE="kanidm"
else
    PACKAGE="$1"
fi

if [  -z "$(echo $PATH | grep -o '/root/.cargo/bin')" ]; then
    echo "Updating path to include local cargo dir"
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Building ${PACKAGE}"

SOURCE_DIR="/usr/src/kanidm"
BUILD_DIR="/build"
PACKAGE_DIR="${BUILD_DIR}/kanidm"
BINARY_DIR="${PACKAGE_DIR}/usr/local/bin"

if [ -z "${SKIP_DEPS}" ]; then
    ./platform/debian/install-deps.sh
fi

KANIDM_VERSION="$(grep -ioE 'version.*' kanidm_tools/Cargo.toml | head -n1 | awk '{print $NF}' | tr -d '"')"
GIT_HEAD="$(git rev-parse HEAD)"
GIT_COMMIT="${GIT_HEAD:0:7}"
# DATESTR="$(date +%Y%m%d%H%M)"

# PACKAGE_VERSION="${KANIDM_VERSION}-${DATESTR}-${GIT_COMMIT}"
PACKAGE_VERSION="${KANIDM_VERSION}-${GIT_COMMIT}"
echo "Package Version: ${PACKAGE_VERSION}"

# echo "Building kanidm"
# make local/kanidm

echo "Building package dir"
rm -rf "${BUILD_DIR}/*"

# where the binary will go
# mkdir -p "${BINARY_DIR}"
# just debian things
# mkdir -p "${PACKAGE_DIR}/DEBIAN"
# cp platform/debian/kanidm/* "${PACKAGE_DIR}/DEBIAN"
# chmod 555 ${PACKAGE_DIR}/DEBIAN/*

# echo "Updating version in control file"
# sed -E --in-place='' "s/Version\:\s+(.*)/Version: ${PACKAGE_VERSION}/" "${PACKAGE_DIR}/DEBIAN/control"

# echo "Copying files around"
# cp target/release/kanidm "${BINARY_DIR}/"
# cd "${PACKAGE_DIR}" || { echo "Failed to cd to ${PACKAGE_DIR}"; exit 1; }


# echo "Building kanidm.deb"
# dpkg-deb --build --root-owner-group "${PACKAGE_DIR}"

# echo "Dumping info"
# dpkg -I "${PACKAGE_DIR}.deb"

# echo "Creating source package"
# cd "${SOURCE_DIR}/../"

# tar czf "/build/kanidm.tar.gz" \
#     --exclude .git \
#     --exclude target \
#     --exclude kanidm_book \
#     --exclude artwork \
#     --exclude pykanidm \
#     --exclude designs \
#     --exclude project_docs \
#     kanidm
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

# echo "Extracting package"
cd "${BUILD_DIR}/kanidm"
# tar zxf kanidm.tar.gz

# cd kanidm

echo "Copying the debian-specific build files"
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
