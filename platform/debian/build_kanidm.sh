#!/usr/bin/env bash
set -e
SOURCE_DIR="/usr/src/kanidm"
BUILD_DIR="/build"
PACKAGE_DIR="${BUILD_DIR}/kanidm"
BINARY_DIR="${PACKAGE_DIR}/usr/local/bin"

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
          dh-make
KANIDM_VERSION="$(grep -ioE 'version.*' kanidm_tools/Cargo.toml | head -n1 | awk '{print $NF}' | tr -d '"')"
GIT_HEAD="$(git rev-parse HEAD)"
GIT_COMMIT="${GIT_HEAD:0:7}"
DATESTR="$(date +%Y%m%d%H%M)"

PACKAGE_VERSION="${KANIDM_VERSION}-${DATESTR}-${GIT_COMMIT}"
echo "Package Version: ${PACKAGE_VERSION}"

# echo "Building kanidm"
# make local/kanidm

echo "Building package dir"
rm -rf "${PACKAGE_DIR}"
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

echo "Creating source package"
cd "${SOURCE_DIR}/../"

tar czf "/build/kanidm.tar.gz" \
    --exclude .git \
    --exclude target \
    --exclude kanidm_book \
    --exclude artwork \
    --exclude pykanidm \
    --exclude designs \
    --exclude project_docs \
    kanidm

cd "${BUILD_DIR}"
tar zxf kanidm.tar.gz

mv kanidm "kanidm-${PACKAGE_VERSION}"