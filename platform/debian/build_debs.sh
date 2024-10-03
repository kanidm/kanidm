#!/usr/bin/bash

# This script chains together the pieces needed to package all supported deb packages.
# For simplicity, it does not run the required build(s) first, that's on you / the CI pipeline.

# you can skip the dependency install by setting the env var SKIP_DEPS=1

set -e

# The target triplet can be set as a param or env variable TRIPLET
# Defaults to the native triplet
if [ -z "${TRIPLET}" ]; then
    NATIVE_TRIPLET="$(rustc --version --verbose | grep host | cut -d ' ' -f 2)"
    TRIPLET="${1:-$NATIVE_TRIPLET}"
fi

if [ -z "${VERBOSE}" ]; then
    VERBOSE=""
else
    VERBOSE="-v"
fi

echo "Packaging for: ${TRIPLET}"

if [ -z "${SKIP_DEPS}" ]; then
    PACKAGING=1 ./scripts/install_ubuntu_dependencies.sh
else
    echo "SKIP_DEPS configured, skipping install of rust and packages. Hope you know what you're doing."
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


# Get the version. cargo-deb does have some version handling but it fails at a few key items such as the `-dev` suffix.
# if we're in a github action, then it's easy to get the commit hash
if [ -n "${GITHUB_SHA}" ]; then
    GIT_HEAD="${GITHUB_SHA}"
else
    GIT_HEAD="$(git rev-parse HEAD)"
fi
KANIDM_VERSION="$(grep -ioE 'version.*' Cargo.toml | head -n1 | awk '{print $NF}' | tr -d '"' | sed -e 's/-/~/')"
DATESTR="$(date +%Y%m%d%H%M)"
GIT_COMMIT="${GIT_HEAD:0:7}"
DEBIAN_REV="${DATESTR}+${GIT_COMMIT}"
PACKAGE_VERSION="${KANIDM_VERSION}-${DEBIAN_REV}"

echo "Package version: ${PACKAGE_VERSION}"

echo "Updating changelog"
mkdir -p target/debian
sed -E \
    "s/#DATE#/$(date -R)/" \
    platform/debian/packaging/templates/changelog  | \
    sed -E "s/#VERSION#/${PACKAGE_VERSION}/" | \
    sed -E "s/#GIT_COMMIT#/${GIT_COMMIT}/" | \
    sed -E "s/#PACKAGE#/${PACKAGE}/" > target/debian/changelog

for workspace in kanidm_unix_int pam_kanidm nss_kanidm; do
    echo "Building deb for: ${workspace}"
    cargo deb "$VERBOSE" -p "$workspace" --no-build --target "$TRIPLET" --deb-version "$PACKAGE_VERSION"
done

echo "Done, packages:"
find "target/${TRIPLET}" -maxdepth 3 -name '*.deb'
