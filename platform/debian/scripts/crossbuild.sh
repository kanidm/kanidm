#!/bin/bash

set -e

BASEDIR="$(readlink -f $(dirname $0)/..)"

if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    if [ -d "${BASEDIR}/crossbuild" ]; then
        echo "Valid targets:"
        find "${BASEDIR}/crossbuild/images/" -maxdepth 1 -mindepth 1 -name "*.dockerfile" -exec basename {} .dockerfile \; | sort
    else
	echo "Missing crossbuild configs, cannot proceed."
    fi
    exit 1
fi

if [ ! -f "Cargo.toml" ]; then
    >&2 echo "Your current working directory doesn't look like we'll find the sources to build. This script must be run from from a checked out copy of the kanidm/kanidm project root."
    exit 1
fi

# Iterate over given targets.
targets=("$@")
for target in "${targets[@]}"; do
	# Find the target OS & rust architecture
	OS=$(echo "$target" | cut -d \- -f 1-2)
	TRIPLET=$(echo "$target" | cut -d \- -f 3-)
	OS_TOML="${BASEDIR}/crossbuild/${OS}.toml"
	DOCKERFILE="${BASEDIR}/crossbuild/images/${target}.dockerfile"

	if [ ! -f "${OS_TOML}" ]; then
	    echo "Could not find OS rules at: ${OS_TOML}"
	    exit 1
	fi
	if [ ! -f "${BASEDIR}/crossbuild/images/${target}.dockerfile" ]; then
	    echo "Could not find arch image at: ${DOCKERFILE}"
	    exit 1
	fi

	echo "Crossbuilding for: ${TRIPLET} on ${OS}"
	rustup target add "$TRIPLET"

	export CROSS_CONFIG="${OS_TOML}"

	cross build --target "$TRIPLET" \
		--bin kanidm_unixd \
		--bin kanidm_unixd_tasks \
		--bin kanidm_ssh_authorizedkeys \
		--bin kanidm-unix \
		--bin kanidm \
		--release
	cross build --target "$TRIPLET" \
		-p pam_kanidm \
		-p nss_kanidm \
		--release

	echo "Build artefacts for ${TRIPLET}:"
	find "./target/${TRIPLET}/release/" -maxdepth 1 \
    	    -type f -not -name '*.d' -not -name '*.rlib' \
	    -name '*kanidm*'
done
echo "All current artefacts across targets:"
find ./target/*/release/ -maxdepth 1 \
    -type f -not -name '*.d' -not -name '*.rlib' \
    -name '*kanidm*'
