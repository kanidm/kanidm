#!/bin/bash

set -e

if [ ! -f build.sh ]; then
    echo "Please run from the package base directory!"
    exit 1
fi

if [ -z "${BUILD_FLAGS}" ]; then
    BUILD_FLAGS="--release"
    # DURING DEV
    # BUILD_FLAGS="--dev"
fi

if [ -z "$(which rsync)" ]; then
    echo "Cannot find rsync which is needed to move things around, quitting!"
    exit 1
fi
if [ -z "$(which wasm-pack)" ]; then
    echo "Cannot find wasm-pack which is needed to build the UI, quitting!"
    exit 1
fi

mkdir -p ./pkg

echo "Cleaning up WASM files before build..."
find ./pkg/ -name 'kanidmd*' -exec rm "{}" \;

# we can disable this since we want it to expand
# shellcheck disable=SC2086
wasm-pack build ${BUILD_FLAGS} --no-typescript --target web --mode no-install --no-pack

echo "######################"
echo "Moving files around..."
echo "######################"
touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    rm ./pkg/.gitignore

echo "######################"
echo "Moving files up into the webui pkg dir..."
echo "######################"
rsync -av pkg/* ../pkg/

echo "######################"
echo "        Done!"
echo "######################"