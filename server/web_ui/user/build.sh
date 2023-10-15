#!/bin/bash

# MODULE="user"

set -e
# This builds the assets for the Admin UI, defaulting to a release build.

if [ ! -f build.sh ]; then
    echo "Please run from the right directory. (server/web_ui/admin)"
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

if [ "$(find ./pkg/ -name 'kanidmd*' | wc -l)" -gt 0 ]; then
    echo "Cleaning up WASM files before build..."
    rm pkg/kanidmd*
fi
# we can disable this since we want it to expand
# shellcheck disable=SC2086
wasm-pack build ${BUILD_FLAGS} --no-typescript --target web --mode no-install --no-pack

echo "######################"
echo "Moving files around..."
echo "######################"
touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_ADD_TO_SRC && \
    rsync --delete-after -r --copy-links -v ./static/* ./pkg/ && \
    cp ../../../README.md ./pkg/
    cp ../../../LICENSE.md ./pkg/
    rm ./pkg/.gitignore

echo "######################"
echo "Moving files up into the webui pkg dir..."
echo "######################"
# if [ "$(find pkg/external/ -type f | wc -l)" -ne 0 ]; then
#     rsync -av pkg/external/* ../pkg/external/
# fi
# find ../pkg/ -type f -name 'kanidmd_web_*' | grep "kanidmd_web_ui_${MODULE}" | xargs rm
# find "pkg/" -name "kanidmd_web_ui_${MODULE}*" -exec cp "{}" "../pkg/" \;

rsync -av pkg/* ../pkg/

echo "######################"
echo "        Done!"
echo "######################"