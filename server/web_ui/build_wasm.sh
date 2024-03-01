#!/bin/sh

set -e

# This builds the assets for the Web UI, defaulting to a release build.
if [ ! -f build_wasm.sh ]; then
    echo "Please run from the crate directory. (server/web_ui)"
    exit 1
fi
if [ -z "$(which rsync)" ]; then
    echo "Cannot find rsync which is needed to move things around, quitting!"
    exit 1
fi
if [ -z "$(which wasm-pack)" ]; then
    echo "Cannot find wasm-pack which is needed to build the UI, quitting!"
    exit 1
fi
if [ -z "$(which wasm-bindgen)" ]; then
    echo "Cannot find wasm-bindgen which is needed to build the UI, quitting!"
    exit 1
fi
if [ -z "$(which bc)" ]; then
    echo "Cannot find bc which is needed to build the UI, quitting!"
    exit 1
fi

if [ -z "${BUILD_FLAGS}" ]; then
    export BUILD_FLAGS="--release"
fi

echo "Cleaning up pkg dir"
find pkg/ -type f -delete
find pkg/ -mindepth 1 -type d -delete

touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_IN_BUILDS
# cp ../../README.md ./pkg/
# cp ../../LICENSE.md ./pkg/
if [ -f ./pkg/.gitignore ]; then
    rm ./pkg/.gitignore
fi

# copy the shared static things
rsync -av shared/static/* admin/static/* user/static/* login_flows/static/* pkg/


cd admin
echo "building admin"
../individual_build.sh || exit 1
cd ..
echo "done building admin"

cd login_flows
echo "building login_flows"
../individual_build.sh || exit 1
cd ..
echo "done building login_flows"

cd user
echo "building user"
../individual_build.sh || exit 1
cd ..
echo "done building user"



if [ -z "${SKIP_BROTLI}" ]; then
    # updates the brotli-compressed files
    echo "brotli-compressing compressible files over 16KB in size..."
    find ./pkg -size +16k -type f \
        -not -name '*.br' \
        -not -name '*.png' \
        -exec ./find_best_brotli.sh "{}" \; || exit 1
fi

