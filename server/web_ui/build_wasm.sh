#!/bin/sh

set -e

# This builds the assets for the Web UI, defaulting to a release build.
if [ ! -f build_wasm.sh ]; then
    echo "Please run from the crate directory. (server/web_ui)"
    exit 1
fi

# if [ -z "${BUILD_FLAGS}" ]; then
#     BUILD_FLAGS="--release"
# fi

if [ -z "$(which rsync)" ]; then
    echo "Cannot find rsync which is needed to move things around, quitting!"
    exit 1
fi

if [ -z "$(which wasm-pack)" ]; then
    echo "Cannot find wasm-pack which is needed to build the UI, quitting!"
    exit 1
fi

# if [ "$(find ./pkg/ -name 'kanidmd*' | wc -l)" -gt 0 ]; then
#     echo "Cleaning up WASM files before build..."
#     rm pkg/kanidmd*
# fi

# # we can disable this since we want it to expand
# # shellcheck disable=SC2086
# wasm-pack build ${BUILD_FLAGS} --no-typescript --target web --mode no-install --no-pack

find pkg/ -type f -delete
find pkg/ -mindepth 1 -type d -delete

touch ./pkg/ANYTHING_HERE_WILL_BE_DELETED_IN_BUILDS
# rsync -av --copy-links ./static/* ./pkg/
cp ../../README.md ./pkg/
cp ../../LICENSE.md ./pkg/
if [ -f ./pkg/.gitignore ]; then
    rm ./pkg/.gitignore
fi

# copy the shared static things
rsync -av shared/static/* shared/static/* pkg/


cd admin
./build.sh
cd ..

cd login_flows
./build.sh
cd ..

cd user
./build.sh
cd ..



if [ -z "${SKIP_BROTLI}" ]; then
    # updates the brotli-compressed files
    echo "brotli-compressing compressible files over 16KB in size..."
    find ./pkg -size +16k -type f -not -name '*.png' -exec ./find_best_brotli.sh "{}" \; || exit 1
fi

