#!/bin/bash

if [ -z "$(which jq)" ]; then
    echo "jq is required to run this script. Please install jq and try again."
    exit 1
fi

PACKAGE_FOR_VERSION="kanidm_proto"

PKG_VERSION="$(cargo metadata --format-version 1 | jq -r ".packages[] | select(.name==\"$PACKAGE_FOR_VERSION\") | .version")-pre"
if [ -z "$PKG_VERSION" ]; then
    echo "Failed to get release version from cargo metadata based on package '$PACKAGE_FOR_VERSION'. Please check the package name and try again."
    exit 1
fi
echo "Confirm the release version will be: ${PKG_VERSION}"
printf '%s' "Press Enter to continue... Ctrl-c if not"
# shellcheck disable=SC2034
read -r release_continue
echo "Committing..."
git commit -m "Release ${PKG_VERSION}"
TAG="v${PKG_VERSION}"
echo "Tagging... ${TAG}"
git tag "$TAG"
echo "Pushing tag ${TAG} to origin..."
git push origin "$TAG" --tags