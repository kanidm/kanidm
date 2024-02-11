#!/bin/sh

# Download and bundle mermaid module files into single Zip
# Author: Frank Rehberger
# Date: 2023.03.09
# Usage: scripts/package_mermaid_release.sh doc/js https://cdn.jsdelivr.net/npm/mermaid@10/dist/ mermaid.esm.min.mjs

PKG_DIR="${1:-./doc/js}"
PKG_URL="${2:-https://cdn.jsdelivr.net/npm/mermaid@10.8.0/dist/}"
PKG_NAME="${3:-mermaid.esm.min.mjs}"

DOWNLOAD_DIR="${PKG_DIR}.dl"

pkg_download() {
  url="$1"

  curl -s "$url" | grep 'href="/npm/mermaid' | grep -io '<a .*href=['"'"'"][^"'"'"']*['"'"'"]' |  sed -e 's/^<a rel="nofollow" href=["'"'"']//i'  -e 's/["'"'"']$//i'  | while read uri; do
    echo "Downloading https://cdn.jsdelivr.net$uri"
    wget  "https://cdn.jsdelivr.net$uri" 2>/dev/null;
  done
}

echo "Downloading packages from $PKG_URL"
if ! test -d "$DOWNLOAD_DIR"; then
  mkdir -p "$DOWNLOAD_DIR"
  ( cd "$DOWNLOAD_DIR";  pkg_download "$PKG_URL")
fi

mkdir -p "$PKG_DIR"
echo "Creating bundle $PKG_DIR/$PKG_NAME.zip"
PKG_FILE=$(realpath $PKG_DIR/$PKG_NAME.zip)
( cd "$DOWNLOAD_DIR"; zip -9 -r "$PKG_FILE" *)
echo
echo "Bundle size"
ls -alh "$PKG_DIR/$PKG_NAME.zip"

