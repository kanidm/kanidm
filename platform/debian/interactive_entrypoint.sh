#!/bin/bash

if [ -z "${TZ}" ]; then
    export TZ="UTC"
fi

ln -snf "/usr/share/zoneinfo/$TZ" "/etc/localtime" && echo "$TZ" > /etc/timezone

# Install dependencies, for example make!
scripts/install_ubuntu_dependencies.sh

# Make git happy
git config --global --add safe.directory /root/kanidm

echo "To launch a deb build, try:"
echo "make -f ./platform/debian/Makefile debs/kanidm"

# Launch shell
exec /bin/bash "$@"
