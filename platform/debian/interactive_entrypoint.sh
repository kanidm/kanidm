#!/bin/bash

# Install dependencies, for example make!
scripts/install_ubuntu_dependencies.sh

# Make git happy
git config --global --add safe.directory /root/kanidm

echo "To launch a deb build, try:"
echo "make -f ./platform/debian/Makefile debs/kanidm"

# Launch shell
exec /bin/bash "$@"
