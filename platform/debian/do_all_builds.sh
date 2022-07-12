#!/usr/bin/env bash

echo "building Kanidm"
./platform/debian/build_kanidm.sh kanidm

echo "building Kanidmd"
./platform/debian/build_kanidm.sh kanidmd

echo "Building kanidm-pamnss"
./platform/debian/build_kanidm.sh kanidm-pamnss


echo "Building kanidm-ssh"
./platform/debian/build_kanidm.sh kanidm-ssh

