#!/bin/bash

# stupid permissions issues
sudo chown vscode ~/ -R
sudo chgrp vscode ~/ -R

export PATH="$HOME/.cargo/bin:$PATH"
SCCACHE_SERVER_UDS="/tmp/sccache.sock" sccache --start-server

# to set up sccache etc
if [ "$(grep -c "devcontainer_poststart" ~/.bashrc)" -eq 0 ]; then
    echo "adding devcontainer_poststart to bashrc"
    echo "source /workspaces/kanidm/scripts/devcontainer_poststart.sh" >> ~/.bashrc
fi
export RUSTC_WRAPPER="sccache"
export CC="sccache /usr/bin/clang"

# disable incremental builds
# cargo docs: https://doc.rust-lang.org/cargo/reference/profiles.html#incremental
# sccache docs on why to disable incremental builds: https://github.com/mozilla/sccache#known-caveats
export CARGO_INCREMENTAL=false
