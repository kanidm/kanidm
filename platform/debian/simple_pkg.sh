#!/usr/bin/env bash

set -xe

## NOTE this is based on the Arch Linux PKGBUILD. It combines kanidm_tools, unixd and ssh
# as well as the systemd services. This is a simple alternative for building a tarball for
# use on debian based systems (tested on ubuntu 22.04).

pushd "$( dirname -- "$0"; )/../../"

pkgdir=$(realpath kanidm_simple_pkg)
rm -rf "$pkgdir"
mkdir -p "$pkgdir"

# build the project
make release/kanidm release/kanidm-unixd release/kanidm-ssh

# enable the following block to include deployment specific configuration files
if [ "${INCLUDE_CONFIG}" -eq 1 ]; then
  mkdir -p deployment-config

  # Customize the following heredocs according to the deployment
  cat << EOF > deployment-config/config
uri = "https://idm.example.com"
verify_ca = true
verify_hostnames = true
EOF

  cat << EOF > deployment-config/unixd
pam_allowed_login_groups = [""]
EOF

  install -Dm644 deployment-config/config "${pkgdir}/etc/kanidm/config"
  install -Dm644 deployment-config/unixd "${pkgdir}/etc/kanidm/unixd"

fi

# This is for allowing login via PAM. It needs to be enabled using `pam-auth-update`
install -Dm644  platform/debian/kanidm-unixd/kanidm-unixd.pam "${pkgdir}/usr/share/pam-configs/kanidm-unixd"

# Install kanidm cli
install -Dm755 target/release/kanidm "${pkgdir}/usr/local/sbin/kanidm"
install -Dm644 target/release/build/completions/_kanidm "${pkgdir}/usr/share/zsh/site-functions/_kanidm"
install -Dm644 target/release/build/completions/kanidm.bash "${pkgdir}/usr/share/bash-completion/completions/kanidm.sh"

# Install systemd service files
install -Dm644 examples/systemd/kanidm-unixd.service "${pkgdir}/usr/lib/systemd/system/kanidm-unixd.service"
install -Dm644 examples/systemd/kanidm-unixd-tasks.service "${pkgdir}/usr/lib/systemd/system/kanidm-unixd-tasks.service"

# NB., the debian style lib dir and security dir
install -Dm755 target/release/libnss_kanidm.so "${pkgdir}/usr/lib/x86_64-linux-gnu/libnss_kanidm.so.2"
install -Dm755 target/release/libpam_kanidm.so "${pkgdir}/usr/lib/x86_64-linux-gnu/security/pam_kanidm.so"

# install kanidm unix utilities
install -Dm755 target/release/kanidm_ssh_authorizedkeys "${pkgdir}/usr/local/sbin/kanidm_ssh_authorizedkeys"
install -Dm755 target/release/kanidm_ssh_authorizedkeys_direct "${pkgdir}/usr/local/sbin/kanidm_ssh_authorizedkeys_direct"
install -Dm755 target/release/kanidm_unixd "${pkgdir}/usr/local/sbin/kanidm_unixd"
install -Dm755 target/release/kanidm-unix "${pkgdir}/usr/local/sbin/kanidm-unix"
install -Dm755 target/release/kanidm_unixd_tasks "${pkgdir}/usr/local/sbin/kanidm_unixd_tasks"

# Install Bash and ZSH  completions
install -Dm644 target/release/build/completions/_kanidm_ssh_authorizedkeys_direct "${pkgdir}/usr/share/zsh/site-functions/_kanidm_ssh_authorizedkeys_direct"
install -Dm644 target/release/build/completions/_kanidm_cache_clear "${pkgdir}/usr/share/zsh/site-functions/_kanidm_cache_clear"
install -Dm644 target/release/build/completions/_kanidm_cache_invalidate "${pkgdir}/usr/share/zsh/site-functions/_kanidm_cache_invalidate"
install -Dm644 target/release/build/completions/_kanidm_ssh_authorizedkeys "${pkgdir}/usr/share/zsh/site-functions/_kanidm_ssh_authorizedkeys"

install -Dm644 target/release/build/completions/kanidm_ssh_authorizedkeys_direct.bash "${pkgdir}/usr/share/bash-completion/completions/kanidm_ssh_authorizedkeys_direct.sh"
install -Dm644 target/release/build/completions/kanidm_cache_clear.bash "${pkgdir}/usr/share/bash-completion/completions/kanidm_cache_clear.sh"
install -Dm644 target/release/build/completions/kanidm_cache_invalidate.bash "${pkgdir}/usr/share/bash-completion/completions/kanidm_cache_invalidate.sh"
install -Dm644 target/release/build/completions/kanidm_ssh_authorizedkeys.bash "${pkgdir}/usr/share/bash-completion/completions/kanidm_ssh_authorizedkeys.sh"

tar cvzf "kanidm-client-tools.tar.gz"  -C "$pkgdir" .

# extract the package in root, enable and run the systemd services and then setup nsswitch according to the docs
# and run pam-auth-update. You may also want to setup the ssh config. It's wise to leave a root console open until
# you've confirmed pam-auth-update worked so you don't lock yourself out.

popd

