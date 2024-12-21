#!/bin/bash

IDM_URI="${1?}"
IDM_GROUP="${2?}"
MIRROR_PORT="${3?}"

set -eu

function debug(){
	>&2 echo "Something went wrong, pausing for debug, to connect:"
	>&2 echo "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost -p 2222 -i ssh_ed25519"
	sleep infinity
}

# Make apt shut up about various things to see relevant output better
export DEBIAN_FRONTEND=noninteractive
export LC_CTYPE=en_US.UTF-8
export LC_ALL=en_US.UTF-8

source /etc/os-release
sed "s/%MIRROR_PORT%/${MIRROR_PORT}/;s/%VERSION_CODENAME%/${VERSION_CODENAME}/" kanidm_ppa.list > /etc/apt/sources.list.d/kanidm_ppa.list
mv kanidm_ppa.asc /etc/apt/trusted.gpg.d/

apt update || debug
apt install -y zsh kanidm-unixd kanidm || debug

>&2 echo "Configuring kanidm-unixd"
sed "s_#uri.*_uri = \"${IDM_URI}\"_" -i /etc/kanidm/config
sed "s@#pam_allowed_login_groups.*@pam_allowed_login_groups = \[\"${IDM_GROUP}\"\]@" -i /etc/kanidm/unixd

>&2 echo "Restarting unixd"
systemctl restart kanidm-unixd.service || debug

>&2 echo "Configuring NSS"
sed -E 's/(passwd|group): (.*)/\1: \2 kanidm/' -i /etc/nsswitch.conf

>&2 echo "Configuring sshd"

cat << EOT >> /etc/ssh/sshd_config
PubkeyAuthentication yes
UsePAM yes
AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u
AuthorizedKeysCommandUser nobody
LogLevel DEBUG1
EOT
systemctl restart ssh.service || debug

>&2 echo "Go test ssh login! Do a ^C here when you're done"
>&2 echo "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost -p 2222"
>&2 echo "Or for direct ssh skipping unixd:"
>&2 echo "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost -p 2222 -i ssh_ed25519"
>&2 echo "Now following ssh log:"
journalctl -fu ssh
