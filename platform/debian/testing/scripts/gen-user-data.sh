#!/bin/bash
# This script generates a midly secure cloud-config.yaml
# It should only be run once per session, not once per target.

if [[ ! -f ssh_ed25519 ]]; then
	ssh-keygen -t ed25519 -f ssh_ed25519 -q -N ""
fi

cat <<EOT
#cloud-config

users:
  - name: root
    ssh_authorized_keys:
      - $(cat ssh_ed25519.pub)
EOT
