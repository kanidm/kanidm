#!/bin/bash
scripts/install-deps.sh
scripts/get-images.sh

# Configs specific to your environment
export SSH_PORT="${SSH_PORT:-2222}" # Any free port will do
export IDM_URI="${IDM_URI?}" # No reasonable default!
export IDM_GROUP="${IDM_GROUP:-posix_login}"
export TELNET_PORT="${TELNET_PORT:-4321}"
export MIRROR_PORT="${MIRROR_PORT:-31625}"

function prompt(){
  read -p "Happy? ^C to stop full run, enter to continue to next target."
}

function run(){
	distro=$1
	shift
	debs=("$@")
	sudo -E scripts/launch-one.sh "$target" images/${distro}-*-${arch}.* ${debs[@]} || exit 1
	prompt
	sleep 2s  # Wait for qemu to release ports
}

### Launch the repo snapshot in the background
# Assumes you've downloaded kanidm_ppa_snapshot.zip from a signed fork branch.
>&2 echo "Launching mirror snapshot"
scripts/run-mirror.sh kanidm_ppa_snapshot.zip &
mirror_pid="$!"
sleep 2s  # A bit of time for the unzip before we try to use the mirror

### Sequencing of permutations. The defaults only test current stable on current native arch
# You could just enable aarch64 manually below, but better off running on a pi5 natively!

target="$(uname -m)"
arch="$(dpkg --print-architecture)"

#target=aarch64
#arch=arm64

run debian-12 debs/stable/stable-debian-12-${target}-unknown-linux-gnu/kanidm*
run jammy debs/stable/stable-ubuntu-22.04-${target}-unknown-linux-gnu/kanidm*
run noble debs/stable/stable-ubuntu-24.04-${target}-unknown-linux-gnu/kanidm*

>&2 echo "Killing mirror snapshot"
kill "$mirror_pid"
