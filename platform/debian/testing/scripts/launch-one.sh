#!/bin/bash

arch="${1?}"
img="${2?}"
shift 2
debglob="$@"

>&2 echo "Generating ssh keys & seed.img"
cloud-localds seed.img <(scripts/gen-user-data.sh)

>&2 echo "Generating EFI artifacts"

native_arch="$(uname -m)"

case "$arch" in
	x86_64)
		if [[ "$arch" != "$native_arch" ]]; then
			>&2 echo "This is a very bad idea, go modify the script if this is what you truly want."
			exit 1
		fi
		MACHINE=q35
		CPU=host
  		ACCEL="-accel kvm"
		EFI=/usr/share/OVMF/OVMF_CODE.fd
		VARSTORE=""
		DRIVE="-drive if=virtio,format=qcow2,file=${img}"
		;;
	aarch64)
		if [[ "$arch" == "$native_arch" ]]; then
			MACHINE=virt
			CPU=max
			ACCEL="-accel kvm"
		else
			# Best we can do for cross arch emulation
			MACHINE=virt,gic-version=3
			CPU=max
			ACCEL="-accel tcg,thread=multi"
		fi

		# The QEMU aarch64 virt machine is super picky and needs an exactly 64MiB EFI image and a varstore.
		truncate -s 64m "${arch}_varstore.img"
		truncate -s 64m "${arch}_efi.img"
		dd if=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd of="${arch}_efi.img" conv=notrunc
		VARSTORE="-drive if=pflash,format=raw,file=${arch}_varstore.img"
		EFI="${arch}_efi.img"
		DRIVE="-drive if=none,file=${img},id=hd0 -device virtio-blk-device,drive=hd0"
		;;
	*)
		>&2 echo "Unsupported architecture"
		exit 1
		;;
esac

SSH_PORT="${SSH_PORT:-2222}"
TELNET_PORT="${TELNET_PORT:-4321}"
MIRROR_PORT="${MIRROR_PORT:-31625}"


>&2 echo "Booting $arch $MACHINE with $EFI from $img"

"qemu-system-$arch"  \
  -machine type="${MACHINE}" -m 1024 \
  -cpu ${CPU} -smp 4 \
  ${ACCEL} \
  -snapshot \
  -drive if=pflash,format=raw,file=${EFI},readonly=on \
  ${VARSTORE} \
  ${DRIVE} \
  -drive if=virtio,format=raw,file=seed.img \
  -netdev id=net00,type=user,hostfwd=tcp::"${SSH_PORT}"-:22 \
  -device virtio-net-pci,netdev=net00 \
  -monitor unix:qemu-monitor.socket,server,nowait \
  -serial telnet:localhost:${TELNET_PORT},server,nowait \
  -display none -daemonize -pidfile qemu.pid || exit 1

SSH_OPTS="-i ssh_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
while true; do
	echo "Waiting for VM.. try 'nc localhost 4321' to see what's going on."
	output=$(ssh $SSH_OPTS -p "$SSH_PORT" -o ConnectTimeout=1 root@localhost whoami)
	[[ "$output" == "root" ]] && break
	sleep 10s
done

>&2 echo "Up! Transferring assets."
scp $SSH_OPTS -P "$SSH_PORT" test_payload.sh kanidm_ppa.list snapshot/kanidm_ppa.asc root@localhost:
>&2 echo "Launching test payload."
ssh $SSH_OPTS -p "$SSH_PORT" root@localhost "./test_payload.sh $IDM_URI $IDM_GROUP $MIRROR_PORT"

>&2 echo "Done, killing qemu"
kill $(cat qemu.pid)
rm qemu.pid
