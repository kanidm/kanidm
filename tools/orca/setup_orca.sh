#!/bin/bash

set -e

if [ ! -f "$0" ]; then
    echo "This script must be run from the tools/orca directory."
    exit 1
fi

MYDIR="$(pwd)"

echo "Running this will run the setup_dev_environment script"
echo "which resets the local dev environment to a default state."
echo ""
echo "Also, you'll need to start the server in another tab."
echo ""
echo "Hit ctrl-c to quit now if that's not what you intend!"

read -rp "Press Enter to continue"

cd ../../server/daemon/ || exit 1

KANI_TEMP="$(mktemp -d)"
echo "Running the script..."
../../scripts/setup_dev_environment.sh | tee "${KANI_TEMP}/kanifile"

echo "#########################"
echo "Back to orca now..."
echo "#########################"

if [ -z "${KANIDM_CONFIG}" ]; then
    KANIDM_CONFIG="../../examples/insecure_server.toml"
fi
IDM_ADMIN_PW=$(grep -E "^idm_admin password" "${KANI_TEMP}/kanifile" | awk '{print $NF}')
rm "${KANI_TEMP}/kanifile"

if [ -n "${DEBUG}" ]; then
    echo "IDM Admin pw: ${IDM_ADMIN_PW}"
fi

cd "$MYDIR" || exit 1

LDAP_DN="DN=$(grep domain "${KANIDM_CONFIG}" | awk '{print $NF}' | tr -d '"' | sed -E 's/\./,DN=/g')"

PROFILE_PATH="/tmp/kanidm/orca.toml"

cargo run --bin orca -- configure \
    --profile "${PROFILE_PATH}" \
    --idm-admin-password "${IDM_ADMIN_PW}" \
    --kanidm-uri "$(grep origin "${KANIDM_CONFIG}" | awk '{print $NF}' | tr -d '"')" \
    --ldap-uri "ldaps://$(grep domain "${KANIDM_CONFIG}" | awk '{print $NF}' | tr -d '"'):636" \
    --ldap-base-dn "${LDAP_DN}"

echo "Generating data..."

cargo run --bin orca -- generate --output /tmp/kanidm/orcatest

echo "Running connection test..."

cargo run --bin orca -- conntest --profile "${PROFILE_PATH}" kanidm

echo "Now you can run things!"

echo "To set up the environment, run:"
echo "cargo run --bin orca --release -- setup --profile /tmp/kanidm/orca.toml kanidm"
echo "cargo run --bin orca --release -- run --profile /tmp/kanidm/orca.toml kanidm search-basic"

