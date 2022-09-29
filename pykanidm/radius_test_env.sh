#!/bin/bash

# This sets up a Kanidm environment for doing RADIUS testing.


read -r  -n 1 -p "This script rather destructively resets the idm_admin and admin passwords and YOLO's its way through setting up a RADIUS user (test) and service account (radius_server) make sure you're not running this on an environment you care deeply about!"

PWD="$(pwd)"

cd ../kanidmd/daemon || exit 1

echo "Resetting IDM_ADMIN"

# set up idm admin account
IDM_ADMIN=$(./run_insecure_dev_server.sh recover_account idm_admin -o json 2>&1 | grep -v Running | grep recover_account | jq .result)

echo "IDM_ADMIN_PASSWORD: ${IDM_ADMIN}"

read -r  -n 1 -p "Copy the idm_admin password somewhere and hit enter to continue"

# set up idm admin account
ADMIN=$(./run_insecure_dev_server.sh recover_account admin -o json 2>&1 | grep -v Running | grep recover_account | jq .result)

echo "ADMIN_PASSWORD: ${ADMIN}"
read -r  -n 1 -p "Copy the admin password somewhere and hit enter to continue"

echo -n "Start the server in another terminal"

KEEP_GOING=1
while [ $KEEP_GOING -eq 1 ]; do
    echo -n "."
    curl -f -s -k https://localhost:8443/status && KEEP_GOING=0
    sleep 1
done


cd ../../ || exit 1

echo "Logging in as admin"
cargo run --bin kanidm -- login --name admin

echo "Logging in as idm_admin"
cargo run --bin kanidm -- login --name idm_admin

echo "Creating person 'test'"
cargo run --bin kanidm -- person create test test --name idm_admin

echo "Creating group 'radius_access_allowed'"
cargo run --bin kanidm -- group create radius_access_allowed --name idm_admin
echo "Adding 'test' to group 'radius_access_allowed'"
cargo run --bin kanidm -- group add_members radius_access_allowed test --name idm_admin

echo "Creating radius secret for 'test'"
cargo run --bin kanidm -- person radius generate_secret test --name idm_admin
echo "Showing radius secret for 'test'"
cargo run --bin kanidm -- person radius show_secret test --name idm_admin


read -r  -n 1 -p "Copy the RADIUS secret above then press enter to continue"


echo "Creating SA 'radius_server'"
cargo run --bin kanidm -- service-account create radius_server radius_server --name idm_admin

echo "Setting radius_server to be allowed to be a RADIUS server"
cargo run --bin kanidm group add_members --name admin idm_radius_servers radius_server

echo "Creating API Token for 'radius_server' account"
cargo run --bin kanidm -- service-account  api-token generate radius_server radius --name admin

echo "Copy the API Token above to the config file"

echo "blep?"
