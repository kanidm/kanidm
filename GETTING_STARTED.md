# Getting Started

WARNING: This document is still in progress, and due to the high rate of change in the cli
tooling, may be OUT OF DATE or otherwise incorrect. If you have questions, please get
in contact!

The goal of this getting started is to give you a quick setup, and overview of how you can setup
a working RADIUS environment with kanidm

# Deploying with docker

Currently we have a docker image based on git master. They can be found at:

    https://hub.docker.com/r/firstyear/kanidmd
    https://hub.docker.com/r/firstyear/kanidm_radius

First we'll deploy the main server. You'll need a volume where you can put certificates and
the database:

    docker volume create kanidmd

You should have a ca.pem, cert.pem and key.pem in your kanidmd volume. The reason for requiring
TLS is explained in [why tls]. To put the certificates in place you can use a shell container
that mounts the volume such as:

[why tls]: https://github.com/Firstyear/kanidm/blob/master/designs/why_tls.rst

    docker run --rm -i -t -v kanidmd:/data -v /my/host/path/work:/work opensuse/leap:latest cp /work/* /data/
    OR for a shell into the volume:
    docker run --rm -i -t -v kanidmd:/data opensuse/leap:latest /bin/sh

Then you can setup the initial admin account and initialise the database into your volume.

    docker run --rm -i -t -v kanidmd:/data firstyear/kanidmd:latest /home/kanidm/target/release/kanidmd recover_account -D /data/kanidm.db -n admin

You can now run the server - note that we provide all the options on the cli, but this pattern
may change in the future.

    docker run -p 8443:8443 -v /Users/william/development/rsidm/insecure:/data firstyear/kanidmd:latest /home/kanidm/target/release/kanidmd server -D /data/kanidm.db -C /data/ca.pem -c /data/cert.pem -k /data/key.pem --bindaddr 0.0.0.0:8443 --domain localhost

# Using the cli

For now, the CLI is still from the source - we'll make a tools container soon!

After you check out the source, navigate to:

    cd kanidm_tools
    cargo build

Now you can check your instance is working. You may need to provide a CA certificate for verification
with the -C parameter:

    cargo run -- self whoami -C ../path/to/ca.pem -H https://localhost:8443 --name anonymous
    cargo run -- self whoami -H https://localhost:8443 --name anonymous

Now you can take some time to look at what commands are available - things may still be rough so
please ask for help at anytime.

# Setting up some accounts and groups

The system admin account (the account you recovered in the setup) has limited privileges - only to
manage high-privilege accounts and services. This is to help seperate system administration
from identity administration actions.

You should generate a secure password for the idm_admin account now, by using the admin account to
reset that credential.

    cargo run -- account credential generate_password -H ... --name admin idm_admin
    Generated password for idm_admin: tqoReZfz....

It's a good idea to use the "generate_password" for high security accounts due to the strong
passwords generated.

We can now use the idm_admin to create groups and accounts.

    cargo run -- group create radius_access_allowed -H ... --name idm_admin
    cargo run -- account create demo_user "Demonstration User" -H ... --name idm_admin
    cargo run -- group add_members radius_access_allowed demo_user -H ... --name idm_admin
    cargo run -- group list_members radius_access_allowed -H ... --name idm_admin
    cargo run -- account get demo_user -H ... --name idm_admin

You can also use anonymous to view users and groups - note that you won't see as many fields due
to the different anonymous access profile limits!

    cargo run -- account get demo_user -H ... --name anonymous

Finally, performa a password reset on the demo_user - we'll be using them from now to show how
accounts can be self sufficent.

    cargo run -- account credential set_password demo_user -H ... --name idm_admin
    cargo run -- self whoami -H ... --name demo_user

# RADIUS

Let's make it so that demo_user can authenticate to our RADIUS. It's an important concept in kanidm
that accounts can have *multiple* credentials, each with unique functions and claims (permissions)
to limit their scope of access. An example of this is that an account has a distinction between
the interactive (primary) credential and the RADIUS credentials.

When you ran set_password above, you were resetting the primary credential of the account. The
account can now *self manage* it's own RADIUS credential which is isolated from the primary
credential. To demonstrate we can have the account self-generate a new RADIUS credential and
then retrieve that when required.

    cargo run -- account radius generate_secret demo_user -H ... --name demo_user
    cargo run -- account radius show_secret demo_user -H ... --name demo_user
    # Radius secret: lyjr-d8...

To read these secrets, the radius server requires a service account. We can create this and
assign it the appropriate privilege group (note we do this as admin not idm due to modifying a high priviliege group,
which idm_admin is *not* allowed to do):

    cargo run -- account create radius_service_account "Radius Service Account" -H ... --name admin
    cargo run -- group add_members idm_radius_servers radius_service_account -H ... --name admin
    cargo run -- account get radius_service_account -H ... --name admin
    cargo run -- account credential generate_password radius_service_account -H ... --name admin

Now that we have a user configured with RADIUS secrets, we can setup a radius container to authenticate
with it. You will need a volume that contains:

    data
    data/ca.pem  # This is the kanidm ca.pem
    data/config.ini
    data/certs
    data/certs/dh  # openssl dhparam -out ./dh 2048
    data/certs/key.pem  # These are the radius ca/cert
    data/certs/cert.pem
    data/certs/ca.pem

It's up to you to get a key/cert/ca for this purpose. The example config.ini looks like this:

    [kanidm_client]
    url =
    strict = false
    ca = /data/ca.crt
    user =
    secret =

    ; default vlans for groups that don't specify one.
    [DEFAULT]
    vlan = 1

    ; [group.test]
    ; vlan =

    [radiusd]
    ca =
    key =
    cert =
    dh =
    required_group =

    ; [client.localhost]
    ; ipaddr =
    ; secret =

A fully configured example is:

    [kanidm_client]
    ; be sure to check the listening port is correct, it's the docker internal port
    ; not the external one!
    url = https://<kanidmd container name or ip>:8443
    strict = true # adjust this if you have ca validation issues
    ca = /data/ca.crt
    user = radius_service_account
    secret = # The generated password from above

    ; default vlans for groups that don't specify one.
    [DEFAULT]
    vlan = 1

    ; [group.test]
    ; vlan =

    [radiusd]
    ca = /data/certs/ca.pem
    key =  /data/certs/key.pem
    cert = /data/certs/cert.pem
    dh = /data/certs/dh
    required_group = radius_access_allowed

    [client.localhost]
    ipaddr = 127.0.0.1
    secret = testing123

    [client.docker]
    ipaddr = 172.17.0.0/16
    secret = testing123

Now we can launch the radius instance:

    docker run --name radiusd -i -t -v ...:/data firstyear/kanidm_radius:latest
    ...
    Listening on auth address 127.0.0.1 port 18120 bound to server inner-tunnel
    Listening on auth address * port 1812 bound to server default
    Listening on acct address * port 1813 bound to server default
    Listening on auth address :: port 1812 bound to server default
    Listening on acct address :: port 1813 bound to server default
    Listening on proxy address * port 53978
    Listening on proxy address :: port 60435
    Ready to process requests

You can now test an authentication with:

    docker exec -i -t radiusd radtest demo_user badpassword 127.0.0.1 10 testing123
    docker exec -i -t radiusd radtest demo_user <radius show_secret value here> 127.0.0.1 10 testing123

You should see Access-Accept or Access-Reject based on your calls.

Finally, to expose this to a wifi infrastructure, add your NAS in config.ini:

    [client.access_point]
    ipaddr = <some ipadd>
    secret = <random value>

And re-create/run your docker instance with `-p 1812:1812 -p 1812:1812/udp` ...

If you have any issues, check the logs from the radius output they tend to indicate the cause
of the problem.

Note the radius container *is* configured to provide Tunnel-Private-Group-ID so if you wish to use
wifi assigned vlans on your infrastructure, you can assign these by groups in the config.ini.

# Raw actions

The server has a low-level stateful API you can use for more complex or advanced tasks on large numbers
of entries at once. Some examples are below, but generally we advise you to use the apis as listed
above.

    # Create from json (group or account)
    cargo run -- raw create -H https://localhost:8443 -C ../insecure/ca.pem -D admin example.create.account.json
    cargo run -- raw create  -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin example.create.group.json

    # Apply a json stateful modification to all entries matching a filter
    cargo run -- raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"Or": [ {"Eq": ["name", "idm_person_account_create_priv"]}, {"Eq": ["name", "idm_service_account_create_priv"]}, {"Eq": ["name", "idm_account_write_priv"]}, {"Eq": ["name", "idm_group_write_priv"]}, {"Eq": ["name", "idm_people_write_priv"]}, {"Eq": ["name", "idm_group_create_priv"]} ]}' example.modify.idm_admin.json
    cargo run -- raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"Eq": ["name", "idm_admins"]}' example.modify.idm_admin.json

    # Search and show the database representations
    cargo run -- raw search -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"Eq": ["name", "idm_admin"]}'
    > Entry { attrs: {"class": ["account", "memberof", "object"], "displayname": ["IDM Admin"], "memberof": ["idm_people_read_priv", "idm_people_write_priv", "idm_group_write_priv", "idm_account_read_priv", "idm_account_write_priv", "idm_service_account_create_priv", "idm_person_account_create_priv", "idm_high_privilege"], "name": ["idm_admin"], "uuid": ["bb852c38-8920-4932-a551-678253cae6ff"]} }

    # Delete all entries matching a filter
    cargo run -- raw delete -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"Eq": ["name", "test_account_delete_me"]}'
