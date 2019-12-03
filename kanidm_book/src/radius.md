
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
