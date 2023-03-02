# RADIUS

Remote Authentication Dial In User Service (RADIUS) is a network protocol that is commonly used to
authenticate Wi-Fi devices or Virtual Private Networks (VPNs). While it should not be a sole point
of trust/authentication to an identity, it's still an important control for protecting network
resources.

Kanidm has a philosophy that each account can have multiple credentials which are related to their
devices, and limited to specific resources. RADIUS is no exception and has a separate credential for
each account to use for RADIUS access.

## Disclaimer

It's worth noting some disclaimers about Kanidm's RADIUS integration.

### One Credential - One Account

Kanidm normally attempts to have credentials for each _device_ and _application_ rather than the
legacy model of one to one.

The RADIUS protocol is only able to attest a _single_ password based credential in an authentication
attempt, which limits us to storing a single RADIUS password credential per account. However,
despite this limitation, it still greatly improves the situation by isolating the RADIUS credential
from the primary or application credentials of the account. This solves many common security
concerns around credential loss or disclosure, and prevents rogue devices from locking out accounts
as they attempt to authenticate to Wi-Fi with expired credentials.

Alternatelly, Kanidm supports mapping users with special configuration of certificates allowing some
systems to use EAP-TLS for RADIUS authentication. This returns to the "per device" credential model.

### Cleartext Credential Storage

RADIUS offers many different types of tunnels and authentication mechanisms. However, most client
devices "out of the box" only attempt a single type when a WPA2-Enterprise network is selected:
MSCHAPv2 with PEAP. This is a challenge-response protocol that requires clear text or Windows NT LAN
Manager (NTLM) credentials.

As MSCHAPv2 with PEAP is the only practical, universal RADIUS-type supported on all devices with
minimal configuration, we consider it imperative that it MUST be supported as the default. Esoteric
RADIUS types can be used as well, but this is up to administrators to test and configure.

Due to this requirement, we must store the RADIUS material as clear text or NTLM hashes. It would be
silly to think that NTLM is secure as it relies on the obsolete and deprecated MD4 cryptographic
hash, providing only an illusion of security.

This means Kanidm stores RADIUS credentials in the database as clear text.

We believe this is a reasonable decision and is a low risk to security because:

- The access controls around RADIUS secrets by default are strong, limited to only self-account read
  and RADIUS-server read.
- As RADIUS credentials are separate from the primary account credentials and have no other rights,
  their disclosure is not going to lead to a full account compromise.
- Having the credentials in clear text allows a better user experience as clients can view the
  credentials at any time to enroll further devices.

### Service Accounts Do Not Have Radius Access

Due to the design of service accounts, they do not have access to radius for credential assignment.
If you require RADIUS usage with a service account you _may_ need to use EAP-TLS or some other
authentication method.

## Account Credential Configuration

For an account to use RADIUS they must first generate a RADIUS secret unique to that account. By
default, all accounts can self-create this secret.

```bash
kanidm person radius generate-secret --name william william
kanidm person radius show-secret --name william william
```

## Account Group Configuration

In Kanidm, accounts which can authenticate to RADIUS must be a member of an allowed group. This
allows you to define which users or groups may use a Wi-Fi or VPN infrastructure, and provides a
path for revoking access to the resources through group management. The key point of this is that
service accounts should not be part of this group:

```bash
kanidm group create --name idm_admin radius_access_allowed
kanidm group add_members --name idm_admin radius_access_allowed william
```

## RADIUS Server Service Account

To read these secrets, the RADIUS server requires an account with the correct privileges. This can
be created and assigned through the group "idm_radius_servers", which is provided by default.

First, create the service account and add it to the group:

```bash
kanidm service-account create --name admin radius_service_account "Radius Service Account"
kanidm group add_members --name admin idm_radius_servers radius_service_account
```

Now reset the account password, using the `admin` account:

```bash
kanidm service-account credential generate --name admin radius_service_account
```

## Deploying a RADIUS Container

We provide a RADIUS container that has all the needed integrations. This container requires some
cryptographic material, with the following files being in `/etc/raddb/certs`. (Modifiable in the
configuration)

| filename | description                                                   |
| -------- | ------------------------------------------------------------- |
| ca.pem   | The signing CA of the RADIUS certificate                      |
| dh.pem   | The output of `openssl dhparam -in ca.pem -out ./dh.pem 2048` |
| cert.pem | The certificate for the RADIUS server                         |
| key.pem  | The signing key for the RADIUS certificate                    |

The configuration file (`/data/kanidm`) has the following template:

```toml
uri = "https://example.com" # URL to the Kanidm server
verify_hostnames = true     # verify the hostname of the Kanidm server

verify_ca = false           # Strict CA verification
ca = /data/ca.pem           # Path to the kanidm ca

auth_token = "ABC..."       # Auth token for the service account
                            # See: kanidm service-account api-token generate

# Default vlans for groups that don't specify one.
radius_default_vlan = 1

# A list of Kanidm groups which must be a member
# before they can authenticate via RADIUS.
radius_required_groups = [
    "radius_access_allowed@idm.example.com",
]

# A mapping between Kanidm groups and VLANS
radius_groups = [
    { spn = "radius_access_allowed@idm.example.com", vlan = 10 },
]

# A mapping of clients and their authentication tokens
radius_clients = [
    { name = "test", ipaddr = "127.0.0.1", secret  = "testing123" },
    { name = "docker" , ipaddr = "172.17.0.0/16", secret = "testing123" },
]

# radius_cert_path = "/etc/raddb/certs/cert.pem"
# the signing key for radius TLS
# radius_key_path = "/etc/raddb/certs/key.pem"
# the diffie-hellman output
# radius_dh_path = "/etc/raddb/certs/dh.pem"
# the CA certificate
# radius_ca_path = "/etc/raddb/certs/ca.pem"
```

## A fully configured example

```toml
url = "https://example.com"

# The auth token for the service account
auth_token = "ABC..."

# default vlan for groups that don't specify one.
radius_default_vlan = 99

# if the user is in one of these Kanidm groups,
# then they're allowed to authenticate
radius_required_groups = [
    "radius_access_allowed@idm.example.com",
]

radius_groups = [
    { spn = "radius_access_allowed@idm.example.com", vlan = 10 }
]

radius_clients = [
    { name = "localhost", ipaddr = "127.0.0.1", secret = "testing123" },
    { name = "docker" , ipaddr = "172.17.0.0/16", secret = "testing123" },
]
```

## Moving to Production

To expose this to a Wi-Fi infrastructure, add your NAS in the configuration:

```toml
radius_clients = [
    { name = "access_point", ipaddr = "10.2.3.4", secret = "<a_random_value>" }
]
```

Then re-create/run your docker instance and expose the ports by adding
`-p 1812:1812 -p 1812:1812/udp` to the command.

If you have any issues, check the logs from the RADIUS output, as they tend to indicate the cause of
the problem. To increase the logging level you can re-run your environment with debug enabled:

```bash
docker rm radiusd
docker run --name radiusd \
    -e DEBUG=True \
    -p 1812:1812 \
    -p 1812:1812/udp
    --interactive --tty \
    --volume /tmp/kanidm:/etc/raddb/certs \
    kanidm/radius:latest
```

Note: the RADIUS container _is_ configured to provide
[Tunnel-Private-Group-ID](https://freeradius.org/rfc/rfc2868.html#Tunnel-Private-Group-ID), so if
you wish to use Wi-Fi-assigned VLANs on your infrastructure, you can assign these by groups in the
configuration file as shown in the above examples.
