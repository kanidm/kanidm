# Legacy Applications -- LDAP

While many applications can support systems like SAML or OAuth, many do not. LDAP
has been the "lingua franca" of authentication for many years, with almost
every application in the world being able to search and bind to LDAP. As there
are still many of these in the world, Kanidm has the ability to host a read-only
LDAP interface.

> **WARNING** The LDAP server in Kanidm is not RFC compliant. This
> is intentional, as Kanidm wants to cover the common use case (simple bind and search).

## What is LDAP

LDAP is a protocol to read data from a directory of information. It is not
a server, but a way to communicate to a server. There are many famous LDAP
implementations such as Active Directory, 389 Directory Server, DSEE,
FreeIPA and many others. Because it is a standard, applications can use
an LDAP client library to authenticate users to LDAP, given "one account" for
many applications - an IDM just like Kanidm!

## Data Mapping

Kanidm is not able to be mapped 100% to LDAP's objects. This is because LDAP
types are simple key-values on objects which are all UTF8 strings or subsets
of based on validation (matching) rules. Kanidm internally implements complex
datatypes such as tagging on SSH keys, or multi-value credentials. These can not
be represented in LDAP.

As well many of the structures in Kanidm don't correlate closely to LDAP. For example
Kanidm only has a gidnumber, where LDAP's schema's define uidnumber and gidnumber.

Entries in the database also have a specific name in LDAP, related to their path
in the directory tree. Kanidm is a flat model, so we have to emulate some tree like
elements, and ignore others.

For this reason, when you search the ldap interface, Kanidm will make some mappinng
decisions.

* Queries requesting objectClass/EntryUUID will be mapped to class/uuid
* Entry attributes to LDAP may be renamed for presentation to LDAP clients (ie class to ObjectClass)
* The domain_info object becomes the suffix root.
* All other entries are direct subordinates of the domain_info for DN purposes
* DN's are generated from the attributes naming attributes
* Bind DN's can be remapped and rewritten, and may not even be a DN during bind.
* The Kanidm domain name is used to generate the basedn.

These decisions were made to make the path as simple and effective as possible,
relying more on the kanidm query and filter system than attempting to generate a tree like
representation of data. As almost all clients can use filters for entry selection
we don't believe this is a limitation for consuming applications.

## Security

### TLS

StartTLS is not supported due to security risks. LDAPS is the only secure method
of communicating to any LDAP server. Kanidm if configured with certificates will
use them for LDAPS (and will not listen on a plaintext LDAP port). If no certificates exist
Kanidm will listen on a plaintext LDAP port, and you MUST TLS terminate in front
of the Kanidm system to secure data and authentication.

### Access Controls

LDAP only supports password authentication. As LDAP is used heavily in posix environments
the LDAP bind for any DN will use it's configured posix password.

As the posix password is not eqivalent in strength to the primary credentials of Kanidm
(which may be MFA), the LDAP bind does not grant rights to elevated read permissions.
All binds, have the permissions of "Anonymous" (even if the anonymous account is locked).

## Server Configuration

To configure Kanidm to provide LDAP you add the argument to the server.toml configuration:

    ldapbindaddress = "127.0.0.1:3636"

You should configure TLS certificates and keys as usual - LDAP will re-use the webserver TLS
material.

## Example

Given a default install with domain "example.com" the configured LDAP dn will be "dc=example,dc=com".
This can be queried with:

    cargo run -- server -D kanidm.db -C ca.pem -c cert.pem -k key.pem -b 127.0.0.1:8443 -l 127.0.0.1:3636
    > LDAPTLS_CACERT=ca.pem ldapsearch -H ldaps://127.0.0.1:3636 -b 'dc=example,dc=com' -x '(name=test1)'

    # test1@example.com, example.com
    dn: spn=test1@example.com,dc=example,dc=com
    objectclass: account
    objectclass: memberof
    objectclass: object
    objectclass: person
    displayname: Test User
    memberof: spn=group240@example.com,dc=example,dc=com
    name: test1
    spn: test1@example.com
    entryuuid: 22a65b6c-80c8-4e1a-9b76-3f3afdff8400

It is recommended that client applications filter accounts that can login with '(class=account)'
and groups with '(class=group)'. If possible, group membership is defined in rfc2307bis or
Active Directory style. This means groups are determined from the "memberof" attribute which contains
a dn to a group.

LDAP binds can use any unique identifier of the account. The following are all valid bind dn's for
the object listed above (if it was a posix account that is).

    ldapwhoami ... -x -D 'name=test1'
    ldapwhoami ... -x -D 'spn=test1@example.com'
    ldapwhoami ... -x -D 'test1@example.com'
    ldapwhoami ... -x -D 'test1'
    ldapwhoami ... -x -D '22a65b6c-80c8-4e1a-9b76-3f3afdff8400'
    ldapwhoami ... -x -D 'spn=test1@example.com,dc=example,dc=com'
    ldapwhoami ... -x -D 'name=test1,dc=example,dc=com'

Most LDAP clients are very picky about TLS, and can be very hard to debug or display errors. For example
these commands:

    ldapsearch -H ldaps://127.0.0.1:3636 -b 'dc=example,dc=com' -x '(name=test1)'
    ldapsearch -H ldap://127.0.0.1:3636 -b 'dc=example,dc=com' -x '(name=test1)'
    ldapsearch -H ldap://127.0.0.1:3389 -b 'dc=example,dc=com' -x '(name=test1)'

All give the same error:

    ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)

This is despite the fact:

* The first command is a certificate validation error
* The second is a missing ldaps on a TLS port
* The third is an incorrect port

To diganose errors like this you may need "-d 1" for your ldap commands or client.

