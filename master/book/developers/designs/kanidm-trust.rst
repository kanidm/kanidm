Trust Design and Thoughts
-------------------------

Trust is a process where users and groups of a separate kanidm instance may be granted access
to resources through this system. Trust is a one way concept, but of course, could be implemented
twice in each direction to achieve bidirectional trust.

Why?
----

There are a number of reasons why a trust configuration may be desired. You may have
a separate business to customer instance, where business users should be able to authenticate
to customer resources, but not the inverse. You may have two businesses merge or cooperate and
require resource sharing. It allows separation of high value credentials onto different infrastructure.
You could also potentially use trust as a method of sync between
between a different IDM project and this.

Why not?
--------

Trust is complicated, and adds more fragility and could be solved in different ways. Applications
could on a case by case basis have multiple backends instead of trying to go through one domain with
trusts. Sync could be designed more as a migration or specialised one way tool rather than needing
a replication design.

Scope of the Trust
------------------

There are different ways we can scope a trust out, each with pros-cons. Here are some possibilities:

* Kerberos Style - you login to your "home" domain, and then that grants you access across the trust boundaries. This means your
 credentials are valid "everywhere" effectively, and the permissions/groups it carries. Everyone
 on one side of the trust is trusted by the other side (you can't filter who is/isn't trusted, but
 you can limit what resources they get via groups). You still have to share some info via
 the global catalog, meaning you can add and remove users locally to your resources.
* x509 style - you trust an authority, and then anyone that authority validates, you trust. There
 is no global catalog, just the details you get in the presented authentication (certificate). You
 may implement some controls around which subject DN's to allow/deny, but this is pretty fraught
 with landminds. You don't know who exists until they login!
* Azure AD individiual account trusting. Instead of trusting a whole domain you allow a user from
 a remote tennant to access your resources. You don't trust everyone in their tennant, just that
 one account that you can invite. You can then revoke them as needed.
* Group-trust - FreeIPA does this with AD. It's still like kerberos, but you only trust a subset
 of the users determined by "groups" from the trusted site.
* All-or-nothing - LDAP style, just bring in the subtree of the remote business (or proxy it) and
 then act like there is one flat namespace.
* Client trust - rather than being server side, clients (applications) like SSSD have a case/switch
 on the authenticating username, and then have multiple backends configured to select who they auth
 to. OpenID somewhat works like this where you just redirect to some OpenID portal that may be in
 a whitelist.
* Fractional Replication - similar to the GC in AD, replicate in a subset of your data, but then
 ask for redirects or other information. This is used with 389 and RO servers where you may only
 replicate a subset of accounts to branch offices or a separate backend.

Each of these has pros and cons, good bad, and different models. They each achieve different things. For example,
the Kerberos style trust creates silos where the accounts credential material is stored (in the home
domain), but others still trust that authentication (via cryptographic means). You can limit what
is seen or sent, and even where the authentication happens. To help choose a model, or determine
properties we want lets write some down.

* Single Sign On - only need to authenticate once
* Forwardable Credentials - once you issue a token in one domain can it forward to another and authenticate you
* Credential Siloing - are credentials (pw, private keys) only stored in your home domain
* PII Limits - limit the transmission of personal information
* Group Management - can you add a trusted account to a local group to manage it's access?
* Invite un-trusted domain - can you invite accounts to use resources from domains you don't know about?
* Fully distributed - openid style, where any openid server could be a trusted provided
* Client Switched - Is it up to the client to trust different domains? Or is it a server side issue?


    |               | Kerberos      | x509          | Azure AD      | Group-Trust   | All-or-nothing| Client Trust  | Fractional    |               |
    | SSO           | y             | y             | y             | ?             | n             | n             | n             |               |
    | Forwarding    | y             | y?            | n             | ?             | n             | n             | n             |               |
    | Cred Silo     | y             | n?            | y             | y             | n             | y             | y             |               |
    | PII Limit     | y             | y             | y             | ?             | n             | y             | y             |               |
    | Group mgmt    | y             | n             | y             | y             | y             | n             | y             |               |
    | Invite Ext    | n             | n             | y             | n             | n             | y             | n             |               |
    | Distributed   | n             | y             | n             | n             | n             | y             | n             |               |
    | Client Swch   | n             | n             | n             | n             | n             | y             | n             |               |

So with a lot of though, I'm going to go with fractional replication.

* Single Sign On - I don't want this, because it causes a lot of harm. It's better to have many devices with different creds and long lived sessions that are revokeable.
* Forwarding - I don't want credentials to be forwarded, or sso to be forwarded.
* Cred Silo - I want this because it means you have defined boundaries of where security material is stored by who.
* PII limit - I want this as you can control who-has-what PII on the system side.
* Group Mgmt - I want this as it enables rbac and familiar group management locally for remote and local entries.
* Invite Ext - On the fence - cool idea, but not sure how it fits into kanidm with trusts.
* Distributed - I don't want this because it's model is really different to what kani is trying to be
* Client Switched - I don't want this because clients should only know they trust an IDM silo, and that does the rest.

But there are some things I want:

* Claims define credential policy, so we need to fractionally replicate the strength of the accounts cred material. This also means
 in any auth-redirection we need to indicate the strength or name of the credential that was authenticated through so we can
 correctly apply claims on the trusting domain. This is something for the design of claims to consider.
* RADIUS pws are per-domain, not replicated. This would breach the cred-silo idea, and really, if domain B has radius it probably has different
 SSID/ca cert to domain A, so why share the pw? If we did want to really share the credentials, we can have RADIUS act as a client switch
 instead.
* We can't proxy authentications because of webuathn domain verification, so clients that want to
 auth users to either side have to redirect through their origin domain to generate the session. This
 means the origin domain may have to be accessible in some cases.
* Public-key auth types can be replicated fractionally, which allows the domain to auth a user via
 ssh key but without needing to access the origin domain. (some questions about sudo exist here though).

Use cases
---------

With the fractional case in mind, this means we have sets of use cases that exist.

* Access to websites via oauth for users on either domain
* Unix server access / Workstation access
* RADIUS authentication to a different network infra in the trusting domain (but the Radius creds are local to the site)
* Limiting presence of credentials in cloud (but making public key credentials avail)
* Limiting distribution of personal information to untrusted sites
* Creating administration domains or other business hierarchies that may exist in some complex scenarios

We need to consider how to support these use cases of course :)

Possible Design
---------------

As trust is a relationship where groups and accounts from domain B are trusted into domain A, this
is a very similar scenario to replication. As Kanidm plans to implement a push based replication
system, this may work very well for our needs.

More formally - domain A trusting domain B is the establishment of a one directional fractional replication
agreement, and resource proxy from A to B.

Let's assume a user and group exists on domain B such as:

::

    spn: claire@domainb
    class: [account, object]
    ssh_public_key: aaaa...
    displayName: claire
    legalName: Super Secret Legal Name
    primary_credential: ...
    uuid: X
    memberOf: [ group@domainb ]

    spn: group@domainb
    class: [group, object]
    member: X (ref to claire)

On domain A, we would replicate a partial entry that serves as:

* A stub for references
* A redirect for auth operations
* A cache for certain attributes

::

    spn: claire@domainb
    class: [trustedaccount, object]
    ssh_public_key: aaaa...
    displayName: claire
    uuid: X
    memberOf: [ group@domainb, group@domaina ]
    source: Y

    spn: group@domainb
    class: [trustedgroup, object]
    member: X (ref to claire)

    name: domainb
    uuid: Y
    class: [trustanchor]
    url: https://idm_1.domainb
    url: https://idm_2.domainb
    cacert: .....
    trust_key: ....

    spn: group@domaina
    class: [group, object]
    member: X

Domain A with this information could:

* Add claire to local groups (due to name + uuid + memberOf presence)
* Generate unix information for claire (from uuid + sshkey + displayname)
* Proxy authentication (limited) to domainb
* Allow claire to use radius or other local resources.

To authenticate claire we have to send a request to the remote domain to get the required information
or to provide the required information to the remote domain.

We would do a normal auth process, but on determining this is a trust account, we have to return
a response to the core.rs layer. This should then trigger an async request to domain B which
contains the request. When this is returned, we then complete the request to the client. This does
increase the liklihood of issues or delays in processing in the domain A IO layers if many requests
exist at the same time.

if multiple urls exist in the trustanchor, we should choose randomly which to contact for
authentications. If a URL is not available, we move to the next URL (failover)

We could consider in-memory caching these values, but then we have to consider the cache expiry
and management of this data. Additionally types like TOTP aren't cacheable. I think we should
avoid caching in these cases.

Auth Scenarios
--------------

We assume a 1 way trust where B trusts A.

Kanidm portal: user@domain_a logs into kanidm portal on domain B

Oauth: user@domain_a logs into oauth portal on domain B

SSH: user@domain_a sshes to a machine on domain B

pam/application pws: user@domain_a uses pam w_ pw on a machine on domain B

RADIUS: user@domain_a authenticates to WIFI_B radius via domain B.


Trust Through
-------------

Not supported. There are some reasons for this, but I think it's adds too much complexity to an
already complex system design. It especially complicates "what entries do we send forward" to
a domain, because we need to send (our entries + all trusted entries) - target domain entries.

I think trust through also is a surprising behaviour - just because my friend trusts another
person, doesn't mean that I implicitly do. We need to establish our own trust relationship.

Security Considerations
-----------------------

There are certain entries on a domain by default that should NOT be replicated.

* schema
* admin
* anonymous
* default privilege groups
* no personal or sensitive fields
* uuids of any of the above

Rather it may be easier to consider what *should* be replicated:

* Groups (member, uuid, spn)
* Accounts ( displayName, spn, uuid, ssh-keys)

It could be questioned if:

* homedirectory
* loginshell
* gidnumber

Should be replicated as the local domain may have other policies around their handling. For now, we
may exclude these, but some consideration is needed here.

Excluding items from Domain B from replicating back
---------------------------------------------------

In a situation where domain A trusts B, and inverse B trusts A, then A will contain trust stubs to
entries in B.

Due to the use of spn's we can replicate only our entries for domain to the trust receiver.

::

    and [
        eq(class, group),
        eq(class, account),
        sub(spn, my_domain),
        andnot(or[
            eq(class, recycled),
            eq(class, tombstone),
        ])
    ]

Because SPN's would be stored on each object, we could not change domain name post install.

Need to do ASAP
---------------

How do we get the domain at setup time for spn? We already require domain for webauthn ... should
we write this into the system_info?

This means we need to determine a difference between a localgroup and a group that will
be synced for trust. This may require a separate class or label?

We need to make name -> SPN on groups/accounts that can be sent across a trust boundary.

Local groups and accounts should have a class name change to allow them to continue
to use "name" or we need to Change setup/fixtures for default accounts to have an spn with
the correct domain.

Must do
-------

Must check and assert that incoming objects via the trust belong to the correct domain (spn)

Gotchas
-------

Server IDs
==========

Every server on both sides of the domain have to have unique SID's to avoid UUID conflicts. This
is a requirement for replication anyway, and SID regeneration is not a complex task. It's highly
unlikely that we would ever see duplicates anyway as this is a 32bit field.

An alternate option is to have the stub objects generate ids, but to have a trusted_uuid field
that is used for replication checking, and a separate CSN for trust replication.


Webauthn
========

Webauthn requires correct presentation of a domain name that matches the TLS name of the host
that is being connected to. Because of this it may not be possible to proxy Webauthn through
in a trust scenario, requiring clients to need to directly authenticate to the trusted domain.

Oauth
=====

Oauth may support some trust resources of it's own, that may support or help the Webauthn cases. This
should be investigated.

An alternate solution to these two is that when domain A wants to issue oauth to a user in domain b
we redirect to domain b, conduct an auth, then from a bearer authorization, domain a then allows
the authentication and generates a domain a uat/oauth from the domain b bearer. More thought on
this topic is needed but I think there are solutions on how to do webauthn/oauth via trust.

