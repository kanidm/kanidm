# Introduction to Kanidm

Kanidm is an identity management server, acting as an authority on accounts and authorisation
within a technical environment.

The intent of the Kanidm project is:

* To provide a single truth source for accounts, groups and privileges.
* To enable integrations to systems and services so they can authenticate accounts.
* To make system, network, application and web authentication easy and accessible.

> **NOTICE:**
> This is a pre-release project. While all effort has been made to ensure no dataloss
> or security flaws, you should still be careful when using this in your environment.

## Why do I want Kanidm?

Whether you work in a business, a volunteer organisation, or an enthusiast who manages some
of their own personal services, we need methods of authenitcating and identifying ourselves
to these systems, and subsequently a way a determine what authorisation and privieleges we have
while accessing these systems.

We've probably all been in work places where you end up with multiple accounts on various
systems - one for a workstation, different ssh keys for different tasks, maybe some shared
account passwords. Not only is it difficult for people to manage all these different credentials
and what they have access to, but it also means that sometimes these credentials have more
access or privelege than they require.

Kanidm acts as a central authority of accounts in your organisation, and allows each account to associate
many devices and credentials with different privileges. An example of how this looks:

                                     ┌──────────────────┐
                                    ┌┴─────────────────┐│
                                    │                  ││
           ┌───────────────────┬───▶│      Kanidm      │◀──────┬─────────────────────────┐
           │                   │    │                  ├┘      │                         │
           │                   │    └──────────────────┘       │                       Verify
      Account Data             │              ▲                │                       Radius
       References              │              │                │                      Password
           │                   │              │                │                         │
           │                   │              │                │                  ┌────────────┐
           │                   │              │                │                  │            │
           │                   │              │             Verify                │   RADIUS   │
     ┌────────────┐            │        Retrieve SSH      Application             │            │
     │            │            │         Public Keys       Password               └────────────┘
     │  Database  │            │              │                │                         ▲
     │            │            │              │                │                         │
     └────────────┘            │              │                │               ┌─────────┴──────────┐
            ▲                  │              │                │               │                    │
            │                  │              │                │               │                    │
     ┌────────────┐            │       ┌────────────┐   ┌────────────┐  ┌────────────┐       ┌────────────┐
     │            │            │       │            │   │            │  │            │       │            │
     │  Web Site  │            │       │    SSH     │   │   Email    │  │    WIFI    │       │    VPN     │
     │            │            │       │            │   │            │  │            │       │            │
     └────────────┘            │       └────────────┘   └────────────┘  └────────────┘       └────────────┘
            ▲                  │              ▲                ▲               ▲                    ▲
            │                  │              │                │               │                    │
            │                  │              │                │               │                    │
            │              Login To           │                │               │                    │
        SSO/Oauth         Oauth/SSO       SSH Keys        Application        Radius              Radius
            │                  │              │            Password         Password            Password
            │                  │              │                │               │                    │
            │                  │              │                │               │                    │
            │                  │              │                │               │                    │
            │                  │        ┌──────────┐           │               │                    │
            │                  │        │          │           │               │                    │
            └──────────────────┴────────│  Laptop  │───────────┴───────────────┴────────────────────┘
                                        │          │
                                        └──────────┘
                                              ▲
                                              │
                                              │
                                        ┌──────────┐
                                        │   You    │
                                        └──────────┘

A key design goal is that you authenticate to your device in some manner, and then your device will
continue to authenticate you in the future. Each of these different types of credential from ssh keys,
application passwords, radius passwords and others, are "things your device knows". Each password
has limited capability, and can only access that exact service or resource.

This helps improve security as a compromise of the service or the network tranmission does not
grant you unlimited access to your account and all it's privileges. As the credentials are specific
to a device, if a device is compromised you are able to revoke it's associated credentials. If a
specific service is compromised, only the credentials for that service need to be revoked.

Due to this model, and the design of Kanidm to centre the device and to have more per-service credentials,
workflows and automations are added or designed to reduce human handling of these. An example of this
is the use of qr codes with deployment profiles to automatically enroll wireless credentials.


