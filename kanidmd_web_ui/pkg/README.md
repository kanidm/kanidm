
<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

# Kanidm

Kanidm is an identity management platform written in rust. Our goals are:

* Modern identity management platform
* Simple to deploy and integrate with
* Extensible for various needs
* Correct and secure behaviour by default

Today the project is still under heavy development to achieve these goals - We have many foundational
parts in place, and many of the required security features, but it is still an Alpha, and should be
treated as such.

## Documentation / Getting Started / Install

If you want to deploy Kanidm to see what it can do, you should read the kanidm book.

- [Kanidm book (Latest commit)](https://kanidm.github.io/kanidm/master/)
- [Kanidm book (Latest stable)](https://kanidm.github.io/kanidm/stable/)


We also publish limited [support guidelines](https://github.com/kanidm/kanidm/blob/master/project_docs/RELEASE_AND_SUPPORT.md).

## Code of Conduct / Ethics

See our [code of conduct]

See our documentation on [rights and ethics]

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/ethics/README.md

## Getting in Contact / Questions

We have a [gitter community channel] where we can talk. Firstyear is also happy to
answer questions via email, which can be found on their github profile.

[gitter community channel]: https://gitter.im/kanidm/community

## Developer Getting Started

If you want to develop on the server, there is a getting started [guide for developers]. IDM
is a diverse topic and we encourage contributions of many kinds in the project, from people of
all backgrounds.

[guide for developers]: https://kanidm.github.io/kanidm/master/DEVELOPER_README.html

## Features

### Implemented

* SSH key distribution for servers
* PAM/nsswitch clients (with limited offline auth)
* MFA - TOTP
* Highly concurrent design (MVCC, COW)
* RADIUS integration
* MFA - Webauthn

### Currently Working On

* CLI for administration
* WebUI for self-service with wifi enrollment, claim management and more.
* RBAC/Claims/Policy (limited by time and credential scope)
* OIDC/Oauth

### Upcoming Focus Areas

* Replication (async multiple active write servers, read-only servers)

### Future

* SSH CA management
* Sudo rule distribution via nsswitch
* WebUI for administration
* Account impersonation
* Synchronisation to other IDM services

## Some key project ideas

* All people should be respected and able to be represented securely.
* Devices represent users and their identities - they are part of the authentication.
* Human error occurs - we should be designed to minimise human mistakes and empower people.
* The system should be easy to understand and reason about for users and admins.

### Features We Want to Avoid

* Auditing: This is better solved by SIEM software, so we should generate data they can consume.
* Fully synchronous behaviour: This prevents scaling and our future ability to expand.
* Generic database: We don't want to be another NoSQL database, we want to be an IDM solution.
* Being like LDAP/GSSAPI/Kerberos: These are all legacy protocols that are hard to use and confine our thinking - we should avoid "being like them" or using them as models.

## What does Kanidm mean?

The original project name was rsidm while it was a thought experiment. Now that it's growing
and developing, we gave it a better project name. Kani is Japanese for "crab". Rust's mascot is a crab.
IDM is the common industry term for identity management services.

