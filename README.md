# Kanidm - Simple and Secure Identity Management

<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

## About

Kanidm is a simple and secure identity management platform, which provides services to allow
other systems and application to authenticate against. The project aims for the highest levels
of reliability, security and ease of use.

The goal of this project is to be a complete idetity management provider, covering the broadest
possible set of requirements and integrations. You should not need any other components (like Keycloak)
when you use Kanidm. We want to create a project that will be suitable for everything
from personal home deployments, to the largest enterprise needs.

To achieve this we rely heavily on strict defaults, simple configuration, and self-healing components.

The project is still growing and some areas are developing at a fast pace. The core of the server
however is reliable and we make all effort to ensure upgrades will always work.

Kanidm supports:

* Oauth2/OIDC Authentication provider for web SSO
* Read only LDAPS gateway
* Linux/Unix integration (with offline authentication)
* SSH key distribution to Linux/Unix systems
* RADIUS for network authentication
* Passkeys / Webauthn for secure cryptographic authentication
* A self service web ui
* Complete CLI tooling for administration

If you want to host your own centralised authentication service, then Kanidm is for you!

## Documentation / Getting Started / Install

If you want to deploy Kanidm to see what it can do, you should read the kanidm book.

- [Kanidm book (Latest stable)](https://kanidm.github.io/kanidm/stable/)
- [Kanidm book (Latest commit)](https://kanidm.github.io/kanidm/master/)

We also publish [support guidelines](https://github.com/kanidm/kanidm/blob/master/project_docs/RELEASE_AND_SUPPORT.md)
for what the project will support.

## Code of Conduct / Ethics

See our [code of conduct]

See our documentation on [rights and ethics]

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/ethics/README.md

## Getting in Contact / Questions

We have a [gitter community channel] where we can talk. Firstyear is also happy to
answer questions via email, which can be found on their github profile.

[gitter community channel]: https://gitter.im/kanidm/community

## Comparison with other services

### LLDAP

[LLDAP](https://github.com/nitnelave/lldap) is a similar project aiming for a small and easy to administer
LDAP server with a web administration portal. Both projects use the [Kanidm LDAP bindings](https://github.com/kanidm/ldap3), and have
many similar ideas.

The primary benefit of Kanidm over LLDAP is that Kanidm offers a broader set of "built in" features
like Oauth2 and OIDC. To use these from LLDAP you need an external portal like Keycloak, where in Kanidm
they are "built in". However that is also a strength of LLDAP is that is offers "less" which may make
it easier to administer and deploy for you.

If Kanidm is too complex for your needs, you should check out LLDAP as a smaller alternative. If you
want a project which has a broader feature set out of the box, then Kanidm might be a better fit.

### 389-ds / OpenLDAP

Both 389-ds and OpenLDAP are generic LDAP servers. This means they only provide LDAP and you need
to bring your own IDM configuration on top.

If you need the highest levels of customisation possible from your LDAP deployment, then these are
probably better alternatives. If you want a service that is easier to setup and focused on IDM, then
Kanidm is a better choice.

Kanidm was originally inspired by many elements of both 389-ds and OpenLDAP. Already Kanidm is as fast
as (or faster than) 389-ds for performance and scaling.

### FreeIPA

FreeIPA is another identity management service for Linux/Unix, and ships a huge number of features
from LDAP, Kerberos, DNS, Certificate Authority, and more.

FreeIPA however is a complex system, with a huge amount of parts and configuration. This adds a lot
of resource overhead and difficulty for administration.

Kanidm aims to have the features richness of FreeIPA, but without the resource and administration
overheads. If you want a complete IDM package, but in a lighter footprint and easier to manage, then
Kanidm is probably for you.

## Developer Getting Started

If you want to develop on the server, there is a getting started [guide for developers]. IDM
is a diverse topic and we encourage contributions of many kinds in the project, from people of
all backgrounds.

[guide for developers]: https://kanidm.github.io/kanidm/master/DEVELOPER_README.html

## What does Kanidm mean?

The original project name was rsidm while it was a thought experiment. Now that it's growing
and developing, we gave it a better project name. Kani is Japanese for "crab". Rust's mascot is a crab.
IDM is the common industry term for identity management services.

