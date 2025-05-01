# Kanidm - Simple and Secure Identity Management

![Kanidm Logo](artwork/logo-small.png)

## About

Kanidm is a simple and secure identity management platform, allowing other applications and services
to offload the challenge of authenticating and storing identities to Kanidm.

The goal of this project is to be a complete identity provider, covering the broadest possible set
of requirements and integrations. You should not need any other components (like Keycloak) when you
use Kanidm - we already have everything you need!

To achieve this we rely heavily on strict defaults, simple configuration, and self-healing
components. This allows Kanidm to support small home labs, families, small businesses, and all the
way to the largest enterprise needs.

If you want to host your own authentication service, then Kanidm is for you!

<details>
  <summary>Supported Features</summary>

Kanidm supports:

- Passkeys (WebAuthn) for secure cryptographic authentication
- Attested passkeys for high security environments
- OAuth2/OIDC authentication provider for web SSO
- Application Portal allowing easy access to linked applications
- Linux/Unix integration with TPM protected offline authentication
- SSH key distribution to Linux/Unix systems
- RADIUS for network and VPN authentication
- Read-only LDAPs gateway for Legacy Systems
- Complete CLI tooling for Administration
- Two node high availability using database replication
- A WebUI for user self-service

</details>

## Documentation / Getting Started / Install

If you want to read more about what Kanidm can do, you should read our documentation.

- [Kanidm book (latest stable)](https://kanidm.github.io/kanidm/stable/)

We also have a set of
[support guidelines](https://github.com/kanidm/kanidm/blob/master/book/src/support.md) for what the
project team will support.

## Code of Conduct / Ethics

All interactions with the project are covered by our [code of conduct].

When we develop features, we follow our project's guidelines on [rights and ethics].

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/book/src/developers/developer_ethics.md

## Getting in Contact / Questions

We have a Matrix-powered [gitter community channel] where project members are always happy to chat
and answer questions. Alternately you can open a new [GitHub discussion].

[gitter community channel]: https://app.gitter.im/#/room/#kanidm_community:gitter.im
[github discussion]: https://github.com/kanidm/kanidm/discussions

## What does Kanidm mean?

Kanidm is a portmanteau of 'kani' and 'idm'. Kani is Japanese for crab, related to Rust's mascot
Ferris the crab. Identity management is often abbreviated to 'idm', and is a common industry term
for authentication providers.

Kanidm is pronounced as "kar - nee - dee - em".

## Comparison with other services

<details>
  <summary>LLDAP</summary>

[LLDAP](https://github.com/nitnelave/lldap) is a similar project aiming for a small and easy to
administer LDAP server with a web administration portal. Both projects use the
[Kanidm LDAP bindings](https://github.com/kanidm/ldap3), and have many similar ideas.

The primary benefit of Kanidm over LLDAP is that Kanidm offers a broader set of "built-in" features
like OAuth2 and OIDC. To use these from LLDAP you need an external portal like Keycloak. However,
that is also a strength of LLDAP is that is offers "less" which may make it easier to administer and
deploy for you.

While LLDAP offers a simple WebUI as the primary user management frontend, Kanidm currently only
offers administration functionality via its CLI. The Kanidm WebUI is tailored to user interactions.

If Kanidm is too complex for your needs, you should check out LLDAP as a smaller alternative. If you
want a project which has a broader feature set out of the box, then Kanidm will be a better fit.

</details>

<details><summary>389-ds / OpenLDAP</summary>
Both 389-ds and OpenLDAP are generic LDAP servers. This means they only provide LDAP and you need to
bring your own IDM components - you need your own OIDC portal, a WebUI for self-service, commandline
tools to administer and more.

If you need the highest levels of customisation possible from your LDAP deployment, then these are
probably better alternatives. If you want a service that is easy to set up and focused on IDM, then
Kanidm is a better choice.

Kanidm was originally inspired by many elements of both 389-ds and OpenLDAP. Already Kanidm is as
fast as (or faster than) 389-ds for performance and scaling as a directory service while having a
richer feature set.

</details>

<details>
  <summary>FreeIPA</summary>

FreeIPA is another identity management service for Linux/Unix, and ships a huge number of features
from LDAP, Kerberos, DNS, Certificate Authority, and more.

FreeIPA however is a complex system, with a huge amount of parts and configuration. This adds a lot
of resource overhead and difficulty for administration and upgrades.

Kanidm aims to have the features richness of FreeIPA, but without the resource and administration
overheads. If you want a complete IDM package, but in a lighter footprint and easier to manage, then
Kanidm is probably for you. In testing with 3000 users and 1500 groups, Kanidm is 3 times faster for
search operations and 5 times faster for modification and addition of entries (your results may
differ however, but generally Kanidm is much faster than FreeIPA).

</details>

<details>
  <summary>Keycloak</summary>

Keycloak is an OIDC/OAuth2/SAML provider. It allows you to layer on WebAuthn to existing IDM
systems. Keycloak can operate as a stand-alone IDM but generally is a component attached to an
existing LDAP server or similar.

Keycloak requires a significant amount of configuration and experience to deploy. It allows high
levels of customisation to every detail of its authentication work flows, which makes it harder to
start with in many cases.

Kanidm does NOT require Keycloak to provide services such as OAuth2 and integrates many of the
elements in a simpler and correct way out of the box in comparison.

</details>

<details>
  <summary>Rauthy</summary>

Rauthy is a minimal OIDC provider. It supports WebAuthn just like Kanidm - they actually use our
libraries for it!

Rauthy only provides support for OIDC and so is unable to support other use cases like RADIUS and
unix authentication.

If you need a minimal OIDC only provider, Rauthy is an excellent choice. If you need more features
then Kanidm will support those.

</details>

<details>
  <summary>Authentik / Authelia / Zitadel</summary>

Authentik is an IDM provider written in Python and, Authelia and Zitadel are written in Go. all
similar to Kanidm in the features it offers but notably all have weaker support for UNIX
authentication and do not support the same level of authentication policy as Kanidm. Notably, all
are missing WebAuthn Attestation.

All three use an external SQL server such as PostgreSQL. This can create a potential single source
of failure and performance limitation compared to Kanidm which opted to write our own high
performance database and replication system instead based on our experience with enterprise LDAP
servers.

</details>

## Developer Getting Started

If you want to contribute to Kanidm there is a getting started [guide for developers]. IDM is a
diverse topic and we encourage contributions of many kinds in the project, from people of all
backgrounds.

When developing the server you should refer to the latest commit documentation instead.

- [Kanidm book (latest commit)](https://kanidm.github.io/kanidm/master/)

[guide for developers]: https://kanidm.github.io/kanidm/master/developers/index.html
