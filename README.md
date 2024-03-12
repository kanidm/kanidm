# Kanidm - Simple and Secure Identity Management

<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

## About

Kanidm is a simple and secure identity management platform, allowing other applications and services
to offload the challenge of authenticating and storing identities to Kanidm.

The goal of this project is to be a complete identity provider, covering the broadest possible set
of requirements and integrations. You should not need any other components (like Keycloak) when you
use Kanidm - we already have everything you need!

To achieve this we rely heavily on strict defaults, simple configuration, and self-healing
components. This allows Kanidm to run from small home labs, families, small business, and all the
way to the largest enterprise needs.

If you want to host your own authentication service, then Kanidm is for you!

<details><summary>Supported Features</summary>

Kanidm supports:

- Passkeys (webauthn) for secure cryptographic authentication
- Attested Passkeys for high security environments
- Oauth2/OIDC Authentication provider for web SSO
- Application Portal allowing easy access to linked applications
- Linux/Unix integration with TPM secured offline authentication
- SSH key distribution to Linux/Unix systems
- RADIUS for network and VPN authentication
- Read only LDAPS gateway for Legacy Systems
- Complete CLI tooling for Administration
- A WebUI for User Self Service
- Two node high availability using database replication

</details>

## Documentation / Getting Started / Install

If you want to read more about what Kanidm can do, you should read our documentation.

- [Kanidm book (Latest stable)](https://kanidm.github.io/kanidm/stable/)

We also have a set of
[support guidelines](https://github.com/kanidm/kanidm/blob/master/book/src/support.md) for what the
project team will support

## Code of Conduct / Ethics

All interactions with the project are covered by our [code of conduct].

When we develop features we follow our projects guidelines on [rights and ethics]

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/book/src/developers/ethics.md

## Getting in Contact / Questions

We have a Matrix-powered [gitter community channel] where project members are always happy to chat
and answer questions. Alternately you can open a new [github discussion].

[gitter community channel]: https://app.gitter.im/#/room/#kanidm_community:gitter.im
[github discussion]: https://github.com/kanidm/kanidm/discussions

## What does Kanidm mean?

Kanidm is a portmanteau of 'kani' and 'idm'. Kani is Japanese for crab, related to Rust's mascot
ferris the crab. Identity management is often abbreviated to 'idm', and is a common industry term
for authentication providers.

Kanidm is pronounced as "kar - nee - dee - em".

## Comparison with other services

<details><summary>LLDAP</summary>
[LLDAP](https://github.com/nitnelave/lldap) is a similar project aiming for a small and easy to
administer LDAP server with a web administration portal. Both projects use the
[Kanidm LDAP bindings](https://github.com/kanidm/ldap3), and have many similar ideas.

The primary benefit of Kanidm over LLDAP is that Kanidm offers a broader set of "built in" features
like Oauth2 and OIDC. To use these from LLDAP you need an external portal like Keycloak. However
that is also a strength of LLDAP is that is offers "less" which may make it easier to administer and
deploy for you.

While LLDAP offers a simple Web UI as the primary user management frontend, Kanidm currently only
offers administration functionality via its CLI. The Kanidm Web UI is tailored to user interactions.

If Kanidm is too complex for your needs, you should check out LLDAP as a smaller alternative. If you
want a project which has a broader feature set out of the box, then Kanidm will be a better fit.

</details>

<details><summary>389-ds / OpenLDAP</summary>
Both 389-ds and OpenLDAP are generic LDAP servers. This means they only provide LDAP and you need to
bring your own IDM components - you need your own OIDC portal, webui's for self service, commandline
tools to administer and more.

If you need the highest levels of customisation possible from your LDAP deployment, then these are
probably better alternatives. If you want a service that is easy to setup and focused on IDM, then
Kanidm is a better choice.

Kanidm was originally inspired by many elements of both 389-ds and OpenLDAP. Already Kanidm is as
fast as (or faster than) 389-ds for performance and scaling as a directory service while having a
richer feature set.

</details>

<details><summary>FreeIPA</summary>
FreeIPA is another identity management service for Linux/Unix, and ships a huge number of features
from LDAP, Kerberos, DNS, Certificate Authority, and more.

FreeIPA however is a complex system, with a huge amount of parts and configuration. This adds a lot
of resource overhead and difficulty for administration and upgrades.

Kanidm aims to have the features richness of FreeIPA, but without the resource and administration
overheads. If you want a complete IDM package, but in a lighter footprint and easier to manage, then
Kanidm is probably for you. In testing with 3000 users + 1500 groups, Kanidm is 3 times faster for
search operations and 5 times faster for modification and addition of entries (your results may
differ however, but generally Kanidm is much faster than FreeIPA).

</details>

<details><summary>Keycloak</summary>
Keycloak is an OIDC/Oauth2/SAML provider. It allows you to layer on Webauthn to existing IDM systems.
Keycloak can operate as a stand alone IDM but generally is a component attached to an existing LDAP
server or similar.

Keycloak requires a significant amount of configuration and experience to deploy. It allows high
levels of customisation to every detail of it's authentication work flows, which makes it harder to
start with in many cases.

Kanidm does NOT require Keycloak to provide services such as Oauth2 and integrates many of the
elements in a simpler and correct way out of the box in comparison.

</details>

## Developer Getting Started

If you want to contribute to Kanidm there is a getting started [guide for developers]. IDM is a
diverse topic and we encourage contributions of many kinds in the project, from people of all
backgrounds.

When developing the server you should refer to the latest commit documentation instead.

- [Kanidm book (Latest commit)](https://kanidm.github.io/kanidm/master/)

[guide for developers]: https://kanidm.github.io/kanidm/stable/developers/readme.html
