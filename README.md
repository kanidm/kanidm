# Kanidm - Simple and Secure Identity Management

![Kanidm Logo](artwork/logo-small.png)

## About

Kanidm is a simple and secure identity management platform, allowing other applications and services to offload the
challenge of authenticating and storing identities to Kanidm.

The goal of this project is to be a complete identity provider, covering the broadest possible set of requirements and
integrations. You should not need any other components (like Keycloak) when you use Kanidm - we already have everything
you need!

To achieve this we rely heavily on strict defaults, simple configuration, and self-healing components. This allows
Kanidm to support small home labs, families, small businesses, and all the way to the largest enterprise needs.

If you want to host your own authentication service, then Kanidm is for you!

<details>
  <summary>Supported Features</summary>

Kanidm supports:

- Passkeys (WebAuthn) for secure cryptographic authentication
  - Attested passkeys for high security environments
- OAuth2/OIDC authentication provider for SSO
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

We also have a set of [support guidelines](https://github.com/kanidm/kanidm/blob/master/book/src/support.md) for what
the project team will support.

## Code of Conduct / Ethics

All interactions with the project are covered by our [code of conduct].

When we develop features, we follow our project's guidelines on [rights and ethics].

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/book/src/developers/developer_ethics.md

## Getting in Contact / Questions

We have a Matrix-powered [gitter community channel] where project members are always happy to chat and answer questions.
Alternately you can open a new [GitHub discussion].

[gitter community channel]: https://app.gitter.im/#/room/#kanidm_community:gitter.im
[github discussion]: https://github.com/kanidm/kanidm/discussions

## What does Kanidm mean?

Kanidm is a portmanteau of 'kani' and 'idm'. Kani is Japanese for crab, related to Rust's mascot Ferris the crab.
Identity management is often abbreviated to 'idm', and is a common industry term for authentication providers.

Kanidm is pronounced as "kar - nee - dee - em".

## Comparison with other services

<details> <summary>LLDAP</summary>

[LLDAP](https://github.com/nitnelave/lldap) is a similar project focused on providing a small, easy-to-administer LDAP server with a web administration portal. Both LLDAP and Kanidm use the [Kanidm LDAP bindings](https://github.com/kanidm/ldap3) and share many common design ideas.

The primary advantage of Kanidm over LLDAP is its broader built-in feature set, including native support for OAuth2 and OIDC. In contrast, LLDAP requires integration with an external portal like Keycloak to provide these features. However, LLDAP’s simplicity—offering fewer features—can make it easier to deploy and manage for certain use cases.

While LLDAP provides a simple Web UI as the main user management interface, Kanidm currently offers administrative functionality primarily via its CLI, with its Web UI designed more for user interactions than for administration.

If Kanidm feels too complex for your needs, LLDAP is a smaller and simpler alternative. But if you want a more feature-rich solution out of the box, Kanidm will likely be a better fit.

</details>

<details> <summary>389-ds / OpenLDAP</summary>

Both 389 Directory Server (389-ds) and OpenLDAP are general-purpose LDAP servers. They provide LDAP functionality only, so you must supply your own Identity Management (IDM) components—such as an OIDC portal, self-service web UI, command-line tools for administration, and more.

If you require maximum customization of your LDAP deployment, 389-ds or OpenLDAP may be better choices. However, if you prefer an easy-to-set-up service focused specifically on IDM, Kanidm is a superior option.

Kanidm draws inspiration from both 389-ds and OpenLDAP and already matches or exceeds 389-ds in directory service performance and scalability, while offering a richer feature set.

</details>

<details> <summary>FreeIPA</summary>

FreeIPA is a comprehensive identity management system for Linux/Unix, bundling many services including LDAP, Kerberos, DNS, and a Certificate Authority.

However, FreeIPA is complex, consisting of numerous components and configurations, which leads to higher resource usage and administrative overhead during setup and upgrades.

Kanidm aims to offer the feature richness of FreeIPA but with a lighter resource footprint and simpler management. In benchmarks with 3,000 users and 1,500 groups, Kanidm demonstrated approximately three times faster search operations and five times faster modifications and additions (results may vary, but Kanidm generally outperforms FreeIPA in speed).

If you want a full IDM solution that’s easier to manage and more efficient, Kanidm is worth considering.

</details>

<details> <summary>Keycloak</summary>

[Keycloak](https://github.com/keycloak/keycloak) is an OIDC/OAuth2/SAML provider that can layer WebAuthn authentication on top of existing IDM systems. Although it can operate as a stand-alone IDM solution, it is commonly used alongside an LDAP server or similar backend.

Deploying Keycloak requires significant configuration and expertise. Its extensive customization options for authentication workflows can make initial setup challenging.

Kanidm does not require Keycloak to provide OAuth2 and other services. It integrates many of these capabilities in a simpler, more streamlined way right out of the box.

</details> <details> <summary>Rauthy</summary>

[Rauthy](https://github.com/sebadob/rauthy) is a minimal OIDC provider supporting WebAuthn—using some of the same libraries as Kanidm.

However, Rauthy focuses exclusively on OIDC and does not support additional use cases such as RADIUS or Unix authentication.

If you need a minimal OIDC-only provider, Rauthy is an excellent choice. But if you require a broader feature set, Kanidm is the better option.

</details>

<details> <summary>Authentik / Authelia / Zitadel</summary>

[Authentik](https://github.com/goauthentik/authentik) (written in Python), [Authelia](https://github.com/authelia/authelia), and [Zitadel](https://github.com/zitadel/zitadel) (both written in Go) are IDM providers similar to Kanidm in many respects. However, all three have weaker support for Unix authentication and do not provide the advanced authentication policies or WebAuthn Attestation capabilities that Kanidm offers.

Additionally, these projects rely on external SQL databases such as PostgreSQL, which can introduce potential single points of failure and performance bottlenecks. In contrast, Kanidm uses its own high-performance database and replication system, developed based on enterprise LDAP server experience.

</details>

## Developer Getting Started

If you want to contribute to Kanidm there is a getting started [guide for developers]. IDM is a diverse topic and we
encourage contributions of many kinds in the project, from people of all backgrounds.

When developing the server you should refer to the latest commit documentation instead.

- [Kanidm book (latest commit)](https://kanidm.github.io/kanidm/master/)

[guide for developers]: https://kanidm.github.io/kanidm/master/developers/index.html
