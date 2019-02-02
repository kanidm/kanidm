# Kanidm

Kanidm is an identity management platform written in rust. Our goals are:

* Modern identity management platform
* Simple to deploy and integrate with
* extensible
* correct

## Code of Conduct

See CODE_OF_CONDUCT.md

## Examples

## MVP features

* Pam/nsswitch clients (with offline auth, and local totp)
* CLI for admin
* OIDC/Oauth
* SSH key distribution
* MFA (TOTP)
* In memory read cache (cow)
* backup/restore

## Planned features

* Replicated database backend (389-ds, couchdb, or custom repl proto)
* SAML
* Read Only Replicas
* Certificate distribution?
* Web UI for admin
* Account impersonation
* Webauthn
* Sudo rule distribution via nsswitch?

## Features we want to avoid

* Audit: This is better solved by ...
* Fully synchronous behaviour: ...
* Generic database: ... (max db size etc)
* Being LDAP: ...
* GSSAPI/Kerberos

## More?

## Get involved

## Designs

See the designs folder

## Why do I see rsidm references?

The original project name was rsidm while it was a thought experiment. Now that it's growing
and developing, we gave it a better project name. Kani is Japanese for "crab". Rust's mascot
is a crab. It all works out in the end.



