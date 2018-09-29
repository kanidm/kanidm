# Rs Identity Manager

rsidm is an identity management platform written in rust. Our goals are:

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

## More?

## Get involved

## Designs

See the designs folder




