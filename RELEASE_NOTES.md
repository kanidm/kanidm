<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

# Getting Started

To get started, see the [kanidm book]

# Feedback

We value your feedback! First, please see our [code of conduct]. If you have questions please join
our [gitter community channel] so that we can help. If you find a bug or issue, we'd love you to
report it to our [issue tracker].

# Release Notes

## 2024-05-01 - Kanidm 1.2.0

This is the first stable release of the Kanidm Identity Management project. We want to thank every
one in our community who has supported to the project to this point with their invaluable
contributions, comments, questions, feedback and support.

Importantly this release makes a number of changes to our projects support processes. You should
review our [support documentation](https://github.com/kanidm/kanidm/blob/master/book/src/support.md)
as this may have important effects on your distribution or upgrades in future.

### 1.2.0 Release Highlights

- The book now contains a list of supported RFCs and standards
- Add code challenge methods to OIDC discovery
- CLI lists authentication methods in security preference order
- Mark replication as stable for two node usage
- Automatically conflict and disable nscd and sssd in the unixd resolver
- Harden unixd resolver against memory inspection
- Enable unixd hardware TPM support
- Allow setting resource limits in account policy to raise query limits
- Reduce logging noise on /status checks
- Allow /dev/tpmrm0 access on older systemd versions
- Add an improved migration test framework
- Create an object graph in the experimental admin ui
- Add a built-in class for all entries that are system provided
- Fix uid number range handling with systemd
- Remodel orca for improved load testing features
- Upgrade concread with non-blocking read transaction acquisition
- ldap-sync allows re-use of attributes on entry import
- Support improved MFA challenge response process in unixd
- Add support for async tasks in unixd
- Add improved TPM handling for unixd
- Migrate cryptographic key handling to an object model with future HSM support
- Limit maximum active sessions on an account to 48

## 2024-02-07 - Kanidm 1.1.0-rc.16

This is the sixteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

This is the final release candidate before we publish a release version. We believe that the API and
server interfaces are stable and reliable enough for people to depend on, and to develop external
tools to interact with Kanidm.

### 1.1.0-rc.16 Release Highlights

- Replication for two node environments is now supported
- Account policy supports password minimum length
- Improve performance of webui
- Add transitional compatability with SSSD
- Improve TPM interfaces in unix clients
- Allow importing more weak password schemes from FreeIPA
- Support Attestation of Passkeys/Webauthn - this makes us the first IDM to support this!
- Add entry-managed-by and hierarchial access control profiles
- Rework and improve default access controls to further restrict default privileges
- New replicated domain migration framework for distributed updates
- Start to add PIV/Smartcard authentication groundwork
- Allow changes to OAuth2 RS origin
- Support RFC8414 OAuth2 metadata
- Improve TLS error dialogs to assist administrators
- Support RFC6749 Client Credentials Grant
- Support custom claim maps in OIDC

## 2023-10-31 - Kanidm 1.1.0-beta14

This is the fourteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

At this point we believe we are on the final stretch to making something we consider "release
ready". After this we will start to ship release candidates as our focus will now be changing to
finish our production components and the stability of the API's for longer term support.

### 1.1.0-beta14 Release Highlights

- Replication is in Beta! Please test carefully!
- Web UI WASM has been split up, significantly improving the responsiveness.
- Resolved API JSON issues from 1.1.0-beta13
- Swapped a lot of internal string constants for enums.
- Added shortcuts for RW token sessions.
- TLS client validation improvement
- Minimum TLS key length enforcement on server code.
- Improvements to exit code returns on CLI commands.
- Credential reset link timeout issues resolved.
- Removed a lot of uses of `unwrap` and `expect` to improve reliabilty.
- Account policy framework is now in place.

## 2023-05-01 - Kanidm 1.1.0-beta13

This is the thirteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

At this point we believe we are on the final stretch to making something we consider "release
ready". After this we will start to ship release candidates as our focus will now be changing to
finish our production components and the stability of the API's for longer term support.

### 1.1.0-beta13 Release Highlights

- Replication foundations
  - Full implementation of replication refresh
  - Full implementation of incremental replication
  - RUV consistency is now stricter
- Allow tpm binding unixd password hash cache
- Use argon2id for all password hash types
- Allow distros to set default shell
- Convert from tide to axum
- Modularise unix integration for third party modules
- Improve account recovery by performing over unix socket for live changes
- Support hsts in all responses
- Allow sync agreements to yield some attrs to kanidm
- Fix bug with posix account gid setting causing gid to be randomised
- Improve account sync import, including mail attrs and better session handling
- Bug fix in unixd when certain operation orders could cause group cache to be ignored
- pre-compress all wasm to improve loading times
- Add preflight headers for SPA oauth2 clients
- Persist nonce through refresh tokens to support public clients
- Allow public (pkce) oauth2 clients
- Add client UX for external credential portals for synchronised accounts
- Improve migration durability with a global transaction
- Cli now shows spn instead of username to allow better multidomain admin
- Add qrcode for self-enrolling other devices with auth methods
- Add tls certgen to main binary to improve developer and quickstart setup
- Unixd now blocks all local account names and id's resolving prevent priv-esc
- Fix bug with service-account session logout access
- Oauth2 app list shows when no applications are available
- Improve ip audit logging
- Improve cli with re-auth when session is expired
- Support legacy cron syntax in backup config
- Improve socket startup in main daemon
- Add support for selinux labeling of home dirs by tasks daemon
- Resolve bug in ssh key management if key tag has a space in it
- Allow tokens to be identified
- Remove incompatible credentials for service accounts during recovery
- Fix issues with signal handling for unix tasks daemon
- Improve create-reset-token user experience
- Improve self-healing for some reference issues

## 2023-05-01 - Kanidm 1.1.0-alpha12

This is the twelfth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon! The main reason we haven't
done so yet is we haven't decided if we want to commit to the current API layout and freeze it yet.
There are still things we want to change there. Otherwise the server is stable and reliable for
production usage.

### Release Highlights

- Allow full server content replication in testing (yes we're finally working on replication!)
- Improve oauth2 to allow scoped members to see RS they can access for UI flows
- Performance improvement by reducing clones
- Track credential uuid used for session authentication in the session
- Remove the legacy webauthn types for newer attributes
- Improve the logo to recurse
- Add privilege separation and re-authentication for time limited access
- Improve builds on windows
- Cleanup source tree layout to make it easier for new contributors
- Improve exit codes of unixd tools
- Restrict valid chars in some string contexts in entries
- Allow configuration of ldap basedn
- Extend oauth2 session lifetimes, add refresh token support
- Improve user experience of credential updates via intent tokens
- Consolidate unix tools
- Add exclusive process lock to daemon
- Allow dns/rdns in ldap search contexts

## 2023-02-01 - Kanidm 1.1.0-alpha11

This is the eleventh alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon! The main reason we haven't
done so yet is we haven't decided if we want to commit to the current API layout and freeze it yet.
There are still things we want to change there. Otherwise the server is stable and reliable.

### Release Highlights

- Support /etc/skel home dir templates in kanidm-unixd
- Improve warning messages for openssl when a cryptographic routine is not supported
- Support windows for server tests
- Add a kanidm tools container
- Initial support for live sync/import of users and groups from FreeIPA
- Oauth2 session logout and global logout support
- UI polish based on hint flags to dynamically enable/disable elements
- Oauth2 single sign on application portal
- Support dn=token for ldap client binds
- Trap more signals for daemons
- Mail read permission group
- Oauth2 add a groups claim
- LDAP support for mail primary and alternate address selectors in queries
- Fix handling of virtual attrs with '\*' searches in ldap
- Support multiple TOTP on accounts
- Add kanidmd healthcheck for containers
- Improve the access control module to evaluate access in a clearer way
- Allow synced users to correct modify their local sessions

## 2022-11-01 - Kanidm 1.1.0-alpha10

This is the tenth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon!

### Upgrade Note!

This version will _require_ TLS on all servers, even if behind a load balancer or TLS terminating
proxy. You should be ready for this change when you upgrade to the latest version.

### Release Highlights

- Management and tracking of authenticated sessions
- Make upgrade migrations more robust when upgrading over multiple versions
- Add support for service account tokens via ldap for extended read permissions
- Unix password management in web ui for posix accounts
- Support internal dynamic group entries
- Allow selection of name/spn in oidc claims
- Admin UI wireframes and basic elements
- TLS enforced as a requirement for all servers
- Support API service account tokens
- Make name rules stricter due to issues found in production
- Improve Oauth2 PKCE testing
- Add support for new password import hashes
- Allow configuration of trusting x forward for headers
- Components for account permission elevation modes
- Make pam\_unix more robust in high latency environments
- Add proc macros for test cases
- Improve authentication requests with cookie/token separation
- Cleanup of expired authentication sessions
- Improved administration of password badlists

## 2022-08-02 - Kanidm 1.1.0-alpha9

This is the ninth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon!

### Release Highlights

- Inclusion of a Python3 API library
- Improve orca usability
- Improved content security hashes of js/wasm elements
- Performance improvements in builds
- Windows development and service support
- WebUI polish and improvements
- Consent is remembered in oauth2 improving access flows
- Replication changelog foundations
- Compression middleware for static assests to reduce load times
- User on boarding now possible with self service credential reset
- TOTP and Webauthn/Passkey support in self service credential reset
- CTAP2+ support in Webauthn via CLI
- Radius supports EAP TLS identities in addition to EAP PEAP

## 2022-05-01 - Kanidm 1.1.0-alpha8

This is the eighth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

### Release Highlights

- Foundations for cryptographic trusted device authentication
- Foundations for new user onboarding and credential reset
- Improve acis for administration of radius secrets
- Simplify initial server setup related to domain naming
- Improve authentication performance during high load
- Developer documentation improvements
- Resolve issues with client tool outputs not being displayed
- Show more errors on api failures
- Extend the features of account person set
- Link pam with pkg-config allowing more portable builds
- Allow self-service email addresses to be delegated
- Highlight that the WebUI is in alpha to prevent confusion
- Remove sync only client paths

## 2022-01-01 - Kanidm 1.1.0-alpha7

This is the seventh alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

### Release Highlights

- Oauth2 scope to group mappings
- Webauthn subdomain support
- Oauth2 rfc7662 token introspection
- Basic OpenID Connect support
- Improve performance of domain rename
- Refactor of entry value internals to improve performance
- Addition of email address attributes
- Web UI improvements for Oauth2

## 2021-10-01 - Kanidm 1.1.0-alpha6

This is the sixth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

It's also a special release as Kanidm has just turned 3 years old! Thank you all for helping to
bring the project this far! 🎉 🦀

### Release Highlights

- Support backup codes as MFA in case of lost TOTP/Webauthn
- Dynamic menus on CLI for usernames when multiple sessions exist
- Dynamic menus on CLI for auth factors when choices exist
- Better handle missing resources for web ui elements at server startup
- Add WAL checkpointing to improve disk usage
- Oauth2 user interface flows for simple authorisation scenarioes
- Improve entry memory usage based on valueset rewrite
- Allow online backups to be scheduled and taken
- Reliability improvements for unixd components with missing sockets
- Error message improvements for humans
- Improve client address logging for auditing
- Add strict HTTP resource headers for incoming/outgoing requests
- Replace rustls with openssl for HTTPS endpoint
- Remove auditscope in favour of the new tracing logging subsystem
- Reduce server memory usage with entry tracking improvements
- Improvements to performance with high cache sizes
- Session tokens persist over a session restart

## 2021-07-07 - Kanidm 1.1.0-alpha5

This is the fifth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

### Release Highlights

- Fix a major defect in how backup/restore worked
- Improve query performance by caching partial queries
- Clarity of error messages and user communication
- Password badlist caching
- Orca, a kanidm and ldap load testing system
- TOTP usability improvements
- Oauth2 foundations
- CLI tool session management improvements
- Default shell falls back if the requested shell is not found
- Optional backup codes in case of lost MFA device
- Statistical analysis of indexes to improve query optimisation
- Handle broken TOTP authenticator apps

## 2021-04-01 - Kanidm 1.1.0-alpha4

This is the fourth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

### Release Highlights

- Performance Improvements
- TOTP CLI enrollment
- Jemalloc in main server instead of system allocator
- Command line completion
- TLS file handling improvements
- Webauthn authentication and enrollment on CLI
- Add db vacuum task
- Unix tasks daemon that automatically creates home directories
- Support for sk-ecdsa public ssh keys
- Badlist checked at login to determine account compromise
- Minor Fixes for attribute display

## 2021-01-01 - Kanidm 1.1.0-alpha3

This is the third alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

### Release Highlights

- Account "valid from" and "expiry" times.
- Rate limiting and softlocking of account credentials to prevent bruteforcing.
- Foundations of webauthn and multiple credential support.
- Rewrite of json authentication protocol components.
- Unixd will cache "non-existent" items to improve nss/pam latency.

## 2020-10-01 - Kanidm 1.1.0-alpha2

This is the second alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

### Release Highlights

- SIMD key lookups in container builds for datastructures
- Server and Client hardening warnings for running users and file permissions
- Search limits and denial of unindexed searches to prevent denial-of-service
- Dynamic Rounds for PBKDF2 based on CPU performance
- Radius module upgraded to python 3
- On-login PW upgrade, allowing weaker hashes to be re-computed to stronger variants on login.
- Replace actix with tide and async
- Reduction in memory footprint during searches
- Change authentication from cookies to auth-bearer tokens

## 2020-07-01 - Kanidm 1.1.0-alpha1

This is the first alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

It would not be possible to create a project like this, without the contributions and help of many
people. I would especially like to thank:

- Pando85
- Alberto Planas (aplanas)
- Jake (slipperyBishop)
- Charelle (Charcol)
- Leigh (excitedleigh)
- Jamie (JJJollyjim)
- Triss Healy (NiryaAestus)
- Samuel Cabrero (scabrero)
- Jim McDonough

### Release Highlights

- A working identity management server, including database
- RADIUS authentication and docker images
- Pam and Nsswitch resolvers for Linux/Unix authentication
- SSH public key distribution
- LDAP server front end for legacy applications
- Password badlisting and quality checking
- Memberof and reverse group management with referential integrity
- Recycle Bin
- Performance analysis tools

[issue tracker]: https://github.com/kanidm/kanidm/issues
[gitter community channel]: https://gitter.im/kanidm/community
[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md
[kanidm book]: https://kanidm.github.io/kanidm/stable/
