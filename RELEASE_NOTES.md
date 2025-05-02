# Kanidm Release Notes

![Kanidm Logo](artwork/logo-small.png)

## Getting Started

To get started, see the [kanidm book]

## Feedback

We value your feedback! First, please see our [code of conduct]. If you have questions please join
our [gitter community channel] so that we can help. If you find a bug or issue, we'd love you to
report it to our [issue tracker].

## Release Notes

### 2025-05-01 - Kanidm 1.6.0

This is the latest stable release of the Kanidm Identity Management project. Every release is the
combined effort of our community and we appreciate their invaluable contributions, comments,
questions, feedback and support.

You should review our
[support documentation] as this
may have important effects on your distribution or upgrades in future.

Before upgrading you should review
[our upgrade documentation]

#### 1.6.0 Important Changes

- The kanidmd server configuration now supports versions. You should review the example server configuration and update to `version = "2"`.

#### 1.6.0 Release Highlights

- Drop fernet in favour of JWE for OAuth2 tokens (#3577)
- Allow spaces in ssh key comments
- Support HAProxy PROXY protocol v2 (#3542)
- Preserve ssh key content on form validation error (#3574)
- Harden pam unix resolver to prevent a token update race (#3553)
- Improve db klock handling (#3551)
- Unix pam unix config parser (#3533)
- Improve handling of systemd notify (#3540)
- Allow versioning of server configs (#3515)
- Remove the protected plugin in favour of access framework (#3504)
- Add `max_ber_size` to freeipa sync tool (#3530)
- Make schema indexing a boolean rather than index type (#3517)
- Add set-description to group cli (#3511)
- pam kanidm now acts as a pam unix replacement (#3501)
- Support rfc2307 in ldap import/sync (3466)
- Handle incorrect OAuth2 clients that ignore response modes (#3467)
- Improve idx validation performance (#3459)
- Improve migration and bootstrapper (#3432)
- Reduce size of docker container (#3452)
- Add limits to maximum queryable ldap attributes (#3431)
- Accept more formats of ldap pwd hashes (#3444, 3458)
- TOTP Label validation (#3419)
- Harden denied names against accidental lockouts (#3429)
- OAuth2 supports redirect uri's with query parameters (#3422)

### 2025-02-09 - Kanidm 1.5.0

This is the latest stable release of the Kanidm Identity Management project. Every release is the
combined effort of our community and we appreciate their invaluable contributions, comments,
questions, feedback and support.

You should review our
[support documentation] as this
may have important effects on your distribution or upgrades in future.

Before upgrading you should review
[our upgrade documentation]

#### 1.5.0 Important Changes

- There has been a lot of tweaks to how cookies are handled in this release, if you're having issues with the login flow please clear all cookies as an initial troubleshooting step.

#### 1.5.0 Release Highlights

- Many updates to the UI!
  - SSH Keys in Credentials Update (#3027)
  - Improved error message when PassKey is missing PIN (mainly for Firefox) (#3403)
  - Fix the password reset form and possible resolver issue (#3398)
  - Fixed unrecoverable error page doesn't include logo or domain name (#3352)
  - Add support for prefers-color-scheme using Bootstrap classes. Dark mode! (#3327)
  - Automatically trigger passkeys on login view (#3307)
- Two new operating systems!
  - Initial OpenBSD support (#3381)
  - FreeBSD client (#3333)
- Many SCIM-related improvements
  - SCIM access control (#3359)
  - SCIM put (#3151)
- OAuth2 Things
  - Allow OAuth2 with empty `state` parameter (#3396)
  - Allow POST on oauth userinfo (#3395)
  - Add OAuth2 `response_mode=fragment` (#3335)
  - Add CORS headers to jwks and userinfo (#3283)
- Allowing SPN query with non-SPN structured data in LDAP (#3400)
- Correctly return that uuid2spn changed on domain rename (#3402)
- RADIUS startup fixing (#3388)
- Repaired systemd reload notifications (#3355)
- Add `ssh_publickeys` as a claim for OAuth2 (#3346)
- Allow modification of password minimum length (#3345)
- PAM on Debian, enable use_first_pass by default (#3326)
- Allow opt-in of easter eggs (#3308)
- Allow reseting account policy values to defaults (#3306)
- Ignore system users for UPG synthesiseation (#3297)
- Allow group managers to modify entry-managed-by (#3272)

And many more!

### 2024-11-01 - Kanidm 1.4.0

This is the latest stable release of the Kanidm Identity Management project. Every release is the
combined effort of our community and we appreciate their invaluable contributions, comments,
questions, feedback and support.

You should review our
[support documentation] as this
may have important effects on your distribution or upgrades in future.

Before upgrading you should review
[our upgrade documentation]

#### 1.4.0 Important Changes

- The web user interface has been rewritten and now supports theming. You will notice that your
domain displayname is included in a number of locations on upgrade, and that you can set
your own domain and OAuth2 client icons.
- OAuth2 strict redirect uri is now required. Ensure you have read
[our upgrade documentation].
and taken the needed steps before upgrading.

#### 1.4.0 Release Highlights

- Improve handling of client timeouts when the server is under high load
- Resolve a minor issue preventing some credential updates from saving
- PAM/NSS unixd now allow non-Kanidm backends - more to come soon
- Mail attributes have substring indexing added
- Access controls for mail servers to read mail attributes
- Admin CLI tools support instance profiles allowing admin of multiple sites to be easier
- Resolve a minor issue in OAuth2 introspection which returned the wrong claim for `token_type`
- Resolve an issue where memberOf should imply dynamicMemberOf in access controls
- Allow configuration of custom domain icons
- Internal representation of attributes changed to an enum to reduce memory consumption
- Add CreatedAt and ModifiedAt timestamps to entries
- Expose RFC7009 and RFC7662 via OIDC metadata discovery
- Improve pipe handling for CLI tools
- Large techdebt cleanups
- PAM/NSS unixd can provide system users, replacing `pam_unix`
- Account policy supports LDAP password fallback to main password
- PAM/NSS unixd can extend a system group with members from remote sources (such as Kanidm)
- Resolve a potential issue in replication on upgrade where migrated entries cause a referential
  integrity conflict leading to a forced initialisation
- Display credential reset token expiry time when created on CLI
- Reload certificates and private keys on SIGHUP
- Remove a large number of dependencies that were either not needed or could be streamlined
- SCIM foundations for getting and modifying entries, reference handling, and complex attribute
  display. Much more to come in this space!
- Rewrite the entire web frontend to be simpler and faster, allowing more features to be added
  in the future. Greatly improves user experience as the pages are now very fast to load!

### 2024-08-07 - Kanidm 1.3.0

This is the latest stable release of the Kanidm Identity Management project. Every release is the
combined effort of our community and we appreciate their invaluable contributions, comments,
questions, feedback and support.

You should review our
[support documentation] as this
may have important effects on your distribution or upgrades in future.

Before upgrading you should review
[our upgrade documentation]

#### 1.3.0 Important Changes

- New GID number constraints are now enforced in this version. To upgrade from 1.2.0 all accounts
  and groups must adhere to these rules. See [our upgrade documentation]. about tools to help you
  detect and correct affected entries.
- OAuth2 URIs require stricter matching rules to be applied from 1.4.0.
- Security Keys will be removed as a second factor alternative to TOTP from accounts in 1.4.0. It
  has not been possible to register a new security for more than 1 year. Security Keys are surpassed
  by PassKeys which give a better user experience.
- Kanidm now supports FreeBSD and Illumos in addition to Linux

#### 1.3.0 Release Highlights

- TOTP update user interface improvements
- Improved error messages when a load balancer is failing
- Reduced server log noise to improve event clarity
- Replace jemalloc with mimalloc
- User session storage can optionally use cookies
- Strictly enforce same-version for backup/restore processes
- Allow name self-write to be withheld
- Add support for LDAP Compare operations
- Upgrade Axum HTTP framework to the latest stable
- Reduced memory usage
- Improved update flow when changing from dev to stable server versions
- PIV authentication foundations
- Significant improvements to performance for write and search operations
- Support Illumos
- Begin rewrite of the webui
- OAuth2 allows multiple origins
- Lengthen replication MTLS certificate lifetime
- UNIX daemon allows home paths to be in an external mount folder
- Strict redirect URI enforcement in OAuth2
- Substring indexing for improved search performance

### 2024-05-01 - Kanidm 1.2.0

This is the first stable release of the Kanidm Identity Management project. We want to thank every
one in our community who has supported to the project to this point with their invaluable
contributions, comments, questions, feedback and support.

Importantly this release makes a number of changes to our project's support processes. You should
review our [support documentation]
as this may have important effects on your distribution or upgrades in future.

#### 1.2.0 Important Changes

- On upgrade all OAuth2 sessions and user sessions will be reset due to changes in cryptographic key
  handling. This does not affect api tokens.
- There is a maximum limit of 48 interactive sessions for persons where older sessions are
  automatically removed.

#### 1.2.0 Release Highlights

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

### 2024-02-07 - Kanidm 1.1.0-rc.16

This is the sixteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

This is the final release candidate before we publish a release version. We believe that the API and
server interfaces are stable and reliable enough for people to depend on, and to develop external
tools to interact with Kanidm.

#### 1.1.0-rc.16 Release Highlights

- Replication for two node environments is now supported
- Account policy supports password minimum length
- Improve performance of webui
- Add transitional compatibility with SSSD
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

### 2023-10-31 - Kanidm 1.1.0-beta14

This is the fourteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

At this point we believe we are on the final stretch to making something we consider "release
ready". After this we will start to ship release candidates as our focus will now be changing to
finish our production components and the stability of the API's for longer term support.

#### 1.1.0-beta14 Release Highlights

- Replication is in Beta! Please test carefully!
- Web UI WASM has been split up, significantly improving the responsiveness.
- Resolved API JSON issues from 1.1.0-beta13
- Swapped a lot of internal string constants for enums.
- Added shortcuts for RW token sessions.
- TLS client validation improvement
- Minimum TLS key length enforcement on server code.
- Improvements to exit code returns on CLI commands.
- Credential reset link timeout issues resolved.
- Removed a lot of uses of `unwrap` and `expect` to improve reliability.
- Account policy framework is now in place.

### 2023-05-01 - Kanidm 1.1.0-beta13

This is the thirteenth pre-release of the Kanidm Identity Management project. Pre-releases are to
help get feedback and ideas from the community on how we can continue to make this project better.

At this point we believe we are on the final stretch to making something we consider "release
ready". After this we will start to ship release candidates as our focus will now be changing to
finish our production components and the stability of the API's for longer term support.

#### 1.1.0-beta13 Release Highlights

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
- Add preflight headers for SPA OAuth2 clients
- Persist nonce through refresh tokens to support public clients
- Allow public (PKCE) OAuth2 clients
- Add client UX for external credential portals for synchronised accounts
- Improve migration durability with a global transaction
- Cli now shows spn instead of username to allow better multidomain admin
- Add qrcode for self-enrolling other devices with auth methods
- Add tls certgen to main binary to improve developer and quickstart setup
- Unixd now blocks all local account names and id's resolving prevent priv-esc
- Fix bug with service-account session logout access
- OAuth2 app list shows when no applications are available
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

### 2023-05-01 - Kanidm 1.1.0-alpha12

This is the twelfth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon! The main reason we haven't
done so yet is we haven't decided if we want to commit to the current API layout and freeze it yet.
There are still things we want to change there. Otherwise the server is stable and reliable for
production usage.

#### 1.1.0-alpha12 Release Highlights

- Allow full server content replication in testing (yes we're finally working on replication!)
- Improve OAuth2 to allow scoped members to see RS they can access for UI flows
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
- Extend OAuth2 session lifetimes, add refresh token support
- Improve user experience of credential updates via intent tokens
- Consolidate unix tools
- Add exclusive process lock to daemon
- Allow dns/rdns in ldap search contexts

### 2023-02-01 - Kanidm 1.1.0-alpha11

This is the eleventh alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon! The main reason we haven't
done so yet is we haven't decided if we want to commit to the current API layout and freeze it yet.
There are still things we want to change there. Otherwise the server is stable and reliable.

#### 1.1.0-alpha11 Release Highlights

- Support /etc/skel home dir templates in kanidm-unixd
- Improve warning messages for openssl when a cryptographic routine is not supported
- Support windows for server tests
- Add a kanidm tools container
- Initial support for live sync/import of users and groups from FreeIPA
- OAuth2 session logout and global logout support
- UI polish based on hint flags to dynamically enable/disable elements
- OAuth2 single sign on application portal
- Support dn=token for ldap client binds
- Trap more signals for daemons
- Mail read permission group
- OAuth2 add a groups claim
- LDAP support for mail primary and alternate address selectors in queries
- Fix handling of virtual attrs with '\*' searches in ldap
- Support multiple TOTP on accounts
- Add kanidmd healthcheck for containers
- Improve the access control module to evaluate access in a clearer way
- Allow synced users to correct modify their local sessions

### 2022-11-01 - Kanidm 1.1.0-alpha10

This is the tenth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon!

#### 1.1.0-alpha10 Upgrade Note

This version will _require_ TLS on all servers, even if behind a load balancer or TLS terminating
proxy. You should be ready for this change when you upgrade to the latest version.

#### 1.1.0-alpha10 Release Highlights

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
- Improve OAuth2 PKCE testing
- Add support for new password import hashes
- Allow configuration of trusting x forward for headers
- Components for account permission elevation modes
- Make pam\_unix more robust in high latency environments
- Add proc macros for test cases
- Improve authentication requests with cookie/token separation
- Cleanup of expired authentication sessions
- Improved administration of password badlists

### 2022-08-02 - Kanidm 1.1.0-alpha9

This is the ninth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

The project is shaping up very nicely, and a beta will be coming soon!

#### 1.1.0-alpha9 Release Highlights

- Inclusion of a Python3 API library
- Improve orca usability
- Improved content security hashes of js/wasm elements
- Performance improvements in builds
- Windows development and service support
- WebUI polish and improvements
- Consent is remembered in OAuth2 improving access flows
- Replication changelog foundations
- Compression middleware for static assests to reduce load times
- User on boarding now possible with self service credential reset
- TOTP and Webauthn/Passkey support in self service credential reset
- CTAP2+ support in Webauthn via CLI
- Radius supports EAP TLS identities in addition to EAP PEAP

### 2022-05-01 - Kanidm 1.1.0-alpha8

This is the eighth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

#### 1.1.0-alpha8 Release Highlights

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

### 2022-01-01 - Kanidm 1.1.0-alpha7

This is the seventh alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

#### 1.1.0-alpha7 Release Highlights

- OAuth2 scope to group mappings
- Webauthn subdomain support
- OAuth2 RFC7662 token introspection
- Basic OpenID Connect support
- Improve performance of domain rename
- Refactor of entry value internals to improve performance
- Addition of email address attributes
- Web UI improvements for OAuth2

### 2021-10-01 - Kanidm 1.1.0-alpha6

This is the sixth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

It's also a special release as Kanidm has just turned 3 years old! Thank you all for helping to
bring the project this far! 🎉 🦀

#### 1.1.0-alpha6 Release Highlights

- Support backup codes as MFA in case of lost TOTP/Webauthn
- Dynamic menus on CLI for usernames when multiple sessions exist
- Dynamic menus on CLI for auth factors when choices exist
- Better handle missing resources for web ui elements at server startup
- Add WAL checkpointing to improve disk usage
- OAuth2 user interface flows for simple authorisation scenarios
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

### 2021-07-07 - Kanidm 1.1.0-alpha5

This is the fifth alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

#### 1.1.0-alpha5 Release Highlights

- Fix a major defect in how backup/restore worked
- Improve query performance by caching partial queries
- Clarity of error messages and user communication
- Password badlist caching
- Orca, a kanidm and ldap load testing system
- TOTP usability improvements
- OAuth2 foundations
- CLI tool session management improvements
- Default shell falls back if the requested shell is not found
- Optional backup codes in case of lost MFA device
- Statistical analysis of indexes to improve query optimisation
- Handle broken TOTP authenticator apps

### 2021-04-01 - Kanidm 1.1.0-alpha4

This is the fourth alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

#### 1.1.0-alpha4 Release Highlights

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

### 2021-01-01 - Kanidm 1.1.0-alpha3

This is the third alpha series release of the Kanidm Identity Management project. Alpha releases are
to help get feedback and ideas from the community on how we can continue to make this project better
for a future supported release.

#### 1.1.0-alpha3 Release Highlights

- Account "valid from" and "expiry" times.
- Rate limiting and softlocking of account credentials to prevent bruteforcing.
- Foundations of webauthn and multiple credential support.
- Rewrite of json authentication protocol components.
- Unixd will cache "non-existent" items to improve nss/pam latency.

### 2020-10-01 - Kanidm 1.1.0-alpha2

This is the second alpha series release of the Kanidm Identity Management project. Alpha releases
are to help get feedback and ideas from the community on how we can continue to make this project
better for a future supported release.

#### 1.1.0-alpha2 Release Highlights

- SIMD key lookups in container builds for datastructures
- Server and Client hardening warnings for running users and file permissions
- Search limits and denial of unindexed searches to prevent denial-of-service
- Dynamic Rounds for PBKDF2 based on CPU performance
- Radius module upgraded to python 3
- On-login PW upgrade, allowing weaker hashes to be re-computed to stronger variants on login.
- Replace actix with tide and async
- Reduction in memory footprint during searches
- Change authentication from cookies to auth-bearer tokens

### 2020-07-01 - Kanidm 1.1.0-alpha1

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

#### 1.1.0-alpha1 Release Highlights

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
[our upgrade documentation]: https://github.com/kanidm/kanidm/blob/master/book/src/server_updates.md#general-update-notes
[support documentation]: https://github.com/kanidm/kanidm/blob/master/book/src/support.md
