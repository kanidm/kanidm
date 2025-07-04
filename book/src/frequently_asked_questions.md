# Frequently Asked Questions

... or ones we think people _might_ ask.

## Why TLS?

You may have noticed that Kanidm requires you to configure TLS in your container or server install.

One of the fundamental goals of the project is a secure-by-design rather than secure-by-configuration system, so TLS for
all connections is mandatory. It is not an optional feature you add later.

> [!NOTE]
>
> Please respect the maintainers decision on TLS-by-default, no discussions on this topic will be entered into.

### Why not allow HTTP (without TLS) between my load balancer and Kanidm?

Because Kanidm is one of the keys to a secure network, and insecure connections to them are not best practice. This can
allow account hijacking, privilege escalation, credential disclosures, personal information leaks and more.

We believe that the **entire** path between a client and the server must be protected at all times. This includes the
path between load balancers or proxies and Kanidm.

### Can Kanidm authentication work without TLS?

No, it can not. TLS is required due to our use of the `Secure` flag our cookies, which requires a client to transmit
them back to the origin site
[if and only if the client
sees HTTPS as the protocol in the URL](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security).

Kanidm's authentication system is a stepped challenge response design, where you initially request an "intent" to
authenticate. Once you establish this intent, the server sets up a session-id into a secure cookie, and informs the
client of what authentication methods can proceed.

If you do NOT have a HTTPS URL, the cookie with the session-id is not transmitted. The server detects this as an
invalid-state request in the authentication design, and immediately breaks the connection, because it appears insecure.
This prevents credential disclosure since the authentication session was not able to be established due to the lost
session-id cookie.

Simply put, we are using settings like secure cookies to add constraints to the server so that you _must_ perform and
adhere to best practices - such as having TLS present on your communication channels.

This is another reason why we do not allow the server to start without a TLS certificate being configured.

### WebAuthn

Similarly, WebAuthn and its various other names like Passkeys, FIDO2 or "scan the QR code to log in" will
[only work over TLS](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API).

## OAuth2

[RFC6819 - OAuth2 Threat Model and Security Considerations](https://www.rfc-editor.org/rfc/rfc6819) is a comprehensive
and valuable resource discussing the security of OAuth2 and influences OpenID Connect as well. In general Kanidm follows
and implements many of the recommendations in this document, as well as choosing not to implement certain known insecure
OAuth2 features.

### Why is disabling PKCE considered insecure?

[RFC7636 - Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636) exists to
prevent authorisation code interception attacks. This is where an attacker can retrieve the authorisation code and then
perform the code exchange without the user being aware. A successful code exchange issues the attacker with an
`access_token` and optionally a `refresh_token`. The RFC has an excellent explanation of the attack. Additionally, this
threat is discussed in [RFC6819 Section 4.4.1](https://www.rfc-editor.org/rfc/rfc6819#section-4.4.1).

As Kanidm aims for "secure by default" design, even with _confidential_ clients, we deem it important to raise the bar
for attackers. For example, an attacker may have access to the `client_id` and `client_secret` of a confidential client
as it was mishandled by a system administrator. While they may not have direct access to the client/application systems,
they could still use this `client_id+secret` to then carry out the authorisation code interception attack listed.

For confidential clients (referred to as a `basic` client in Kanidm due to the use of HTTP Basic for `client_id+secret`
presentation) PKCE may optionally be disabled. This can allow authorisation code attacks to be carried out - however
_if_ TLS is used and the `client_secret` never leaks, then these attacks will not be possible. Since there are many
public references to system administrators mishandling secrets such as these so we should not rely on this as our sole
defence.

For public clients (which have no `client_id` authentication) we strictly enforce PKCE since disclosure of the
authorisation code to an attacker will allow them to perform the code exchange.

OpenID connect internally has a `nonce` parameter in its operations. Commonly it is argued that this value removes the
need for OpenID connect clients to implement PKCE. It does not. This parameter is not equivalent or a replacement for
PKCE. While the `nonce` can assist with certain attack mitigations, authorisation code interception is not prevented by
the presence or validation of the `nonce` value.

We would strongly encourage OAuth2 client implementations to implement and support PKCE, as it provides defense in depth
to known and exploited authorisation code interception attacks.

### Why do you allow disabling PKCE but not TLS?

Because there are still many applications where PKCE is not available and it is not trivial to solve for all downstream
applications. In the case that PKCE is absent on a single OAuth2 client, the scope of failure is reduced to that single
client. This is not the case with TLS, which is trivial to configure, and in the case of compromise of an internal
network between a load balancer and Kanidm, the attacker can access and steal all traffic and authentication data.

### Why is RSA considered legacy?

While RSA is cryptographically sound, to achieve the same level as security as ECDSA it requires signatures and keys
that are significantly larger. This has costs for network transmission and CPU time to verify these signatures. At this
time (2024) to achieve the same level of security as a 256 bit ECDSA, RSA requires a 3072 bit key. Similarly a 384 bit
ECDSA key requires a 8192 bit RSA for equivalent cryptographic strength, and a 521 bit ECDSA key would likely require a
16884 bit RSA key (or greater).

This means that going forward more applications will require ECDSA over RSA due to its increased strength for
significantly faster and smaller key sizes.

Where this has more serious costs is our future desire to add support for Hardware Security Modules. Since RSA keys are
much larger on these devices it may significantly impact performance of the HSM and may also limit the amount of keys we
can store on the device. In the case of some HSM models, they do not even support RSA keys up to 8192 bits (but they do
support ECDSA 384 and 521). An example of this is TPMs, which only support up to 4096 bit RSA keys at this time.

As a result, we want to guide people toward smaller, faster and more secure cryptographic standards like ECDSA. We want
to encourage application developers to implement ECDSA in their OAuth2 applications as it is likely that limitations of
RSA will be hit in the future.

Generally, it's also positive to encourage applications to review and update their cryptographic implementations over
time too. Cryptography and security is not stangnant, it requires continual review, assessment and improvement.

## Can I change the database backend from SQLite to - name of favourite database here -

No, it is not possible swap out the SQLite database for any other type of SQL server, nor will it be considered as an
option.

**_ATTEMPTING THIS WILL BREAK YOUR KANIDM INSTANCE IRREPARABLY_**

This question is normally asked because people want to setup multiple Kanidm servers connected to a single database.

Kanidm does not use SQL as a _database_. Kanidm uses SQL as a durable key-value store and Kanidm implements its own
database, caching, querying, optimisation and indexing on top of that key-value store.

As a result, because Kanidm specifically implements its own cache layer above the key-value store (sqlite in this
example) then if you were to connect two Kanidm instances to the same key-value store, as each server has its own cache
layer and they are not in contact, it is possible for writes on one server to never be observed by the second, and if
the second were to then write over those entries it will cause loss of the changes from the first server.

Kanidm now implements its own eventually consistent distributed replication which also removes the need for external
databases to be considered.

## Why aren't snaps launching with `home_alias` set?

Snaps rely on AppArmor and [AppArmor doesn't follow symlinks](https://bugs.launchpad.net/apparmor/+bug/1485055). When
`home_alias` is any value other than `none` a symlink will be created and pointing to `home_attr`. It is recommended to
use alternative software packages to snaps.

All users in Kanidm can change their name (and their spn) at any time. If you change `home_attr` from `uuid` you must
have a plan on how to manage these directory renames in your system.

## Why so many crabs?

It's [a rust thing](https://rustacean.net).

## Will you implement -insert protocol here-

Probably, on an infinite time-scale! As long as it's not STARTTLS. Please log an issue and start the discussion!

## Why do the crabs have knives?

Don't [ask](https://www.youtube.com/watch?v=0QaAKi0NFkA). They just [do](https://www.youtube.com/shorts/WizH5ae9ozw).

## Why won't you take this FAQ thing seriously?

Look, people just haven't asked many questions yet. Sorry, there are no easter eggs in this document, but there may be
elsewhere 🥚
