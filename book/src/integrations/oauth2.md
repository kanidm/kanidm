# OAuth2

OAuth is a web authorisation protocol that allows "single sign on". It's key to note OAuth only provides authorisation,
as the protocol in its default forms do not provide identity or authentication information. All that OAuth can provide
is information that an entity is authorised for the requested resources.

OAuth can tie into extensions allowing an identity provider to reveal information about authorised sessions. This
extends OAuth from an authorisation only system to a system capable of identity and authorisation. Two primary methods
of this exist today: RFC7662 token introspection, and OpenID connect.

## Resource Server and Clients

This is the resource that a user wants to access. Common [examples](oauth2/examples.md) could be Nextcloud, a Wiki, or a
chat service. In these cases the service is both the _client_ and the _resource server_ within the OAuth2 workflow. We
will refer to the combination of both client and resource server as a service.

It's important for you to know _how_ your service will interact with OAuth2. For example, does it rely on OpenID connect
for identity information, or does it support RFC7662 token introspection?

In general, Kanidm **requires** that your service supports three things:

- HTTP basic authentication to the authorisation server (Kanidm)

- PKCE `S256` code verification (`code_challenge_methods_supported`)

- If it uses OIDC, `ES256` for token signatures (`id_token_signing_alg_values_supported`)

If your service doesn't support PKCE or only supports `RS256` token signatures, see
[extended options for legacy clients](#extended-options-for-legacy-clients).

Kanidm issues tokens which are [RFC 9068 JWTs](https://datatracker.ietf.org/doc/html/rfc9068), allowing service
introspection.

> [!NOTE]
>
> Previous versions of this document incorrectly described "clients" as "resource servers" due to clarity issues in the
> OAuth2 RFC.

## Kanidm's OAuth2 URLs

Kanidm will expose its OAuth2 APIs at the following URLs, substituting `:client_id:` with an OAuth2 client ID.

<!-- markdownlint-disable MD033 -->

<dl>
<dt>

[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) URL **(recommended)**

</dt>
<dd>

`https://idm.example.com/oauth2/openid/:client_id:/.well-known/openid-configuration`

This document includes all the URLs and attributes an app needs to be able to authenticate using OIDC with Kanidm,
_except_ for the `client_id` and `client_secret`.

Use this document wherever possible, as it will allow you to easily build and/or configure an interoperable OIDC client
without needing to code or configure anything special for Kanidm (or another provider).

**Note:** some apps automatically append `/.well-known/openid-configuration` to the end of an OIDC Discovery URL, so you
may need to omit that.

<dt>

[RFC 8414 OAuth 2.0 Authorisation Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) URL **(recommended)**

</dt>

<dd>

`https://idm.example.com/oauth2/openid/:client_id:/.well-known/oauth-authorization-server`

</dd>

<dt>

[WebFinger URL](#webfinger) **(discouraged)**

</dt>

<dd>

`https://idm.example.com/oauth2/openid/:client_id:/.well-known/webfinger`

See [the WebFinger section](#webfinger) for more details, as there a number of caveats for WebFinger clients.

</dd>

<dt>

User auth

</dt>

<dd>

`https://idm.example.com/ui/oauth2`

</dd>

<dt>

API auth

</dt>

<dd>

`https://idm.example.com/oauth2/authorise`

**Note:** "authorise" is spelled the British English (non-OED) way.

</dd>

<dt>

Token endpoint

</dt>

<dd>

`https://idm.example.com/oauth2/token`

</dd>

<dt>

[RFC 7662 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662) URL

</dt>

<dd>

`https://idm.example.com/oauth2/token/introspect`

</dd>

<dt>

[RFC 7662 token revocation](https://datatracker.ietf.org/doc/html/rfc7009) URL

</dt>

<dd>

`https://idm.example.com/oauth2/token/revoke`

</dd>

<dt>

OpenID Connect Issuer URL

</dt>

<dd>

`https://idm.example.com/oauth2/openid/:client_id:`

</dd>

<dt>

OpenID Connect user info

</dt>

<dd>

`https://idm.example.com/oauth2/openid/:client_id:/userinfo`

</dd>

<dt>

Token signing public key

</dt>

<dd>

`https://idm.example.com/oauth2/openid/:client_id:/public_key.jwk`

</dd>

</dl>

<!-- markdownlint-enable MD037 -->

## Configuration

### Create the Kanidm Configuration

By default, members of the `idm_admins` or `idm_oauth2_admins` groups are able to create or manage OAuth2 client
integrations.

You can create a new client by specifying its client name, application display name and the landing page (home page) of
the client. The landing page is where users will be redirected to from the Kanidm application portal.

```bash
kanidm system oauth2 create <name> <displayname> <landing page url>
kanidm system oauth2 create nextcloud "Nextcloud Production" https://nextcloud.example.com
```

You must now configure the redirect URL where the application expects OAuth2 requests to be sent.

```bash
kanidm system oauth2 add-redirect-url <name> <redirect url>
kanidm system oauth2 add-redirect-url nextcloud https://nextcloud.example.com/oauth2/handler
```

You can create a scope map with:

```bash
kanidm system oauth2 update-scope-map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update-scope-map nextcloud nextcloud_users email profile openid
```

> [!TIP]
>
> OpenID connect allows a number of scopes that affect the content of the resulting authorisation token. If one of the
> following scopes are requested by the OpenID client, then the associated claims may be added to the authorisation
> token. It is not guaranteed that all of the associated claims will be added.
>
> - **profile** - name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website,
>   gender, birthdate, zoneinfo, locale, and updated_at
> - **email** - email, email_verified
> - **address** - address
> - **phone** - phone_number, phone_number_verified
> - **groups** - groups (uuid and spn)
> - **groups_name** - groups (name only)
> - **groups_spn** - groups (spn only)
>
> In addition Kanidm supports some vendor specific scopes that can include additional claims.
>
> - **ssh_publickeys** - array of ssh_publickey of the user

<!-- this is just to split the templates up -->

> [!WARNING]
>
> If you are creating an OpenID Connect (OIDC) client you **MUST** provide a scope map containing `openid`. Without
> this, OpenID Connect clients **WILL NOT WORK**!
>
> ```bash
> kanidm system oauth2 update-scope-map nextcloud nextcloud_users openid
> ```

You can create a supplemental scope map with:

```bash
kanidm system oauth2 update-sup-scope-map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update-sup-scope-map nextcloud nextcloud_admins admin
```

Once created you can view the details of the client.

```bash
kanidm system oauth2 get nextcloud
---
name: nextcloud
class: oauth2_resource_server
class: oauth2_resource_server_basic
class: object
displayname: Nextcloud Production
oauth2_rs_basic_secret: hidden
oauth2_rs_origin_landing: https://nextcloud.example.com
oauth2_rs_token_key: hidden
```

You can see the value of `oauth2_rs_basic_secret` with:

```bash
kanidm system oauth2 show-basic-secret nextcloud
---
<secret>
```

### Configure the Client/Resource Server

On your client, you should configure the client ID as the `name` from Kanidm, and the password to be the value shown in
`oauth2_rs_basic_secret`. Ensure that the code challenge/verification method is set to S256.

You should now be able to test authorisation to the client.

## Scope Relationships

For an authorisation to proceed, the client will request a list of scopes. For example, when a user wishes to login to
the admin panel of the resource server, it may request the "admin" scope from Kanidm for authorisation. But when a user
wants to login, it may only request "access" as a scope from Kanidm.

As each service may have its own scopes and understanding of these, Kanidm isolates scopes to each service connected to
Kanidm. Kanidm has two methods of granting scopes to accounts (users).

The first is scope mappings. These provide a set of scopes if a user is a member of a specific group within Kanidm. This
allows you to create a relationship between the scopes of a service, and the groups/roles in Kanidm which can be
specific to that service.

For an authorisation to proceed, all scopes requested by the client must be available in the final scope set that is
granted to the account.

The second part is supplemental scope mappings. These function the same as scope maps where membership of a group
provides a set of scopes to the account. However these scopes are NOT consulted during authorisation decisions made by
Kanidm. These scopes exist to allow optional properties to be provided (such as personal information about a subset of
accounts to be revealed) or so that the service may make its own authorisation decisions based on the provided scopes.

This use of scopes is the primary means to control who can access what resources. These access decisions can take place
either on Kanidm or the service.

For example, if you have a client that always requests a scope of "read", then users with scope maps that supply the
read scope will be allowed by Kanidm to proceed to the service. Kanidm can then provide the supplementary scopes into
provided tokens, so that the service can use these to choose if it wishes to display UI elements. If a user has a
supplemental "admin" scope, then that user may be able to access an administration panel of the service. In this way
Kanidm is still providing the authorisation information, but the control is then exercised by the service.

## Public Client Configuration

Some applications are unable to provide client authentication. A common example is single page web applications that act
as the OAuth2 client and its corresponding webserver is the resource server. In this case, the SPA is unable to act as a
confidential client since the basic secret would need to be embedded in every client.

For this reason, public clients require PKCE to bind a specific browser session to its OAuth2 exchange. PKCE can not be
disabled for public clients for this reason.

To create an OAuth2 public client:

```bash
kanidm system oauth2 create-public <name> <displayname> <origin>
kanidm system oauth2 create-public mywebapp "My Web App" https://webapp.example.com
```

## Native Applications

Some applications will run a local web server on the user's device which directs users to the IDP for authentication,
then back to the local server. [BCP212](https://www.rfc-editor.org/info/bcp212) "OAuth 2.0 for Native Apps" specifies
the rules for this.

First allow localhost redirects:

```bash
kanidm system oauth2 enable-localhost-redirects <name>
kanidm system oauth2 disable-localhost-redirects <name>
kanidm system oauth2 enable-localhost-redirects mywebapp
```

> [!WARNING]
>
> Kanidm only allows these to be enabled on public clients where PKCE is enforced.

## Alternate Redirect URLs

Some services may have a website URL as well as native applications with opaque origins. These native applications
require alternate redirection URLs to be configured so that after an OAuth2 exchange, the system can redirect to the
native application.

To support this Kanidm allows supplemental opaque origins to be configured on clients.

```bash
kanidm system oauth2 add-redirect-url <name> <url>
kanidm system oauth2 remove-redirect-url <name> <url>

kanidm system oauth2 add-redirect-url nextcloud app://ios-nextcloud
```

Supplemental URLs are shown in the OAuth2 client configuration in the `oauth2_rs_origin` attribute.

> [!WARNING]
>
> Security Risk!
>
> You **MUST NOT** share a single OAuth2 client definition between multiple applications.
>
> The ability to configure multiple redirect URLs is **NOT** intended to allow you to share a single Kanidm client
> definition between multiple OAuth2 clients.
>
> Sharing OAuth2 client configurations between applications **FUNDAMENTALLY BREAKS** the OAuth2 security model and is
> **NOT SUPPORTED** as a configuration. The Kanidm Project **WILL NOT** support you if you attempt this.
>
> Multiple origins are **ONLY** to allow supplemental redirects within the _same_ client application.

## Short names

By default Kanidm will use SPN as a display username for users. In some cases you may want to use the
user's `name` instead. To change this setting:

```
kanidm system oauth2 prefer-short-username <client name>
kanidm system oauth2 prefer-spn-username <client name>
```

## Extended Options for Legacy Clients

Not all clients support modern standards like PKCE or ECDSA. In these situations it may be necessary to disable these on
a per-client basis. Disabling these on one client will not affect others. These settings are explained in detail in
[our FAQ](../frequently_asked_questions.html#oauth2)

> [!WARNING]
>
> Changing these settings MAY have serious consequences on the security of your services. You should avoid changing
> these if at all possible!

To disable PKCE for a confidential client:

```bash
kanidm system oauth2 warning-insecure-client-disable-pkce <client name>
```

To use the legacy RSA PKCS1-5 SHA256 cryptographic algorithm (`id_token_signing_alg_values_supported` = `RS256`):

```bash
kanidm system oauth2 warning-enable-legacy-crypto <client name>
```

In this mode, Kanidm will not offer `ES256` support for the client at all.

## Resetting Client Security Material

In the case of disclosure of the basic secret or some other security event where you may wish to invalidate a services
active sessions/tokens. You can reset the secret material of the server with:

```bash
kanidm system oauth2 reset-secrets
```

Each client has unique signing keys and access secrets, so this is limited to each service.

## WebFinger

[WebFinger][webfinger] provides a mechanism for discovering information about entities at a well-known URL
(`https://{hostname}/.well-known/webfinger`).

It can be used by a WebFinger client to [discover the OIDC Issuer URL][webfinger-oidc] of an identity provider from the
hostname alone, and seems to be intended to support dynamic client registration flows for large public identity
providers.

Kanidm v1.5.1 and later can respond to WebFinger requests, using a user's SPN as part of [an `acct` URI][rfc7565] (eg:
`acct:user@idm.example.com`). While SPNs and `acct` URIs look like email addresses, [as per RFC 7565][rfc7565s4], there
is no guarantee that it is valid for any particular application protocol, unless an administrator explicitly provides
for it.

When setting up an application to authenticate with Kanidm, WebFinger **does not add any security** over configuring an
OIDC Discovery URL directly. In an OIDC context, the specification makes a number of flawed assumptions which make it
difficult to use with Kanidm:

- WebFinger assumes that an identity provider will use the same Issuer URL and OIDC Discovery document (which contains
  endpoint URLs and token signing keys) for _all_ OAuth 2.0/OIDC clients.

  Kanidm uses _client-specific_ Issuer URLs, endpoint URLs and token signing keys. This ensures that tokens can only be
  used with their intended service.

- WebFinger endpoints must be served at the _root_ of the domain of a user's SPN (ie: information about the user with
  SPN `user@idm.example.com` is at
  `https://idm.example.com/.well-known/webfinger?resource=acct%3Auser%40idm.example.com`).

  Unlike OIDC Discovery, WebFinger clients do not report their OAuth 2.0/OIDC client ID in the request, so there is no
  way to tell them apart.

  As a result, Kanidm _does not_ provide a WebFinger endpoint at its root URL, because it could report an incorrect
  Issuer URL and lead the client to an incorrect OIDC Discovery document.

  You will need a load balancer in front of Kanidm's HTTPS server to send a HTTP 307 redirect to the appropriate
  `/oauth2/openid/:client_id:/.well-known/webfinger` URL, _while preserving all query parameters_. For example, with
  Caddy:

  ```caddy
  # Match on a prefix, and use {uri} to preserve all query parameters.
  # This only supports *one* client.
  example.com {
    redir /.well-known/webfinger https://idm.example.com/oauth2/openid/:client_id:{uri} 307
  }
  ```

  If you have _multiple_ WebFinger clients, it will need to map some other property of the request (such as a source IP
  address or `User-Agent` header) to a client ID, and redirect to the appropriate WebFinger URL for that client.

- Kanidm responds to _all_ WebFinger queries with [an Identity Provider Discovery for OIDC URL][webfinger-oidc],
  **ignoring** [`rel` parameter(s)][webfinger-rel].

  If you want to use WebFinger in any _other_ context on Kanidm's hostname, you'll need a load balancer in front of
  Kanidm which matches on some property of the request.

  WebFinger clients _may_ omit the `rel=` parameter, so if you host another service with relations for a Kanidm
  [`acct:` entity][rfc7565s4] and a client _does not_ supply the `rel=` parameter, your load balancer will need to merge
  JSON responses from Kanidm and the other service(s).

Because of these issues, we recommend that applications support _directly_ configuring OIDC using a Discovery URL or
OAuth 2.0 Authorisation Server Metadata URL instead of WebFinger.

If a WebFinger client only checks WebFinger once during setup, you may wish to temporarily serve an appropriate static
WebFinger document for that client instead.

[rfc7565]: https://datatracker.ietf.org/doc/html/rfc7565
[rfc7565s4]: https://datatracker.ietf.org/doc/html/rfc7565#section-4
[webfinger]: https://datatracker.ietf.org/doc/html/rfc7033
[webfinger-oidc]: https://datatracker.ietf.org/doc/html/rfc7033#section-3.1
[webfinger-rel]: https://datatracker.ietf.org/doc/html/rfc7033#section-4.3
