# OAuth2

OAuth is a web authorisation protocol that allows "single sign on". It's key to note OAuth only
provides authorisation, as the protocol in its default forms do not provide identity or
authentication information. All that OAuth can provide is information that an entity is authorised
for the requested resources.

OAuth can tie into extensions allowing an identity provider to reveal information about authorised
sessions. This extends OAuth from an authorisation only system to a system capable of identity and
authorisation. Two primary methods of this exist today: RFC7662 token introspection, and OpenID
connect.

## Resource Server and Clients

This is the resource that a user wants to access. Common [examples](oauth2/examples.md) could be
Nextcloud, a Wiki, or a chat service. In these cases the service is both the _client_ and the
_resource server_ within the OAuth2 workflow. We will refer to the combination of both client and
resource server as a service.

It's important for you to know _how_ your service will interact with OAuth2. For example, does it
rely on OpenID connect for identity information, or does it support RFC7662 token introspection?

Kanidm will expose its OAuth2 APIs at the following URLs:

- User auth: `https://idm.example.com/ui/oauth2`
- API auth: `https://idm.example.com/oauth2/authorise`
- Token: `https://idm.example.com/oauth2/token`
- RFC7662 token introspection URL: `https://idm.example.com/oauth2/token/introspect`
- RFC7009 token revoke URL: `https://idm.example.com/oauth2/token/revoke`

In general Kanidm requires that your service supports:

- HTTP basic authentication to the authorisation server (Kanidm)
- PKCE S256 code verification
- If it uses OIDC, JWT ES256 for token signatures

Kanidm issues tokens that are RFC9068 JWT's allowing service introspection.

> [!NOTE]
>
> Previous versions of this document incorrectly named clients as resource servers due to clarity
> issues in the OAuth2 RFC.

### OAuth2 Server Metadata

You need to substitute your OAuth2 `:client_id:` in the following urls

- OAuth2 issuer URL: `https://idm.example.com/oauth2/openid/:client_id:/`
- OAuth2 RFC8414 discovery:
  `https://idm.example.com/oauth2/openid/:client_id:/.well-known/oauth-authorization-server`

### OpenID Connect Discovery

You need to substitute your OAuth2 `:client_id:` in the following urls:

- OpenID connect issuer uri: `https://idm.example.com/oauth2/openid/:client_id:/`
- OpenID connect discovery:
  `https://idm.example.com/oauth2/openid/:client_id:/.well-known/openid-configuration`

### Manual OpenID Configuration

- OpenID connect userinfo: `https://idm.example.com/oauth2/openid/:client_id:/userinfo`
- token signing public key: `https://idm.example.com/oauth2/openid/:client_id:/public_key.jwk`

## Configuration

### Create the Kanidm Configuration

By default, members of the `system_admins` or `idm_hp_oauth2_manage_priv` groups are able to create
or manage OAuth2 client integrations.

You can create a new client by specifying its client name, application display name and the landing
page (home page) of the client. The landing page is where users will be redirected to from the
Kanidm application portal.

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
kanidm system oauth2 update-scope-map nextcloud nextcloud_admins admin
```

> [!TIP]
>
> OpenID connect allows a number of scopes that affect the content of the resulting authorisation
> token. If one of the following scopes are requested by the OpenID client, then the associated
> claims may be added to the authorisation token. It is not guaranteed that all of the associated
> claims will be added.
>
> - **profile** - name, family_name, given_name, middle_name, nickname, preferred_username, profile,
>   picture, website, gender, birthdate, zoneinfo, locale, and updated_at
> - **email** - email, email_verified
> - **address** - address
> - **phone** - phone_number, phone_number_verified

<!-- this is just to split the templates up -->

> [!WARNING]
>
> If you are creating an OpenID Connect (OIDC) client you **MUST** provide a scope map named
> `openid`. Without this, OpenID Connect clients **WILL NOT WORK**!

You can create a supplemental scope map with:

```bash
kanidm system oauth2 update-sup-scope-map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update-sup-scope-map nextcloud nextcloud_admins admin
```

Once created you can view the details of the client.

```bash
kanidm system oauth2 get nextcloud
---
class: oauth2_resource_server
class: oauth2_resource_server_basic
class: object
displayname: Nextcloud Production
oauth2_rs_basic_secret: hidden
oauth2_rs_name: nextcloud
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

On your client, you should configure the client ID as the `oauth2_rs_name` from Kanidm, and the
password to be the value shown in `oauth2_rs_basic_secret`. Ensure that the code
challenge/verification method is set to S256.

You should now be able to test authorisation to the client.

## Scope Relationships

For an authorisation to proceed, the client will request a list of scopes. For example, when a user
wishes to login to the admin panel of the resource server, it may request the "admin" scope from
Kanidm for authorisation. But when a user wants to login, it may only request "access" as a scope
from Kanidm.

As each service may have its own scopes and understanding of these, Kanidm isolates scopes to each
service connected to Kanidm. Kanidm has two methods of granting scopes to accounts (users).

The first is scope mappings. These provide a set of scopes if a user is a member of a specific group
within Kanidm. This allows you to create a relationship between the scopes of a service, and the
groups/roles in Kanidm which can be specific to that service.

For an authorisation to proceed, all scopes requested by the client must be available in the final
scope set that is granted to the account.

The second part is supplemental scope mappings. These function the same as scope maps where
membership of a group provides a set of scopes to the account. However these scopes are NOT
consulted during authorisation decisions made by Kanidm. These scopes exist to allow optional
properties to be provided (such as personal information about a subset of accounts to be revealed)
or so that the service may make its own authorisation decisions based on the provided scopes.

This use of scopes is the primary means to control who can access what resources. These access
decisions can take place either on Kanidm or the service.

For example, if you have a client that always requests a scope of "read", then users with scope maps
that supply the read scope will be allowed by Kanidm to proceed to the service. Kanidm can then
provide the supplementary scopes into provided tokens, so that the service can use these to choose
if it wishes to display UI elements. If a user has a supplemental "admin" scope, then that user may
be able to access an administration panel of the service. In this way Kanidm is still providing the
authorisation information, but the control is then exercised by the service.

## Public Client Configuration

Some applications are unable to provide client authentication. A common example is single page web
applications that act as the OAuth2 client and its corresponding webserver is the resource server.
In this case, the SPA is unable to act as a confidential client since the basic secret would need to
be embedded in every client.

Another common example is native applications that use a redirect to localhost. These can't have a
client secret embedded, so must act as public clients.

Public clients for this reason require PKCE to bind a specific browser session to its OAuth2
exchange. PKCE can not be disabled for public clients for this reason.

To create an OAuth2 public client:

```bash
kanidm system oauth2 create-public <name> <displayname> <origin>
kanidm system oauth2 create-public mywebapp "My Web App" https://webapp.example.com
```

To allow localhost redirection

```bash
kanidm system oauth2 enable-localhost-redirects <name>
kanidm system oauth2 disable-localhost-redirects <name>
kanidm system oauth2 enable-localhost-redirects mywebapp
```

## Alternate Redirect URLs

> [!WARNING]
>
> Security Risk!
>
> You **MUST NOT** share a single OAuth2 client definition between multiple applications.
>
> The ability to configure multiple redirect URLs is **NOT** intended to allow you to share a single
> Kanidm client definition between multiple OAuth2 clients.
>
> Sharing OAuth2 client configurations between applications **FUNDAMENTALLY BREAKS** the OAuth2
> security model and is **NOT SUPPORTED** as a configuration. The Kanidm Project **WILL NOT**
> support you if you attempt this.
>
> Multiple origins are **ONLY** to allow supplemental redirects within the _same_ client
> application.

Some services may have a website URL as well as native applications with opaque origins. These
native applications require alternate redirection URLs to be configured so that after an OAuth2
exchange, the system can redirect to the native application.

To support this Kanidm allows supplemental opaque origins to be configured on clients.

```bash
kanidm system oauth2 add-redirect-url <name> <url>
kanidm system oauth2 remove-redirect-url <name> <url>

kanidm system oauth2 add-redirect-url nextcloud app://ios-nextcloud
```

Supplemental URLs are shown in the OAuth2 client configuration in the `oauth2_rs_origin` attribute.

### Strict Redirect URLs

Kanidm previously enforced that redirection targets only matched by _origin_, not the full URL. In
1.4.0 these URLs will enforce a full URL match instead.

To indicate your readiness for this transition, all OAuth2 clients must have the field
`strict-redirect-url` enabled. Once enabled, the client will begin to enforce the 1.4.0 strict
validation behaviour.

If you have not enabled `strict-redirect-url` on all OAuth2 clients the upgrade to 1.4.0 will refuse
to proceed.

To enable or disable strict validation:

```bash
kanidm system oauth2 enable-strict-redirect-url <name>
kanidm system oauth2 disable-strict-redirect-url <name>
```

## Extended Options for Legacy Clients

Not all clients support modern standards like PKCE or ECDSA. In these situations it may be necessary
to disable these on a per-client basis. Disabling these on one client will not affect others. These
settings are explained in detail in [our FAQ](../frequently_asked_questions.html#oauth2)

> [!WARNING]
>
> Changing these settings MAY have serious consequences on the security of your services. You should
> avoid changing these if at all possible!

To disable PKCE for a confidential client:

```bash
kanidm system oauth2 warning-insecure-client-disable-pkce <client name>
```

To enable legacy cryptography (RSA PKCS1-5 SHA256):

```bash
kanidm system oauth2 warning-enable-legacy-crypto <client name>
```

## Resetting Client Security Material

In the case of disclosure of the basic secret or some other security event where you may wish to
invalidate a services active sessions/tokens. You can reset the secret material of the server with:

```bash
kanidm system oauth2 reset-secrets
```

Each client has unique signing keys and access secrets, so this is limited to each service.
