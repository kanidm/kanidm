# OAuth2

OAuth is a web authorisation protocol that allows "single sign on". It's key to note OAuth only
provides authorisation, as the protocol in its default forms do not provide identity or
authentication information. All that Oauth2 provides is information that an entity is authorised for
the requested resources.

OAuth can tie into extensions allowing an identity provider to reveal information about authorised
sessions. This extends OAuth from an authorisation only system to a system capable of identity and
authorisation. Two primary methods of this exist today: RFC7662 token introspection, and OpenID
connect.

## How Does OAuth2 Work?

OAuth2 uses a number of terms in surprising ways that makes it often unclear and difficult to
understand.

A user wishes to access a service (resource, resource server) through an OAuth2 client. The client
does not have an active session for the user so it redirects to the authorisation server (Kanidm) to
determine if the user should be allowed to proceed, and has the appropriate permissions (scopes) for
the requested resources.

The authorisation server checks the current session of the user and may present a login flow if
required. Given the identity of the user known to the authorisation sever, and the requested scopes,
the authorisation server makes a decision if it allows the authorisation to proceed. The user is
then prompted to consent to the authorisation from the authorisation server to the client as some
identity information may be revealed by granting this consent.

If successful and consent is given, the user is redirected back to the client with an authorisation
code. The client then contacts the authorisation server directly with this code and exchanges it for
a valid OAuth token.

The client may then optionally contact the token introspection endpoint of the authorisation server
about the provided OAuth token, which yields extra metadata about the identity that holds the token
from the authorisation. This metadata may include identity information, but also may include
extended metadata, sometimes referred to as "claims". Claims are information bound to a token based
on properties of the session that may allow the client to make extended authorisation decisions
without the need to contact the authorisation server to arbitrate.

In many cases the client and the resource server are the same entity. When the client and resource
server are _separate_ services, the client can then forward the access token to the resource server
for authorisation of the user's request.

It's important to note that OAuth2 at its core is an authorisation system which has layered
identity-providing elements on top.

### Resource Server and Clients

This is the resource that a user wants to access. Common examples could be Nextcloud, a Wiki, or a
chat service. In these cases the service is both the _client_ and the _resource server_ within the
OAuth2 workflow. We will refer to the combination of both client and resource server as a service.

> NOTE: previous versions of this document incorrectly named clients as resource servers due to
> clarity issues in the OAuth2 RFC.

It's important for you to know _how_ your service will interact with OAuth2. For example, does it
support RFC 7662 token introspection or does it rely on OpenID connect for identity information?

In general Kanidm requires that your service supports:

- HTTP basic authentication to the authorisation server
- PKCE S256 code verification
- OIDC only - JWT ES256 for token signatures

Kanidm issues tokens that are RFC 9068 JWT's allowing service introspection.

Kanidm will expose its OAuth2 APIs at the following URLs:

- user auth url: `https://idm.example.com/ui/oauth2`
- api auth url: `https://idm.example.com/oauth2/authorise`
- token url: `https://idm.example.com/oauth2/token`
- rfc7662 token introspection url: `https://idm.example.com/oauth2/token/introspect`
- rfc7009 token revoke url: `https://idm.example.com/oauth2/token/revoke`

Oauth2 Server Metadata - you need to substitute your OAuth2 `:client_id:` in the following urls:

- Oauth2 issuer uri: `https://idm.example.com/oauth2/openid/:client_id:/`
- Oauth2 rfc8414 discovery:
  `https://idm.example.com/oauth2/openid/:client_id:/.well-known/oauth-authorization-server`

OpenID Connect discovery - you need to substitute your OAuth2 `:client_id:` in the following urls:

- OpenID connect issuer uri: `https://idm.example.com/oauth2/openid/:client_id:/`
- OpenID connect discovery:
  `https://idm.example.com/oauth2/openid/:client_id:/.well-known/openid-configuration`

For manual OpenID configuration:

- OpenID connect userinfo: `https://idm.example.com/oauth2/openid/:client_id:/userinfo`
- token signing public key: `https://idm.example.com/oauth2/openid/:client_id:/public_key.jwk`

### Scope Relationships

For an authorisation to proceed, the client will request a list of scopes, which are unique to that
service. For example, when a user wishes to login to the admin panel of the resource server, it may
request the "admin" scope from Kanidm for authorisation. But when a user wants to login, it may only
request "access" as a scope from Kanidm.

As each service may have its own scopes and understanding of these, Kanidm isolates scopes to each
service connected to Kanidm. Kanidm has two methods of granting scopes to accounts (users).

The first is scope mappings. These provide a set of scopes if a user is a member of a specific group
within Kanidm. This allows you to create a relationship between the scopes of a service, and the
groups/roles in Kanidm which can be specific to that service.

For an authorisation to proceed, all scopes requested by the client must be available in the final
scope set that is granted to the account.

The second is supplemental scope mappings. These function the same as scope maps where membership of
a group provides a set of scopes to the account. However these scopes are NOT consulted during
authorisation decisions made by Kanidm. These scopes exists to allow optional properties to be
provided (such as personal information about a subset of accounts to be revealed) or so that the
service may make its own authorisation decisions based on the provided scopes.

This use of scopes is the primary means to control who can access what resources. These access
decisions can take place either on Kanidm or the service.

For example, if you have a client that always requests a scope of "read", then users with scope maps
that supply the read scope will be allowed by Kanidm to proceed to the service. Kanidm can then
provide the supplementary scopes into provided tokens, so that the service can use these to choose
if it wishes to display UI elements. If a user has a supplemental "admin" scope, then that user may
be able to access an administration panel of the service. In this way Kanidm is still providing the
authorisation information, but the control is then exercised by the service.

## Configuration

### Create the Kanidm Configuration

After you have understood your service requirements you first need to configure Kanidm. By default
members of `system_admins` or `idm_hp_oauth2_manage_priv` are able to create or manage OAuth2 client
integrations.

You can create a new client with:

```bash
kanidm system oauth2 create <name> <displayname> <origin>
kanidm system oauth2 create nextcloud "Nextcloud Production" https://nextcloud.example.com
```

You can create a scope map with:

```bash
kanidm system oauth2 update-scope-map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update-scope-map nextcloud nextcloud_admins admin
```

<!-- deno-fmt-ignore-start -->

{{#template ../templates/kani-warning.md
imagepath=../images
title=WARNING
text=If you are creating an OpenID Connect (OIDC) client you <b>MUST</b> provide a scope map named <code>openid</code>. Without this, OpenID Connect clients <b>WILL NOT WORK</b>!
}}

<!-- deno-fmt-ignore-end -->

> **HINT** OpenID connect allows a number of scopes that affect the content of the resulting
> authorisation token. If one of the following scopes are requested by the OpenID client, then the
> associated claims may be added to the authorisation token. It is not guaranteed that all of the
> associated claims will be added.
>
> - profile - (name, family\_name, given\_name, middle\_name, nickname, preferred\_username,
>   profile, picture, website, gender, birthdate, zoneinfo, locale, and updated\_at)
> - email - (email, email\_verified)
> - address - (address)
> - phone - (phone\_number, phone\_number\_verified)

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

You can see "oauth2\_rs\_basic\_secret" with:

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

## Resetting Client Security Material

In the case of disclosure of the basic secret or some other security event where you may wish to
invalidate a services active sessions/tokens. You can reset the secret material of the server with:

```bash
kanidm system oauth2 reset-secrets
```

Each client has unique signing keys and access secrets, so this is limited to each service.

## Custom Claim Maps

Some OAuth services may consume custom claims from an id token for access control or other policy
decisions. Each custom claim is a key:values set, where there can be many values associated to a
claim name. Different applications may expect these values to be formatted (joined) in different
ways.

Claim values are mapped based on membership to groups. When an account is a member of multiple
groups that would recieve the same claim, the values of these maps are merged.

To create or update a claim map on a client:

```
kanidm system oauth2 update-claim-map <name> <claim_name> <kanidm_group_name> [values]...
kanidm system oauth2 update-claim-map nextcloud account_role nextcloud_admins admin login ...
```

To change the join strategy for a claim name. Valid strategies are csv (comma separated value), ssv
(space separated value) and array (a native json array). The default strategy is array.

```
kanidm system oauth2 update-claim-map-join <name> <claim_name> [csv|ssv|array]
kanidm system oauth2 update-claim-map-join nextcloud account_role csv
```

```
# Example claim formats
# csv
claim: "value_a,value_b"

# ssv
claim: "value_a value_b"

# array
claim: ["value_a", "value_b"]
```

To delete a group from a claim map

```
kanidm system oauth2 delete-claim-map <name> <claim_name> <kanidm_group_name>
kanidm system oauth2 delete-claim-map nextcloud account_role nextcloud_admins
```

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

## Alternate Redirect Origins

Some services may have a website url as well as native applications. These native applications
require alternate redirection urls to be configured so that after an oauth2 exchange, the system can
redirect to the native application.

To support this Kanidm allows supplemental origins to be configured on clients.

{{#template ../templates/kani-warning.md imagepath=../images title=WARNING text=The ability to
configure multiple origins is NOT intended to allow you to share a single Kanidm client definition
between multiple OAuth2 clients. This fundamentally breaks the OAuth2 security model and is NOT
SUPPORTED as a configuration. Multiple origins is only to allow supplemental redirects within the
_same_ client application. }}

```bash
kanidm system oauth2 add-origin <name> <origin>
kanidm system oauth2 remove-origin <name> <origin>

kanidm system oauth2 add-origin nextcloud app://ios-nextcloud
```

Supplemental urls are shown in the OAuth2 client configuration in the `oauth2_rs_origin` attribute.

## Extended Options for Legacy Clients

Not all clients support modern standards like PKCE or ECDSA. In these situations it may be necessary
to disable these on a per-client basis. Disabling these on one client will not affect others. These
settings are explained in detail in [our FAQ](../frequently_asked_questions.html#oauth2)

<!-- deno-fmt-ignore-start -->

{{#template ../templates/kani-warning.md
imagepath=../images
title=WARNING
text=Changing these settings MAY have serious consequences on the security of your services. You should avoid changing these if at all possible!
}}

<!-- deno-fmt-ignore-end -->

To disable PKCE for a confidential client:

```bash
kanidm system oauth2 warning-insecure-client-disable-pkce <client name>
```

To enable legacy cryptograhy (RSA PKCS1-5 SHA256):

```bash
kanidm system oauth2 warning-enable-legacy-crypto <client name>
```

## Example Integrations

### Apache mod\_auth\_openidc

Add the following to a `mod_auth_openidc.conf`. It should be included in a `mods_enabled` folder or
with an appropriate include.

```conf
# NB: may be just path, reduces copy-paste
OIDCRedirectURI /oauth2/callback
OIDCCryptoPassphrase <random password here>
OIDCProviderMetadataURL https://kanidm.example.com/oauth2/openid/<client name>/.well-known/openid-configuration
OIDCScope "openid"
OIDCUserInfoTokenMethod authz_header
OIDCClientID <client name>
OIDCClientSecret <client password>
OIDCPKCEMethod S256
OIDCCookieSameSite On
# Set the `REMOTE_USER` field to the `preferred_username` instead of the UUID.
# Remember that the username can change, but this can help with systems like Nagios which use this as a display name.
# OIDCRemoteUserClaim preferred_username
```

Other scopes can be added as required to the `OIDCScope` line, eg:
`OIDCScope "openid scope2 scope3"`

In the virtual host, to handle OIDC redirect, a special location _must_ be defined:

```apache
# NB: you must allocate this virtual location matching OIDCRedirectURI and allow it for _any valid user_
<Location /oauth2/callback>
    AuthType openid-connect
    Require valid-user
</Location>
```

In the virtual host, to protect a location/directory
[see wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization):

```apache
<Directory /foo>
    AuthType openid-connect

    # you can authorize by the groups if you requested OIDCScope "openid groups"
    # Require claim groups:<spn | uuid>
    Require claim groups:apache_access_allowed@example.com

    # or authorize by exact preferred_username
    # Require user john.doe
</Directory>
```

### Miniflux

Miniflux is a feedreader that supports OAuth 2.0 and OpenID connect. It automatically appends the
`.well-known` parts to the discovery endpoint. The application name in the redirect URL needs to
match the `OAUTH2_PROVIDER` name.

```
OAUTH2_PROVIDER = "oidc";
OAUTH2_CLIENT_ID = "miniflux";
OAUTH2_CLIENT_SECRET = "<oauth2_rs_basic_secret>";
OAUTH2_REDIRECT_URL = "https://feeds.example.com/oauth2/oidc/callback";
OAUTH2_OIDC_DISCOVERY_ENDPOINT = "https://idm.example.com/oauth2/openid/<oauth2_rs_name>";
```

### Nextcloud

Install the module [from the nextcloud market place](https://apps.nextcloud.com/apps/user_oidc) - it
can also be found in the Apps section of your deployment as "OpenID Connect user backend".

In Nextcloud's config.php you need to allow connection to remote servers and enable PKCE:

```php
'allow_local_remote_servers' => true,

'user_oidc' => [
    'use_pkce' => true,
],
```

You may optionally choose to add:

```php
'allow_user_to_change_display_name' => false,
'lost_password_link' => 'disabled',
```

If you forget this, you may see the following error in logs:

```bash
Host 172.24.11.129 was not connected to because it violates local access rules
```

In the settings menu, configure the discovery URL and client ID and secret.

You can choose to disable other login methods with:

```bash
php occ config:app:set --value=0 user_oidc allow_multiple_user_backends
```

You can login directly by appending `?direct=1` to your login page. You can re-enable other backends
by setting the value to `1`

### Velociraptor

Velociraptor supports OIDC. To configure it select "Authenticate with SSO" then "OIDC" during the
interactive configuration generator. Alternately, you can set the following keys in
server.config.yaml:

```yaml
GUI:
  authenticator:
    type: OIDC
    oidc_issuer: https://idm.example.com/oauth2/openid/:client\_id:/
    oauth_client_id: <client name/>
    oauth_client_secret: <client secret>
```

Velociraptor does not support PKCE. You will need to run the following:

```bash
kanidm system oauth2 warning-insecure-client-disable-pkce <client name>
```

Initial users are mapped via their email in the Velociraptor server.config.yaml config:

```yaml
GUI:
  initial_users:
  - name: <email address>
```

Accounts require the `openid` and `email` scopes to be authenticated. It is recommended you limit
these to a group with a scope map due to Velociraptors high impact.

```bash
# kanidm group create velociraptor_users
# kanidm group add_members velociraptor_users ...
kanidm system oauth2 create_scope_map <client name> velociraptor_users openid email
```

### Grafana

Grafana is a open source analytics and interactive visualization web application. It provides
charts, graphs and alerts when connected to supported data source.

Prepare the environment:

```bash
$ kanidm system oauth2 create grafana "grafana.domain.name" https://grafana.domain.name
$ kanidm system oauth2 update-scope-map grafana grafana_users email openid profile
$ kanidm system oauth2 enable-pkce grafana
$ kanidm system oauth2 get grafana
$ kanidm system oauth2 show-basic-secret grafana
<SECRET>
```

Create Grafana user groups:

```bash
$ kanidm group create 'grafana_superadmins'
$ kanidm group create 'grafana_admins'
$ kanidm group create 'grafana_editors'
$ kanidm group create 'grafana_users'
```

Setup the claim-map that will set what role each group will map to in Grafana:

```bash
$ kanidm system oauth2 update-claim-map-join 'grafana' 'grafana_role' array
$ kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_superadmins' 'GrafanaAdmin'
$ kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_admins' 'Admin'
$ kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_editors' 'Editor'
```

Don't forget that every Grafana user needs be member of one of above group and have name and e-mail:

```bash
$ kanidm person update <user> --legalname "Personal Name" --mail "user@example.com"
$ kanidm group add-members 'grafana_users' 'my_user_group_or_user_name'
```

And add the following to your Grafana config:

```ini
[auth.generic_oauth]
enabled = true
name = Kanidm
client_id = grafana
client_secret = <SECRET>
scopes = openid,profile,email,groups
auth_url = https://idm.example.com/ui/oauth2
token_url = https://idm.example.com/oauth2/token
api_url = https://idm.example.com/oauth2/openid/grafana/userinfo
use_pkce = true
use_refresh_token = true
allow_sign_up = true
login_attribute_path = preferred_username
groups_attribute_path = groups
role_attribute_path = contains(grafana_role[*], 'GrafanaAdmin') && 'GrafanaAdmin' || contains(grafana_role[*], 'Admin') && 'Admin' || contains(grafana_role[*], 'Editor') && 'Editor' || 'Viewer'
allow_assign_grafana_admin = true
```

### Vouch Proxy

> **WARNING** Vouch proxy requires a unique identifier but does not use the proper scope, "sub". It
> uses the fields "username" or "email" as primary identifiers instead. As a result, this can cause
> user or deployment issues, at worst security bypasses. You should avoid Vouch Proxy if possible
> due to these issues.
>
> - <https://github.com/vouch/vouch-proxy/issues/309>
> - <https://github.com/vouch/vouch-proxy/issues/310>

Note: **You need to run at least the version 0.37.0**

Vouch Proxy supports multiple OAuth and OIDC login providers. To configure it you need to pass:

```yaml
oauth:
  auth_url: https://idm.wherekanidmruns.com/ui/oauth2
  callback_url: https://login.wherevouchproxyruns.com/auth
  client_id: <oauth2_rs_name> # Found in kanidm system oauth2 get XXXX (should be the same as XXXX)
  client_secret: <oauth2_rs_basic_secret> # Found in kanidm system oauth2 get XXXX
  code_challenge_method: S256
  provider: oidc
  scopes:
    - email # Required due to vouch proxy reliance on mail as a primary identifier
  token_url: https://idm.wherekanidmruns.com/oauth2/token
  user_info_url: https://idm.wherekanidmruns.com/oauth2/openid/<oauth2_rs_name>/userinfo
```

The `email` scope needs to be passed and thus the mail attribute needs to exist on the account:

```bash
kanidm person update <ID> --mail "YYYY@somedomain.com" --name idm_admin
```
