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

A user wishes to access a service (resource, resource server). The resource server does not have an
active session for the client, so it redirects to the authorisation server (Kanidm) to determine if
the client should be allowed to proceed, and has the appropriate permissions (scopes) for the
requested resources.

The authorisation server checks the current session of the user and may present a login flow if
required. Given the identity of the user known to the authorisation sever, and the requested scopes,
the authorisation server makes a decision if it allows the authorisation to proceed. The user is
then prompted to consent to the authorisation from the authorisation server to the resource server
as some identity information may be revealed by granting this consent.

If successful and consent given, the user is redirected back to the resource server with an
authorisation code. The resource server then contacts the authorisation server directly with this
code and exchanges it for a valid token that may be provided to the user's browser.

The resource server may then optionally contact the token introspection endpoint of the
authorisation server about the provided OAuth token, which yields extra metadata about the identity
that holds the token from the authorisation. This metadata may include identity information, but
also may include extended metadata, sometimes refered to as "claims". Claims are information bound
to a token based on properties of the session that may allow the resource server to make extended
authorisation decisions without the need to contact the authorisation server to arbitrate.

It's important to note that OAuth2 at its core is an authorisation system which has layered
identity-providing elements on top.

### Resource Server

This is the server that a user wants to access. Common examples could be Nextcloud, a wiki, or
something else. This is the system that "needs protecting" and wants to delegate authorisation
decisions to Kanidm.

It's important for you to know _how_ your resource server supports OAuth2. For example, does it
support RFC 7662 token introspection or does it rely on OpenID connect for identity information?
Does the resource server support PKCE S256?

In general Kanidm requires that your resource server supports:

- HTTP basic authentication to the authorisation server
- PKCE S256 code verification to prevent certain token attack classes
- OIDC only - JWT ES256 for token signatures

Kanidm will expose its OAuth2 APIs at the following URLs:

- user auth url: `https://idm.example.com/ui/oauth2`
- api auth url: `https://idm.example.com/oauth2/authorise`
- token url: `https://idm.example.com/oauth2/token`
- rfc7662 token introspection url: `https://idm.example.com/oauth2/token/introspect`
- rfc7009 token revoke url: `https://idm.example.com/oauth2/token/revoke`

OpenID Connect discovery - you need to substitute your OAuth2 client id in the following urls:

- OpenID connect issuer uri: `https://idm.example.com/oauth2/openid/:client\_id:/`
- OpenID connect discovery:
  `https://idm.example.com/oauth2/openid/:client\_id:/.well-known/openid-configuration`

For manual OpenID configuration:

- OpenID connect userinfo: `https://idm.example.com/oauth2/openid/:client\_id:/userinfo`
- token signing public key: `https://idm.example.com/oauth2/openid/:client\_id:/public\_key.jwk`

### Scope Relationships

For an authorisation to proceed, the resource server will request a list of scopes, which are unique
to that resource server. For example, when a user wishes to login to the admin panel of the resource
server, it may request the "admin" scope from Kanidm for authorisation. But when a user wants to
login, it may only request "access" as a scope from Kanidm.

As each resource server may have its own scopes and understanding of these, Kanidm isolates scopes
to each resource server connected to Kanidm. Kanidm has two methods of granting scopes to accounts
(users).

The first is scope mappings. These provide a set of scopes if a user is a member of a specific group
within Kanidm. This allows you to create a relationship between the scopes of a resource server, and
the groups/roles in Kanidm which can be specific to that resource server.

For an authorisation to proceed, all scopes requested by the resource server must be available in
the final scope set that is granted to the account.

The second is supplemental scope mappings. These function the same as scope maps where membership of
a group provides a set of scopes to the account. However these scopes are NOT consulted during
authorisation decisions made by Kanidm. These scopes exists to allow optional properties to be
provided (such as personal information about a subset of accounts to be revealed) or so that the
resource server may make it's own authorisation decisions based on the provided scopes.

This use of scopes is the primary means to control who can access what resources. These access
decisions can take place either on Kanidm or the resource server.

For example, if you have a resource server that always requests a scope of "read", then users with
scope maps that supply the read scope will be allowed by Kanidm to proceed to the resource server.
Kanidm can then provide the supplementary scopes into provided tokens, so that the resource server
can use these to choose if it wishes to display UI elements. If a user has a supplemental "admin"
scope, then that user may be able to access an administration panel of the resource server. In this
way Kanidm is still providing the authorisation information, but the control is then exercised by
the resource server.

## Configuration

### Create the Kanidm Configuration

After you have understood your resource server requirements you first need to configure Kanidm. By
default members of "system\_admins" or "idm\_hp\_oauth2\_manage\_priv" are able to create or manage
OAuth2 resource server integrations.

You can create a new resource server with:

```bash
kanidm system oauth2 create <name> <displayname> <origin>
kanidm system oauth2 create nextcloud "Nextcloud Production" https://nextcloud.example.com
```

You can create a scope map with:

```bash
kanidm system oauth2 update_scope_map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update_scope_map nextcloud nextcloud_admins admin
```

{{#template ../templates/kani-warning.md
imagepath=../images
title=WARNING
text=If you are creating an OpenID Connect (OIDC) resource server you <b>MUST</b> provide a scope map named <code>openid</code>. Without this, OpenID clients <b>WILL NOT WORK</b>!
}}

> **HINT** OpenID connect allows a number of scopes that affect the content of the resulting
> authorisation token. If one of the following scopes are requested by the OpenID client, then the
> associated claims may be added to the authorisation token. It is not guaranteed that all of the
> associated claims will be added.
>
> - profile - (name, family\_name, given\_name, middle\_name, nickname, preferred\_username,
  > profile, picture, website, gender, birthdate, zoneinfo, locale, and updated\_at)
> - email - (email, email\_verified)
> - address - (address)
> - phone - (phone\_number, phone\_number\_verified)

You can create a supplemental scope map with:

```bash
kanidm system oauth2 update_sup_scope_map <name> <kanidm_group_name> [scopes]...
kanidm system oauth2 update_sup_scope_map nextcloud nextcloud_admins admin
```

Once created you can view the details of the resource server.

```bash
kanidm system oauth2 get nextcloud
---
class: oauth2_resource_server
class: oauth2_resource_server_basic
class: object
displayname: Nextcloud Production
oauth2_rs_basic_secret: <secret>
oauth2_rs_name: nextcloud
oauth2_rs_origin: https://nextcloud.example.com
oauth2_rs_token_key: hidden
```

### Configure the Resource Server

On your resource server, you should configure the client ID as the "oauth2\_rs\_name" from Kanidm,
and the password to be the value shown in "oauth2\_rs\_basic\_secret". Ensure that the code
challenge/verification method is set to S256.

You should now be able to test authorisation.

## Resetting Resource Server Security Material

In the case of disclosure of the basic secret, or some other security event where you may wish to
invalidate a resource servers active sessions/tokens, you can reset the secret material of the
server with:

```bash
kanidm system oauth2 reset_secrets
```

Each resource server has unique signing keys and access secrets, so this is limited to each resource
server.

## Extended Options for Legacy Clients

Not all resource servers support modern standards like PKCE or ECDSA. In these situations it may be
necessary to disable these on a per-resource server basis. Disabling these on one resource server
will not affect others.

{{#template ../templates/kani-warning.md
imagepath=../images
title=WARNING text=Changing these settings MAY have serious consequences on the security of your resource server. You should avoid changing these if at all possible!
}}

To disable PKCE for a resource server:

```bash
kanidm system oauth2 warning_insecure_client_disable_pkce <resource server name>
```

To enable legacy cryptograhy (RSA PKCS1-5 SHA256):

```bash
kanidm system oauth2 warning_enable_legacy_crypto <resource server name>
```

## Example Integrations

### Apache mod\_auth\_openidc

Add the following to a `mod_auth_openidc.conf`. It should be included in a `mods_enabled` folder or
with an appropriate include.

```conf
OIDCRedirectURI /protected/redirect_uri
OIDCCryptoPassphrase <random password here>
OIDCProviderMetadataURL https://kanidm.example.com/oauth2/openid/<resource server name>/.well-known/openid-configuration
OIDCScope "openid" 
OIDCUserInfoTokenMethod authz_header
OIDCClientID <resource server name>
OIDCClientSecret <resource server password>
OIDCPKCEMethod S256
OIDCCookieSameSite On
# Set the `REMOTE_USER` field to the `preferred_username` instead of the UUID.
# Remember that the username can change, but this can help with systems like Nagios which use this as a display name.
# OIDCRemoteUserClaim preferred_username
```

Other scopes can be added as required to the `OIDCScope` line, eg:
`OIDCScope "openid scope2 scope3"`

In the virtual host, to protect a location:

```apache
<Location />
    AuthType openid-connect
    Require valid-user
</Location>
```

### Nextcloud

Install the module [from the nextcloud market place](https://apps.nextcloud.com/apps/user_oidc) - it
can also be found in the Apps section of your deployment as "OpenID Connect user backend".

In Nextcloud's config.php you need to allow connection to remote servers:

```php
'allow_local_remote_servers' => true,
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

This module does not support PKCE or ES256. You will need to run:

```bash
kanidm system oauth2 warning_insecure_client_disable_pkce <resource server name>
kanidm system oauth2 warning_enable_legacy_crypto <resource server name>
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
    oauth_client_id: <resource server name/>
    oauth_client_secret: <resource server secret>
```

Velociraptor does not support PKCE. You will need to run the following:

```bash
kanidm system oauth2 warning_insecure_client_disable_pkce <resource server name>
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
kanidm system oauth2 create_scope_map <resource server name> velociraptor_users openid email
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
