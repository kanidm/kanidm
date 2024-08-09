# Example OAuth2 Configurations

## Apache `mod_auth_openidc`

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

## Miniflux

Miniflux is a feedreader that supports OAuth 2.0 and OpenID connect. It automatically appends the
`.well-known` parts to the discovery endpoint. The application name in the redirect URL needs to
match the `OAUTH2_PROVIDER` name.

```conf
OAUTH2_PROVIDER = "oidc";
OAUTH2_CLIENT_ID = "miniflux";
OAUTH2_CLIENT_SECRET = "<oauth2_rs_basic_secret>";
OAUTH2_REDIRECT_URL = "https://feeds.example.com/oauth2/oidc/callback";
OAUTH2_OIDC_DISCOVERY_ENDPOINT = "https://idm.example.com/oauth2/openid/<oauth2_rs_name>";
```

## Nextcloud

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

## Velociraptor

Velociraptor supports OIDC. To configure it select "Authenticate with SSO" then "OIDC" during the
interactive configuration generator. Alternately, you can set the following keys in
server.config.yaml:

```yaml
GUI:
  authenticator:
    type: OIDC
    oidc_issuer: https://idm.example.com/oauth2/openid/:client_id:/
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

## Grafana

Grafana is a open source analytics and interactive visualization web application. It provides
charts, graphs and alerts when connected to supported data source.

Prepare the environment:

```bash
kanidm system oauth2 create grafana "grafana.domain.name" https://grafana.domain.name
kanidm system oauth2 update-scope-map grafana grafana_users email openid profile groups
kanidm system oauth2 enable-pkce grafana
kanidm system oauth2 get grafana
kanidm system oauth2 show-basic-secret grafana
<SECRET>
```

Create Grafana user groups:

```bash
kanidm group create 'grafana_superadmins'
kanidm group create 'grafana_admins'
kanidm group create 'grafana_editors'
kanidm group create 'grafana_users'
```

Setup the claim-map that will set what role each group will map to in Grafana:

```bash
kanidm system oauth2 update-claim-map-join 'grafana' 'grafana_role' array
kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_superadmins' 'GrafanaAdmin'
kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_admins' 'Admin'
kanidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_editors' 'Editor'
```

Don't forget that every Grafana user needs be member of one of above group and have name and e-mail:

```bash
kanidm person update <user> --legalname "Personal Name" --mail "user@example.com"
kanidm group add-members 'grafana_users' 'my_user_group_or_user_name'
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

## Vouch Proxy

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
