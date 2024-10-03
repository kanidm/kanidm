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

## GitLab

[GitLab](https://gitlab.com) is a Git-based software development platform, which
[supports OpenID Connect](https://docs.gitlab.com/ee/administration/auth/oidc.html)
on [self-managed installations](https://docs.gitlab.com/ee/install/) *only*
(ie: **not** GitLab.com).

To set up a self-managed GitLab instance to authenticate with Kanidm:

1.  Add an email address to your regular Kanidm account, if it doesn't have one
    already:

    ```sh
    kanidm person update your_username -m your_username@example.com
    ```

2.  Create a new Kanidm group for your GitLab users (`gitlab_users`), and
    add your regular account to it:

    ```sh
    kanidm group create gitlab_users
    kanidm group add-members gitlab_users your_username
    ```

3.  Create a new OAuth2 application configuration in Kanidm (`gitlab`),
    configure the redirect URL, and scope access to the `gitlab_users` group:

    ```sh
    kanidm system oauth2 create gitlab GitLab https://gitlab.example.com
    kanidm system oauth2 add-redirect-url gitlab https://gitlab.example.com/users/auth/oauth2_generic/callback
    kanidm system oauth2 update-scope-map gitlab gitlab_users email openid profile groups
    ```

4.  Get the `gitlab` OAuth2 client secret from Kanidm:

    ```sh
    kanidm system oauth2 show-basic-secret gitlab
    ```

5.  Configure GitLab to authenticate to Kanidm with OpenID Connect in
    `/etc/gitlab/gitlab.rb`:

    ```ruby
    # Allow OpenID Connect for single sign on
    gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']

    # Automatically approve any account from an OmniAuth provider.
    #
    # This is insecure if you *don't* control *all* the providers in use.
    # For example, if you allowed sign in Kanidm *and* with some public identity
    # provider, it will let anyone with an account sign in to your GitLab
    # instance.
    gitlab_rails['omniauth_block_auto_created_users'] = false

    # Automatically link existing users to Kanidm by email address.
    #
    # This is insecure if users are allowed to change their own email address
    # in Kanidm (disabled by default), or any provider doesn't validate
    # ownership of email addresses.
    gitlab_rails['omniauth_auto_link_user'] = ['openid_connect']

    # Update the user's profile with info from Kanidm whenever they log in.
    # GitLab locks these fields when sync is enabled.
    gitlab_rails['omniauth_sync_profile_from_provider'] = ['openid_connect']
    gitlab_rails['omniauth_sync_profile_attributes'] = ['name', 'email']

    # Connect to Kanidm
    gitlab_rails['omniauth_providers'] = [
      {
        name: "openid_connect",
        label: "Kanidm",
        icon: "https://kanidm.example.com/pkg/img/logo-192.png",
        args: {
          name: "openid_connect",
          scope: ["openid","profile","email"],
          response_type: "code",
          # Point this at your Kanidm host. "gitlab" is the OAuth2 client ID.
          # Don't include a trailing slash!
          issuer: "https://kanidm.example.com/oauth2/openid/gitlab",
          discovery: true,
          client_auth_method: "query",
          # Key the GitLab identity by UUID.
          uid_field: "sub",
          pkce: true,
          client_options: {
            # OAuth2 client ID
            identifier: "gitlab",
            secret: "YOUR KANIDM BASIC SECRET HERE",
            redirect_uri: "https://gitlab.example.com/users/auth/openid_connect/callback"
          }
        },
      },
    ]
    ```

    > [!TIP]
    >
    > If you're running GitLab in Docker (or other container platform), you can add
    > this configuration to the `GITLAB_OMNIBUS_CONFIG` environment variable.

6.  Restart GitLab (`gitlab-ctl reconfigure`), and wait for it to come back up
    again (this may take several minutes).

Once GitLab is up and running, you should now see a "Kanidm" option on your
GitLab sign-in page below the normal login form.

## JetBrains Hub and YouTrack

> These instructions were tested with the on-prem version of JetBrains YouTrack
> 2024.3.44799 and its built-in Hub.

[JetBrains Hub](https://www.jetbrains.com/hub/) is an authentication and
authorisation system for TeamCity and YouTrack, which also provides a "single
pane of glass" view of those applications.

TeamCity is a CI/CD tool, and YouTrack is a project and issue management tool.

The on-prem version of YouTrack comes with a built-in version of Hub, which it
uses for all authentication.

[JetBrains Hub supports OAuth2](https://www.jetbrains.com/help/hub/oauth2-authentication-module.html),
but has some limitations:

*   JetBrains Hub's OAuth2 Auth Module does not support PKCE (as a client),
    [which is a security issue][pkce-disable-security].

*   JetBrains Hub does not automatically update profile attributes after account
    creation.

    However, users can update their own profile manually.

*   JetBrains Hub does not support using an auto-configuration URL, which means
    you have to set a lot of options manually (which this guide will describe).

To set up YouTrack (with its built-in JetBrains Hub) to authenticate with Kanidm
using OAuth2:

1.  Add an email address to your regular Kanidm account, if it doesn't have one
    already:

    ```sh
    kanidm person update your_username -m your_username@example.com
    ```

2.  Create a new Kanidm group for your YouTrack users (`youtrack_users`), and
    add your regular account to it:

    ```sh
    kanidm group create youtrack_users
    kanidm group add-members youtrack_users your_username
    ```

3.  Create a new OAuth2 application configuration in Kanidm (`youtrack`),
    disable the PKCE requirement ([this is insecure][pkce-disable-security], but
    YouTrack doesn't support it), and scope access to the `youtrack_users` group:

    ```sh
    kanidm system oauth2 create youtrack YouTrack https://youtrack.example.com
    kanidm system oauth2 warning-insecure-client-disable-pkce youtrack
    kanidm system oauth2 update-scope-map gitlab gitlab_users email openid profile groups
    ```

4.  **(optional)** By default, Kanidm presents the account's full SPN (eg:
    `your_username@kanidm.example.com`) as its "preferred username".

    You can set `youtrack` to use a short username (eg: `your_username`) with:

    ```sh
    kanidm system oauth2 prefer-short-username youtrack
    ```

5.  Log in to YouTrack with an account that has full system administrator
    rights.

6.  Open the Auth Modules configuration in YouTrack
    (<kbd>⚙️ Administration</kbd> → <kbd>Access Management</kbd> → <kbd>Auth
    Modules</kbd>)

7.  Click <kbd>New module</kbd> → <kbd>OAuth2</kbd>, and enter the following
    details:

    * Name: `Kanidm`
    * Authorization URL: `https://kanidm.example.com/ui/oauth2`

    Click Create, and you'll be taken to the Auth Module's settings page.

8.  Copy the <kbd>Redirect URI</kbd> from YouTrack and set it in Kanidm:

    ```sh
    kanidm system oauth2 add-redirect-url youtrack https://youtrack.example.com/hub/...
    ```

9.  Configure the Kanidm Auth Module as follows:

    <dl>

    <dt>Button image</dt>

    <dd>

    Upload a Kanidm or other organisational logo.
    
    This will appear on the login form (with no text) to prompt users to sign
    in.

    By default, this is the OAuth2 logo.

    </dd>

    <dt>Client ID</dt>

    <dd>

    `youtrack`

    </dd>

    <dt>Client secret</dt>

    <dd>

    Copy the secret from the output of this command:

    ```sh
    kanidm system oauth2 show-basic-secret youtrack
    ```

    </dd>

    <dt>Extension grant</dt>

    <dd>

    _Leave blank_

    </dd>

    <dt><strong>Authorization Service Endpoints</strong></dt>
    <dd></dd>

    <dt>Authorization URL</dt>

    <dd>

    `https://kanidm.example.com/ui/oauth2`

    </dd>

    <dt>Token endpoint URL</dt>

    <dd>

    `https://kanidm.example.com/oauth2/token`

    </dd>

    <dt>User data endpoint URL</dt>

    <dd>

    `https://kanidm.example.com/oauth2/openid/youtrack/userinfo`

    </dd>

    <dt>Email endpoint URL</dt>

    <dd>

    _Leave blank_

    </dd>

    <dt>Avatar endpoint URL</dt>

    <dd>

    _Leave blank_

    </dd>

    <dt><strong>Field mapping</strong></dt>
    <dd></dd>

    <dt>User ID</dt>

    <dd>

    `sub`

    </dd>

    <dt>Username</dt>

    <dd>

    `preferred_username`

    </dd>

    <dt>Full name</dt>

    <dd>

    `name`

    </dd>

    <dt>Email</dt>

    <dd>

    `email`

    </dd>

    <dt><strong>Additional settings</strong></dt>
    <dd></dd>

    <dt>Scope</dt>

    <dd>

    `openid,profile,email`

    </dd>

    <dt>User creation</dt>

    <dd>Enabled</dd>

    </dl>

10. Click <kbd>Save</kbd> at the bottom of the page.

11. Click <kbd>Enable module</kbd> at the top of the page.

12. Click <kbd>Test login...</kbd> at the top of the page to try logging in with
    Kanidm.

    You may need to allow pop-ups for YouTrack in your browser for this to work.

YouTrack's log in page should now have show the button image you set for Kanidm
below the normal log in form – which you can use to log in with Kanidm.

[pkce-disable-security]: ../../frequently_asked_questions.md#why-is-disabling-pkce-considered-insecure

## Miniflux

Miniflux is a feedreader that supports OAuth 2.0 and OpenID connect. It automatically appends the
`.well-known` parts to the discovery endpoint. The application name in the redirect URL needs to
match the `OAUTH2_PROVIDER` name.

```conf
OAUTH2_PROVIDER = "oidc";
OAUTH2_CLIENT_ID = "miniflux";
OAUTH2_CLIENT_SECRET = "<oauth2_rs_basic_secret>";
OAUTH2_REDIRECT_URL = "https://feeds.example.com/oauth2/oidc/callback";
OAUTH2_OIDC_DISCOVERY_ENDPOINT = "https://idm.example.com/oauth2/openid/<name>";
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

## ownCloud

> These instructions were tested with ownCloud 10.15.10.

To set up an ownCloud instance to authenticate with Kanidm:

1.  Install the [ownCloud OpenID Connect app](https://marketplace.owncloud.com/apps/openidconnect)
    (for web auth) **and** [ownCloud OAuth2 app][owncloud-oauth2-app] (for
    desktop and mobile app auth) from the ownCloud Market.

2.  Add an email address to your regular Kanidm account, if it doesn't have one
    already:

    ```sh
    kanidm person update your_username -m your_username@example.com
    ```

3.  Create a new Kanidm group for your ownCloud users (`owncloud_users`), and
    add your regular account to it:

    ```sh
    kanidm group create owncloud_users
    kanidm group add-members owncloud_users your_username
    ```

4.  Create a new OAuth2 application configuration in Kanidm (`owncloud`), allow
    use of legacy crypto
    ([ownCloud does not support `ES256`](https://github.com/owncloud/openidconnect/issues/313)),
    configure the redirect URLs, and scope access to the `owncloud_users` group:

    ```sh
    kanidm system oauth2 create owncloud ownCloud https://owncloud.example.com
    kanidm system oauth2 warning-enable-legacy-crypto owncloud
    kanidm system oauth2 add-redirect-url owncloud https://owncloud.example.com/apps/openidconnect/redirect
    kanidm system oauth2 update-scope-map owncloud owncloud_users email openid profile groups
    ```

5.  **(optional)** By default, Kanidm presents the account's full SPN (eg:
    `your_username@kanidm.example.com`) as its "preferred username".
    You can set `owncloud` to use a short username (eg: `your_username`) with:

    ```sh
    kanidm system oauth2 prefer-short-username owncloud
    ```

6.  Get the `owncloud` OAuth2 client secret from Kanidm:

    ```sh
    kanidm system oauth2 show-basic-secret owncloud
    ```

7.  Create a JSON configuration file (`oidc-config.json`) for ownCloud's OIDC
    App.

    To key users by UID (most secure configuration, but not suitable if you have
    existing ownCloud accounts) – so their UID is their ownCloud username, use
    this configuration:

    ```json
    {
      "provider-url": "https://kanidm.example.com/oauth2/openid/owncloud",
      "client-id": "owncloud",
      "client-secret": "YOUR CLIENT SECRET HERE",
      "loginButtonName": "Kanidm",
      "mode": "userid",
      "search-attribute": "sub",
      "auto-provision": {
        "enabled": true,
        "email-claim": "email",
        "display-name-claim": "name",
        "update": {"enabled": true}
      },
      "scopes": ["openid", "profile", "email"]
    }
    ```

    To key users by email address (vulnerable to account take-over, but allows
    for migrating existing ownCloud accounts), modify the `mode` and
    `search-attribute` settings to use the `email` attribute:

    ```json
    {
      "mode": "email",
      "search-attribute": "email"
    }
    ```

8.  Deploy the config file you created with [`occ`][occ].

    [The exact command varies][occ] depending on how you've deployed ownCloud.

    ```sh
    occ config:app:set openidconnect openid-connect --value="$(<oidc-config.json)"
    ```

ownCloud's login page should now show "Alternative logins" below the normal
login form, which you can use to sign in.

> [!WARNING]
>
> **Do not** configure [OIDC Service Discovery][owncloud-oidcsd] rewrite rules
> (`/.well-known/openid-configuration`) in ownCloud – **this breaks the ownCloud
> desktop and mobile clients**.
>
> The ownCloud desktop and mobile clients use
> [hard coded secrets][owncloud-secrets] which **cannot** be entered into
> Kanidm, because this is a security risk.
>
> With the [ownCloud OAuth2 app][owncloud-oauth2-app] installed, the ownCloud
> clients will instead authenticate to ownCloud Server as an OAuth provider
> (which has [the hard coded secrets][owncloud-secrets] installed by default),
> which then in turn can authenticate to ownCloud locally or to Kanidm with
> your own client ID/secret.
>
> To use OIDC Service Discovery with the ownCloud clients, you'd need to create
> OAuth2 client configurations in Kanidm for the ownCloud Android, desktop and
> iOS apps, and get those secrets added to the clients either by:
>
> * modifying and recompiling the apps yourself from source, or,
> * [using an iOS MDM configuration][owncloud-ios-mdm] (iOS only), or,
> * [requesting branded apps as part of an ownCloud Enterprise subscription][owncloud-branding]
>
> Setting that up is beyond the scope of this document.

[owncloud-branding]: https://doc.owncloud.com/server/next/admin_manual/enterprise/clients/creating_branded_apps.html
[owncloud-oidcsd]: https://doc.owncloud.com/server/next/admin_manual/configuration/user/oidc/oidc.html#set-up-service-discovery
[owncloud-secrets]: https://doc.owncloud.com/server/next/admin_manual/configuration/user/oidc/oidc.html#client-ids-secrets-and-redirect-uris
[owncloud-oauth2-app]: https://marketplace.owncloud.com/apps/oauth2
[owncloud-ios-mdm]: https://doc.owncloud.com/ios-app/12.2/appendices/mdm.html#oauth2-based-authentication
[occ]: https://doc.owncloud.com/server/next/admin_manual/configuration/server/occ_command.html

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

> [!WARNING]
>
> Vouch proxy requires a unique identifier but does not use the proper scope, "sub". It uses the
> fields "username" or "email" as primary identifiers instead. As a result, this can cause user or
> deployment issues, at worst security bypasses. You should avoid Vouch Proxy if possible due to
> these issues.
>
> - <https://github.com/vouch/vouch-proxy/issues/309>
> - <https://github.com/vouch/vouch-proxy/issues/310>

&nbsp;

> [!NOTE]
>
> You need to run at least version 0.37.0

Vouch Proxy supports multiple OAuth and OIDC login providers. To configure it you need to pass:

```yaml
oauth:
  auth_url: https://idm.wherekanidmruns.com/ui/oauth2
  callback_url: https://login.wherevouchproxyruns.com/auth
  client_id: <name> # Found in kanidm system oauth2 get XXXX (should be the same as XXXX)
  client_secret: <oauth2_rs_basic_secret> # Found in kanidm system oauth2 get XXXX
  code_challenge_method: S256
  provider: oidc
  scopes:
    - email # Required due to vouch proxy reliance on mail as a primary identifier
  token_url: https://idm.wherekanidmruns.com/oauth2/token
  user_info_url: https://idm.wherekanidmruns.com/oauth2/openid/<name>/userinfo
```

The `email` scope needs to be passed and thus the mail attribute needs to exist on the account:

```bash
kanidm person update <ID> --mail "YYYY@somedomain.com" --name idm_admin
```
