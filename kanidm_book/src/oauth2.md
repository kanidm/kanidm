# Oauth2

Oauth is a web authorisation protocol that allows "single sign on". It's key to note
oauth is authorisation, not authentication, as the protocol in it's default forms
do not provide identity or authentication information, only information that
an entity is authorised for the requested resources.

Oauth can tie into extensions allowing an identity provider to reveal information
about authorised sessions. This extends oauth from an authorisation only system
to a system capable of identity and authorisation. Two primary methods of this
exist today: rfc7662 token introspection, and openid connect.

## How Does Oauth2 Work?

A user wishes to access a service (resource, resource server). The resource
server does not have an active session for the client, so it redirects to the
authorisation server (Kanidm) to determine if the client should be allowed to proceed, and
has the appropriate permissions (scopes) for the requested resources.

The authorisation server checks the current session of the user and may present
a login flow if required. Given the identity of the user known to the authorisation
sever, and the requested scopes, the authorisation server makes a decision if it
allows the authorisation to proceed. The user is then prompted to consent to the
authorisation from the authorisation server to the resource server as some identity
information may be revealed by granting this consent.

If successful and consent given, the user is redirected back to the resource server with an authorisation
code. The resource server then contacts the authorisation server directly with this
code and exchanges it for a valid token that may be provided to the users browser.

The resource server may then optionally contact the token introspection endpoint of the authorisation server about the
provided oauth token, which yields extra metadata about the identity that holds the
token from the authorisation. This metadata may include identity information,
but also may include extended metadata, sometimes refered to as "claims". Claims are
information bound to a token based on properties of the session that may allow
the resource server to make extended authorisation decisions without the need
to contact the authorisation server to arbitrate.

It's important to note that oauth2 at it's core is an authorisation system which has layered
identity providing elements on top.

### Resource Server

This is the server that a user wants to access. Common examples could be nextcloud, a wiki
or something else. This is the system that "needs protecting" and wants to delegate authorisation
decisions to Kanidm.

It's important for you to know *how* your resource server supports oauth2. For example, does it
support rfc7662 token introspection or does it rely on openid connect for identity information?
Does the resource server support PKCE S256 or not?

In general Kanidm requires that your resource server supports:

* HTTP basic authentication to the authorisation server
* PKCE S256 code verification to prevent certain token attack classes

Kanidm will expose it's oauth2 apis at the urls:

* auth url: https://idm.example.com/ui/oauth2
* token url: https://idm.example.com/oauth2/token
* token inspect url: https://idm.example.com/oauth2/inspect

### Scope Relationships

For an authorisation to proceed, the resource server will request a list of scopes, which are
unique to that resource server. For example, when a user wishes to login to the admin panel
of the resource server, it may request the "admin" scope from kanidm for authorisation. But when
a user wants to login, it may only request "acces" as a scope from kanidm.

As each resource server may have it's own scopes and understanding of these, Kanidm isolates
scopes to each resource server connected to Kanidm. Kanidm has two methods of granting scopes to accounts (users).

The first are implicit scopes. These are scopes granted to all accounts that Kanidm holds.

The second is scope mappings. These provide a set of scopes if a user is a member of a specific
group within Kanidm. This allows you to create a relationship between the scopes of a resource
server, and the groups/roles in Kanidm which can be specific to that resource server.

For an authorisation to proceed, all scopes requested must be available in the final scope set
that is granted to the account. This final scope set can be built from implicit and mapped
scopes.

## Configuration

### Create the Kanidm Configuration

After you have understood your resource server requirements you first need to configure Kanidm.
By default members of "system\_admins" or "idm\_hp\_oauth2\_manage\_priv" are able to create or
manage oauth2 resource server integrations.

You can create a new resource server with:

    kanidm system oauth2 create <name> <displayname> <origin>
    kanidm system oauth2 create nextcloud "Nextcloud Production" https://nextcloud.example.com

If you wish to create implicit scopes you can set these with:

    kanidm system oauth2 set_implicit_scopes <name> [scopes]...
    kanidm system oauth2 set_implicit_scopes nextcloud login read_user

You can create a scope map with:

    kanidm system oauth2 create_scope_map <name> <kanidm_group_name> [scopes]...
    kanidm system oauth2 create_scope_map nextcloud nextcloud_admins admin

Once created you can view the details of the resource server.

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

### Configure the Resource Server

On your resource server, you should configure the client id as the "oauth2\_rs\_name" from
kanidm, and the password to be the value shown in "oauth2\_rs\_basic\_secret". Ensure that
the code challenge/verification method is set to S256.

You should now be able to test authorisation.

## Resetting Resource Server Security Material

In the case of disclosure of the basic secret, or some other security event where you may wish
to invalidate a resource servers active sessions/tokens, you can reset the secret material of
the server with:

    kanidm system oauth2 reset_secrets

Each resource server has unique signing keys and access secrets, so this is limited to each
resource server.

