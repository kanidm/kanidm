Oauth + Scopes + Claims
-----------------------

Oauth is a web authorisation protocol that allows "single sign on". It's key to note
oauth is authorisation, not authentication, as the protocol in it's default forms
do not provide identity or authentication information, only information that
an entity is authorised for the requested resources.

Oauth can tie into extensions allowing an identity provider to reveal information
about authorised sessions. This extends oauth from an authorisation only system
to a system capable of identity and authorisation. Two primary methods of this
exist today: rfc7662 token introspection, and openid connect.

High Level Process
------------------

A client (user) wishes to access a service (resource, resource server). The resource
server does not have an active session for the client, so it redirects to the
authorisation server to determine if the client should be allowed to proceed, and
has the appropriate permissions (scopes).

The authorisation server checks the current session of the client and may present
a login flow if required. Given the identity of the client known to the authorisation
sever, and the requested scopes, the authorisation server makes a decision if it
allows the authorisation to proceed. The client is also prompted to consent to the
authorisation.

If successful the client is redirected back to the resource server with an authorisation
code. The resource server the contacts the authorisation server directly with this
code and exchanges it for a valid token that may be provided to the client.

The resource server may optionally contact the token introspection endpoint about the
provided oauth token, which yields extra metadata about the identity that holds the
token and completed the authorisation. This metadata may include identity information,
but also may include extended metadata, sometimes refered to as "claims". Claims are
information bound to a token based on properties of the session that may allow
the resource server to make extended authorisation decisions without the need
to contact the authorisation server to arbitrate.

In this model, Kanidm will function as the authorisation server.

Kanidm UAT Claims
-----------------

To ensure that we can filter and make certain autorisation decisions, the Kanidm UAT
needs to be extended with extra claims similar to the token claims. Since we have the
ability to strongly type these, we can add these to the UAT. These should include.

* The UUID of the authenticating credential
* The expiry time of this session
* the classification of authentication used (MFA, SFA, Cryptographic)
* The expiry time of any elevated permissions
* If the session is "interactive" IE from a true human rather than an API pw.
* If the user is anonymous (?)

The UAT should be signed with ECDSA so that client applications may inspect the content
IE the session expiry time. This may also allow offline validation.

The ECDSA public key for this should be stored in the Kanidm "domain" configuration. The
private key should also be stored in this configuration, but thought will be needed about how
to handle this with replication securely IE readonly servers.

HTTP Endpoints
--------------

We should expose the following endpoints:

* /oauth/authorise
* /oauth/token
* /oauth/token/introspect

All api responses must have:

::

     Cache-Control: no-store
     Pragma: no-cache


Resource Servers
----------------

For a resource server to work with the authorisation server, it must be a registered
application within the authorisation server.

Each registered resource server will have an associated secret for authentication. The
most simple for of this is a "basic" authorisation header.

This resource server entry will nominially list what scopes map to which kanidm roles,
which scopes are "always" available to all authenticated users. Additionally, it may
be that we have an extra set of "filter rules" to allow authorisation decisions to be
made based on other factors like group membership.

::

    class: oauth2_resource_server
    class: oauth2_resource_server_basic
    oauth2_rs_name: String,
    oauth2_rs_basic_secret: String,
    # To validate the redirect root
    oauth2_rs_origin: String/URI
    # Scopes that apply to all users
    oauth2_rs_scope_implicit: String
    # Scopes that map to groups which will be enforced.
    oauth2_rs_scope_map: (String, reference)
    # Filter of accounts that may authorise through this.
    oauth2_rs_account_filter: Filter
    # A per-resource server fernet key for token/codes.
    # Allows reset per/application in case of suspect compromise.
    oauth2_rs_token_key: String

The returned authorisation code should be fernet encrypted and contains the unsigned UAT content of the authorised
user.

The provided oauth token for this method will be encrypted with the fernet key of the related
resource server. It will contain the unsigned uat of the account in authorised, allowing token
introspection/reflection without needing to access the database.

Token Introspection
-------------------

Claims will be mapped to a kanidm namespace. Otherwise the rfc will be followed.

Security
--------

Only PKCE Oauth 2.0 clients are accepted today. Alternately stronger exchange types may be considered
in the future.

The default filter of accounts will exclude anonymous and tombstones/recycled.

Should the default filter only allow interactive accounts to participate in this work flow?

Test Cases / Use Cases
----------------------

roles such as idm_admin/admin should also require claim=sudo to use.

To change your own details (self write) sudo should be required.

read_self, mail etc should always be granted.

Anonymous should not have access to any claims.

sudo time expiry

The ability to use oauth should require

Links
-----

Oauth2: https://tools.ietf.org/html/rfc6749
pkce: https://tools.ietf.org/html/rfc7636
token introspection: https://tools.ietf.org/html/rfc7662
bearer: https://tools.ietf.org/html/rfc6750
device authorisation grant: https://datatracker.ietf.org/doc/html/rfc8628
claims ad krb: https://syfuhs.net/2017/07/29/active-directory-claims-and-kerberos-net/ 
openid connect: https://openid.net/developers/specs/



