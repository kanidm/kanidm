# How Does OAuth2 Work?

OAuth2 uses a number of terms in ways that can make it unclear and difficult to understand.

A user wishes to access a service (resource, resource server) through an OAuth2 client. The client does not have an
active session for the userm so it redirects to the authorisation server (Kanidm) to determine if the user has the
appropriate permissions (scopes) for the requested resources, and should be allowed to proceed.

The authorisation server checks the current session of the user and may present a login flow if required. Based on the
identity of the user and the requested scopes, the authorisation server makes a decision if it allows the authorisation
to proceed. The user is then prompted to consent to the authorisation from the authorisation server to the client as
some identity information may be revealed by granting this consent.

If successful and consent is given, the user is redirected back to the client with an authorisation code. The client
then contacts the authorisation server directly with this code and exchanges it for a valid OAuth token.

The client may then optionally contact the token introspection endpoint of the authorisation server about the provided
OAuth token, which yields extra metadata about the identity that holds the token from the authorisation. This metadata
may include identity information, but also may include extended metadata, sometimes referred to as "claims". Claims are
information bound to a token based on properties of the session that may allow the client to make extended authorisation
decisions without the need to contact the authorisation server to arbitrate.

In many cases the client and the resource server are the same entity. When the client and resource server are _separate_
services, the client can then forward the access token to the resource server for authorisation of the user's request.

It's important to note that OAuth2 at its core is an authorisation system which has layered identity-providing elements
on top.

### Why Does Sharing a Client Weaken OAuth2?

By sharing a client ID between multiple applications this implies that all of these applications are a singular client
in Kanidm's view. This means tokens issued to one application can be reused on any other application.

This limits your ability to enforce scopes, presents a large compromise blast radius if a token is stolen, and also
increases the damage radius if the client credentials are stolen.

Generally this also provides a bad user experience since the Kanidm application portal only lists a single landing URL
of the client, so subsequent applications that "piggy back" can not be redirected to from the application portal meaning
that users will not easily be able to access the application.
