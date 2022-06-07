
Session Logout
--------------

Currently, Kanidm relies on "short session times" to manage and limit issues with session
disclosure, but this is obviously not optimal long term! In addition, there are systems like
OAuth 2.0 token revocation ( https://datatracker.ietf.org/doc/html/rfc7009 ) which we may want
to use to allow global logouts across linked applications.

Goals
=====

* When a user selects "logout" the active session is canceled
* A user can view their list of active sessions and audit or revoke them
* A user can view what oauth2 applications an active session has interacted with
* A oauth2 application can use rfc7009 logout to revoke a token that is associated to a session
* Revokation of a session, implies revokation of all oauth2 sessions.
* Management of other session types that may exist in the future.

On Login
========

To achieve this, on login we need a way to record the creation of the session. This session will be
bound to the uuid of the session that is part of the user auth token. This will be added to the users
entry along with metadata about the session such as the:

* Source IP that created the session
* Time the session was created
* Time the session *may* expire, if an expiry exists
* Any limits or details (for example, sudo mode) on the session.
* A state flag defining that the session is *active*
* Mappings from sub-sessions through other protocols, IE oauth2 and their related session id's

The session will need to have a refresh-time, similar to an oauth2 refresh token, or kerberos
refresh window. This still allows each token to have a maximum usage time window, without
needing a limit to the maximum duration of the session.

On Logout
=========

Logout events have an impact with regard to replication.

On logout, if the session id is found, it's state is transitioned to the expired state. No other
details are changed.

If the session id is NOT found, a session stub is created, with the expired state. Since we lack the
metadata of the "creation" of the session, this is why we use the stub form that only lists the id and
it's expiry.

On a replication attribute conflict, an expired state will always "overrule" an active state, even
if the CID of expiry preceeds that of the active state. We merge the expiry into the metadata in
this case.

Token Usage
===========

This will require that during calls to /v1/auth/valid that the token can be re-issued with an
updated refresh time for the client. Clients will need to be modified to accomodate this.

When any api endpoint is called, if the token is valid and does not need a refresh:

* If no session id is stored, assume the token is VALID and we have a replication delay.
* If a session is found and active, respond Ok
* If a session is found and expired, respond unauthorized.

When auth/valid is called, if the token requires a refresh:

* If no session id is found, assume it is revoked and indicate unauthorised. (This can happen if the session is cleaned up post expiry, and the refresh token is used)
* If a session is found and active, respond Ok
* If a session is found and expired, respond unauthorized.

There are likely to be some issues here around refreshes and re-issuing, so this needs a bit of thought

Session Management
==================

Expired sessions are not displayed to the user. Only active sessions are shown.

Sessions can be revoked provided the user has the ability to "write" to the session attribute. This
allows access controls to be used, and other users to administer another users session when delegation
is required.

Oauth2 rfc7009 revoke
=====================

Oauth2 will need refresh tokens issued along with access tokens. The same rules apply as above for
user auth tokens. When a refresh is required, the oauth2 session id looked up to find the corresponding
session and it's validity.

Clean Up
========

Sessions can only be cleaned up once the refresh window has passed. We also need to consider the
replication changelog window.

As a result, the refresh window should be a small subset of the maximum changelog window, such
that cleanups always occur correctly and allow the refresh windows to pass. 25% of the window is a reasonable amount, up to 16 hours maximum.

Updates
=======

We may wish to allow updates to the session state to reflect things such as a change of IP of the session
in response to a call to auth/valid. We may wish to use the delayed update mechanism for this.


