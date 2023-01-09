
Session Logout
--------------

Currently, Kanidm relies on "short session times" to manage and limit issues with session
disclosure, but this is obviously not optimal long term! In addition, there are systems like
OAuth 2.0 token revocation ( https://datatracker.ietf.org/doc/html/rfc7009 ) which we may want
to use to allow global logouts across linked applications.

Goals
=====

* When a user selects "logout" in kanidm the active session is canceled
* A user can view their list of active sessions and audit or revoke them
* A user can view which OAuth 2.0 applications an active session has been used with
* An OAuth 2.0 application can use the RFC7009  logout mechanism to revoke a token that is associated to a session for that application
* Revocation of a kanidm session implies revocation of all OAuth 2.0 sessions.
* Management of other session types that may exist in the future.

On Login
========

On login the session creation will be added to the users active session list. This session will be
bound to the uuid of the session that is part of the user auth token. This will be added to the users
entry along with metadata about the session such as the:

* Source IP that created the session
* Time the session was created
* Time the session *may* expire, if an expiry exists
* Any limits or details (for example, sudo mode) on the session.
* A state flag defining that the session is *active*
* Mappings from sub-sessions through other protocols, IE OAuth 2.0 and their related session IDs

On Logout
=========

Logout events have an impact with regard to replication.

On logout, if the session id is found, its state is transitioned to the expired state. No other
details are changed.

If the session id is NOT found, a session stub is created, with the expired state. Since we lack the
metadata of the "creation" of the session, this is why we use the stub form that only lists the ID and
its expiry.

On a replication attribute conflict, an expired state will always "overrule" an active state, even
if the CID of expiry precedes that of the active state. We merge the expiry into the metadata in
this case.

Token Usage / Revocation
========================

There are two possible ways to provide session validity management. Revocation, a list of tokens
that are no longer valid to use, and allow-lists which describe the tokens that *are* valid to use.

Both are described, but we have chosen to use positive validation with limited internal negative validation lists.

Positive Validation
-------------------

This is a positive validation of the validity of a session. The absence of a positive session
existence, is what implies revocation.

The session will have a "grace window", to account for replication delay. This is so that if the
session is used on another kanidm server which has not yet received the latest revocation list
changes, it "assumes" the best intent and proceeds. This window should be short, likely in minutes.

When any API endpoint is called, if the token is valid and does not need a refresh:

* If a session is found and active, respond Ok
* If a session is found and expired, respond unauthorized.
* If no session id is stored, and the gracewindow has not elapsed, assume the token is VALID and we have a replication delay.
* If no session id is stored, and the gracewindow has passed, assume the token is INVALID. This can happen if the server session
  is cleaned up after it has expired, and the token is used.

The gracewindow as a result, must be shorter or equal to the validity length of the token.

For our initial development, we will set this to 10 minutes, which is a "generous" window for replication, but
still "strict" enough for security.

The risk is setting the gracewindow too short, we may accidentally cause tokens to "appear" invalid
when the revocation / validity lists have not yet synced due to replication latency.

This allows "unlimited length" sessions (while refreshes occur) since we rely on positive validation of the session existing.

Clean Up
^^^^^^^^

Sessions can only be cleaned up once a sufficient replication window has passed, and the session is in an expired state,
since the absence of the session also implies revocation has occurred.
This way once the changelog window is passed, we assume the specific session in question can be removed.

An active session *should never* be deleted, it *must* pass through the expired state first. This is so that
if replication conflicts occur, the expiry of the session always takes precedence, where other event
sequences could cause the session to re-activate.

Negative Validation
-------------------

This is a negative validation of if a session has been revoked. A session is considered valid
unless it's unique id appears in the revocation list.

The session "validity" stored on the account details are for metadata an inspection purposes only, and to
help drive the UI elements so a user can understand which sessions can be revoked that belong to them.

When a session is invalidated, it's session id is added to a "site-wide" revocation list, along with
the maximum time of use of that session id.

When a session is check as part of a standard UAT check, or an OAuth 2.0 refresh, if the session
id is present in the revocation list, it is denied access. Abscence from the revocation list implies
the session remains valid.

This method requires no gracewindow, since the replication of the revocation list will be bound to the
performance of replication and it's distribution.

The risk is that all sessions *must* have a maximum life, so that their existence in the revocation
list is not unbounded. This version may have a greater risk of disk/memory usage due to the size of
the list that may exist in large deployments.

Clean Up
^^^^^^^^

Sessions on the account can be cleaned up at anytime, but must have their ID's inserted to the revocation
list to prevent orphan tokens remaining valid without a UI for the user to remove them.

Items in the revocation list can be removed only after the expiry of the associated session has passed
since the expiry then prevents the token usage. The primary bound on this method is the possible size of the
list, and the fact that sessions must have some reasonable expiry length to allow reasonable cleanup.

Why Not?
^^^^^^^^

These lists grow in an unbounded manner, and it still requires us to maintain and curate a list of
all sessions that have ever existed. There is a risk that during a "restore" from backup, that a session
id may be lost, meaning it could never be added to the revocation list without manual investigation
and intervention. As a result, it is safer and more thorough for us to provide a positive validation
system, which accurately describes the exact state of what is valid at a point in time.

The specific restore scenario is that a token is issued at time A. A backup is taken now at time B.
Next the user revokes the token at time C, and replication has not yet occurred. At this point the backup
from time B was restored.

In this scenario, without access to the token itself, or without scouring logs to find the session
id that was issued, this token is effectively "lost" and can be used until it's expiry, and would
be difficult to revoke.

Session Management
==================

Expired sessions are not displayed to the user. Only active sessions are shown.

Sessions can be revoked provided the user has the ability to "write" to the session attribute. This
allows access controls to be used, and other users to administer another users session when delegation
is required.

OAuth 2.0 (RFC7009) revoke
==========================

OAuth 2.0 doesn't need the access token to be sent frequently to kanidm to check for validity. The method
to "enforce" frequent check-ins to the authentication server is through the issuance of an access_token
with a "short" window, and a refresh window with a "long" expiration.

As such we should issue the refresh token with the "expiry" of the session time, and an access token
with the duration of *at least* the gracewindow, but not more than 1 hour. Many online services tend to vary
between 15 minutes to 1 hour.

We can treat out refresh token as having the same gracewindow, and apply the same logic as to the UAT.

Updates
=======

We may wish to allow updates to the session state to reflect things such as a change of client IP of the session
in response to a call to auth/valid. We may wish to use the delayed update mechanism for this. This allows
the user to see "changes" in the current state of the tokens usage.

Refresh
=======

A key security aspect of managing refresh tokens, is preventing divergent token chains. this is where
some refresh token is used to create multiple access or session tokens and paired refresh tokens.

Since Kanidm is a distributed system with eventually consistent replication we need to be able to
detect this state and prevent the usage of refresh tokens in this manner. This affects both user auth tokens
and OAuth 2.0 tokens.

A "worst case" scenario is when we involve system failure along with an attempted attack. In this scenario, we
have three kanidm servers in replication.

* Refresh Token A is stolen, but not used used.
* Token A expires. The refresh is sent to Server 1. Token B is issued.
* Before replication can occur, Server 1 goes down.
* Stolen refresh Token A is exchanged on Server 3.
* Token B is used on Server 2.
* Replication between server 2 and 3 occurs.

In this situation, the end goal we want is that the attackers stolen token is revoked, and the users
legitimate token B can continue to be used.

To achieve this we need to determine an order of the events. Let's assume a better scenario first.

* Refresh Token A is stolen, but not used used.
* Token A expires. The refresh is sent to Server 1. Token B is issued.
* Token B is used on Server 1.
* Stolen refresh Token A is exchanged on Server 1.

We store a "refresh id" in the refresh token, and a issued-by id in the access token. Additionally
we store an issued-at timestamp (from the replication CID) in both.

When we exchange the refresh token, we check that it's refresh id, is the next allowed refresh id that can proceed.
We store in the session the "latest" issued-by id + timestamp in the session,
as well as the next "refresh token" id in the session.

When an access token is used, we check not just that it is valid, but that the issued-by id is the matching
id.

When we attempt to use our access token, and the session details have NOT yet replicated, we use the
gracewindow to assume that our issuance was *valid*.

In this design we can see the following would occur.

* Refresh Token A is stolen, but not used used.
* Token A expires. The refresh is sent to Server 1. Token B is issued. (This updates the issued-by id)
* Token B is used on Server 1. (valid, issued-by id matches)
* Stolen refresh Token A is exchanged on Server 1. (invalid, not the currently defined refresh token)

In the first case.

* Refresh Token A is stolen, but not used used.
* Token A expires. The refresh is sent to Server 1. Token B is issued. (updates the issued-by id)
* Before replication can occur, Server 1 goes down.
* Stolen refresh Token A is exchanged on Server 3. Token C is issued (updates the issued-by id)
* Token B is used on Server 2. (valid, matches the current defined issued-by id)
* Token B is used on Server 3. (valid, within gracewindow even though issued-by is incorrect)
* Replication between server 2 and 3 occurs. (Conflict occurs in session. Second issued-by is revoked, meaning token C is now invalid)

> NOTE: Refresh tokens can only be used if the session *exists* on the server as they have NO GRACEWINDOW.

