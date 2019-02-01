
Auth Summary
------------

* auth is a stepped protocol (similar to SASL)
* we offer possible authentications
* these proceed until a deny or allow is hit.

* we provide a cookie that is valid on all server instances (except read-onlies
that have unique cookie keys to prevent forgery of writable master cookies)

* cookies can request tokens, tokens are signed cbor that contains the set
of group uuids + names derferenced so that a client can make all authorisation
decisions from a single datapoint

* each token can be unique based on the type of auth (ie 2fa needed to get access
to admin groups)

Auth Considerations
-------------------

* Must prevent replay attacks from occuring at any point during the authentication process

* Minimise (but not eliminate) state on the server. This means that an auth process must
  remain on a single server, but the token granted should be valid on any server.

Auth Detail
-----------

Clients begin with no cookie, and no session.

The client sends an AuthRequest to the server in the Init state. Any other request
results in AuthDenied due to lack of cookie.

The server issues a cookie, and allocates a session id to the cookie. The session id is
also stored in the server with a timeout. The AuthResponse indicates the current possible
auth types that can proceed.

The client now sends the cookie and an AuthRequest with type Step, that contains the type
of authentication credential being provided.

The server verifies the credential, and marks that type of credential as failed or fufilled.
On failure of a credential, AuthDenied is immediately sent. On success of a credential
the server can issue AuthSuccess or AuthResponse with new possible challenges. For example,
consider we initiall send "password". The client provides the password. The server follows
 by "totp" as the next type. The client fails the totp, and is denied.

If the response is AuthSuccess, an auth token is issued. The auth token is a bearer token
(that's what reqwest supports). For more consideration, see, https://tools.ietf.org/html/rfc6750.

Notes:

* By tracking what auth steps we have seen in the server, we prevent replay attacks by re-starting
the state machine part way through. THe server enforces the client must always advance.
* If the account has done "too many" auth attempts, we just don't send a cookie in the
initial authRequest, which cause the client to always be denied.
* If the AuthRequest is started but not completed, we time it out within a set number of minutes
by walking the set of sessions and purging incomplete ones which have passed the time stamp.

Auth Questions
--------------

At a design level, we want to support ephemeral group information. There are two ways I have
thought of to achieve this.

Consider we have a "low priv" and a "high priv" group. The low priv only needs password
to "assign" membership, and the high priv requires password and totp.


Method One
==========

We have metadata on each groups generate memberOf (based on group info itself). This metadata
says what "strength and type" of authentication is required. The auth request would ask for
password, then when password is provided (and correct), it then requests
totp OR finalise. If you take finalise, you get authSuccess but the issued token
only has the group "low". 

If you take totp, then finalise, you get authSuccess and the group low *and* high.

Method Two
==========

Groups define if they are "always issued" or "requestable". All group types define
requirements to be fufilled for the request such as auth strength, connection
type, auth location etc.

In the AuthRequest if you specific no groups, you do the 'minimum' auth required by
the set of your "always" groups. 

If you do AuthRequest and you request "high", this is now extended into the set
of your minimum auth required, which causes potentially more auth steps. However
the issued token now has group high in addition to low.

extra: groups could define a "number of ID points" required, where the
server lists each auth type based on strength. So group high would request
30 points. Password is 10 points, totp is 20 points, webauthn could be 20
for example. This way, using totp + webauth would still get you a login.

There may be other ways to define this logic, but this applies to method
one as well.


Method Three
============

Rather than have groups define always or requestable, have a "parent" user
and that templates "high priv" users which have extended credentials. So you
may have:

alice {
    password
    memberof: low
}

alice+high {
    parent: alice
    totp
    memberof: high
}

So to distinguish the request, you would login with a different username
compared to normal, and that would then enforce extra auth requirements on
the user.

Considerations
==============

ssh key auth: When we ssh to a machine with ssh distributed id's how do
we manage this system? Because the keys are sent to the machine, I think
that the best way is either method three (the ssh key is an attr of the
+high account. However, it would be valid for the client on the machine
to check "yep they used ssh keys" and then assert group high lists ssh
as a valid single factor, which would allow the machine to "login" the
user but no token is generated for the authentication. A benefit to Method
three is that the +high and "low" have unique uid/gid so no possible data
leak if they can both ssh in!

With regard to forwarding tokens (no consideration is made to security of this
system yet), method two probably is the best, but you need token constraint
to make sure you can't replay to another host.


