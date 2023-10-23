# Authentication Use Cases

There are many planned integrations for authentication for a service like this. The uses cases for
what kind of auth are below. It's important to consider that today a lot of identification is not
just who you are, but what device you are using, so device security is paramount in the design of
this system. We strongly recommend patching and full disk encryption, as well as high quality
webauthn token like yubikeys or macOS touchid.

As a result, most of the important parts of this system become the auditing and co-operation between
admins on high security events and changes, rather than limiting time of credentials. An important
part of this also is limitation of scope of the credential rather than time as well.

<https://pages.nist.gov/800-63-3/sp800-63b.html>

## Kanidm account system

The login screen is presented to the user. They are challenged for a series of credentials. When
they request an action that is of a certain privilege, they must re-provide the strongest credential
(ie Webauthn token, TOTP). Some actions may require another account to sign off on the action for it
to persist.

This applies to web or CLI usage.

Similar to sudo the privilege lasts for a short time within the session (ie 5 minutes).

## SSO to websites

The login screen is presented to the user. They are challenged for a series of credentials. They are
then able to select any supplemental permissions (if any) they wish to request for the session,
which may request further credentials. They are then redirected to the target site with an
appropriate (oauth) token describing the requested rights.

- <https://developers.google.com/identity/sign-in/web/incremental-auth>
- <https://openid.net/specs/openid-connect-core-1_0.html#UserInfo>
- <https://tools.ietf.org/html/rfc7519>

## Login to workstation (connected)

The user is prompted for a password and or token auth. These are verified by the Kanidm server, and
the login proceeds.

## Login to workstation (disconnected)

The user must have pre-configured their account after a successful authentication as above to
support local password and token authentication. They are then able to provide MFA when disconnected
from the network.

## Sudo on workstation

These are reuse of the above two scenarios.

## Access to VPN or Wifi

The user provides their password OR they provide a distinct network access password which allows
them access.

MFA could be provided here with TOTP?

## SSH to machine (legacy, disconnected)

The user pre-enrolls their SSH key to their account via the Kanidm console. They are then able to
SSH to the machine as usual with their key. SUDO rights are granted via password only once they are
connected (see sudo on workstation).

Agent forwarding is a concern in this scenario to limit scope and lateral movement. Can this be
limited correctly? IMO no, so don't allow it.

## SSH to machine

The user calls a special Kanidm SSH command. This generates a once-off SSH key, and an
authentication request is lodged to the system. Based on policy, the user may need to allow the
request via a web console, or another user may need to sign off to allow the access. Once granted
the module then allows the authentication to continue, and the ephemeral key is allowed access and
the login completes. The key may only be valid for a short time.

Agent forwarding is not a concern in this scenario due to the fact the key is only allowed to be
used for this specific host.

_W: Probably the main one is if a group/permission is granted always or ephemerally on the session.
But that's per group/permission.

I want to limit the amount of configuration policy here, because there are lots of ways that over
configuration can create too many scenarios to effective audit and test. So the permissions would
probably come down to something like "always", "request", and "request-approve", where always is you
always have that, request means you have to re-auth then the permission lasts for X time, and
request-approve would mean you have to request, reauth, then someone else signs off on the approval
to grant.

## SSH via a bastion host

This would work with the SSH to machine scenario, but in thiscase the key is granted rights to the
bastion and the target machine so that agent forwarding can work.

Is there a way to ensure that only this series of jumps is allowed?

## Additionally

- Support services must be able to assist in an account recovery situation
- Some sites may wish allow self-sign up for accounts
- Some sites may want self supporting account recovery
- Accounts should support ephemeral or group-requests

## References

Secure SSH Key Storage

- <https://github.com/sekey/sekey>
- <https://gist.github.com/lizthegrey/9c21673f33186a9cc775464afbdce820>

Secure Bastion hosting

- <https://krypt.co/docs/ssh/using-a-bastion-host.html>

## Implementation ideas for use cases

For identification

- Issue "ID tokens" as an api where you lookup name/uuid and get the `userentry` + `sshkeys` + group
  entries. This allows one-shot caching of relevant types, and groups would not store the member
  link on the client. Allows the client to "cache" any extra details into the stored record as
  required. This would be used for linux/mac to get `uid`/`gid` details and SSH keys for
  distribution.
  - Would inherit search permissions for connection.
  - Some service accounts with permission would get the ntpassword field in this for radius.
  - Hosts can use anonymous or have a service account
  - Allows cached/disconnected auth.
  - Need to be checked periodically for validity (IE account revoke)

- For authentication:
  - Cookie/Auth proto - this is for checking pw's and mfa details as required from clients both web
    cli and pam. This is probably the most important and core proto, as everything else will derive
    from this session in some way.
    - Must have a max lifetime or refresh time up to max life to allow revoking.
    - If you want to "gain" higher privs, you need to auth-up to the shadow accounts extra
      requirements
    - You would then have two ID's associated, which may have different lifetimes?

    - SSH Key Distribution via the ID tokens (this is great for offline / disconnected auth ...).
      - Clients can add password hashes to the ID tokens on successful auth.

    - Request based auth proto - a service account creates an auth request, which then must be
      acknowledged by the correct Kanidm api, and when acknowledged the authentication can proceed.

    - OAuth - This would issue a different token type as required with the right details embedded as
      requested.

    - Another idea: cli tool that says "I want to login" which generates an ephemeral key that only
      works on that host, for that identity with those specific roles you have requested.

Authorisation is a client-specific issue, we just need to provide the correct metadata for each
client to be able to construct correct authorisations.

## Auth Summary

- auth is a stepped protocol (similar to SASL)
- we offer possible authentications
- these proceed until a deny or allow is hit.

- we provide a token that is valid on all server instances (except read-onlies that have unique
  cookie keys to prevent forgery of writable master cookies)

- cookies can request tokens, tokens are signed cbor that contains the set of group uuids + names
  derferenced so that a client can make all authorisation decisions from a single datapoint

- Groups require the ability to be ephemeral/temporary or permanent.

- each token can be unique based on the type of auth (ie 2fa needed to get access to admin groups)

## Cookie/Token Auth Considerations

- Must prevent replay attacks from occurring at any point during the authentication process

- Minimise (but not eliminate) state on the server. This means that an auth process must remain on a
  single server, but the token granted should be valid on any server.

## Cookie/Token Auth Detail

The client sends an AuthRequest to the server in the Init state. Any other request results in
AuthDenied due to lack of the `x-authsession-id` header.

```rust
struct AuthClientRequest {
    name: String
    application: Option<String>
}
```

The server issues a cookie, and allocates a session id to the cookie. The session id is also stored
in the server with a timeout. The AuthResponse indicates the current possible auth types that can
proceed. This should provided challenges or nonces if required by the auth type.

```rust
enum AuthAllowed {
    Anonymous,
    Password,
    Webauthn {
        challenge: // see the webauthn implementation for this
    },
    TOTP,
}

enum AuthState {
    Response {
        next: AuthAllowedMech
    },
    AuthDenied,
    AuthSuccess,
}

struct AuthServerResponse {
    state AuthState
}
```

The client now sends the cookie and an `AuthRequest` with type Step, that contains the type of
authentication credential being provided, and any other details. This COULD contain multiple
credentials, or a single one.

```rust
enum AuthCredential {
    Anonymous,
    Password { String },
    Webauthn {
        // see the webauthn impl for all the bits this will contain ...
    },
    TOTP {
        String
    }
}

struct AuthClientStep {
    Vec<AuthDetails>
}
```

The server verifies the credential, and marks that type of credential as failed or fulfilled. On
failure of a credential, AuthDenied is immediately sent. On success of a credential the server can
issue AuthSuccess or AuthResponse with new possible challenges. For example, consider we initially
send "password". The client provides the password. The server follows by "totp" as the next type.
The client fails the totp, and is denied.

If the response is AuthSuccess, an auth token is issued. The auth token is a bearer token (that's
what reqwest supports). For more consideration, see, <https://tools.ietf.org/html/rfc6750>.

### Notes

- By tracking what auth steps we have seen in the server, we prevent replay attacks by re-starting
  the state machine part way through. THe server enforces the client must always advance.
- If the account has done "too many" auth attempts, we just don't send a cookie in the initial
  authRequest, which cause the client to always be denied.
- If the AuthRequest is started but not completed, we time it out within a set number of minutes by
  walking the set of sessions and purging incomplete ones which have passed the time stamp.
- The session id is in the cookie to eliminate leaking of the session id (secure cookies), and to
  prevent tampering of the session id if possible. It's not perfect, but it helps to prevent casual
  attkcs. The session id itself is really the thing that protects us from replays.

## Auth Questions

At a design level, we want to support ephemeral group information. There are two ways I have thought
of to achieve this.

Consider we have a "low priv" and a "high priv" group. The low priv only needs password to "assign"
membership, and the high priv requires password and totp.

### Method One

We have metadata on each groups generate `memberOf` (based on group info itself). This metadata says
what "strength and type" of authentication is required. The auth request would ask for password,
then when password is provided (and correct), it then requests TOTP OR finalise. If you take
finalise, you get authSuccess but the issued token only has the group "low".

If you take TOTP, then finalise, you get authSuccess and the group low _and_ high.

### Method Two

Groups define if they are "always issued" or "requestable". All group types define requirements to
be fulfilled for the request such as auth strength, connection type, auth location etc.

In the AuthRequest if you specific no groups, you do the 'minimum' auth required by the set of your
"always" groups.

If you do AuthRequest and you request "high", this is now extended into the set of your minimum auth
required, which causes potentially more auth steps. However the issued token now has group high in
addition to low.

extra: groups could define a "number of ID points" required, where the server lists each auth type
based on strength. So group high would request 30 points. Password is 10 points, totp is 20 points,
webauthn could be 20 for example. This way, using totp + webauth would still get you a login.

There may be other ways to define this logic, but this applies to method one as well.

### Method Three

Rather than have groups define always or requestable, have a "parent" user and that templates "high
priv" users which have extended credentials. So you may have:

```text
alice {
    password
    memberof: low
}

alice+high {
    parent: alice
    totp
    memberof: high
}
```

So to distinguish the request, you would login with a different username compared to normal, and
that would then enforce extra auth requirements on the user.

## Considerations

SSH key auth: When we SSH to a machine with SSH distributed id's how do we manage this system?
Because the keys are sent to the machine, I think that the best way is either method three (the SSH
key is an attr of the +high account). However, it would be valid for the client on the machine to
check "yep they used SSH keys" and then assert group high lists SSH as a valid single factor, which
would allow the machine to "login" the user but no token is generated for the authentication. A
benefit to Method three is that the +high and "low" have unique uid/gid so no possible data leak if
they can both SSH in!

With regard to forwarding tokens (no consideration is made to security of this system yet), method
two probably is the best, but you need token constraint to make sure you can't replay to another
host.

<https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984>

## Brain Dump Internal Details

Credentials should be a real struct on entry, that is serialised to str to dbentry. This allows repl
to still work, but then we can actually keep detailed structures for types in the DB instead. When
we send to proto entry, we could probably keep it as a real struct on protoentry, but then we could
eliminate all private types from transmission.

When we login, we need to know what groups/roles are relevant to that authentication. To achieve
this we can have each group contain a policy of auth types (the credentials above all provide an
auth type). The login then has a known auth type of "how" they logged in, so when we go to generate
the users "token" for that session, we can correlate these, and only attach groups that satisfy the
authentication type requirements.

IE the session associates the method you used to login to your token and a cookie.

If you require extra groups, then we should support a token refresh that given the prior auth +
extra factors, we can then re-issue the token to support the extra groups as presented. We may also
want some auth types to NOT allow refresh.

We may want groups to support expiry where they are not valid past some time stamp. This may
required tagging or other details.

How do we ensure integrity of the token? Do we have to? Is the clients job to trust the token given
the TLS tunnel?

## More Brain Dumping

- need a way to just pw check even if mfa is on (for sudo). Perhaps have a separate sudo password
  attr?
- ntpassword attr is separate
- a way to check application pw which attaches certain rights (is this just a generalisation of
  sudo?)
  - the provided token (bearer etc?) contains the "memberof" for the session.
  - How to determine what memberof an api provides? Could be policy object that says "api pw of name
    X is allowed Y, Z group". Could be that the user is presented with a list or subset of the
    related? Could be both?
    - Means we need a "name" and "type" for the api password, also need to be able to search on both
      of those details potentially.

- The oauth system is just a case of follow that and provide the scope/groups as required.

- That would make userPassword and webauthn only for webui and api direct access.
  - All other pw validations would use application pw case.
  - SSH would just read SSH key - should this have a similar group filter/allow mechanism like
    application pw?

- Groups take a "type"
  - credentials also have a "type"
  - The credential if used can provide groups of "type" to that session during auth token generation
  - An auth request says it as an auth of type X, to associate what creds it might check.
- Means a change to auth to take an entry as part of auth, or at least, it's group list for the
  session.

- policy to define if pw types like sudo or radius are linked.
  - Some applications may need to read a credential type.
  - attribute/value tagging required?

```text
apptype: unix

apptype: groupware

group: admins
 type: unix  <<-- indicates it's a requested group

group: emailusers
 type: groupware <<-- indicates it's a requested group

user: admin
memberof: admins <<-- Should this be in mo if they are reqgroups? I think yes, because it's only for that "session"
                      based on the cred do they get the "group list" in cred.
memberof: emailusers
cred: {
    'type': unix,
    'hash': ...
    'grants': 'admins'
}
cred: {
    'type': groupware
    'hash': ...,
    'grants': 'emailusers',
}
cred: {
    'type': blah
    'hash': ...,
    'grants': 'bar', // Can't work because not a memberof bar. Should this only grant valid MO's?
}

ntpassword: ... <<-- needs limited read, and doesn't allocate groups.
sshPublicKey: ... <<-- different due to needing anon read.
```

## Some Dirty Rust Brain Dumps

- Credentials need per-cred locking
  - This means they have to be in memory and uniquely ided.
  - How can we display to a user that a credential back-off is inplace?

- UAT need to know what Credential was used and its state.
  - The Credential associates the claims
