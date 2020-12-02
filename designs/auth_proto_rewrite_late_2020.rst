Authentication Proto Rewrite
----------------------------

The initial design and implementation of authentication of Kanidm is already showing a number of
limitations and issues since the implementation of Webauthn has been nearly completed. Part of this
is due to the expansion of ideas around account policy, partly due to defects in Webauthn, and part
due to information based on real usage and deployments.

Current (initial to late 2020)
==============================

The current design uses a stepped challenge-response system, where after the initial request
to authenticate is made, the server responds with what credentials can continue. Subsequent,
the server can check the credentials and then requests the subsequent steps from the client.
This can continue until the client abandons the session, the auth session expires, the server
denies the request or the server allows the authentication to be considered valid.

A first issue here is that leads to a complex set of state management within `idm/authsession.rs`.
It requires more extensive testing and it's hard to follow the code that exists currently to achieve
correct MFA situations.

Clients that have already been implemented don't used the stepped model. As the server is sending
*all* required steps the client responds with all needed credentials to fufil the request. This means
that a large part of the model is not used effectively, and this shows in the client which even today
doesn't actually check what's requested due to the complexity of callbacks that would require
to implement.

The stepped model is ambiguous about what credential combinations would be valid together in the
situation the account has multiple credentials available to it. This leads to challenges in creating
a user interface that is clear and usable.

It's difficult to store the credentials in a way that makes sense because the assumption is that a
combination of the credentials could be combined, so these are currently un-typed and have to be
re-assembled at runtime from the DB types. Due to this lack of typing that also makes transforms
between credential states (ie from password to password + totp) more challenging to assert the
validity of the change, as well as asserting the account policy over this.

Webauthn complicates presentation of the next available steps due to flaws in the webauthn spec about
userverification and how that is requested. This can lead to ambiguity if multiple challenges are sent
to which credential could be used and how they are able to respond. If the server sends multiple
webauthn requests it can be difficult to program a ui that can handle this situation.

As a result of these, I believe it may be time to rethink how authentication is managed given the
information we now have.

New Design (late 2020 - future)
===============================

A clearer configuration of credentials and how they function for the account is needed. This means
changing how the current credential memory representation works. The database format does *not* need
to change, but *may* be extended.

Currently Credentials can have *any* combination of factors.

This should be changed to reperesent the valid set of factors.

* Password (only)
* GeneratedPassword
* Password && (TOTP || Webauthn no verification)
* Password && Webauthn no verification
* Webauthn Verified
* Password && Webauthn Verified

Some credentials *should* support upgrade to other types. This would be
Password to Password with TOTP/Webauthn.

After an auth init request, the server will respond with the list of possible
authentication factors (as above). The client will indicate a single factor
set it wishes to proceed with.

The server will then issue one challenge at a time, and the client will issue
one step at a time in response. This continues until authentication is complete.

This will simplify the state machines in authsession, as well as allowing better
UI decisions in clients for how we want to interact with possible credentials
on the client system.

Credentials In Memory
---------------------

To support this the representation of credentials in memory must change. The current struct (2020-12)
is:

    pub struct Credential {
        pub(crate) password: Option<Password>,
        pub(crate) webauthn: Option<Map<String, WebauthnCredential>>,
        pub(crate) totp: Option<TOTP>,
        pub(crate) claims: Vec<String>,
        pub(crate) uuid: Uuid,
    }

There are numerous issues with this design. It does not express clearly the combination
of credentials that are valid in the credential, nor their capabilities and usage. A situation
such as `Password && (TOTP || Webauthn no verification)` OR `Password && Webauthn no verification`
are now ambiguous with this representation. It also does not clearly allow us to see where is the
correct entry/starting point for the authentication session.

An improved design will have Credential become an enum representing the valid authentication methods

    pub enum Credential {
        Anonymous,
        Password(),
        GeneratedPassword(),
        PasswordMFA(),
        PasswordWebauthn(),
        Webauthn(),
        WebauthnVerified(),
        PasswordWebauthnVerified(),
    }

This allows a clearer set of logic flows in the credential and it's handling, as well as defined
transforms between credential states and type level guarantees of the consistency of the credential.

Database Credentials
--------------------

Database Credentials are currently stored as:

    #[derive(Serialize, Deserialize, Debug)]
    pub struct DbCredV1 {
        pub password: Option<DbPasswordV1>,
        pub webauthn: Option<Vec<DbWebauthnV1>>,
        pub totp: Option<DbTotpV1>,
        pub claims: Vec<String>,
        pub uuid: Uuid,
    }

This will be extended with an enum to represent the correct type/policy to deserialise into:

    pub struct DbCredV1 {
        pub type_: DbCredTypeV1,
    }

An in place upgrade will be required to add this type to all existing credentials in the
database.

Protocol
--------

The current design of the step/response is as follows.

    pub enum AuthStep {
        Init(String),
        Creds(Vec<AuthCredential>),
    }

    pub enum AuthState {
        Success(String),
        Denied(String),
        Continue(Vec<AuthAllowed>),
    }

This will be extended to include the selection criteria to choose which method to use and be presented
with. Additionally, only one AuthCredential can be presented by the server at a time, and the server
may respond with many choices for the next step. This allows the server to propose TOTP *OR* Webauthn
but the client must choose which (It can not supply both, creating an AND situation or ambiguity around
the correct way to handle these).

    pub enum AuthMech {
        Anonymous,
        Password,
        // This covers PasswordWebauthn as well.
        PasswordMFA,
        Webauthn,
        WebauthnVerified,
        PasswordWebauthnVerified,
    }

    pub enum AuthStep {
        Init(String), // server responds with AuthState::Choose|Denied
        Begin(AuthMech), // server responds with AuthState::Continue|Success|Denied
        Cred(AuthCredential), // server response with AuthState::Continue|Success|Denied
    }

    pub enum AuthState {
        Choose(Vec<AuthMech>),
        Continue(Vec<AuthAllowed>),
        Success(String),
        Denied(String),
    }

A key reason to have this "Choose" step is related to an issue in the design and construction of
Webauthn Challenges. For more details see: https://fy.blackhats.net.au/blog/html/2020/11/21/webauthn_userverificationpolicy_curiosities.html

AuthSession
-----------

Once these other changes are made, AuthSession will need to be simplified but it's core state machines
will remain mostly unchanged. This set of changes will likely result in the AuthSession being much
clearer due to the enforcement of credential presentation order instead of the current design that
may allow "all in one" submissions.

Other Benefits
==============

* During an MFA authentication, the Password if incorrect can be re-prompted for a number of times subsequent to the TOTP/Webauthn having been found valid, improving user experience.
* Allows Webauthn Verified credentials to be used with clearer expression of the claims of the device associated to the credential.
* Policy will be simpler to enforce on credentials due to them more clearly stating their design and layouts.

