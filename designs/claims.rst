Claims Design
-------------

Claims are a way of associating privileges to sessions, to scope and limit access of an identity.
This can be based on what credentials were used to authenticate, by the user requesting claims
for a session, or by time limiting claims.

These tend to fall into three major categories

Default Interactive Claims
--------------------------

When an identity authenticates they are given a set of claims associated to their interactive
login. This could include the ability to trigger a claim request or to view personal details.

Static Application Claims (or lack of)
--------------------------------------

Static application passwords (IE a device imap/smtp password) should have a claim to "email"
but not to read personal data and shouldn't be able to change passwords etc.

Ephemeral Claims
----------------

These are permissions that are limited in time - they *must* be requested and generally require
re-authentication with a subset of credentials. This can include the ability to alter ones own
account or time limiting admins ability to alter other accounts.

Detailed Design
---------------

As a result of these scenarios this leads to the following required observations.

* Claims must be associated to the credentials of the account
* Possible claims that could be assigned derive from membership to a group
* Claims must be understood by access controls of the server
* Claims must be present in user auth tokens for end applications to be able to verify
* Two types of claims exist - ephemeral and static

This leads to a pseudo design such as:

    name: claim_email
    claim_name: email
    member: account_1

    name: claim_unused
    claim_name: unused

    name: claim_interactive
    claim_name: interactive
    member: account_1

    name: claim_alter_self
    claim_name: alter_self
    claim_lifetime: 300 # seconds
    member: account_1

    name: account_1
    ...
    primary_credential: {
        type: password|webauthn|password+webauthn
        claims: [ claim_alter_self, claim_interactive ]
    }
    application_credentialn: {
        name: iphone imap password
        type: generated_password
        claims: [ claim_email ]
    }

When we authenticate with the email password, because there is no lifetime this becomes a static
claim:

    UserAuthToken {
        name: account_1
        claims: [ email ]
    }

If we authenticate with the primary credential, the static claims are initially issued:

    UserAuthToken {
        name; account_1
        claims: [ interactive ]
    }

To have the "alter_self" claim, we must perform an auth-request-claim operation which re-verifies
a credential. This is a subset of the Auth operation

    auth-request-claim ---->  verify aci of request (are you interactive? )
                       <---- return challenge
    send password/cred ---->  verify credential
                       <---- update UAT with ephemeral claim

Then the UserAuthToken would be:

    UserAuthToken {
        name; account_1
        claims: [ interactive, alter_self(expire_at_time) ]
    }

This means:

    * Consuming applications need to verify the claim list
    * They need te verify the claim's expiry times.

For kanidm, to use claims in access controls, these must become filterable elements. On
UAT to Entry as part of the event conversion we will perform

    load entry to member
    for each claim in UAT:
        if claim is not expired
            alter memory entry -> add claim

ACP's can then have filters such as:

    Eq('claim', 'alter_self')


Questions
---------

We should only be able to request claims on interactive (primary) credential sessions. How should
we mark this? I think the UAT needs to retain "what credential id" was used to authenticate, and then
emit this to the entry so that it can also be filtered on to determine primary vs application cred.

Claim and other generated attrs must be system protected, even though they have to exist in schema
for filter verification. This likely needs to be added to system_protected plugin to prevent claims
from being added to any entry type.

Once a claim is dynamically added to the entry it must move to a new state that prevents reserialisation to the DB.


Trust Considerations
--------------------

Claims should not be replicated, and are auth-silo specific. This is because
trusts as designed are about account and group sharing, rather than about detailed privilege or
resource granting in the trusting domain.

Because claims should be associated to groups, we can also apply account pw policy to groups.

This means that at the very least we have to consider replication of credential metadata though
so that the trusting domain can assign the claims somewhere (this metadata will be needed for
account cred policy and group membership later anyway). For example:

    spn: claire@domainb
    class: [trustedaccount, object]
    trustedcredential: [ name, id, claims ]

This way when the account authenticates to the trusting domain, because the credential ID that was
used is in the UAT, this allows the trusting domain to inspect what credential was used, and to
be able to assign it's domain local claims to the session. This could then have a similar work
flow when ephemeral claims are needed.

mental note: because groups will define account policy, when a trusted account is a member of a group
and it doesn't meet that groups account policy requirements, it should be listed in the uat as
a rejected group so that we can easily diagnose when an account is insufficient to receive that group
or that claim as a result. This may affect how we treat memberof on the session though when
we do UAT to entry. An argument could be made to strip the memberofs when they are in the rejected
list ...
