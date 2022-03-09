
Credential Update and Onboarding Workflow
-----------------------------------------

Letting users update their own credentials, but also allowing new users to create their own credentials
needs a new workflow. Since these are nearly identical, these processes can be combined.

Major considerations are:

* Ability to start the credential creation (onboarding) work flow from a secured link.
* Delegation of this permission from accounts to provide a reset path to users when needed.
* Ensure that any credential updates are consistent and atomic.
* Improved client side feedback around credential policy and rules.

Initiation of the Credential Update Process
===========================================

The start of this process is that a user requests a credential update to begin for
themself, or on behalf of another user.

Self Update Workflow
^^^^^^^^^^^^^^^^^^^^

The user signals intent to update their credentials.

An ACP check is made to check that the user has self-write to the relevant credential fields. If they
do not, the credential update session is rejected.

If they do have the access, a new credential update session is created, and the user is given a time
limited token allowing them to interact with the credential update session.

If the credental update session is abandoned it can not be re-accessed until it is expired.

Onboarding/Reset Account Workflow
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The user signals intent that another users credentials should be updated.

An ACP check is made to assert that the user has rights over the target users credential fields.
If they do not, the update session is rejected. Note that the target user does *NOT* need self
write permissions in this situation, which allows for a constrained permission on the target
users (IE anonymous has no self write).

If the access exists, a intent token is created into a link which can be provided to the user.

Exchange of this intent token, creates the time limited credential update session token.

This allows the intent token to have a seperate time window, to the credential update session token.

If the intent token creates a credential update session, and the credential update session is *not*
commited, it can be re-started by the intent token.

If the credential update session has been committed, then the intent token can NOT create new
credential update sessions (it is once-use).

Consistency
^^^^^^^^^^^

Only one credential update process may exist at a time for a user. Attempts to create a second
credential update session while an existing session exists is rejected until the previous session
is committed or timed out.

The credential update session can be rejected by the user, canceling it's progress.

A credential update session IS tied to a single server, similar to authentication.

Credential Update Process
=========================

The client on initiation of the credential update session is sent the policy related to the current
update session including:

* The classes of valid credentials that *may* be created
* The current set of credentials that exist along with their metadata (private elements are NOT disclosed).

The client then can build a set of changes to the set of credentials, expressing:

* Modification of an existing credential.
* Creation of a new credential.
* Deletion of a credential.

These changes are stored in the credential update session on the server. The reason for server side
assistance is that some classes of credentials require the server to be involved for the updates to function
and for consistent policy enforcement.

Passwords may need to be sent to the server for checking against the badlist - since the badlist can
be very large, it is infeasible to send this to the client, so server assistance is required.

Webauthn MUST use strong random challenges, and so the server MUST generate these to prevent
client side tampering. The server also MUST be involved in the attestation process.

TOTP we must be able to detect SHA1 only authenticators.

As a result, the built set of changes *is* persisted on the server in the credential update session
as the user interacts with and builds the set of changes. This allows the server to enforce that the update
session *must* represent a valid and complete set of compliant credentials before commit.

The user may cancel the session at anytime, discarding any set of changes they had inflight. This allows
another session to now begin.

If the user chooses to commit the changes, the server will assemble the changes into a modification 
and apply it. The write is applied with server internal permissions - since we checked the permissions
during the create of the update session we can trust that the origin of this update has been validated.
Additionally since this is not an arbitrary write interface, this constrains potential risk.

The update session MUST have an idle timeout, where a lack of interaction for an extended period causes
the session to invalidated. Interaction should extend the current time of the session up to a maximum window to
allow users to update their credentials without rush.

A modification to a credential MUST change the UUID of the credential. This allows replication conflict ordering
to occur and create a linear and consistent timeline.

A modification to a credential *should* offer a checkbox allowing users to invalidate sessions that were created
with that credential if they wish.

A *deleted* credential *must* invalidate sessions that were created using that credential.

Addition of Device Credentials
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

During a credential update session, a device credential may wish to be added.

This should create a stub credential with a uuid. The client can then poll for updates to this
stub to determine when the device credential has been registered and it can display in the main user agent.

A link is created that contains an encrypted device enrollment token. This contains the stub uuid
as well as the credential update session details. The device can partake in the enrollment process.

The device enrollment token contains the relevant information related to the policy of the credential
so that the server that receives the token can enforce the credential adheres to this policy.

If the client successfully enrolls, a new entry for the enrollment is created in the database. This
allows replication of the new credential to occur.

The main session of the credential update can then check for the existance of this stub uuid in the
db and wait for it to replicate in. This can be checked by the "polling" action.

When it has been replicated in, and polling has found the credential, the credentials are added to the session. The credential
can then have associated metadata altered (IE ident-only).

During the commit, the stub credential object is DELETED.

To prevent issues with DB size/growth, a stub credential reaper task MUST exist (similar to recycle/tombstone reaping).


Future Changes to ACP/Credentials
=================================

Sudo Mode / Ident Only credentials

These need flags in credentials, but we can add these later defaulting currently to the same which
is that all added credentials are sudo capable.


