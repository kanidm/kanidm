# Domain Join - Machine Accounts

There are a number of features we have been considering that will require us to finally give in and support machine
accounts also know as domain joining.

## Feature Requirements

### Limiting Unix Password Auth

Currently unix password authentication is targeted as the method for sudo. Initial access to the machine should come
from ssh keys (and in future, ctap2).

In order to maintain compatibility with LDAP style authentication, we allow "anonymous hosts" to retrieve ssh public
keys, and then perform sudo authentication.

This has the obvious caveat that anyone can stand up a machine that trusts a Kanidm instance. This presents a double
edged sword:

- By configuring a machine to authenticate via Kanidm, there is full trust in the authentication decisions Kanidm makes.
- Users of Kanidm may be tricked into accessing a machine that is not managed by their IT or other central authority.

To prevent this, UNIX authentication should be configurable to prevent usage from unregistered machines. This will
require the machine to present machine authentication credentials simultaneously with the user's credentials.

A potential change is removing the current unix password auth mechanism as a whole. Instead the user's auth token would
contain a TPM bound credential that only the domain joined machine's TPM could access and use.

### Requesting Cryptographic Credentials

When a user logs in to a machine, it may be required that they can use that authentication to identify themself to other
systems. When a user authenticates with credentials such as ssh-keys, it's not possible to use these to request other
forwardable credentials - and ssh agent forwarding only allows forwarding of ssh credentials, not other types of
credentials that may be needed.

In this case, when a user authenticates with SSH, since they're using a trusted machine, Kanidm can request short-term
and limited credentials on the users behalf.

An example is that we could dynamically request TLS certificates or Kerberos credentials.

Normally with ssh in this manner, everything has to use kerberos. This would force users to kinit on their machine to
ssh and forward their credentials to the next machine. This causes friction since configuring kerberos on machines is an
exercise in frustration, and with BYOD it gets even worse. In addition when using ssh with an ssh key, the only viable
kinit mechanism is password or password + totp once the user has logged in. This is because pkcs11 can't be forwarded
over ssh, nor can CTAP2, limiting kinit to weaker authentication mechanisms.

## Security Considerations

- Anonymous joins should not be allowed or permitted.
- Join tokens need to be revoked (causing related machines to request re-enrollment) or expired (related machines can
  continue to function)
- Join tokens must be auditable.
- Private keys SHOULD be stored in a TPM, or at least a software HSM with a secured unlock key.
- The use of the private key must prevent replay attacks

## Overview

Since the machine would now be an entity requiring authentication, we need to have a process to establish and maintain
this trust relationship.

1. A join token is created by a user who is authorised to perform domain joins.
2. The machine is audited for a known trust state. This process may vary from site to site. A future improvement could
   be that the join token can only release on certain TPM PCR values.
3. The join token is yielded to the Kanidm UNIX daemon which submits its signing key to the Kanidm server.
4. The kanidm server verifies the submission and creates a machine account.
5. The Kanidm UNIX daemon now uses its signing key to sign a challenge that is submitted with all requests to the kanidm
   server.

Extra

6. Machines should be able to "re-join" with an alternate join token, moving their machine account join token
   relationship.
7. Machines must be able to self-enroll newer keys which may have stronger cryptographic requirements.

## Details

### Join Token Creation

Join tokens are persisted in the database allowing tracing back to the usage of the token.

Every machine that is joined by that token will related back to that token. This allows auditing of which token was used
to join which machine.

Machines may re-enroll with an alternate token.

The join token should be signed. The JWK pub key should be available at a known HTTPS uri so that the client can use it
to validate the join token and its content. This _may_ allow policy to be embedded into the join token for the client to
self-adhere to in the join process.

### Machine Auditing

The machine should be audited to be in a secure state. It's not yet clear how to proceed here, but we should consider
using TPM PCRs with secure boot to measure this and validate the machine state.

One possible way to achieve this could be with full disk encryption that is bound to secure boot and TPM PCRs.
Kanidm-unixd could validate the same PCR's to start operating. The challenge here would be updates of the expected PCR
values during a system update. Alternately, Kanidm could "assume" that if started, then the FDE must have passed and
attestation of health "is out of scope" for us.

### Public Key Submission

The private key should be generated and stored in a TPM/HSM. If possible, we should also submit attestation of this.

The submission of the public key should prevent replays, and should sign either a nonce or the current time. The current
time must be valid to within a number of seconds. The nonce must be created by the server.

The machine must submit its public key, the time value and the signature. This should accompany the join token.

If the signature is valid, and the join token is correct, then the machine is joined and has a machine account created.
The machine account is linked to the join token.

### Machine Account

The machine account is a new form of account, similar to a service account. It should identify the machine, its
hostname, and other properties. It should also contain the machine's public key id.

When the machine requests certain API's from Kanidm, it should submit signed requests that include the current time. The
kid is used to find the machine account that is submitting the request. This then validates the identity of the caller,
and then allows the action to proceed.
