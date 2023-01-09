Multiple Device Enrollment Workflow
-----------------------------------

As we continue to develop kanidm, we'll add support for OTP and Webauthn. A constraint we must
consider is that many webauthn devices are tied to (bound) to the device. This could be a yubikey
nano that may not pluginto a phone, a built in touch id, a tpm, or even a softtoken in firefox.

As a result, we must have a way for an account to be able to authenticate the addition of a new
webauthn token *without* being able to provide an existing token to the new device.

We must also consider that the process should be simple and easy to follow. We have taken
inspiration from existing systems to support this.

Situation
=========

We have a user with a device E(nrolled), and a device N(ew) that they wish to be able to use.

Each device contains a unique webauthn device that is inseperable from the device.

Each device may be connected to a separate Kanidm instance - IE we can not assume that
the data in the system may be point-in-time consistent due to replication as an asynchronous
process.

The process "will" come under attack. It must not be an avenue for partial credential disclosure.

The enrollment process and credentials issued must only be for the purpose of enrollment of webauthn
devices and must not grant any other permission.

The overall security of the system must not be "lowered" to allow the enrollment to occur.

Schema
======

MFAEnrollmentToken: TOTP/HOTP seed/counter
WebauthnCredential: Storage of a webauthn pubkey
WebauthnCredentialRequest: Storage of a webauthn pubkey that is awaiting acceptance.

Preparation
===========

When the account is created, a private recovery TOTP seed is created and stored in the account
as an MFAEnrollmentToken.

This is so that all replicas in the topology have the same credential tokens available.

The "login" page has an "enroll new device" option.

A claim for self write to webauthn registration must exist.

Process
=======

Device N is accessed (which is not yet enrolled). The "enroll new device" option is selected.

The username is entered. This goes to the next step

The TOTP is requested.

On the enrolled device E, the TOTP is "generated". It is then typed into device N.

Device N then prompts for the user primary password (if exists).

The session is logged in with a single self-write claim that allows creation of a webauthn pub key
on the account. alt: the server just does the change as internal system to bypassword acp, but I think
there are some attack vectors here.

The session has a 5 minute timelimit.

Device N challenged for a webauthn registration process. The public key is written to the account's
WebauthCredentialRequest.

On Device E, the user approves the WebauthCredentialRequest, and it is moved from WebauthCredentialRequest
to WebauthnCredential. It may now be used.


Possible Issues
===============

TOTP has a time window, and if we are near that window it may not last long enough. We could consider
HOTP instead, assuming that the HOTP has not been accessed +- 10 times between the replicas.

Handling for accounts with no user primary password.

Device E may be connected to a different replica to Device N, so there may be a delay in requested
token enrollments from appearing in the request list.

Device N may have to wait for replication back for the WebauthnCredential to appear.


Possible Changes
================

Do not require the approval step, as an OTP has already been provided, which is evidence of possesion
of an account which has sufficent permissions.


