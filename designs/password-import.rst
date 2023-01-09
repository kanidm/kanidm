Password Import
---------------

It's common that an external system may want to synchronise passwords or other
security material into a system like Kanidm. Two major examples is a once off
import of data from a different identity system, and a setup where an external
idm system feeds account, credentials and other data into the system.

Kanidm is already well placed to handle much of this due to the raw api's stateful
nature (though as with anything could always be improved further as further use
cases are developed, for example a stateful create-or-assert batch system).

One area that is lacking however is the ability to provide external password
material to an account. This is a case where kanidm never sees the plaintext
password, we are only sent a hash of the material.

Scenarioes
----------

* Once off account import - this is where we are migrating from an existing system to kanidm
* Long term password sync - this is where an external system will sync and provide password hashes into kanidm.

In the situation where the external system has access to the cleartext of the password, the
standard password set mechanisms and apis can be used instead.

Possible Account Configurations
-------------------------------

We have to consider that because kanidm will support various 2FA methods, or in some cases, only
webauthn, we must correctly handle this.

* Password only - synced as expected.
* Password + TOTP - the password is updated, TOTP remains.
* Password + Webauthn - the password is updated, webauthn remains.
* Webauthn only - the password sync is ignored.

The reason to ignore on webauthn only is that this is not an account recovery mechanism, but
a mechanism to allow password material to be supplied. If the account with webauthn only
is in need of recovery, other actions must be taken such as a password generate from the
idm admin to remove the webauthn devices.

Similar, if an account has configured 2FA, this must have been performed in kanidm on top of the
existing password sync. As a result, we do not fall-back to password only, but only change
the password material to match the sync in this case.

Security Considerations
-----------------------

Since this bypasses all password quality checks that kanidm provides, this is possible to misuse
and weaken the security position of accounts.

Additionally, being able to supply password materials to accounts may allow a compromised password
provided to be able to take over high privilege kanidm accounts.

For this reason, the ability to import passwords must be limited to:

* A service account with strong credentials
* high_privilege accounts may NOT have their passwords set in this manner

Once kanidm implements password badlist checks in the auth path, passwords that have been synced
into kanidm via this route may not function as they are found in the badlist, causing the account
to be locked - this sounds like a good thing :)

Design
------

The current design would be that passwords are provided on a create or modification statement
with a unique attribute name such as "password_import". Note this is not a credential type per schema
but a UTF-8 string. As many systems keep there passwords as utf-8 strings, this is a reasonable
choice for import.

As password_import is an attribute, it can be limited by access controls in the normal manner for
create and modify operations. A default password_import capable permission group should be supplied
for service accounts to be added to if this functionality is required.

Pre-create-transform and pre-modify both run before schema - a plugin would be at this step
that takes the content of password_import, and applies it to the account primary credential
as mentioned above. The password_import attribute would then be removed from the entry/modification.

At this step the content of password_import could be sanity checked as a format. We would need to
be capable of attempting to parse multiple formats in this step.

Risks
-----

Due to the addition of the password_import in the modify, we need to be sure in replication that
we don't commit the password_import value into the changelog when it will be removed after.


