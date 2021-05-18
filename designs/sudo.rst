Sudo Mode
---------

To ensure that certain actions are only performed after re-authentication, we should introduce
a sudo mode to kanidm. This relies on some changes from Oauth.rst (namely interactive session
identification).

Only interactive sessions (IE not api passwords or radius) must be elligble for sudo mode.

Sudo mode when requested will perform a partial-reauthentication of the account using a single
factor (if mfa). This is determined based on the credential uuid of the associated session.

When entered, a short sudo expiry timer is attached to the UAT, which is re-issued after the
re-authentication.

During UAT to entry processing for api calls, the sudo timer will be checked. If current
time is less than the expiry, then the phantom attribute "sudo" which is boolean, will be set
to the entry. If it is not present, or invalid, it will be set to "false".

This will allow filtering on sudo=true, meaning that certain default access controls can be
altered to enforce that they require sudo mode.

Some accounts by default represent a high level of privilege. These should have implicit sudo
granted when they are autheticated. This will be based on a group membership idm_hp_implicit_sudo
and should only apply to admin/idm_admin by default. This will pin the sudo expiry to the expiry
time of the session (rather than a shorter time).

Some accounts should never be able to enter sudo mode, and this will be based on the lack of
appropriate credentials. IE anonymous can never enter sudo mode, and will always fail. This
will allow the removal of a number of hardcoded anonymous exceptions in the IDM server, allowing
us to use the acp's to enforce rules instead.

