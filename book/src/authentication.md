# Authentication and Credentials

A primary job of a system like Kanidm is to manage credentials for persons. This can involve a range
of operations from new user onboarding, credential resets, and self service.

## Types of Credentials

### Passkeys

This is the preferred method of authentication in Kanidm. Passkeys represent "all possible cryptographic"
authenticators that support Webauthn. Examples of this include Yubikeys, TouchID, Windows Hello, TPM's
and more.

These devices are unphishable, self contained multifactor authenticators and are considered the most
secure method of authentication in Kanidm.

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=Warning!
text=Kanidm's definition of Passkeys differs to other systems. This is because we adopted the term very early before it has changed and evolved.
}}

<!-- deno-fmt-ignore-end -->

### Password + TOTP

This is a classic Time-based One Time Password combined with a password. Different to other systems
Kanidm will prompt for the TOTP *first* before the password. This is to prevent drive by bruteforce
against the password of the account and testing if the password is vulnerable.

While this authentication method is mostly secure, we do not advise it for high security environments
due to the fact it is still possible to perform realtime phishing attacks.

## Resetting Person Account Credentials

Members of the `idm_account_manage_priv` group have the rights to manage person and service accounts
security and login aspects. This includes resetting account credentials.

### Onboarding a New Person / Resetting Credentials

These processes are very similar. You can send a credential reset link to a user so that they can
directly enroll their own credentials. To generate this link or qrcode:

```bash
kanidm person credential create-reset-token demo_user --name idm_admin
# The person can use one of the following to allow the credential reset
# 
# Scan this QR Code:
# 
# █████████████████████████████████████████████
# █████████████████████████████████████████████
# ████ ▄▄▄▄▄ █▄██ ▀▀▀▄▀▀█ ▄▀▀▀▀▄▀▀▄█ ▄▄▄▄▄ ████
# ████ █   █ █▀   ▄▄▄▀█  █▀ ██ ▀ ▀▄█ █   █ ████
# ████ █▄▄▄█ █ █▄█  ▀   ▄███▄ ▀▄▀▄ █ █▄▄▄█ ████
# ████▄▄▄▄▄▄▄█ █▄▀▄█▄█ █▄▀▄▀▄█▄█ █▄█▄▄▄▄▄▄▄████
# ████ ▀█▀ ▀▄▄▄ ▄▄▄▄▄▄▄█▀ ▄█▀█▀  ▄▀ ▄   █▀▄████
# ████▄ █ ▀ ▄█▀█ ▀█   ▀█▄ ▀█▀ ▄█▄ █▀▄▀██▄▀█████
# ████ ▀▀▀█▀▄██▄▀█ ▄▀█▄▄█▀▄▀▀▀▀▀▄▀▀▄▄▄▀ ▄▄ ████
# ████ █▄▀ ▄▄ ▄▀▀ ▀ █▄█ ▀▀ █▀▄▄█▄   ▀  ▄ ▀▀████
# ████ █▀▄ █▄▄  █ █▀▀█▀█▄ ▀█▄█▄█▀▄▄ ▀▀ ▄▄ ▄████
# █████ ▀█▄▀▄▄▀▀ ██▀▀█▄█▄█▄█ █▀▄█ ▄█  ▄▄▀▀█████
# ████▄▄▀  ▄▄ ▀▀▄▀▀ ▄▄█ ▄ █▄ ▄▄ ▀▀▀▄▄ ▀▄▄██████
# ████▄▄▀ ▀▀▄▀▄  ▀▀▀▀█▀█▄▀▀ ▄▄▄ ▄ ▄█▀  ▄ ▄ ████
# ████▀▄  ▀▄▄█▀█▀▄ ▄██▄█▀ ▄█▀█ ▀▄ ███▄█ ▄█▄████
# ██████ ▀▄█▄██▀ ▀█▄▀ ▀▀▄ ▀▀█ ██▀█▄▄▀██  ▀▀████
# ████▄▄██▄▄▄▄  ▀▄██▀█ ███▀ ██▄▀▀█ ▄▄▄ ███ ████
# ████ ▄▄▄▄▄ █▄ ▄▄  ▀█▀ ▀▀ █▀▄▄▄▄█ █▄█ ▀▀ ▀████
# ████ █   █ █▄█▄▀  ██▀█▄ ▀█▄▀▄ ▀▀▄   ▄▄▄▀ ████
# ████ █▄▄▄█ ██▀█ ▀▄▀█▄█▄█▄▀▀▄▄ ▀ ▄▄▄█▀█  █████
# ████▄▄▄▄▄▄▄█▄█▄▄▄▄▄▄█▄█▄██▄█▄▄▄█▄██▄███▄▄████
# █████████████████████████████████████████████
# ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
# 
# This link: https://localhost:8443/ui/reset?token=8qDRG-AE1qC-zjjAT-0Fkd6
# Or run this command: kanidm person credential use_reset_token 8qDRG-AE1qC-zjjAT-0Fkd6
```

If the user wishes you can direct them to `https://idm.mydomain.name/ui/reset` where they can
manually enter their token value.

Each token can be used only once within a 24 hour period. Once the credentials have been set the token
is immediately invalidated.

### Resetting Credentials Directly

You can perform a password reset on the demo\_user, for example as the idm\_admin user, who is a
default member of this group. The lines below prefixed with `#` are the interactive credential
update interface. This allows the user to directly manage the credentials of another account.

```bash
kanidm person credential update demo_user --name idm_admin
# spn: demo_user@idm.example.com
# Name: Demonstration User
# Primary Credential:
# uuid: 0e19cd08-f943-489e-8ff2-69f9eacb1f31
# generated password: set
# Can Commit: true
# 
# cred update (? for help) # : pass
# New password: 
# New password: [hidden]
# Confirm password: 
# Confirm password: [hidden]
# success
# 
# cred update (? for help) # : commit
# Do you want to commit your changes? yes
# success
kanidm login --name demo_user
kanidm self whoami --name demo_user
```

## Reauthentication / Privilege Access Mode

To allow for longer lived sessions in Kanidm, by default sessions are issued in a "privilege capable" but
read-only mode. In order to access privileges for a short time, you must re-authenticate. This re-issues
your session with a small time limited read-write session internally. You can consider this to be
like `sudo` on a unix system or `UAC` on windows where you reauthenticate for short periods to access higher
levels of privilege.

When using a user command that requires these privileges you will be warned:

```
kanidm person credential update william
# Privileges have expired for william@idm.example.com - you need to re-authenticate again.
```

To reauthenticate

```
kanidm reauth -D william
```

> **NOTE** During reauthentication can only use the same credential that was used to initially authenticate
> to the session. The reauth flow will not allow any other credentials to be used!



