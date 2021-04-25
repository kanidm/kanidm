
Credential Display UI
---------------------

We need a way to display the credentials associated to a user, that may be in a variety
of formats. We need to ensure that:

* Credential disclosure is not possible in any form.
* Multiple classes and types of credentials are supported.
* That the displayed information matches what is configured for other commands to consume.


Draft Display (CLI)
-------------------

An example of this display for the CLI:

::

    kanidm account credential list <account> [-D account]
    - account_metadata
    locked: true|false
    valid_from: <date>
    expire_at: <date>

    - <credential_id>
    type: Password|APIKey|PasswordMfa
    locked: true|false
    valid_from: <date>
    expire_at: <date>
    password: <type of hash>
    totp: enabled|disabled
    webauthn:
      - token_name
      - token_name
    recovery_codes: enabled|disabled

    - <credential_id>
    ...

API
---

This would require a new api that goes via the IDM gateway to ensure that on the server side we
perform the correct transforms over the credential types to prevent data leaks.

The ability to view credentials is bound by the standard search access control rules.

The API would return a list of credential details, which is an enum of the possible classes supported
by the server. This ensures during addition of new credetial types or changes we update these protocol
types.

This also helps to support future webui elements for credentials.
