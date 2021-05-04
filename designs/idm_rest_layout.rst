IDM API Design and Layout
-------------------------

To think about this, we need to look at what the eventual structure of the CLI will look like as
it roughly maps to the same operations.

The cli layout will be (roughly, not actual final product):

::

    - raw
    | - search
    | - create
    | - modify
    | - delete
    - recycle_bin
    | - list
    | - display (view, get)
    | - search
    | - revive (is restore better)
    - self
    | - display
    | - set_credential (--appid/primary, --password, --totp, --webauthn, or combinations?)
    | - reset_radius_password
    | - add_credential_claim
    | - remove_credential_claim
    | - set_name
    | - set_displayname
    | - set_legalname
    | - add_sshpublickey
    | - remove_sshpublickey
    | - modify (with --arg, could we get this from schema)
    | - get_radius_android
    | - get_radius_ios_macos
    | - get_radius_config
    - account
    | - list
    | - display
    | - create
    | - delete
    | - modify
    | - reset_credential
    | - add_credential_claim
    | - remove_credential_claim
    | - set_name
    | - set_displayname
    | - set_legalname
    | - enroll_sshpublickey
    | - remove_sshpublickey
    | - lock
    | - unlock
    | - expire_at
    - group
    | - list
    | - display
    | - create
    | - delete
    | - modify
    | - add_members
    | - remove_members
    - claims
    | - list
    | - display
    | - create
    | - delete
    | - modify
    | - set_credential_policy
    - access_profiles
    | - list
    | - display
    | - create
    | - delete
    | - modify
    | - enable
    | - disable
    - schema
    | - class
    |   - list
    |   - get
    |   - create
    |   - add_may_attribute
    |   - add_must_attribute
    | - attribute
    |   - list
    |   - get
    |   - create
    |   - query_class (--may, --must)
    - radius
    | - TBD

To support this, I think we need to break the api resources down in a similar pattern. We'd need
to think about how this looks with rest ...

raw
===

This is the server's internal CRUD (well, CSMD) protocol exposed at a low level
for batch operations if required. We could simply have /raw take a list of
the CUD/CMD ops for a real batching system ...

::

    /v1/raw/search
        POST -> search request
    /v1/raw/create
        POST -> create request
    /v1/raw/modify
        POST -> modify request
    /v1/raw/delete
        POST -> modify request
    /v1/auth
        POST -> Auth requests

account
=======

::

    /v1/account/
        GET -> list all account ids
        POST -> create new account
    /v1/account/{id}
        GET -> display account
        PUT -> overwrite account attrs
        PATCH -> update via diff
        DELETE -> delete this account
    /v1/account/{id}/_attr/{attr}
        GET -> display this attr
        PUT -> overwrite this attr value list
        POST -> append this list to attr
        DELETE -> purge this attr
    /v1/account/{id}/_lock
        POST -> lock this account until time (or null for permanent)
        DELETE -> unlock this account
    /v1/account/{id}/_credential
        GET -> list the credentials
        DELETE ->
    /v1/account/{id}/_credential/{id}/_lock
        POST -> lock this credential until time (or null for permament)
        DELETE -> unlock this account
    /v1/account/{id}/_radius
        GET -> get the accounts radius credentials
        (note: more methods to come to update/reset this credential
    /v1/account/{id}/_radius/_token
        GET -> let's the radius server get all required details for radius to work


self
====

Modify and perform actions on self - generally this is an extension of capability
from account and person, but combined to one.

::

    /v1/self
        GET -> view self (aka whoami)
        PUT -> overwrite self content
        PATCH -> update self via diff
    /v1/self/_attr/{attr}
        GET -> view self attribute.
        PUT -> overwrite attr
        POST -> append list of attr
        DELETE -> purge attr
    /v1/self/_credential
        (note: more to come re setting/updating credentials, see account)
    /v1/self/_radius
        GET -> list radius cred
        (note: more to come re setting/updating this credential)
    /v1/self/_radius/_config
        POST -> create new config link w_ secret key?
    /v1/self/_radius/_config/{secret_key}
        GET -> get radius config json (no auth needed, secret_key is OTP)
    /v1/self/_radius/_config/{secret_key}/apple
        GET -> get radius config profile for apple (secret_key is OTP)
    /v1/self/_radius/_config/{secret_key}/android
        GET -> get radius config profile for android (secret_key is OTP)

group
=====

::

    /v1/group
        GET -> list all group ids
        POST -> create new group
    /v1/group/{id}
        GET -> get this group id
        PUT -> overwrite group content
        PATCH -> update via diff
        DELETE -> whole entry
    /v1/group/{id}/_attr/{attr}
        GET -> get this groups attr
        PUT -> overwrite this group attr value list
        POST -> append this list to group attr
        DELETE -> purge this attr (if body empty) or the elements listed in the body

schema
======

Schema defines how we structure and store attributes, so we need a way to query
this and see what it contains.

::

    /v1/schema
        GET -> list all class and attr types

::

    /v1/schema/classtype
        GET -> list schema class names
        POST -> create new class
    /v1/schema/classtype/{id}
        GET -> list schema class
        PUT -> overwrite schema content
        PATCH -> update via diff
    /v1/schema/classtype/{id}/_attr/{attr}
        GET -> list value of attr
        PUT -> overwrite attr value
        POST -> append list of values to attr
        DELETE -> purge attr

::

    /v1/schema/attributetype
        GET -> list schema class names
        POST -> create new class
    /v1/schema/attributetype/{id}
        GET -> list schema class
        PUT -> overwrite schema content
        PATCH -> update via diff
    /v1/schema/attributetype/{id}/_attr/{attr}
        GET -> list value of attr
        PUT -> overwrite attr value
        POST -> append list of values to attr
        DELETE -> purge attr

claims
======

TBD

recycle_bin
===========

List and restore from the recycle bin if possible.

::

    /v1/recycle_bin/
        GET -> list
    /v1/recycle_bin/{id}
        GET -> view recycled type
    /v1/recycle_bin/{id}/_restore
        POST -> restore this id.

access_profile
==============

::

    /v1/access_profiles
        GET -> list
        POST -> create new acp
    /v1/access_profiles/{id}
        GET -> display acp
        PUT -> overwrite acp
        PATCH -> update via diff
        DELETE -> delete this acp
    /v1/access_profiles/{id}/_attr
        GET -> list value of attr
        PUT -> overwrite attr value
        POST -> append list of values to attr
        DELETE -> purge attr


References
==========

Great resource on api design
https://docs.microsoft.com/en-us/azure/architecture/best-practices/api-design

Has a great section on filtering strings that we should implement
https://github.com/Microsoft/api-guidelines/blob/master/Guidelines.md


Azure AD api as inspiration.
https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/functions-and-actions#changePassword

https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/users-operations

https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/groups-operations

https://github.com/mozilla-services/fernet-rs/blob/master/src/lib.rs

Other Notes
===========

What about a sudo/temporal claim assignment for pw change instead?
-- temporal claim that requires re-auth to add?
-- similar for self-write?

claims:
- enforce cred policy
- may not always be granted
- need a reauth+claim request interface
- claims must be able to be scoped by time
- uat signed/tamper proof
  - similar when bearer.

- pw reset links must expire
  - url should be a bearer signed containing expiry

  - similar for radius profile view, should have a limited time scope on url.



