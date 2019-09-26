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
    | - display
    | - search
    | - revive
    - self
    | - display
    | - set_credential (--appid/primary, --password, --totp, --webauthn, or combinations?)
    | - set_radius_password
    | - add_credential_claim
    | - remove_credential_claim
    | - change_name
    | - change_displayname
    | - change_legalname
    | - enroll_sshpublickey
    | - remove_sshpublickey
    | - modify
    | - show_radius_android
    | - show_radius_ios_macos
    | - show_radius_config
    - account
    | - list
    | - display
    | - create
    | - delete
    | - modify
    | - reset_credential
    | - add_credential_claim
    | - remove_credential_claim
    | - change_name
    | - change_displayname
    | - change_legalname
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
    | - list
    | - display
    | - create
    | - add_may_attribute
    | - add_must_attribute
    | - what_may
    | - what_must
    - radius
    | - TBD

To support this, I think we need to break the api resources down in a similar pattern. We'd need
to think about how this looks with rest ...

::

    /v1
        /raw
            /search
                -> POST -> request request
            /create
                -> POST -> create request
            /modify
                -> POST -> modify request
            /delete
                -> POST -> delete request
        /recycle_bin
            -> GET -> list
            -> GET?id -> display
            -> GET?filter -> search
            -> POST { id } -> revive
        /self
            -> GET -> whoami?
            -> POST -> modify?
            -> GET?attr -> get specific attr
            /credential
                -> GET -> list
                -> GET?id -> display credential
                -> POST? { credentialupdate } -> new or update?
                -> DELETE?id -> delete a credential
            /radius
                -> GET -> display the cred id/cred
                -> POST -> modify radius cred
                /<secret key>/ <-- this has to be stored privately on the entry w_ timeout?
                    /apple
                        -> GET -> configuration profile (no uat check)
                    /android
                        -> GET -> configuration profile (no uat check)
                    /
                        -> GET -> config json
        /account
            -> GET -> list
            -> POST -> create
            /id
                -> GET -> display
                -> GET?attr -> display attr
                -> POST -> modify
                -> DELETE -> delete id
                -> global account lock?
                /credential
                    -> GET?id -> show credentials for id?
                    -> POST?id
                    -> what about lock/unlock?
        /group
            -> GET -> list
            -> POST -> create
            /id
                -> GET -> display
                -> GET?attr -> display attr
                -> POST -> modify
                -> DELETE -> delete this group
        /access_profile
            -> GET -> list
            -> POST -> create
            /id
                -> GET -> display
                -> DELETE -> delete
                -> POST -> modify

        /schema
            -> GET -> list
            -> POST -> create
            /id
                -> GET -> display
                -> MODIFY -> modify
            /what
                /may
                    -> GET?attr
            /what
                /must
                    -> GET?attr
        /claims
        /radius


https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/functions-and-actions#changePassword

https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/users-operations

https://docs.microsoft.com/en-au/previous-versions/azure/ad/graph/api/groups-operations

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





