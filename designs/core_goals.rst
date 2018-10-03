

* JSON objects (or cbor if I feel game ...)
* Simpler schema for objects and index management
** Schema should be profile based, similar to AD
* Objects are categorised and sorted by URI
** Rather than search a generic tree, the URL of /v1/search/<class>/<query> is used.
* Access profiles
* Web integrated authentication process
** WebAUTHN, OIDC
* Replication
** This is the responsibility of a backend, but we may add a new cleanroom BE.
* Simple and stateful configuration to work with tools like ansible and docker
* Features "on by default": minimal need to configure to make good.
* All ID's are UUID that can derive to UID for unix
* Groups can have ephemeral memberships on login events (IE auth tokens)
* Identity and group info is mainly token based, but lookups of certain data is allowed IE ssh key for authentication

* Group requests in login for ephemeral tokens

* Groups are roles, and can be dynamically requested on login (william+admin), or saml/oid present list of groups to bind (can req further auth)
* Groups are only a fact of a login - users have groups, but we don't need to see all members of a group for it to be valid, especially given ephemeral groups
* Passwords generated for services IE email client with no privs, a cron job with partial privs, etc.

* Access controls to allow creation of different credential levels, which can requests group memberships of certain types.


Schema ideas:

A schema would look like:

::

   /v1/schema/attributes/displayname
   {
      'name': 'displayname',
      'system': 'true',
      'multivalue': 'false',
      'index': [
         'equality'
      ]
      'syntax': 'utf-8',
      'description': 'A persons chosen name that they wish to display to the world'
   }

   /v1/schema/classes/person
   {
      'name': 'person',
      'systemmay': [
         'displayname',
      ],
      'may': [
      ]
   }



A group would look like:

   /v1/groups/admins
   'admins': {
      'name': 'admins',
      'class': [
         'group',
      ],
      'member': 'UUID of member', // derefence? URI?
      // Does this work given the belowe credentials per account idea?
      // always provide, must request, must request and require stricter auth requirements
      'policy': '[default|request|request_strict]'

   }

A person with group derferencing would look like:

   /v1/accounts/william
   {
      'name': 'william',
      'class': [
         'person',
      ]
      'displayname': 'William Brown',
      'email': [
         'william at blackhats.net.au',
      ]
      'memberof': [
         'admins': {
            'name': 'admins',
            'class': [
               'group',
            ],
            // Members are omitted - we only need to know the groups here.
         }
      ]

      'ssh_publickey': [
         'name': '...',
      ]

      // We need to also store other usually useful business stuff like mail
      // address etc.


      // SAML/OIDC: On login we req name + <type> defined by the server
      // then we can get pw + optional mfa
      // then we present UI of "roles" to embed in token

      // Static PW:
      // login with name+req and the static pw, then we get the defined
      // roles of the cred

      // Unix login:
      // name+<type>, ssh key is an option, and nss/pam service can just
      // lookup name+<type> roles associated.
      //
      // pw generation: based on name+<cred>, and pw, we associate
      // roles.

      // These could be child objects with classes and rules on them that
      // access profiles could be used to manage.

      // role examples
      // * email
      // * calendar
      // * self_manage
      // * login
      // * directory_admin
      // * ...

      // Should memberof be part of credentials?


      // What should the UX be?

      // ssh for interactive
      //    * key
      //    * pw + mfa
      //  This should be username with ssh key. can accept username+role
      //  and then the client application "trusts" the extra roles for the
      //  username. If they authenticated, then they get 'the role'. Because
      //  of the design of this, it's hard to know if they used the right
      //  auth material (seperate ssh key for +role name? or mfa)

      // ssh for git style applications
      //    * key
      //  just use the username + ssh key, no extra roles

      // graphical login
      //    * pw + mfa
      //  username and mfa (no +role, or allows +role)

      // oidc/saml
      //    * pw + mfa
      // given the username +pw (maybe mfa), then allow the roles to be selected

      // applications
      //    * static pw
      //  give the pw, allow the role, even if priv elevated.

      //  conclusion:
      //  * list of ssh keys
      //  * list of service-pws + roles
      //  * list of mfa
      //   * you can only be in a role with request_strict *if* you have
      //     mfa enabled
      //   *  if you remove mfa you leave the request_strict roles
      //   * default_strict is always given but forces account mfa

      // is there a reason for request?
      //  * should login open ff cookie jar?
      //  * any other kind of auth bits?


      // * returned token to host gives different uid+gid for +role than -role
      //   allowing seperation of interests.

      // * Allow impersonation during login?

      // Every login always returns a token of all available roles to the
      // client base on the request

      // Other - static pw for rfid auth?

      // Is there a way to enroll an mfa to the host for offline mfa w_out ccid?

      credentials : {
         // this is when there is no other type, ie unix login
         default : {
            'password': 'hash',
            'totp_secret': 'totp_secret',
            'webauthn': '...',
            // Allow an auth from this to have access to requested 2fa groups
            'group_policy': request_strict,
         }
         self: {
            // Could we ref the default, but extend the roles?
         }
         admin: {
         }
         email : {
            'password': 'hash',
            'group_policy': 'default',
            'memberof': ['email_access', 'calendar_access']
         }
      }
   }

   /v1/accounts/william+admin
   {
      // Same but extre members-of
   }
   /v1/accounts/william+admin+extra
   {
      // Same but extre members-of of extra groups
   }


   /v1/permissions/anonymous_read
   {
      'class': 'permission',
      'read_attr' : [
      ], // implies search
      'write_attr': [
      ],
      // Read/Write class? do these use defaults from schema?
      // Do we need anything else? modify only? append only?
      // delete object/write object

      // manage creds auth? IE pw reset. Can we scope auth resets to certain
      // creds

      // IE can add new creds, or remove of certain pol types but can't
      // change requiremnts for mfa?
   }


Requirements:

* Fast UUID to URI lookup
* Login cookie should embed groups (think linux login)
** these should be ephemeral if required
* saml/oidc present a nicer group selection interface

