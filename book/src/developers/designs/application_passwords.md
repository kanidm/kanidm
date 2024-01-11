# Rationale

Kanidm exists to provide an authentication source for external applications.
These applications need to have standardised ways to integrate with Kanidm to
allow that application to interact and trust Kanidm's authentication results.

For web based applications we offer Oauth2/OIDC. For Linux machines we offer a
Kanidm specific HTTPS channel for identifying users (UNIX integration).
Currently, for applications that don't support other protocols we offer an LDAPS
gateway that allows users to bind using their UNIX password.

However this has the issue that due to how limited Linux authentication is, UNIX
passwords are always single factor. We also don't want the same UNIX credentials
that are used, e.g. for sudo on machines, to be leaked and used for applications
like email.

To improve this we need a way to offer authentication services to applications
that are unable to support anything modern.

Since LDAP is the "lingua franca" of authentication and almost universally
implemented as an authentication for all applications, we can use this to
provide *application specific* password based authentication and remove the
ability to bind with the UNIX password.

# User experience

The administrator configures two applications on their Kanidm instance. One is
"mail" for a generic SMTP+IMAP service. The other is HTTP basic auth to a legacy
web server. Once applications are added, the administrator adds the allowed
users to the applications as if they were regular groups.

The mail services and web services are configured to point to Kanidm's LDAP
gateway with a customized search base DN.

The user can login to the webui or command line and list what linked
applications exist on their account that require application passwords.

The user can then request a new "application password" for the mail server for
their laptop. They can copy-paste the generated password to their mail client
which uses this password on their behalf. Similarly, they can request a new
application password to access the web server basic auth.

As a user can request several application passwords for each application.

# Technical Details

## Client

Currently the LDAP basedn is configurable by an admin, or generated from domain.
For example, example.com <http://example.com/> becomes dc=example,dc=com.

Each configured application has a new container such as
app=mail,dc=example,dc=com or app=httpd,dc=example,dc=com

(NOTE: Should this be app=? Some broken clients could try to validate this rdn
and error, so perhaps it should be a standard rdn value like cn?)

The application then uses this app=mail,dc=example,dc=com as their search base
rather than dc=example,dc=com. Within this search base, we show the same content
from dc=example,dc=com.

(NOTE: We could limit this to application only entries via group membership, but
the issue then is when you have a group for allowing access to the application,
but then still need other groups reflected into the subtree. In this case, if we
limited the view to application access only, we wouldn't be displaying the
non-access groups that the application may still rely on. Ultimately, in this
case the application needs to make it's own authorisation decisions to an
extend. Kanidm can limit which users are members of the access allowed group as
only they can bind still as an extra layer of defence)

The application must bind with its token if it wishes to read extended user
information. With this, only basic info limited to anonymous rights are granted.

(NOTE: We can't assume these DNs are private - I did consider making these
app=<secret key>,dc=example,dc=com, but client applications may disclose this
basedn in ui elements).

When a user authenticates the binddn of the account is set to
spn=user,app=name,dc=example,dc=com. This difference in base DN triggers Kanidm
to re-route the authentication to the application specific password, rather than
the UNIX one.

## Kanidm

### Application Entries

A new class for applications will be added that has an associated reference to a
set of groups that are allowed access.

(NOTE: It could be good to make this a group such that members of the group
inherit "memberof=application X". This would make presentation of application
password links in the UI easier since we can then do a search on (memberof &&
class = application). Alternately we don't need this since we can in-memory
cache applications and just compare their member sets to the user sessions
memberof)

Applications need to have service-account like properties where tokens can be
generated for them. These are optional since an anonymous bind to kanidm and
searching under the basedn will continue to work.

Application should have a URL reference to help admins identify where the
application may be located or accessed.

(NOTE: Future, it could be good to allow customisable instructions for users on
where to go to use their app password?)

(NOTE: To make it easier to manage tokens, it could be good to have a
"token-capable" class type to prevent duplication this with service-accounts,
and allows adding tokens to future types).

### Accounts

The user may wish to have multiple passwords per application. Each password may
have a label to identify it. For example:

```
  MAIL
    iphone: abcd...
    laptop: bcde...
  HTTP
    workstation: cdef...
```

Person accounts will need a new `Attribute::ApplicationPassword` that stores a
`ValueSetApplicationPassword`. Each value in the set is a new type to manage these
secrets and their labeling and the references to the applications.

```
type ApplicationPasswords = BTreeMap<Uuid, (String, Password)>;
                                     ^        ^         ^
                                     |        |         +-> The hashed password
                                     |        +-> Application password label
                                     +-> Application password UUID

type ApplicationUuid = Uuid;

struct ValueSetApplicationPassword {
  map: Map<ApplicationUuid, ApplicationPasswords>
}
```

Each value in the set is queried by its UUID. This defines the value as
`Value::ApplicationPassword(Uuid, ApplicationPassword)`. The
`ApplicationPassword` type implements `PartialEq` so two application passwords
are equal if their label is equal and they refer to the same application.

(NOTE: We could consider extending the `CredentialType` to add
`CredentialType::ApplicationPassword<Map<Uuid, ApplicationPassword>>`. Then we
wouldn't need `Attribute::ApplicationPassword`, nor `Value::ApplicationPassword`,
neither `ValueSetApplicationPassword`).

The user must be able to delete credentials individually. The generated password
is only displayed once when the user creates it and it is not possible to
recover the clear-text form, only hashed form is stored. It is not allowed to
store duplicated application passwords (same app refer and label).

We do not need temporary locks or holds - users can delete and recreate as
needed.

### Reference integrity

Since application passwords are related to applications, on delete of an
application all entries that have a bound application password should be removed
from user accounts.

### Access controls

The IDM administrators group can manage the applications and user's application
passwords.

Users can manage their own application passwords.

### LDAP

The bind DN regular expression needs to adjusted to detect and determine the
bind dn if it is related to an application or not. The application bind dn
regular expression will capture the user name, the label and the application
name.

The rootdse needs to be extended to include the applications as additional
naming contexts.

If the session is related to an application we should only accept application
passwords in the bind. The user needs to be a member of the application. Binds
to an application password must be limited by account validity and expiration.

We need to add a cache of available applications for lookup.

(NOTE: Caching and reload needs more explanation)

### kanidm CLI

The `kanidm` command line tool will be extended with the following commands to
manage the applications:

* kanidm application create <NAME>
* kanidm application delete <NAME>
* kanidm application list
* kanidm application get <NAME>
* kanidm application add-members <NAME> <MEMBER> ... <MEMBER>
* kanidm application remove-members <NAME> <MEMBER> ... <MEMBER>
* kanidm application list-members
* kanidm application set-members <NAME> <MEMBER> ... <MEMBER>
* kanidm application purge-members <NAME>

If possible, implementation will reuse group command line arguments handling.

The `kanidm` command line tool will be extended with the following commands to
manage the application passwords:

* kanidm person application-password create <ACCOUNT_ID> <APP_ID> <LABEL>
* kanidm person application-password delete <ACCOUNT_ID> <UUID>
* kanidm person application-password list <ACCOUNT_ID>

Same commands will be available for "self".
