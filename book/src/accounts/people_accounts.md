# People Accounts

A person represents a human's account in Kanidm. The majority of your users will be a person who will use this account
in their daily activities. These entries may contain personally identifying information that _is_ considered by Kanidm
to be sensitive. Because of this, there are default limits to who may access these data.

## Creating Person Accounts

Members of the `idm_people_admins` group have the privileges to create new persons in the system. By default `idm_admin`
has this permission.

```bash
kanidm login --name idm_admin
kanidm person create demo_user "Demonstration User" --name idm_admin
kanidm person get demo_user --name idm_admin
```

Kanidm allows person accounts to include personally identifying attributes, such as their legal name and email address.

Initially, a person does not have these attributes. If desired, a person may be modified to have these attributes.

```bash
# Note, both the --legalname and --mail flags may be omitted
kanidm person update demo_user --legalname "initial name" --mail "initial@email.address"
```

You can also use anonymous to view accounts - note that you won't see certain fields due to the limits of the anonymous
access control profile.

```bash
kanidm login --name anonymous
kanidm person get demo_user --name anonymous
```

> [!NOTE]
>
> Only members of `idm_people_pii_read` and `idm_people_admins` may read personal information by default.

Also

> [!WARNING]
>
> Persons may change their own displayname, name and legal name at any time. You MUST NOT use these values as primary
> keys in external systems. You MUST use the `uuid` attribute present on all entries as an external primary key.

## Account Validity

Kanidm supports accounts that are only able to authenticate between a pair of dates and times; the "valid from" and
"expires" timestamps define these points in time. By default members of `idm_people_admins` may change these values.

The account validity can be displayed with:

```bash
kanidm person validity show demo_user --name idm_admin
user: demo_user
valid after: any time
expire: never
```

```bash
kanidm person validity show demo_user --name idm_admin
valid after: 2020-09-25T21:22:04+10:00
expire: 2020-09-25T01:22:04+10:00
```

These datetimes are stored in the server as UTC, but presented according to your local system time to aid correct
understanding of when the events will occur.

You may set these time and date values in any timezone you wish (such as your local timezone), and the server will
transform these to UTC. These time values are in ISO8601 format, and you should specify this as:

```shell
YYYY-MM-DDThh:mm:ssZ+-hh:mm
Year-Month-Day T hour:minutes:seconds Z +- timezone offset
```

Set the earliest time the account can start authenticating:

```bash
kanidm person validity begin-from demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```

Set the expiry or end date of the account:

```bash
kanidm person validity expire-at demo_user '2020-09-25T11:22:04+00:00' --name idm_admin
```

To unset or remove these values the following can be used, where `any|clear` means you may use either `any` or `clear`.

```bash
kanidm person validity begin-from demo_user any|clear --name idm_admin
kanidm person validity expire-at demo_user clear|epoch|now --name idm_admin
```

To "lock" an account, you can set the `expire_at` value to `now` or `epoch`. Even in the situation where the "valid
from" is _after_ the `expire_at`, the `expire_at` will be respected.

These validity settings impact all authentication functions of the account (kanidm, ldap, radius).

### Allowing people accounts to change their mail attribute

By default, Kanidm allows an account to change some attributes, but not their mail address.

Adding the user to the `idm_people_self_mail_write` group, as shown below, allows the user to edit their own mail.

```bash
kanidm group add-members idm_people_self_mail_write demo_user --name idm_admin
```
