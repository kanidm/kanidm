# Anonymous Account

Within Kanidm there is a single "special" account. This is the anonymous service account. This allows clients without
any credentials to perform limited read actions against Kanidm.

The anonymous account is primarily used by stateless unix clients to read account and group information.

## Authentication

Even though anonymous does not have credentials it still must authenticate to establish a session to access Kanidm. To
achieve this there is a special `anonymous` credential method. Anonymous is the only account that may use this
credential method.

## OAuth2 / OIDC

Anonymous is a service account which prevents it from using OAuth2/OIDC to access other applications.

## Access

By default anonymous has limited access to information in Kanidm. Anonymous may read the following data.

> NOTE: The `Name` attribute is the user's public username. This is different to their private and sensitive `LegalName`
> attribute.

### People

- Name
- DisplayName
- MemberOf
- Uuid
- GidNumber
- LoginShell
- SshPublicKey

### Groups

- Name
- Member
- DynMember
- GidNumber

## Disabling the Anonymous Account

The anonymous is like any other and can be expired to prevent its use. See the
[account validity section](./people_accounts.md#account-validity)

When disabled, this will prevent stateless unix clients from authenticating to Kanidm.
