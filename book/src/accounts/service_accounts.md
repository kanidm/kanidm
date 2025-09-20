# Service Accounts

## Creating Service Accounts

Members of `idm_service_account_admins` have the privileges to create new service accounts. By default `idm_admin` has
this access.

When creating a service account you must delegate entry management to another group or account. This allows other users
or groups to update the service account.

The `entry_managed_by` attribute of a service account may be created and modified by members of
`idm_service_account_admins`.

> NOTE: If a service account is a member of `idm_high_privilege` its `entry_managed_by` may only be modified by members
> of `idm_access_control_admins`

```bash
kanidm service-account create <ACCOUNT_ID> <display-name> <entry-managed-by>
kanidm service-account create demo_service "Demonstration Service" demo_group --name idm_admin
kanidm service-account get demo_service --name idm_admin
```

By delegating the administration of this service account to `demo_group` this allows our `demo_user` to administer the
service account.

## Generating API Tokens For Service Accounts

Service accounts can have API tokens generated and associated with them. These tokens can be used for identification of
the service account, and for granting extended access rights where the service account may previously have not had the
access. Additionally service accounts can have expiry times and other auditing information attached.

To show API tokens for a service account:

```bash
kanidm service-account api-token status --name ENTRY_MANAGER ACCOUNT_ID
kanidm service-account api-token status --name demo_user demo_service
```

By default API tokens are issued to be "read only", so they are unable to make changes on behalf of the service account
they represent. To generate a new read only API token with optional expiry time:

```bash
kanidm service-account api-token generate --name ENTRY_MANAGER ACCOUNT_ID LABEL [EXPIRY]
kanidm service-account api-token generate --name demo_user demo_service "Test Token"
kanidm service-account api-token generate --name demo_user demo_service "Test Token" 2020-09-25T11:22:02+10:00
```

If you wish to issue a token that is able to make changes on behalf of the service account, you must add the `--rw` flag
during the generate command. It is recommended you only add `--rw` when the API token is performing writes to Kanidm.

```bash
kanidm service-account api-token generate --name ENTRY_MANAGER ACCOUNT_ID LABEL [EXPIRY] --rw
kanidm service-account api-token generate --name demo_user demo_service "Test Token" --rw
kanidm service-account api-token generate --name demo_user demo_service "Test Token" 2020-09-25T11:22:02+10:00 --rw
```

To destroy (revoke) an API token you will need its token id. This can be shown with the "status" command.

```bash
kanidm service-account api-token status --name ENTRY_MANAGER ACCOUNT_ID
kanidm service-account api-token status --name demo_user demo_service
kanidm service-account api-token destroy --name ENTRY_MANAGER ACCOUNT_ID TOKEN_ID
kanidm service-account api-token destroy --name demo_user demo_service 4de2a4e9-e06a-4c5e-8a1b-33f4e7dd5dc7
```

### API Tokens with Kanidm HTTPS/REST API

The API token issued for a service account can be used by putting the token into the HTTP request `Authorization` header
with the format `Bearer <token>`.

For more see the
[MDN documentation for Authorisation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization)

### API Tokens with LDAP

API tokens can also be used to gain extended search permissions with LDAP. To do this you can bind with a dn of
`dn=token` and provide the API token as the password.

```bash
ldapwhoami -H ldaps://URL -x -D "dn=token" -w "TOKEN"
ldapwhoami -H ldaps://idm.example.com -x -D "dn=token" -w "..."
# u: demo_service@idm.example.com
```
