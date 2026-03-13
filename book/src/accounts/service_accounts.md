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

If you wish to issue a token that is able to make changes on behalf of the service account, you must add the `-w` flag
during the generate command. It is recommended you only add `-w` when the API token is performing writes to Kanidm.

```bash
kanidm service-account api-token generate --name ENTRY_MANAGER ACCOUNT_ID LABEL [EXPIRY] --readwrite
kanidm service-account api-token generate --name demo_user demo_service "Test Token" --readwrite
kanidm service-account api-token generate --name demo_user demo_service "Test Token" 2020-09-25T11:22:02+10:00 --readwrite
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

### API Tokens with OIDC Token Exchange (RFC 8693)

Service accounts can exchange their API bearer token for OAuth2/OIDC tokens (access/id/refresh) without user consent or
interaction. For Basic OAuth2 clients, do not provide the client secret during this flow; the API token is the
credential, and sending a secret is rejected. Use the token endpoint with the RFC 8693 grant:

- `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token`: the service-account API token (see `kanidm service-account api-token generate`)
- `subject_token_type`: `urn:ietf:params:oauth:token-type:access_token`
- `audience`: OAuth2 `client_id` of the target resource server
- `resource` (optional): absolute URI for that same resource server; other values return `invalid_target`
- `requested_token_type` (optional): defaults to an access token; other values are rejected
- `scope`: scopes permitted for the service account on that client

`actor_token` is not supported for this flow.

Example `application/x-www-form-urlencoded` request:

```bash
curl -X POST https://idm.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=test_resource_server" \
  -d "subject_token=$API_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=test_resource_server" \
  -d "scope=openid groups"
```

Responses include an `access_token`, `id_token` when `openid` is requested, and a `refresh_token` when allowed. Scopes
are still enforced against the service account’s group membership and the client’s scope map.

### API Tokens with LDAP

API tokens can also be used to gain extended search permissions with LDAP. To do this you can bind with a dn of
`dn=token` and provide the API token as the password.

```bash
ldapwhoami -H ldaps://URL -x -D "dn=token" -w "TOKEN"
ldapwhoami -H ldaps://idm.example.com -x -D "dn=token" -w "..."
# u: demo_service@idm.example.com
```

### Compact API Tokens

API Tokens issued by Kanidm are a JWS object that contains metadata about the service account that is being granted
access. To encode the necessary information, the token can be quite long.

Some services cannot work with tokens over a certain size and will truncate them during use. This causes the token to
fail validation and Kanidm will refuse it.

In these cases a compact token format can be used that creates a token which is 120 ASCII characters or less.

> NOTE: Compact tokens do come with downsides, which is why they are not the default:
>
> 1. They are marginally more expensive for the server to process.
> 2. Since they contain less metadata, they are more difficult to introspect to understand "who" the token belongs to.
> 3. In a replicated environment, it may take some time for the token to be accepted as valid on all servers (~5
>    minutes).

```bash
kanidm service-account api-token generate --name ENTRY_MANAGER ACCOUNT_ID LABEL [EXPIRY] --compact
kanidm service-account api-token generate --name demo_user demo_service "Test Token" --compact
```

All other token management commands and workflows remain the same. Only the length of the emitted token is different.
