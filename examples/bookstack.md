# Bookstack (non-docker version)

## On Kanidm 
### 1. Create the bookstack resource server
```
kanidm system oauth2 create bookstack "Bookstack" https://yourbookstack.example.com
```
### 2. Create the appropriate group(s)
```
kanidm group create bookstack-users --name idm_admin
```
### 3. Add the appropriate users to the group
```
kanidm group add-members bookstack-users user.name
```
### 4. Add the scopes:
```
kanidm system ouath2 update-scope-map bookstack openid profile email keys
```
### 5. Get the client secret:
```
kanidm system oauth2 show-basic-secret bookstack
```
Copy the value that is returned.

### 6. Disable PKCE / Enable Legacy crypto
```
kanidm system oauth2 warning-insecure-client-disable-pkce bookstack
kanidm system oauth2 warning-enable-legacy-crypto
```
## On Bookstack server
### 1. Add the following to the .env file at the bottom
```
#OIDC
AUTH_AUTO_INITIATE=false
OIDC_NAME=Kanidm
OIDC_DISPLAY_NAME_CLAIMS=openid
OIDC_CLIENT_ID=bookstack
OIDC_CLIENT_SECRET=<secret from step 5>
OIDC_ISSUER=https://idm.example.com:8443/oauth2/openid/bookstack
OIDC_END_SESSION_ENDPOINT=false
OIDC_ISSUER_DISCOVER=true
OIDC_DUMP_USER_DETAILS=false
OIDC_EXTERNAL_ID_CLAIM=openid
```
### 2. Change the AUTH_METHOD to oidc in the .env file
```
AUTH_METHOD=oidc
```
### 3. Open the `app/Access/Oidc/OidcService.php` file with your favorite editor.
### 4. Go to line 214 and make the following changes:
```
       return [
           'external_id' =>  $token->getClaim('sub'),
            'email'       => $token->getClaim('email'),
            'name' => $token->getClaim('name'),
            'groups'      => $this->getUserGroups($token),
        ];
```
Open your bookstack URL and click the Signin with Kanidm button.
