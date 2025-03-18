# Automatic Certificate Management Environment (ACME)

> [!WARNING]  
> This is very much a working progress. This is a very minimal possible implementation to get a discussion going. 

## Rationale

Kanidm already provides support for several types of public key systems, such as passkeys and ssh, and 
mTLS altough only for replication.

ACME is the standard protocol for obtaining and managing TLS certificates.

Implementing ACME protocol support in Kanidm will enable person and system accounts to easily obtain and
manage TLS certificates for their services, improving security and convenience.

## Design

### Add a new enrollment method for creating an External Account Binding

#### `/v2/acme/eab` 

which would return
```json
{"hmac_key": "deadbeef", "kid": "1"}
```
### Create a new Account

#### `/v2/acme/directory` 

```rust
/// ACME Directory Endpoint - The entry point for the ACME protocol
///
/// As defined in https://www.rfc-editor.org/rfc/rfc8555#section-7.1.1
#[utoipa::path(
    get,
    path = "/v2/acme/directory",
    responses(
        (status = 200, description = "ACME directory information", body = Directory)
    ),
    tag = "acme"
)]
pub async fn acme_directory(State(state): State<ServerState>) -> impl IntoResponse {
    // Build the base URL from the server's origin
    let base_url = format!("{}acme", state.origin);

    Json(Directory {
        new_nonce: format!("{}/new-nonce", base_url),
        new_account: format!("{}/new-account", base_url),
        new_order: format!("{}/new-order", base_url),
        new_authorization: None,
        key_change: format!("{}/key-change", base_url),
        revoke_certificate: format!("{}/revoke-cert", base_url),
        metadata: Some(DirectoryMetadata {
            terms_of_service: None,
            website: None,
            caa_identities: None,
            external_account_required: Some(true),
        }),
    })
}
```
The code can then be used to create a new account by any acme compatible client. 

```shell
cd /tmp/kanidm && acme.sh --debug --server https://localhost:8443/v2/acme/directory --register-account --email test@example.com --eab-kid 1 --eab-hmac-key 121  --ca-bundle chain.pem
```

#### `/v2/acme/new-nonce`
```rust
/// ACME New Nonce Endpoint
///
/// As defined in https://www.rfc-editor.org/rfc/rfc8555#section-7.2
#[utoipa::path(
    get,
    path = "/v2/acme/new-nonce",
    responses(
        (status = 200, description = "New nonce issued", headers(("Replay-Nonce" = String, description = "The generated nonce")))
    ),
    tag = "acme"
)]
pub async fn acme_new_nonce() -> impl IntoResponse {
    // Generate a nonce (for now just using a UUID)
    let nonce = Uuid::new_v4().to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("Replay-Nonce", nonce)
        .body(axum::body::Body::empty())
        .unwrap()
}
```
### `/v2/acme/new-account`
```rust
/// ACME New Account Endpoint
///
/// As defined in https://www.rfc-editor.org/rfc/rfc8555#section-7.3
#[utoipa::path(
    post,
    path = "/v2/acme/new-account",
    request_body = JsonWebSignature,
    responses(
        (status = 201, description = "Account created successfully", body = Account,
         headers(
            ("Replay-Nonce" = String, description = "A new nonce for the next request"),
            ("Location" = String, description = "URL of the created account")
         )
        )
    ),
    tag = "acme"
)]
pub async fn acme_new_account(
    State(_state): State<ServerState>,
    Json(payload): Json<JsonWebSignature>,
) -> impl IntoResponse {
    let Ok(new_account) = payload.try_into_payload::<NewAccount>() else {
        return Response::builder().status(400).body(Body::empty()).unwrap();
    };

    let Some(external_account_binding) = new_account.external_account_binding else {
        return Response::builder().status(400).body(Body::empty()).unwrap();
    };
    // For now, return a placeholder response
    let nonce = Uuid::new_v4().to_string();
    let account_id = Uuid::new_v4().to_string();

    Response::builder()
        .status(StatusCode::CREATED)
        .header("Content-Type", "application/json")
        .header("Replay-Nonce", nonce)
        .header("Location", format!("/acme/acct/{}", account_id))
        .body(axum::body::Body::from(
            serde_json::to_vec(&Account {
                status: acme_types::v2::AccountStatus::Valid,
                contact: Some(vec!["mailto:test@example.com".to_string()]),
                terms_of_service_agreed: Some(true),
                orders: format!("/acme/orders/{}", account_id),
                external_account_binding: None,
            })
            .unwrap(),
        ))
        .unwrap()
}
```
And this is really the base minimum to get an account going. 
