# Cryptography Key Domains

Within Kanidm we have to manage a number of private keys with various cryptographic purposes. In the current design, we
have evolved where for each purposes keys are managed in unique ways. However we need to improve this for a number
reasons including shared keys for OAuth2 domains and a future integration with PKCS11.

## Current System

In the current system we store keys in database records in a variety of bespoke ways for different uses. Often this
means that keys are associated to the object they are integrated with, such as the OAuth2 client configuration. However
this limits us since we may have users that wish to combine multiple OAuth2 clients into a single security domain, where
access tokens may be exchanged between clients for forwarded authentication.

Another example is api-tokens for service accounts. In the past we associated a private key to each service-account,
however this causes issues with key management. We want to combine all of these keys but preserve existing api-token
signatures. Currently we have no mechanism to do this.

## Use Cases

- Multiple OAuth2 clients wish to be able to access a shared resource server. `access_tokens` issued to client `a` or
  `b` should be accepted by the resource server.
- Support key-rotation within a key-domain, where former public keys are retained (can verify existing signatures but
  not create new ones), or can be revoked (verification can not succeed, and can not create new ones). Keys should be
  able to be retained for auditing purposes.
- Replication Coordinator role needs a way to issue keys that only work within the replication coordinator scope.
- Migration of key-domains and private keys into PKCS11 modules, or creation of new keys in PKCS11 to replace former
  keys.

## Design

To accommodate future changes, keys will be associated to a Key Provider. Key Objects relate to a single Key Provider.
Migration of a Key Object to another Key Provider in the future _may_ be possible.

Entities that rely on a cryptographic key will relate to a Key Object.

```text
  ┌─────────────────────┐
  │                     │
  │                     │
  │    Key Provider     │
  │                     │
  │                     │
  │                     │
  └─────────────────────┘
             ▲
             │
           ┌─┘
     ┌─────┼───────────────┐
    ┌┴─────┼──────────────┐│
  ┌─┴──────┴────────────┐ ││
┌─┴───────────────────┐ │ ││
│                     │ │ ││
│                     │ │ ││
│     Key Object      │ │ ││
│                     │ │ ├┘
│                     │ ├─┘
│                     ├─┘
└─────────────────────┘
           ▲
           │
           │
           │
┌─────────────────────┐
│                     │
│    Key Consumer     │
│                     │
│   * OAuth2 Client   │
│    * Domain Keys    │
│                     │
└─────────────────────┘
```

Key Objects have a Key Type denoting the type of material they contain. The types will be named after the JWA algorithms
from [RFC7518](https://www.rfc-editor.org/rfc/rfc7518). This allows easy mapping to OAuth2 concepts and PKCS11 in the
future.

- `ES256` (ECDSA using P-256 and SHA-256, `CKM_ECDSA_SHA256`)
- `RS256` (`RSASSA-PKCS1-v1_5` using `SHA-256`, `CKM_SHA256_RSA_PKCS`)
- `HS256` (HMAC using SHA-256, `CKM_SHA256_HMAC`)

Possible future classes could be

- `A256GCM` (AES GCM with 256 bit key `CKM_AES_GCM`)

The type defines the possible operations of the Key Object but not how the operation is performed.

A key object MAY have multiple Key Types.

Key Objects also must define their structure related to their Key Provider. For example, a possible TPM Key Provider
needs to store its Public and Private components in the Key Object, where our internal provider needs to store the DER
portions of the keys.

Between the type and the provider, this provides a concrete way to determine how a key needs to be used.

For each private/public key pair, or each symmetric key, a record of its status (valid, retained, expired, revoked)

In the valid state, a key has a validity "from" a point in time. The latest `valid_from` attribute defines the currently
active signing key for the object.

> EXAMPLE

We have 3 keys defined with:

```text
k1 { status: valid, valid_from: 10 }
k2 { status: valid, valid_from: 14 }
k3 { status: valid, valid_from: 19 }
```

Assume the current time is `15`. During a signing operation since `k3` would not-yet be valid, then we use the nearest
key which is `k2`.

If a signed object was presented with `k3` and the time is `15` then we reject the signature as it could not have
validly been produced. (we may allow some small time window).

If a signed object was presented with `k1` and the time is `15`, then we validate the signature as `k1` is still valid,
and still is accepted for signatures.

Each key may have one Key Identifier. Key Identifiers must be unique.

Key rotation is triggered by adding a new key with a newer `valid_from` attribute.

If a key object is missing a valid key, a new one MUST be generated.

On replication revoked, expired, retained and valid take precedence in that order. If two keys are marked as valid, the
"latest write" wins.

On rotation the private key is _discarded_ to prevent future use of a rotated key.

Keys must be merged, and not deleted.

```text
class: KeyObject
uuid: ...
key_object_type: ECDSA_SHA256
key_object_type: RSA_SHA256
key_object_type: RSA_SHA256

key_internal_es256: { id: ..., status: valid, public_key, private_key }
key_internal_es256: { id: ..., status: retained, public_key }
key_internal_es256: { id: ..., status: retained, public_key, private_key }

hs256_private: { id: ..., status: valid, public_key, private_key }

rs256_public: { id: ..., status: valid, public_key }
```

```text
     ┌─────────────────────┐                ┌─────────────────────┐
    ┌┴────────────────────┐│               ┌┴────────────────────┐│
  ┌─┴───────────────────┐ ││             ┌─┴───────────────────┐ ││
┌─┴───────────────────┐ │ ││           ┌─┴───────────────────┐ │ ││
│                     │ │ ││           │                     │ │ ││
│                     │ │ ││           │                     │ │ ││
│        Valid        │ │ ││           │       Expired       │ │ ││
│                     │─┼─┼┴──────────▶│                     │ │ ├┘
│                     │ ├─┘            │                     │ ├─┘
│                     ├─┘              │                     ├─┘
└─────────────────────┘                └─────────────────────┘
           │                                      │
           │                                      │
           │                                      │
           │                                      │
           │                                      │
           │                                      │
           │        ┌─────────────────────┐       │
           │       ┌┴────────────────────┐│       │
           │     ┌─┴───────────────────┐ ││       │
           │   ┌─┴───────────────────┐ │ ││       │
           │   │                     │ │ ││       │
           │   │                     │ │ ││       │
           │   │       Revoked       │ │ ││       │
           └──▶│                     │◀┼─┼┴───────┘
               │                     │ ├─┘
               │                     ├─┘
               └─────────────────────┘
```

A central key-object store is maintained with keys in memory/other. This allows dynamic reference to these keys at run
time. The object store must extract and have key-id lookup to a key-object.

Entries that use a keyObject have a reference to it.

```text
class: oauth2_rs
key_object: Refer( ... )
```

This allows access to the keyObject from the primary store. Due to kanidm's transactions, it's guaranteed that any
reference to a keyObject must be valid with a key in the keyObject store. Care must still be taken at run time in the
extremely unlikely case this no longer holds true.

Key Objects likely will be referenced from other cached items like the domain, idmserver and oauth2 so Key Object
changes will trigger reloads of these other services.

Calls to Key Objects must be async to allow for future cases with single threaded providers.

## Future Considerations

Key objects map "closely" but probably not perfectly to pkcs11 objects. This will allow an easier migration in future to
pkcs11 without needing to up-end all our existing key infra. We only need to move keyObjects into the pkcs11 model.

In the future we may need to migrate keyObjects to be part of their own "security" domain, which represents a pkcs11 or
other key-trust store.

Key trust stores need to consider that some handlers are single threaded only, so we need to design some form of
asynchronicity into our handlers so that they can use work queues to the HSM for keys.

We also need to consider key-wrapping for import of keys to HSM's on disjoint nodes. As well we probably need to
consider keyObjects that are not always accessible to all nodes so that the replication coordinator keys may only be
loaded on a subset of nodes. However I think that's a pkcs11 problem, not a problem for this change.

### Internal to PKCS11 migration

In the future we need to consider how to perform a migration from internal keys to HSM's in a non disruptive manner.

The design presented above associates a Key Object with its Key Provider. There isn't a way to mix Key Objects with
multiple possible providers.

However, we _can_ create a migration helper object. This would be a Key Object / Key Provider that acts as a router
toward different providers. This would allow us to route operations to the correct backend as required during the
migration, until all objects reside in a single provider.

Alternately, an option is to allow a Key Provider (like a PKCS11 provider) to migrate Key Objects into itself with a
marker that denotes that as internal to allow validation, but not to allow new signatures.
