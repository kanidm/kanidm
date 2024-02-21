# Cryptography Key Domains

Within Kanidm we have to manage a number of private keys with various cryptograhpic purposes. In the
current design, we have evolved where for each purposes keys are managed in unique ways. However we
need to improve this for a number reasons including shared keys for Oauth2 domains and a future
integration with PKCS11.

## Current System

In the current system we store keys in database records in a variety of bespoke ways for different
uses. Often this means that keys are associated to the object they are integrated with, such as the
oauth2 client configuration. However this limits us since we may have users that wish to combine
multiple oauth2 clients into a single security domain, where access tokens may be exchanged between
clients for forwarded authentication.

Another example is api-tokens for service accounts. In the past we associated a private key to each
service-account, however this causes issues with key management. We want to combine all of these
keys but preserve existing api-token signatures. Currently we have no mechanism to do this.

## Use Cases

- Multiple OAuth2 clients wish to be able to access a shared resource server. `access_tokens` issued
  to client a or b should be accepted by the resource server.
- Support key-rotation within a key-domain, where former public keys are retained in a valid state,
  or can be revoked.
- Replication Coordinator role needs a way to issue keys that only work within the replication
  coordinator scope.
- Migration of key-domains and private keys into PKCS11 modules, or creation of new keys in PKCS11
  to replace former keys.

## Design

Keys will be moved to dedicated key-objects in the database. Each key-object can have many
associated keys of various cryptographic types.

For each key present, they have a key-id related to the public keys. This allows lookup based on
keyid.

When a private key is created, it's public key is added to a public key record along with a key
status such as "valid" or "expired".

As HMAC keys don't have a public portion, they can only exist as a private key. Similar for AES.

When a public key is marked as expired, if it's private key is the active private key, it must be
rotated.

On replication expiry of a public key always takes precedence over valid. Public key maps are
merged.

```
class: KeyObject
uuid: ...
ec256: <private key>
ec256_public_key: { id: ..., status: valid, public_key }
hs256: <private key>
rs256: <private key>
rs256_public_key: { id: ..., status: valid, public_key }
```

A central key-object store is maintained with keys in memory/other. This allows dynamic reference to
these keys at run time. The object store must extract and have key-id lookup to a key-object.

Entries that use a keyObject have a reference to it.

```
class: oauth2_rs
key_object: Refer( ... )
```

This allows access to the keyObject from the primary store. Due to kanidm's transactions, it's
guaranteed that any reference to a keyObject must be valid with a key in the keyObject store.

## Future Considerations

Key objects map "closely" but probably not perfectly to pkcs11 objects. This will allow an easier
migration in future to pkcs11 without needing to up-end all our existing key infra. We only need to
move keyObjects into the pkcs11 model.

In the future we may need to migrate keyObjects to be part of their own "security" domain, which
represents a pkcs11 or other key-trust store.

Key trust stores need to consider that some handlers are single threaded only, so we need to design
some form of asynchronisity into our handlers so that they can use work queues to the HSM for keys.

We also need to consider key-wrapping for import of keys to HSM's on disjoint nodes. As well we
probably need to consider keyObjects that are not always accessible to all nodes so that the
replication coordinator keys may only be loaded on a subset of nodes. However I think that's a
pkcs11 problem, not a problem for this change.
