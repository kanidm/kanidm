## Unixd MultiResolver Support

Up until July 2024 the purpose and motivation of the Kanidm Unixd component (`unix_integration` in the source tree) was
to allow Unix-like platforms to authenticate and resolve users against a Kanidm instance.

However, throughout 2023 and 2024 this project has expanded in scope - from the addition of TPM support to protect
cached credentials (the first pam module to do so!), to use of the framework by himmelblau to enable Azure AD
authentication.

We also have new features we want to add including LDAP backends (as an alternative to SSSD), the ability to resolve
local system users, as well as support for PIV and CTAP2 for desktop login.

This has pushed the current design of the resolver to it's limits, and it's increasingly challenging to improve it as a
result. This will necesitate a major rework of the project.

### Current Architecture

```
                                                    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

                ┌───────┐  ┌───────┐  ┌───────┐     │ ┌───────────────────┐     │
                │       │  │       │  │       │       │                   │
                │  NSS  │  │  PAM  │  │  CLI  │     │ │   Tasks Daemon    │     │
                │       │  │       │  │       │       │                   │
                └───────┘  └───────┘  └───────┘     │ └───────────────────┘     │
                    ▲          ▲          ▲                     ▲
            ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┴ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ┤
            │       ▼          ▼          ▼                     │
                ┌─────────────────────────────┐           ┌───────────┐         │
            │   │                             │           │           │
                │         ClientCodec         │           │   Tasks   │         │
            │   │                             │           │           │
                └─────────────────────────────┘           └───────────┘         │
┌ ─ ─ ─ ─ ─ ┘                  ▲                                ▲
                               │                                │               │
│                              ▼                                │
  ┌───────────────┐      ┌────────────────────────────────┐     │               │
│ │               │      │                                │     │
  │  Kani Client  │◀────▶│      Daemon / Event Loop       │─────┘               │
│ │               │      │                                │
  └───────────────┘      └────────────────────────────────┘                     │
│                                   ▲                 ▲
                                    │                 │                         │
│                                   ▼                 ▼
                          ┌──────────────────┐   ┌────────┐                     │
│                         │                  │   │        │
                          │    DB / Cache    │   │  TPM   │                     │
│                         │                  │   │        │
                          └──────────────────┘   └────────┘                     │
│
 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┴
```

The current design treated the client as a trivial communication layer. The daemon/event loop contained all state
including if the resolver was online or offline. Additionally the TPM and password caching operations primarily occurred
in the daemon layer, which limited the access of these features to the client backend itself.

### Future Features

#### Files Resolver

The ability to resolve and authenticate local users from `/etc/{passwd,group,shadow}`. The classic mechanisms to resolve
this are considered "slow" since they require a full-file-parse each operation.

In addition, these files are limited by their formats and can not be extended with future authentication mechanisms like
CTAP2 or PIV.

Unixd already needs to parse these files to understand and prevent conflicts between local items and remote ones.
Extending this functionality will allow us to resolve local users from memory.

Not only this, we need to store information _permanently_ that goes beyore what /etc/passwd and similar can store. It
would be damaging to users if their CTAP2 (passkeys) were deleted randomly on a cache clear!

#### Local Group Extension

An often requested feature is the ability to extend a local group with the members from a remote group. Often people
attempt to achieve this by "overloading" a group remotely such as creating a group called "wheel" in Kanidm and then
attempting to resolve it on their systems. This can introduce issues as different distributions may have the same groups
but with different gidNumbers which can break systems, or it can cause locally configured items to be masked.

Instead, we should allow group _extension_. A local group can be nominated for extension, and paired to a remote group.
For example this could be configured as:

```
[group."wheel"]
extend_from = "opensuse_wheel"
```

This allows the local group "wheel" to be resolved and _extended_ with the members from the remote group
`opensuse_wheel`.

#### Multiple Resolvers

We would like to support multiple backends simultaneously and in our source tree. This is a major motivator of this
rework as the himmelblau project wishes to contribute their client layer into our source tree, while maintaining the
bulk of their authentication code in a separate libhimmelblau project.

We also want to support LDAP and other resolvers too.

The major challenge here is that this shift the cache state from the daemon to the client. This requires each client to
track it's own online/offline state and to self-handle that state machine correctly. Since we won't allow dynamic
modules this mitigates the risk as we can audit all the source of interfaces committed to the project for correct
behaviour here.

#### Resolvers That Can't Resolve Without Authentication Attempts

Some resolvers are unable to resolve accounts without actually attempting an authentication attempt such as Himmelblau.
This isn't a limitation of Himmelblau, but of Azure AD itself.

This has consequences on how we performance authentication flows generally.

#### Domain Joining of Resolvers

Some Clients (and in the future Kanidm) need to be able to persist some state related to Domain Joining, where the
client registers to the authentication provider. This provides extra functionality beyond the scope of this document,
but a domain join work flow needs to be possible for the providers in some manner.

#### Encrypted Caches

To protect caches from offline modification content should be optionally encrypted / signed in the future.

#### CTAP2 / TPM-PIN

We want to allow local authentication with CTAP2 or a TPM with PIN. Both provide stronger assurances of both who the
user is, and that they are in possession of a specific cryptographic device. The nice part of this is that they both
implement hardware bruteforce protections. For soft-tpm we can emulate this with a strict bruteforce lockout prevention
mechanism.

The weakness is that PIN's which are used on both CTAP2 and TPM, tend to be shorter, ranging from 4 to 8 characters,
generally numeric. This makes them unsuitable for remote auth.

This means for SSH without keys, we _must_ use a passphrase or similar instead. We must not allow SSH auth with PIN to a
TPM as this can easily become a remote DOS via the bruteforce prevention mechanism.

This introduces it's own challenge - we are now juggling multiple potential credentials and need to account for their
addition and removal, as well as changing.

Another significant challenge is that linux is heavily embedded in "passwords as the only factor" meaning that many
systems are underdeveloped like gnome keyring - this expects stacked pam modules to unlock the keyring as it proceeds.

_Local Users_

Local Users will expect on login equivalent functionality that `/etc/passwd` provides today, meaning that local wallets
and keyrings are unlocked at login. This necesitates that any CTAP2 or TPM unlock need to be able to unlock the keyring.

This also has implications for how users expect to interact with the feature. A user will expect that changing their PIN
will continue to allow unlock of their system. And a change of the users password should not invalidate their existing
PIN's or CTAP devices. To achieve this we will need some methods to cryptographically protect credentials and allow
these updates.

To achieve this, we need to make the compromise that the users password must be stored in a reversible form on the
system. Without this, the various wallets/keyrings won't work. This trade is acceptable since `pam_kanidm` is already a
module that handles password material in plaintext, so having a mechanism to securely retrieve this _while_ the user is
entering equivalent security material is reasonable.

The primary shift is that rather than storing a _kdf/hash_ of the users output, we will be storing an authenticated
encrypted object where valid decryption of that object is proof that the password matches.

For the soft-tpm, due to PIN's short length, we will need to aggressively increase the KDF rounds and consider HMAC of
the output.

```
                                                  HMAC-Secret
      Password                  PIN                 output
          │                      │                     │
          │                      │                     │
          │                      │                     │
          ▼                      ▼                     ▼
┌──────────────────┐    ┌─────────────────┐   ┌─────────────────┐
│                  │    │                 │   │                 │
│       KDF        │    │   PIN Object    │   │   CTAP Object   │
│                  │    │                 │   │                 │
└──────────────────┘    └─────────────────┘   └─────────────────┘
          │                      │     ▲               │   ▲
          │                      │     │               │   │
          │        Releases      │                     │
          ├───────KDF value──────┴─────┼───────────────┘   │
          │
          │                            │                   │
          ▼
┌──────────────────┐                   │                   │
│                  │
│  Sealed Object   │                   │                   │
│                  │─ ─ ─ ─Unlocks─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
│                  │
└──────────────────┘
          │
       Release
      Password
          │
          ▼
┌──────────────────┐
│                  │
│pam_gnome_keyring │
│   pam_kwallet    │
│                  │
└──────────────────┘
```

_Remote Users (such as Kanidm)_

After a lot of thinking, the conclusion we arrived at is that trying to handle password stacking for later pam modules
is out of scope at this time.

Initially, remote users will be expected to have a password they can use to access the system. In the future we may
derive a way to distribute TPM PIN objects securely to domain joined machines.

We may allow PINs to be set on a per-machine basis, rather than syncing them via the remote source.

This would require that a change of the password remotely invalidates set PINs unless we think of some way around this.

We also think that in the case of things like password managers such as desktop wallets, these should have passwords
that are the concern of the user, not the remote auth source so that our IDM has no knowledge of the material to unlock
these.

### Challenges

- The order of backend resolvers needs to be stable.
- Accounts/Groups should _not_ move/flip-flop between resolvers.
- Resolvers need to uniquely identify entries in some manner.
- The ability to store persistent/permananent accounts in the DB that can _not_ be purged in a cache clear.
- Simplicity of the interfaces for providers so that they don't need to duplicate effort.
- Ability to clear _single items_ from the cache rather than a full clear.
- Resolvers that can't pre-resolve items

### New Architecture

```
                                                    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

                ┌───────┐  ┌───────┐  ┌───────┐     │ ┌───────────────────┐     │
                │       │  │       │  │       │       │                   │
                │  NSS  │  │  PAM  │  │  CLI  │     │ │   Tasks Daemon    │     │
                │       │  │       │  │       │       │                   │
                └───────┘  └───────┘  └───────┘     │ └───────────────────┘     │
                    ▲          ▲          ▲                     ▲
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┴ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ┤
                    ▼          ▼          ▼                     │
│               ┌─────────────────────────────┐           ┌───────────┐         │
                │                             │           │           │
│               │         ClientCodec         │           │   Tasks   │         │
  ┌──────────┐  │                             │           │           │
│ │          │  └─────────────────────────────┘           └───────────┘         │
  │  Files   │◀────┐           ▲                                ▲
│ │          │     │           │                                │               │
  └──────────┘     │           ▼                                │
│ ┌───────────────┐│     ┌────────────────────────────────┐     │               │
  │               │└─────┤                                │     │
│ │  Kani Client  │◀─┬──▶│      Daemon / Event Loop       │─────┘               │
  │               │  │   │                                │
│ └───────────────┘◀─│┐  └────────────────────────────────┘                     │
  ┌───────────────┐  │                           ▲
│ │               │  ││                          │                              │
  │  LDAP Client  │◀─┤                           ▼
│ │               │  ││    ┌────────┐  ┌──────────────────┐                     │
  └───────────────┘◀ ┼     │        │  │                  │
│ ┌───────────────┐  │└ ─ ─│  TPM   │  │    DB / Cache    │                     │
  │  Himmleblau   │  │     │        │  │                  │
│ │    Client     │◀─┘     └────────┘  └──────────────────┘                     │
  │               │
└ ┴───────────────┴ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┴
```

#### Online/Offline State Machine

The major change that that this diagram may not clearly show is that the online/offline state machine moves into each of
the named clients (excluding files). This also has some future impacts on things like pre-emptive item reloading and
other task scheduling. This will require the backends to "upcall" into the daemon, as the TPM transaction needs to be
passed from the daemon back down to the provider. Alternately, the provider needs to be able to register scheduled tasks
into the daemon with some generic interface.

#### Resolution Flow

The most important change is that with multiple resolvers we need to change how accounts resolve. In pseudo code the
"online" flow (ignoring caches) is:

```
if files.contains(item_id):
    if item_id.is_extensible:
        # This only seeks items from the providers, not files for extensibility.
        item += resolver.get(item_id.extended_from)
    return item

# Providers are sorted by priority.
for provider in providers:
    if provider.contains(item_id)
        return item

return None
```

Key points here:

- One provider is marked as "default".
- Providers are sorted by priority from highest to lowest.
- Default always sorts as "highest".
- The default provider returns items with Name OR SPN.
- Non-default providers always return by SPN.

Once at item is located it is then added to the cache. The provider marks the item with a cache timeout that the cache
respects. The item is also marked to which provider is the _origin_ of the item.

Once an item-id exists in the cache, it may only be serviced by the corresponding origin provider. This prevents an
earlier stacked provider from "hijacking" an item from another provider. Only if the provider indicates the item no
longer exists OR the cache is cleared of that item (either by single item or full clear) can the item change provider as
the item goes through the general resolution path.

If we consider these behaviours now with the cache, the flow becomes:

```
def resolve:
  if files.contains(item_id):
      if item_id.is_extensible:
          # This only seeks items from the providers, not files for extensibility.
          item += resolver.get(item_id.extended_from)
      return item

  resolver.get(item_id)


def resolver.get:
  # Hot Path
  if cache.contains(item):
      if item.expired:
          provider = item.provider
          # refresh if possible
          let refreshed_item = provider.refresh(item)
          match refreshed_item {
             Missing => break; # Bail and let other providers have at it.
             Offline => Return the cached item
             Updated => item = refreshed_item
          };

          return item

  # Cold Path
  #
  # Providers are sorted by priority. Default provider is first.
  #
  # Providers are looped *only* if an item isn't already in
  # the cache in some manner.
  let item = {
    for provider in providers:
        if provider.contains(item_id)
            if provider.is_default():
                item.id = name || spn
            else:
                item.id = spn
            break item
  }

  cache.add(item)

  return None
```

#### Cache and Database Persistence

The existing cache has always been considered ephemeral and able to be deleted at any time. With a move to Domain Join
and other needs for long term persistence our cache must now also include elements that are permanent.

The existing cache of items also is highly limited by the fact that we "rolled our own" db schema and rely on sqlite
heavily.

We should migrate to a primarily in-memory cache, where sqlite is used only for persistence. The sqlite content should
be optionally able to be encrypted by a TPM bound key.

To obfuscate details, the sqlite db should be a single table of key:value where keys are uuids associated to the item.
The uuid is a local detail, not related to the provider.

The cache should move to a concread based concurrent tree which will also allow us to multi-thread the resolver for high
performance deployments. Mail servers is an often requested use case for Kanidm in this space.

#### Extensible Entries

Currently UserToken and GroupTokens are limited and are unable to contain provider specific keys. We should allow a
generic BTreeMap of Key:Values. This will allow providers to extend entries as required

#### Offline Password/Credential Caching

The caching of credentials should move to be a provider specific mechanism supported by the presence of extensible
UserToken entries. This also allows other types of credentials to be stored that can be consumed by the User.

#### Alternate Credential Caching

A usecase is that for application passwords a mail server may wish to cache and locally store the application password.
Only domain joined systems should be capable of this, and need to protect the application password appropriately.
