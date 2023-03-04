## Draft proposal for and Identity verification system with an out of band challenge

Implements #337

### Goal:

Providing a way to allow 2 subject to authenticate each other without prior knowledge of each other

### Assumptions:

Both subjects will have to be connected to a Kanidm server (not necessarily the same or under the same domain), and the servers will have to mutually trust each other; the trust bond must be established beforehand.

### High level overview:

The idea is to associate a [ECDH](https://docs.rs/openssl/latest/openssl/pkey_ctx/struct.PkeyCtxRef.html#method.derive_set_peer) public/secret key pair with each user and make each server share a token time and a secret. If two users want to authenticate each other, their private key will be used to encrypt a HMAC hash of the token time and the secret shared between their servers, and the servers will use the public key to decrypt the hash and verify if it matches with the one computed locally. We could also allow users to use their public key to encrypt whatever they want, and then use their private key to decrypt it, providing a more flexible out of band challenge.

### Trust bond between servers:

The way two Kanidm servers create a bond of trust is in many ways similar to the way SAML establishes trust between entities belonging to the same federation.
Depending on wether the servers belong to the same domain or not, the process will be slightly different.
Since dealing with different domains would add some degrees of complexity, the initial focus will be on the case where the servers belong to the same domain.

### Servers belonging to the same domain:

```
┌──────────────────────────────────────────┐
│Domain A                                  │
│┌────────────┐              ┌────────────┐│
││            │              │            ││
││            │              │            ││
││            │              │            ││
││  Server 1  │◀────────────▶│  Server 2  ││
││            │              │            ││
││            │              │            ││
││            │              │            ││
│└────────────┘              └────────────┘│
│                                          │
└──────────────────────────────────────────┘
```

- Two servers interested in creating such trust bond will perform a ECDH key exchange to create a shared secret, encrypting the communication with TLS
- a KBKDF, such as the [Scrypt](https://docs.rs/openssl/latest/openssl/pkey_ctx/struct.PkeyCtxRef.html#method.derive_set_peer) KDF will be used to generate a secret key from the shared secret,
- the secret key will stored in the database of both servers,
- Finally, they both store the current unix time in the database (which will be referred as _T0_); it will be used for TOTP generation. Every time a new authentication request is received, the _token-time_ will be equal to the number of 30 seconds interval that have passed since _T0_, ie _token-time = (current_unix_time - T0) / 30_.

Note that this design will allow users to mutually authenticate each other only if their servers already share a trust bond. "Manually" building trust between servers could become very cumbersome if we want to support a large number of servers, probably a smarter design will be required in the future.

### Servers belonging to different domains:

// TODO

```
 ┌──────────────────────────────────────────┐
 │Domain A                                  │
 │┌────────────┐              ┌────────────┐│
 ││            │              │            ││
 ││            │              │            ││
 ││            │              │            ││
 ││  Server 1  │◀────────────▶│  Server 2  ││
 ││            │              │            ││
 ││            │              │            ││
 ││            │              │            ││
 │└────────────┘              └────────────┘│
 │                                          │
 └──────────────────────────────────────────┘
                       ▲
                       │
                       │
                       │
                       │
                       ▼
 ┌──────────────────────────────────────────┐
 │Domain B                                  │
 │┌────────────┐              ┌────────────┐│
 ││            │              │            ││
 ││            │              │            ││
 ││            │              │            ││
 ││  Server 3  │◀────────────▶│  Server 4  ││
 ││            │              │            ││
 ││            │              │            ││
 ││            │              │            ││
 │└────────────┘              └────────────┘│
 │                                          │
 └──────────────────────────────────────────┘
```

## User flows:

### Disclaimer: the following user flows assume that the servers have already established a trust bond.

- ### Servers belonging to the same domain:

  Since the servers belong to the same domain, it will be safe to replicate the database between them, and therefore all the pub/secrets keys of every person will be available on both servers.
  Let's suppose that Alice and Bob want to mutually authenticate each other, then the following steps will be performed:

  1. Alice shares her SPN with Bob and asks for Bob's SPN
  1. Bob receives Alice's SPN and replies by sending his SPN
  1. Both Alice and Bob insert the acquired information in their Kanidm client.
  1. Their servers compute a HMAC hash using the secret key and the _token-time_ associated with the server identified by the domain name provided by the user, and then to shorten it to ~6 digits
  1. The servers will then encrypt the hash using the private key of the respective users.
  1. The encrypted hash will be transformed in a more human readable format for the users, so that the users will be able to easily communicate it to each other, ie in a phone call or in a chat.
  1. The users will then decrypt the message using the public key associated with the SPN they received, and will compare the decrypted hash with the one computed by their server.

  ```
                  ┌──────────────────────────────────────────┐
                  │Domain A                                  │
                  │┌────────────┐              ┌────────────┐│
                  ││            │              │            ││
                  ││            │              │            ││
  ┌──────────┐    ││            │              │            ││    ┌──────────┐
  │  Alice   │    ││  Server 1  │◀────────────▶│  Server 2  ││    │   Bob    │
  └──────────┘    ││            │              │            ││    └──────────┘
                  ││            │              │            ││
                  ││            │              │            ││
                  │└────────────┘              └────────────┘│
                  │                                          │
                  └──────────────────────────────────────────┘
  ```

- ### Servers belonging to different domains:
  This case is very similar to the previous one, except that the servers don't belong to the same domain, and therefore the database is not replicated between them. In this case, the servers will stil have to share all the users' public keys, but the way that will be achieved is (for now) out of the scope of this document.
  ```
                  ┌──────────────────────────────────────────┐
                  │Domain A                                  │
                  │┌────────────┐              ┌────────────┐│
                  ││            │              │            ││
                  ││            │              │            ││
  ┌──────────┐    ││            │              │            ││
  │  Alice   │    ││  Server 1  │◀────────────▶│  Server 2  ││
  └──────────┘    ││            │              │            ││
                  ││            │              │            ││
                  ││            │              │            ││
                  │└────────────┘              └────────────┘│
                  │                                          │
                  └──────────────────────────────────────────┘
                                        ▲
                                        │
                                        │
                                        │
                                        │
                                        ▼
                  ┌──────────────────────────────────────────┐
                  │Domain B                                  │
                  │┌────────────┐              ┌────────────┐│
                  ││            │              │            ││
                  ││            │              │            ││
                  ││            │              │            ││   ┌──────────┐
                  ││  Server 3  │◀────────────▶│  Server 4  ││   │   Bob    │
                  ││            │              │            ││   └──────────┘
                  ││            │              │            ││
                  ││            │              │            ││
                  │└────────────┘              └────────────┘│
                  │                                          │
                  └──────────────────────────────────────────┘
  ```

## Possible weaknesses and general notes:

First of all, this designed is based on the assumption that the secret key is not leaked, and that both the servers involved are not compromised. If either of these assumptions is broken, then impersonation attacks would indeed be possible.
It would also be helpful for a server to provide some basic info regarding the other user's server, such as the the company/organization associated with the server (if any), and the server's domain name, to help the user understand if the server is legitimate or not.
