## Draft proposal for and Identity verification system with an out of band challenge

Implements #337

### Goal:

Providing a way to allow 2 subject to authenticate each other using an out of band challenge.

### Assumptions:

Both subjects will have to be connected to a Kanidm server (not necessarily the same or under the same domain), and the servers will have to mutually trust each other; the trust bond must be established beforehand.

### High level overview:

The idea is to associate a [ECDH](https://docs.rs/openssl/latest/openssl/pkey_ctx/struct.PkeyCtxRef.html#method.derive_set_peer) public/secret key pair with each user. If two users want to authenticate each other, their private key and the other subject's public keys will be used to encrypt an HMAC message that uses both of the users UUID. Kanidm currently doesn't support ECDH keys for users, but once they will be implemented we will be able to use them for other purposes as well.

### Trust bond between servers:

The way two Kanidm servers create a bond of trust is by partially replicating the database between them, specifically sharing the public keys of all the users and their UUID. This will allow the servers to encrypt and decrypt messages using the public and private keys of the users, guaranteeing that the messages are coming from the users themselves.

## Different types of trust bonds:

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
```

In this case the servers will be a full replica of each other, and therefore they will share the same database, thus having access to the private and public keys of all the users.

### Servers belonging to different domains:

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

  Since the servers belong to the same domain they will have a replica of the same database, and therefore all the pub/secrets keys of every person will be available on both servers.
  Let's suppose that Alice and Bob want to mutually authenticate each other, then the following steps will be performed:

  1. Alice shares her SPN with Bob and asks for Bob's SPN
  1. Bob receives Alice's SPN and replies by sending his SPN
  1. Both Alice and Bob insert the acquired information in their Kanidm client.
  1. The servers derive a key from their users' UUIDs
  1. The servers compute a HMAC hash using the derived key as key, the current time and the user's UUID
  1. The servers will then encrypt the hash using the private key of the respective users and the public key of the other user.
  1. The encrypted hash will be transformed in a more human readable format for the users, so that they will be able to easily communicate it to each other, ie in a phone call or in a chat.
  1. The servers will then decrypt the message using their users' private key and the public key associated with the SPN they received, and will compare the decrypted hash with the one computed locally.

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
  This case is very similar to the previous one, except that the servers don't belong to the same domain, and therefore the database is not fully replicated between them. In this case, the servers will stil have to share all the users' UUIDs and also their public keys.
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

## General notes:

It would also be helpful for a server to provide some basic info regarding the other user's server, such as the the company/organization associated with the server (if any), and the server's domain name, to help the user understand if the server is legitimate or not.
