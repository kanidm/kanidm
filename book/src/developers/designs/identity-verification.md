## Draft proposal for and Identity verification system with an out of bound challenge

Implements #337

### Goal:

Providing a way to allow 2 subject to authenticate each other without prior knowledge of each other

### Assumptions:

Both subjects will have to be connected to a Kanidm server (not necessarily the same), and the servers will have to mutually trust each other; the trust bond must be established beforehand.

## Achieving mutual trust between servers:

The way two Kanidm servers create a bond of trust is in many ways similar to the way SAML establishes trust between entities belonging to the same federation.

- Two servers interested in creating such trust bond will perform a DH key exchange to create a shared secret, encrypting the communication with TLS
- a KBKDF, such as the [Scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt) KDF will be used to generate a secret key from the shared secret,
- the secret key will stored in the database of both servers,
- Finally, they both store the current unix time in the database (which will be referred as _T0_); it will be used for TOTP generation. Every time a new authentication request is received, the _token-time_ will be equal to the number of 30 seconds interval that have passed since _T0_, ie _token-time = (current_unix_time - T0) / 30_.

Note that this design will allow users to mutually authenticate each other only if their servers already share a trust bond. "Manually" building trust between servers could become very cumbersome if we want to support a large number of servers, probably a smarter design will be required in the future.

## User flow:

### Disclaimer: the following user flow assumes that the servers have already established a trust bond.

Let's suppose that Alice and Bob want to mutually authenticate each other, then the following steps will be performed:

1. Alice shares her email and server domain name with Bob and asks for Bob's email and server domain name
1. Bob receives Alice's email and domain name and replies by sending his email and domain name
1. Both Alice and Bob insert the acquired information in their Kanidm client.
1. Their servers compute a HMAC hash using the secret key and the _token-time_ associated with the server identified by the domain name provided by the user, and both of the users email address, placing the authentication initiator email first.
   That would mean that both of them will compute HMAC(secret_key, token-time, Alice_email, Bob_email)
1. The servers will then process the HMAC to shorten it to ~6 digits and then send an email to their users containing the processed HMAC.

## Possible weaknesses and general notes:

First of all, this designed is based on the assumption that the secret key is not leaked, and that both the servers involved are not compromised. If either of these assumptions is broken, then impersonation attacks would indeed be possible.
Properly configured access control _must_ ensure that hashes are computed only with the email address of the user that is currently logged in, otherwise it would be possible for an attacker having access to a kanidm server to impersonate any user within that server.
Also this design is vulnerable to replay attacks, but I don't think it's a big issue since the token-time is only valid for 30 seconds, and the attacker would have to know the secret key.
It would also be helpful for a server to provide some basic info regarding the other user's server, such as the the company/organization associated with the server (if any), and the server's domain name, to help the user understand if the server is legitimate or not.
