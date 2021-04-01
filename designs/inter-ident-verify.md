# Interpersonal Identity Verification
### Inspired by GitHub user [Charcol](https://github.com/kanidm/kanidm/issues/337)

___
## Motivation
Social engineering scams over the phone can be used to manipulate users into unknowingly giving up information to third parties with malicious intent. The primary issue is that one party does not know the identity of the other, while the other already knows or doesn't particularly care. If we can allow at least one party to verify the identity of the other, then we can solve this issue.
___
## Existing solutions
The issue of verifying identities when a company initiates contact via phone is still mostly unsolved, so the existing solution is to avoid phone calls from companies, and only trust them if the user is the caller and the company is the receiver. While this solution works, it doesn't address the issue that scammers will still scam through phone calls, and that if a user picks up the phone, they have no reasonable method to verify the authenticity of the call. For example, it is unsafe to trust anything that an unknown caller claims, such as going to a website to "verify" identities.
___
## Proposed solution
Many companies have various branches that operate different parts of the company. For example, take the following parties:
* U, the individual user
* A, the big name corporation the user knows of
* S, a branch of A that handles tech support, and is trusted by A

If A wanted to contact U, the CEO wouldn't call them directly. Instead, they would reach out through S, which lives in a tightly vetted whitelist of callers approved by A. S calls U, and U must verify that S is a trusted branch of A, with only the knowledge that S supposedly is trusted by A. U doesn't care about the exact identity of the caller, only that they are trusted by A, since no scam company could make A's tightly vetted whitelist of trusted callers. Since they're not contacting A directly, there are four key connections that must be verified:
1. U needs to know the S is trusted by A.
2. A needs to verify the S is trusted.
3. U must verify their request for verification was directly verified by A and nobody else.
4. U needs to know the response received is not a replay attack, and that the response received is unique to their request for verification.

This can be accomplished by sending a nonce encrypted message to A, and then sending it back to U with a different encryption pattern. If the message received is the same as the message sent, then all identities are verified. Since the message sent is always unique, replay attacks are meaningless.

### Kanidm Server setup
In this situation, there are two Kanidm instances which can be remote from each other:
* X, local to A
* Y, local to S and U

All users (individuals, companies, company branches, etc.) of this verification system will have an existing RSA key linked to their Kanidm credentials on their local servers. This key will not change (unless for very good reason), and the private key is only known by the exact account without exception. Since these keys are linked to credentials, we can safely find the authentic public key of any user we want, without real time communication between servers around the world. Additionally, all trusted callers for A will also have a copy of their information (name, public key) linked to A's credentials on server X. This is acceptable since there are limited trusted callers for A. Furthermore, server Y will store a copy of A's information (name, public key) locally. This is acceptable, since there are limited large corporations. It's also important to note that A doesn't need to store any information about any particular U on server X.

In summary:
* X stores A, which holds name and public key of S
* Y stores U and S, and also name and public key of A

### Methodology
#### Individual user (U)
1. U generates random, unique message, and stores a copy for later.
2. U encrypts message with their private key, ensuring that the end target (A) must acknowledge them when modifying the result.
3. U encrypts result with A public key from server Y, preventing S from decrypting to get the original message.
4. U sends result to S via phone call.

#### Trusted caller (S)
5. S encrypts message with S private key from server Y, ensuring that A knows it's from them.
6. S sends result _and_ U public key to A via other channel, like WiFi.

#### Big-name corporation (A)
7. A recognizes S as valid, so proceeds.
8. A decrypts message with S public key from server X.
9. A decrypts result with A private key from server X.
10. A decrypts result with U public key from message. A now has the original message.

11. A encrypts result with A private key from server X, acting as a signature from A directly.
12. A encrypts result with user public key from message, preventing S from decrypting the original message.
13. A encrypts result with S public key from server X, verifying validity of S.
14. A sends result to S.

#### Trusted caller (S)
15. S decrypts message with S private key from server Y, and can't decrypted further.
16. S sends result to U via phone call.

#### Individual user (U)
17. U decrypts result with U private key from server Y.
18. U decrypts message with A public key from server Y.
19. U verifies that result is the same as the original message generated.

It's important to note that S has no obligation to send U's public key to A, but then A would not be able to recover the original message, and the verification would fail because garbage in, garbage out. Therefore, the verification can only pass if S sends a valid copy of U's public key to A. Following this algorithm, S can never decrypt the message being sent between the U and the A, and the A verifies and signs U's unique message. 

The key aspect here is that the message being sent and received by U is the same, but encrypted in a different order. This means that it's essential to use a non-communitive cryptosystem.
___
## Readable hashes
An important aspect of this process is that users are able to read their hashes over the phone. To increase the readability of these hashes, I propose a modified number representation system similar to hexadecimal where each digit has 64 variants, `{a-z, A-Z, 0-9, *, #}`, allowing 6-bits of information to be stored per digit. With only 6 digits in this number system, we can represent up to 68,719,476,736, covering all 32-bit numbers. With 11 digits, we can represent up to 7.38e19, covering all 64-bit numbers. For shorter messages, this should be enough to read these values over voice.
___
## User interface
When the user receives a call, they ask for the callers root company. They then navigate and log into the Kanidm web interface on their smartphone, running on server Y, search up the root company, and click a button that does steps 1-3, and displays the result to the user in the number system specified above. This hash is displayed to the user, where they can transmit the code directly over the phone since it should be relatively short. The caller enters these numbers into their end, where steps 5-15 are performed remotely from the user. Once the caller reads the resulting hash back to the user, they will enter this back into the web interface, which performs steps 17-19, and tells the user if the verification was successful. This allows the user to verify that the caller on the other end of the phone is the company that the corporation sees and validates.

This system is only safe for when the trusted caller is the initiator of contact, since otherwise a scam could act as a man-in-the-middle between a user and a trusted caller by initiating contact with a trusted caller and having them verify a hash provided by a potential scam victim. However, this is okay because if the user is the initiator of the call, they have no need to verify the identity of the other side because they (hopefully) would have obtained the number through a trusted source, such as an official website.

