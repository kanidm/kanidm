# Interpersonal Identity Verification
### Inspired by GitHub user [Charcol](https://github.com/kanidm/kanidm/issues/337)

___
## Motivation
Social engineering scams over the phone can be used to manipulate users into unknowingly giving up information to third parties with malicious intent. These work when at least one party isn't unable to verify the identity of the other party, leaving them vulnerable to malicious behavior. However, phone calls can still provide value outside of direct personal contacts, such as through business connections or contact between disconnected branches of the same corporation. We can combat this type of scam by providing users a way to verify the identities of opposing parties, enabling these cases to function securely.
___
## Existing solutions
Address both interpersonal calls and intracorporation calls. (Is that a word? I don't know)

The issue of verifying identities when a company initiates contact via phone is still mostly unsolved, so the existing solution is to avoid phone calls from companies, and only trust them if the user is the caller and the company is the receiver. While this solution works, it doesn't address the issue that scammers will still scam through phone calls, and that if a user picks up the phone, they have no reasonable method to verify the authenticity of the call. For example, it is unsafe to trust anything that an unknown caller claims, such as going to a website to "verify" identities.
___
## Proposed solution
Many companies have various branches that operate different parts of the company. For example, take the following parties:
* User, an individual user
* Corp, the big name corporation the user knows of
* Support, a branch of Corp that handles tech support, and is trusted by Corp

If Corp wants to contact User, the CEO wouldn't call them directly. Instead, they would reach out through Support, which lives in a tightly vetted whitelist of callers approved by Corp. Support calls User, and User must verify that Support is a trusted branch of Corp, with only the knowledge that Support supposedly is trusted by Corp. User doesn't care about the exact identity of the caller, only that they are trusted by Corp, since no scam company could make Corp's tightly vetted whitelist of trusted callers. Since they're not contacting Corp directly, there are four key connections that must be verified:
1. User needs to know the Support is trusted by Corp.
2. Corp needs to verify the Support is trusted.
3. User must verify their request for verification was directly verified by Corp and nobody else.
4. User needs to know the response received is not a replay attack, and that the response received is unique to their request for verification.

This can be accomplished by sending a nonce encrypted message to Corp, and then sending it back to User with a different encryption pattern. If the message received is the same as the message sent, then all identities are verified. Since the message sent is always unique, replay attacks are meaningless.

### Kanidm Server setup
In this situation, there are two Kanidm instances which can be remote from each other:
* X, local to Corp
* Y, local to Support and User

All users (individuals, companies, company branches, etc.) of this verification system will have an existing Ed25519 key stored as an attribute on their account entry on the Kanidm server. This key will not change (unless for very good reason), and the private key is only known by the exact account without exception. Since these keys are linked to accounts, we can safely find the authentic public key of any user we want, without real time communication between servers around the world. Additionally, all trusted callers for Corp will also have a copy of their information (name, public key) linked to Corp's credentials on server X. This is acceptable since there are limited trusted callers for Corp. Furthermore, server Y will store a copy of Corp's information (name, public key) locally. This is acceptable, since there are limited large corporations. It's also important to note that Corp doesn't need to store any information about any particular User on server X.

In summary:
* X stores Corp, which holds name and public key of Support
* Y stores User and Support, and also name and public key of Corp

### Methodology
#### Individual user (User)
1. User generates random, unique message, and stores a copy for later.
2. User encrypts message with their private key, ensuring that the end target (Corp) must acknowledge them when modifying the result.
3. User encrypts result with Corp public key from server Y, preventing Support from decrypting to get the original message.
4. User sends result to Support via phone call.

#### Trusted caller (Support)
5. Support encrypts message with Support private key from server Y, ensuring that Corp knows it's from them.
6. Support sends result _and_ User public key to Corp via other channel, like WiFi.

#### Big-name corporation (Corp)
7. Corp recognizes Support as valid, so proceeds.
8. Corp decrypts message with Support public key from server X.
9. Corp decrypts result with Corp private key from server X.
10. Corp decrypts result with User public key from message. Corp now has the original message.

11. Corp encrypts result with Corp private key from server X, acting as a signature from Corp directly.
12. Corp encrypts result with user public key from message, preventing Support from decrypting the original message.
13. Corp encrypts result with Support public key from server X, verifying validity of Support.
14. Corp sends result to Support.

#### Trusted caller (Support)
15. Support decrypts message with Support private key from server Y, and can't decrypted further.
16. Support sends result to User via phone call.

#### Individual user (User)
17. User decrypts result with User private key from server Y.
18. User decrypts message with Corp public key from server Y.
19. User verifies that result is the same as the original message generated.

It's important to note that Support has no obligation to send User's public key to Corp, but then Corp would not be able to recover the original message, and the verification would fail because garbage in, garbage out. Therefore, the verification can only pass if Support sends a valid copy of User's public key to Corp. Following this algorithm, Support can never decrypt the message being sent between the User and Corp, and the Corp verifies and signs User's unique message. 

The key aspect here is that the message being sent and received by User is the same, but encrypted in a different order. This means that it's essential to use a non-communitive cryptosystem.
___
## Readable hashes
An important aspect of this process is that users are able to read their hashes over the phone. To increase the readability of these hashes, I propose using English sentences to encode hashes. Since Ed25519 hashes create 512-bit signatures, we would need 36 words if we had a word bank with 20,000 words. If we followed a basic sentence structure to make these envoding more natural to read, where each sentence could be made up of 5 words, we could encode a hashing in ~7 simple sentences, which is incredible for the security we are ensuring.

TODO: this requires 20,000 words for each object in the sentence, so not quite feasible?
___
## User interface
When the user receives a call, they ask for the callers root company. They then navigate and log into the Kanidm web interface on their smartphone, running on server Y, search up the root company, and click a button that does steps 1-3, and displays the result to the user in the number system specified above. This hash is displayed to the user, where they can transmit the code directly over the phone since it should be relatively short. The caller enters these numbers into their end, where steps 5-15 are performed remotely from the user. Once the caller reads the resulting hash back to the user, they will enter this back into the web interface, which performs steps 17-19, and tells the user if the verification was successful. This allows the user to verify that the caller on the other end of the phone is the company that the corporation sees and validates.

This system is only safe for when the trusted caller is the initiator of contact, since otherwise a scam could act as a man-in-the-middle between a user and a trusted caller by initiating contact with a trusted caller and having them verify a hash provided by a potential scam victim. However, this is okay because if the user is the initiator of the call, they have no need to verify the identity of the other side because they (hopefully) would have obtained the number through a trusted source, such as an official website.


# Ongoing feedback:
* Ed25519 Rust implementation: [ed25519-dalek](https://crates.io/crates/ed25519-dalek)

I think you are actually solving a different problem here maybe. I think that the intent is say ... if I from software engineering call someone in finance, and we want to verify each other's as individuals within a single corp.
* Problem I am solving: verify each others' identities within a single corp.

What you have here though, is a bit closer to say ... you have a support person, who needs to be verified, so there needs to be a separate "support group" verification credential that they can access through membership of that group. Which is similar, but different.
* Problem I say I'm solving: Individual verifies membership of support group through Corp group.

For example, it's common that to do this kind of thing, you need each party to know the identity of the other, and it may not be appropriate for a support staff member to hand out their username or identity. So you want the user to verify the support group and the member of that group can verify the user. Because then you are verifying their legitimacy to the membership.
* User and support group verification

But I think that should be a second stage. For now, I think you may benefit to rework the example for "user 1 speaking to user 2", and then doing group membership verification is a stage 2 (but probably has a lot of overlap).
* MVP: User 1 speaks to user 2
* End goal: group membership verification