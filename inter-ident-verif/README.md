# Interpersonal Identity Verification
### Inspired by GitHub user [Charcoal](https://github.com/kanidm/kanidm/issues/337)

___
## Motivation
Social engineering scams over the phone can be used to manipulate users into unknowingly giving up information to third parties with malicious intent. The primary issue is that one party does not know the identity of the other, while the other already knows or doesn't particularly care. If we can allow at least one party to verify the identity of the other, then we can solve this issue.
___
## Existing solutions
The issue of verifying identities when a company initiates contact via phone is still mostly unsolved, so the existing solution is to avoid phone calls from companies, and only trust them if the user is the caller and the company is the receiver. While this solution works, it doesn't address the issue that scammers will still scam through phone calls, and that if a user picks up the phone, they have no reasonable method to verify the authenticity of the call. For example, it is unsafe to trust anything that an unknown caller claims, such as going to a website to "verify" identities.
___
## Proposed solution
Many companies have various branches that operate different parts of the company. For example, if Apple Tech Support were to call you, it likely wouldn't be Tim Cook on the other end. Instead, it would be some branch of Apple that put on a tightly vetted list of Apple-trusted callers. If a caller calls a user and the user needs to verify that branch is a trusted Apple caller, they need a way to verify this with only the knowledge that the caller is supposedly an Apple-verified source. This is where Kanidm comes into play.

All users (individuals, companies, company branches, etc.) of this verification system will have an existing RSA key linked to their Kanidm credentials on the servers. This key will not change (unless for very good reason), and the private key is only known by the exact account without exception. Since these keys are linked to credentials, we can safely find the authentic public key of any user we want, without real time communication between servers around the world.

Say Apple Tech Support is calling a user. They claim to work for Apple, and the user wants to verify. The user doesn't care about the exact identity of the caller, only that they are Apple-trusted, since no scam company could make Apple's tightly vetted list of trusted branches. Since they're not contacting Apple directly, there are three key connections that must be verified:
1. The user needs to know the caller is Apple-trusted.
2. Apple needs to verify the caller is trusted.
3. The user must verify their request for verification was directly verified by Apple and nobody else.

This can be accomplished by sending an encrypted message to Apple, and then sending it back to the user with a different encryption pattern. If the message received is the same as the message sent, then all identities are verified. These guarentees can be made with the following messaging pattern:

### User
1. User generates random, unique message, and stores a copy for later.
2. User encrypts message with their private key, ensuring that the end target (Apple) must acknowledge them when modifying the result.
3. User encrypts result with Apple public key, preventing the caller from decrypting to get the original message.
4. User sends result to Apple Tech Support.

### Apple Tech Support
5. Apple Tech Support encrypts message with Apple Tech Support private key, ensuring that Apple knows it's from them.
6. Apple Tech Support sends result to Apple.

### Apple
7. Apple recognizes Apple Tech Support as valid, so proceeds.
8. Apple decrypts message with Apple Tech Support public key.
9. Apple decrypts result with Apple private key.
10. Apple decrypts result with user public key, which was previously protected by Apple RSA key. Apple now has the original message.

11. Apple encrypts result with Apple private key, acting as a signature from Apple directly.
12. Apple encrypts result with user public key, preventing the caller from decrypting the original message.
13. Apple encrypts result with Apple Tech Support public key, verifying validity of trusted caller.
14. Apple sends result to Apple Tech Support.

### Apple Tech Support
15. Apple Tech Support decrypts message with Apple Tech Support private key, and can't decrypted further.
16. Apple Tech Support sends result to user.

### User
17. User decrypts result with user private key.
18. User decrypts message with Apple public key.
19. User verifies that result is the same as the original message generated.

Following this algorithm, the caller can never decrypt the message being sent between the user and the main company, and the main company verifies and signs the users unique message.

The key aspect here is that the message being sent and received by the user is the same, but encrypted in a different order. This means that it's essential to use a non-communitive cryptosystem.
___
## Readable hashes
An important aspect of this process is that users are able to read their hashes over the phone. To increase the readability of these hashes, I propose a modified number representation system similar to hexadecimal where each digit has 64 variants, `{a-z, A-Z, 0-9, *, #}`, allowing 6-bits of information to be stored per digit. With only 6 digits in this number system, we can represent up to 68,719,476,736, covering all 32-bit numbers. With 11 digits, we can represent up to 7.38e19, covering all 64-bit numbers. For shorter messages, this should be enough to read these values over voice.
___
## User interface
When the user receives a call, they ask for the callers root company. They then navigate and log into the Kanidm web interface on their smartphone, search up the root company, and click a button that does steps 1-3, and displays the result to the user in the number system specified above. This code is read over the phone, where 5-15 are performed remotely for the user. Once the caller reads the resulting message back to the user, they will enter this back into the web interface, which performs steps 17-19, and tells the user if the verification was successful.

