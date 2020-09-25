Account Policy and Lockouts
---------------------------

For accounts we need to be able to define securite constraints and limits to prevent malicious use
or attacks from succeeding. While these attacks may have similar sources or goals, the defences
to them may vary.

A list (not comprehensive) of these include:

* Credential Stuffing
* Phishing (Site Impersonation)
* Key Logging / Physical Discovery
* Common Password / Spray
* Brute Force

Credential Policies
===================

As the majority of the attacks listed can be prevented with TOTP, and all effectively defeated with
Webauthn, it's essential that policies can exist that allow an administrator to set requirements
on accounts to what level of authentication they require to protect resources.

Credential Polcies are inherited from groups, as groups grant rights and claims to other resources.
Since it is these resources and privileges we wish to protect, logically the credential policy becomes
part of the group that should be protected.

When multiple credential policies exist that may be conflicting, the "stricter" policy is enforced
as a group in the set requires it.

The strength of credentials is today sorted as:

* (weakest)
* Password
* GeneratedPassword
* Webauthn (with out verification)
* TOTP + Password
* Webauthn + Password
* WebauthnVerified
* WebauthnVerified + Password
* (strongest)

Rate Limiting
======================

Rate Limiting is the process of delaying authentication responses to slow the number of attempts
against an account to deter attackers. This is often used to prevent attackers from bruteforcing
passwords at a high rate.

The best defence again these attacks is MFA. Due to the design of Kanidm, the second factor
(ie the webauthn token or the otp) is always checked *before* the password, meaning that the
attacker is unable to attack the password *unless* they also have the corresponding MFA token.

However, not all accounts will have MFA enabled, which means that defences are still required to
prevent these attacks for password-only accounts. Accounts protected with TOTP must also be rate
limited according to NIST sp800 63b. Webauthn does *not* require ratelimiting as a single factor
or multi factor device.

As an account can only have a single proceeding authentication session at a time, this provides
serialisation and rate limiting per account of the service. However, as Kanidm will in the future
support multiple, distributed replicas, we must consider an architecture that allows eventually
consistent behaviour.

NIST SP800 63b recommends that after 100 failed attempts that the account be locked. Due to the
eventually consistent nature, this poses a challenge, namely that:

* Synchronising this account lock may not be instant, allowing further attempts on parallel servers.
* That read only servers may exist in the system which can not write to the entries.
* A malicious party may intentionally send incorrect values to force an account to lock.

To account for this for accounts with TOTP:

* After an 5 incorrect TOTP's within the time window, the account is locked for 60 seconds. This prevents bruteforce of the TOTP.

For accounts with password-only:

* After 5 incorrect attempts the account is rate limited by an increasing time window within the API. This limit delays the response to the auth (regardless of success)
* After X attempts, the account is soft locked on the affected server only for a time window of Y increasing up to Z.
* If the attempts continue, the account is hard locked and signalled to an external system that this has occured.

The value of X should be less than 100, so that the NIST guidelines can be met. This is beacuse when there are
many replicas, each replica maintains it's own locking state, so "eventually" as each replica is attempted to be
bruteforced, then they will all eventually soft lock the account. In larger environments, we require
external signalling to coordinate the locking of the account.

In the future, this can also be informed by:

* IP/GEOIP from past login's to determine if the behaviour is expected.
* HTTP/Browser ID to determine if it's "likely" the person in question.

These can then assist with choosing to lock or allow an auth to proceed in the face of an attack.

FUTURE:
* Delayed notification about suspect login?

Ratelimit on unix auth

Hard Lock + Expiry/Active Time Limits
=====================================

It must be possible to expire an account so it no longer operates (IE temporary contractor) or
accounts that can only operate after a known point in time (Student enrollments and their course
commencment date).

This expiry must exist at the account level, but also on issued token/api password levels. This allows revocation of
individual tokens, but also the expiry of the account and all tokens as a whole. This expiry may be
undone, allowing the credentials to become valid once again.

On the account, this is represented by two date times. AuthAllowFrom and AuthAllowUntil. These
are stored on the server in unix epoch to account for timezones and geographic distribution.

* Interaction with already issued tokens.
    * it prevents them from working?

Must prevent creation of radius auth tokens

Must prevent login via unix.

Application Passwords / Issued Oauth Tokens
===========================================

* Relates to claims
* Need their own expirys
* Need ratelimit as above?





