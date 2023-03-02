
Device Authentication
---------------------

It is common for people to have multiple devices that they wish to access their accounts from. These
devices vary from desktops, laptops, tablets, mobile phones and more. Each of these devices have
different security and trust levels, as well as a variety of input methods.

Historically authentication providers have *not* factored in multiple device classes to
authentication leading to processes that are inconvenient to insecure for humans to handle when they
want to use their account between devices.

Example of a Bad Workflow
=========================

In this example we will consider a user who has a laptop with secure element (ie touchid, tpm)
capable of webauthn, and a phone with a secure element (touchid, etc).

The user signs up to a website example.com, and configures a password and their webauthn
via the secure element from the laptop.

If the user wishes now to authenticate to their account from their phone they are unable to, as
only the password can be moved between the devices. The secure element can not be moved between
the devices.

In this case the user would need to add another method of MFA such as TOTP. This necessitates
the user to install another app (on their laptop or phone) for managing TOTP. This then allows the
user to use TOTP and the Password to "bootstrap" the phone as a device to their account, and they
are then able to enroll the phone's secure element via webauthn. To summarise this process.

* (laptop) Create account with password
* (laptop) Enroll webauthn for laptop SE to account
* (phone/laptop) configure TOTP capable authenticator application
* (laptop) Enroll TOTP to account
* (laptop) Retrieve and send the password to the phone (if machine generated/long/random)
* (phone) Login to website with password + TOTP application
* (phone) Enroll webauthn for phone SE to account
* OPTIONAL - deconfigure TOTP used to bootstrap the phone.

As we can see there is a lot of messing about here and lots of room for confusion and human error.
Looking at this, it's any wonder why people don't like MFA ...

* The user is expected to understand different classes of MFA and how they are device bound or not
* The user must install an extra application capable of TOTP
* The password needs to be sent between devices (phones lack a good keyboard, and typing out a long high entropy password is an error prone task)

To improve this situation there have been different types of "fixes" provided for various issues
in this workflow. Let's explore some of these.

Roaming vs Platform Authenticators
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In our example our laptop and phone both have platform authenticators, which are security devices
bound to the platform (they are inseparable). Rather than using a platform authenticator we *may*
allow a roaming authenticator to be used to bootstrap the phone's platform authenticator. An example
of a roaming authenticator is a yubikey, which can be plugged into the laptop, and then disconnected
and connected to the phone. This changes the steps of the process to be.

* (laptop) Create account with password
* (laptop) Enroll webauthn for laptop SE to account
* (laptop) Enroll webauthn for roaming authenticator to account
* (laptop) Retrieve and send the password to the phone (if machine generated/long/random)
* (phone) Login to website with password + roaming authenticator
* (phone) Enroll webauthn for phone SE to account
* OPTIONAL - deconfigure roaming authenticator used to bootstrap the phone.

OR, if we do not wish to use the platform authenticator of the laptop, relying on the roaming
authenticator for the laptops webauthn:

* (laptop) Create account with password
* (laptop) Enroll webauthn for roaming authenticator to account
* (laptop) Retrieve and send the password to the phone (if machine generated/long/random)
* (phone) Login to website with password + roaming authenticator
* (phone) Enroll webauthn for phone SE to account

While this process does not invole as much fiddling with TOTP, it still has weaknesses.

* The user is expected to own a roaming authenticator capable of working on their phone
* The user is expected to understand different classes of MFA and how they are device bound or not
* The password still needs to be sent between devices

The major issue here is most people do *not own a roaming authenticator* and likely would not (and should
not need to) purchase one just for this process.

Shared Secure Enclave Content
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Given the number of websites that have a poor workflow as above, and that the general population
does not own roaming authenticator, Apple as a vendor with their tight knit ecosystem has begun
to provide a system of sharing platform based credentials between devices signed into the same
Apple id account. Let's assume in our example the user owns a macbook pro and an iphone which are authenticated
to the same Apple id allowing platform credentials to be shared. The process now would look like:

* PRECONFIGURED - Apple id configured allowing platform credentials to be shared.
* (laptop) Create account with password
* (laptop) Enroll webauthn for shared authenticator to account
* (laptop) Retrieve and send the password to the phone (if machine generated/long/random)
* (phone) Login to website with password + shared authenticator

This actually is pretty good! There are still some weaknesses but our work flow is significantly
improved.

* The user needs to be completely on the Apple ecosystem
* The user needs to understand their Apple id features and how platform credential sharing works
* The user MUST use safari as their MacOS device web browser
* The password still needs to be sent between devices (in this case, it could be achieved with keychain via iCloud securely)

The major issue here is the user must be completely on the Apple ecosystem, use only safari as
a browser, and must have enabled keychain sharing. Without these, this functionality does not
work and we are back to requiring a roaming authenticator or TOTP.

It's worth noting in this scenario that if the user is using keychain as a password manager, then
the trust root is *only* in the secure enclave, since the touchid/faceid/pin is used to access the
password manager, and the same touchid/faceid/pin is used to authenticate the webauthn operations.

Summary
^^^^^^^

For most people setting up MFA is an annoying process especially when you want to allow your accounts
to be portable between multiple devices. At it's core, it's a failure of authentication providers
to consider devices as part of their authentication workflow and how humans interact with these
services.

Trusted Device Authentication Design
====================================

In Kanidm we want to solve this in a manner that:

* Does not require the user to be bound to a single manufacturer ecosystem
* Does not require the user to purchase additional hardware
* Does not required external applications to be configured
* Does not required passwords to be shared between devices
* Does provide MFA on the enrolled device
* Does allow the enrolled device to be paused or removed without affecting other credentials

The workflow that we want to achieve is:

* (laptop) Create account with password
* (laptop) Enroll webauthn for laptop SE to account
* (laptop) Request a device to be added to the account, generating a link/qr code
* (phone) scan the qr code OR follow the link provided
* (phone) Enroll webauthn for phone SE to account

In more precise technical details for Kanidm:

* (laptop) The user is authenticated to Kanidm
* (laptop) The user requests a new trusted device to be added to the account, providing the name of the device they are enrolling
* (kanidm) An encrypted token containing the device name, account uuid, a uuid and a time limit is generated
* (kanidm) The encrypted token is appended to the enrollment uri and returned
* (laptop) The enrollment uri with token is presented for copy-paste AND rendered as a QR code for scanning
* (phone) The enrollment uri is followed via the link or qr code
* (phone) The user is asked to consent that they are about to enroll a device to their account
* (kanidm) The token is decrypted and validated.
* (kanidm) The token time limit is asserted to not be expired.
* (kanidm) The token uuid is checked against the account to ensure the device is not already enrolled
* (kanidm) A webauthn registration request with user-verification required is generated and returned
* (phone) The user follows the presented device prompts to enroll the device
* (kanidm) The token uuid is checked against the account to ensure the device is not already enrolled
* (kanidm) The webauthn credential is registered as a device to the account
* (phone) The user is redirected to login from their device


Considerations
==============

Reuse of the device enrollment URI
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To prevent the URI being used to enroll multiple devices, the uuid is generated in the token, and
used to create the credential uuid. This allows validation that only a single device credential
could be created from a single request. In the case of a replicated system, if multiple devices
were created on different replicas, the created uuid will conflict and cause only a single device
credential to remain. In this situation we MAY consider that on conflict we delete the conflicting
device to remove possibility of compromise due to link disclosure.

Reuse of this URI is also mitigated by the time limit built into the token itself.

Device enrollments do not require a password
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On a mobile device we should NOT require a password to be entered to the account. This is because
the password rules we attempt to enforce in Kanidm should create passwords that are *not* memorisable
meaning that the user is likely to store this in a password manager. Since the password manager
is already on the mobile device, then compromise of the device yields access to the password, nullifying
it's security benefit.

Since we require UV required, this means the credential is a self contained MFA of possession of the
device, and authentication to the device (biometric, password/pin). Devices today contain hardware
rate limiting to prevent bruteforce of pins and other protections to prevent biometric extractions.

Additionally, if the device were compromised such that an attacker could login to the device bypassing
these requirements, the attacker then has access to the cookies of the device and already gains access
to the session without needing the password, meaning that the device security is critical in this environment.
A password defends against none of these attacks, and only adds extra steps for a user, and so it is not considered
a required element for a secure authentication from a trusted device.

Binding Credentials to Sessions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As this enables sessions to be from different devices and initiated by different credentials, if
a user on the laptop disableds the credentials of an enrolled device, then any session that used
that credential should also be considered invalidated.

Future Ideas
============

Require Acknowledgement of the New Credential
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After the device is enrolled, we *may* enroll the credential initially disabled, and the user on
the laptop must then interact to allow the device to be "usable" for future authentications. This
would assist to mitigate risk of token URI disclosure, and helps to involve the user in asserting
consent and knowledge of which devices are trusted to their account for platform authenticator
authentication.

A risk of this is replication delay, where if the laptop and phone are interacting with disjoint
Kanidm servers, then a delay may be experienced between the enrollment of the phone and the laptop
from being able to see that credential to enable it. This may lead to user confusion or frustration.

As the user must have authenticated to the laptop to generate the URI to sign in a new device, the
URI generated may be considered trusted and so access to that URI implies that the device enrolled
is highly likely be in the possession of the account owner. Since this is a timed limited link, this
further mitigates risk of misuse of this.

A example of this in the wild is the QR codes generated by fastmail for device email access - these
can only be created by an authenticated account, and they do not require post-enrollment interaction
to enable as the model assumes that access to the link or QR code implies that you are the account
owner who generated that content.

References
==========

https://pages.nist.gov/800-63-3/sp800-63b.html
