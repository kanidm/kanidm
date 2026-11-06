# Account Signup

Account signup allows public users to create accounts on your instance. This feature is disabled by default.

## Setup

> [Outgoing email](email_setup.md) is required for verification emails to be sent.

Enable the account signup feature

```
kanidm system feature enable account_signup_feature -D admin
```

A signup link will now be present on the login screen.

## Privacy

Currently to prevent email or username enumeration, if a user attempts a signup with an already taken username or email
then the request will silently fail to prevent disclosure.
