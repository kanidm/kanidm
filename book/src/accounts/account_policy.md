# Account Policy

Account Policy defines the security requirements that accounts must meet and influences users sessions.

Policy is defined on groups so that membership of a group influences the security of its members. This allows you to
express that if you can access a system or resource, then the account must also meet the policy requirements.

All account policy settings may be managed by members of `idm_account_policy_admins`. This is assigned to `idm_admin` by
default.

## Default Account Policy

A default Account Policy is applied to `idm_all_persons`. This provides the defaults that influence all people in
Kanidm. This policy can be modified the same as any other group's policy.

## Enforced Attributes

### Auth Expiry

The maximum length in seconds that an authentication session may exist for.

### Credential Type Minimum

The minimum security strength of credentials that may be assigned to this account. In order from weakest to strongest:

- `any`
- `mfa`
- `passkey`
- `attested_passkey`

`attested_passkey` requires
[configuring an allowlist of trusted authenticators](#setting-webauthn-attestation-ca-lists).

### Password Minimum Length

The minimum length for passwords (if they are allowed).

### Privilege Expiry

The maximum length in seconds (<= 3600) that privileges will exist after reauthentication for to a read/write session.

### Webauthn Attestation

The list of certificate authorities and device aaguids that must be used by members of this policy. This allows limiting
devices to specific models.

To generate this list you should [use `fido-mds-tool`](#setting-webauthn-attestation-ca-lists).

## Policy Resolution

When an account is affected by multiple policies, the strictest component from each policy is applied. This can mean
that two policies interact and make their combination stricter than their parts.

| value                        | ordering                     |
| ---------------------------- | ---------------------------- |
| auth-expiry                  | smallest value               |
| credential-type-minimum      | largest value                |
| password-minimum-length      | largest value                |
| privilege-expiry             | smallest value               |
| webauthn-attestation-ca-list | intersection of equal values |

### Example Resolution

If we had two policies where the first defined:

```text
auth-session: 86400
password-minimum-length: 10
privilege-expiry: 600
webauthn-attestation-ca-list: [ "yubikey 5ci", "yubikey 5fips" ]
```

And the second

```text
auth-session: 3600
password-minimum-length: 15
privilege-expiry: 3600
webauthn-attestation-ca-list: [ "yubikey 5fips", "feitian epass" ]
```

As the value of auth-session from the second is smaller we would take that. We would take the smallest value of
privilege-expiry from the first. We would take the largest value of password-minimum-length. From the intersection of
the webauthn attestation CA lists we would take only the elements that are in both. This leaves:

```text
auth-session: 3600
password-minimum-length: 15
privilege-expiry: 600
webauthn-attestation-ca-list: [ "yubikey 5fips" ]
```

## Enabling Account Policy

Account Policy is enabled on a group with the command:

```shell
kanidm group account-policy enable <group name>
kanidm group account-policy enable my_admin_group
```

Note that the Account Policy is already enabled for `idm_all_persons`.

### Setting Maximum Session Time

The auth-session value influences the maximum time in seconds that an authenticated session can exist. After this time,
the user must reauthenticate.

This value provides a difficult balance - forcing frequent re-authentications can frustrate and annoy users. However
extremely long sessions allow a stolen or disclosed session token/device to read data for an extended period. Due to
Kanidm's read/write separation this mitigates the risk of disclosed sessions as they can only _read_ data, not write it.

To set the maximum authentication session time

```shell
kanidm group account-policy auth-expiry <group name> <seconds>
kanidm group account-policy auth-expiry my_admin_group 86400
```

### Setting Minimum Password Length

The password-minimum-length value defines the character length of passwords that are acceptable. There are no other
tunables for passwords in account policy. Other settings such as complexity, symbols, numbers and so on, have been
proven to not matter in any real world attacks.

To set this value:

```shell
kanidm group account-policy password-minimum-length <group name> <length>
kanidm group account-policy password-minimum-length my_admin_group 12
```

### Setting Maximum Privilege Time

The privilege-expiry time defines how long a session retains its write privileges after a reauthentication. After this
time (maximum 1 hour), the session returns to read-only mode.

To set the maximum privilege time

```shell
kanidm group account-policy privilege-expiry <group name> <seconds>
kanidm group account-policy privilege-expiry my_admin_group 900
kanidm group account-policy privilege-expiry my_admin_group 86400 # NB: will be limited to 3600
```

### Setting Webauthn Attestation CA Lists

To verify Webauthn authenticators with attestation, Kanidm needs an allowlist of authenticators to trust. Generate this
list with the `fido-mds-tool` from the [webauthn-rs project](https://github.com/kanidm/webauthn-rs). If you have a Rust
toolchain installed, it can built and installed from source with

```bash
cargo install fido-mds-tool
```

Alternatively, `fido-mds-tool` is available in the [tools container](../installing_client_tools.md#tools-container).

First, fetch the MDS data provided by the FIDO Alliance:

```bash
fido-mds-tool fetch
```

Then, query the MDS data to generate your allowlist of authenticators. For example, to trust all authenticators made by
Yubico, run

```bash
fido-mds-tool query --output-cert-roots "desc cnt yubikey" > trusted-authenticators
```

For details of how to query the MDS data, run

```bash
fido-mds-tool query --help
```

Once you have generated the authenticator allowlist, use it to configure Kanidm's account policy for a group. For
example, to set the allowlist for all persons, run

```bash
kanidm group account-policy webauthn-attestation-ca-list idm_all_persons trusted-authenticators
```

### Setting Primary Credential Fallback

The primary credential fallback enables behavior which allows authenticating using the primary account password when
logging in via LDAP.

If both an LDAP and primary password are specified, Kanidm will only accept the LDAP password.

```bash
kanidm group account-policy allow-primary-cred-fallback <group name> <enabled>
```

to disable it for a group you would run:

```bash
kanidm group account-policy allow-primary-cred-fallback <group name> false
```

## Global Settings

There are a small number of account policy settings that are set globally rather than on a per group basis.

### Denied Names

Users of Kanidm can change their name at any time. However, there are some cases where you may wish to deny some name
values from being usable. This can be due to conflicting system account names or to exclude insulting or other abusive
terms.

To achieve this you can set names to be in the denied-name list:

```bash
kanidm system denied-names append <name> [<name> ...]
```

You can display the currently denied names with:

```bash
kanidm system denied-names show
```

To allow a name to be used again it can be removed from the list:

```shell
kanidm system denied-names remove <name> [<name> ...]
```

### Password Quality

Kanidm enforces that all passwords are checked by the library "[zxcvbn](https://github.com/dropbox/zxcvbn)". This has a
large number of checks for password quality. It also provides constructive feedback to users on how to improve their
passwords if they are rejected.

Some things that zxcvbn looks for is use of the account name or email in the password, common passwords, low entropy
passwords, dates, reverse words and more.

This library can not be disabled - all passwords in Kanidm must pass this check.

### Password Badlisting

This is the process of configuring a list of passwords to exclude from being able to be used. This is especially useful
if a specific business has been notified of compromised accounts, allowing you to maintain a list of customised excluded
passwords.

The other value to this feature is being able to badlist common passwords that zxcvbn does not detect, or from other
large scale password compromises.

By default we ship with a preconfigured badlist that is updated over time as new password breach lists are made
available.

The password badlist by default is append only, meaning it can only grow, but will never remove passwords previously
considered breached.

You can display the current badlist with:

```bash
kanidm system pw-badlist show
```

You can update your own badlist with:

```bash
kanidm system pw-badlist upload "path/to/badlist" [...]
```

Multiple bad lists can be listed and uploaded at once. These are preprocessed to identify and remove passwords that
zxcvbn and our password rules would already have eliminated. That helps to make the bad list more efficient to operate
over at run time.

### Password Rotation

Kanidm will never support this "anti-feature". Password rotation encourages poor password hygiene and is not shown to
prevent any attacks - rather it _significantly weakens password security_.
