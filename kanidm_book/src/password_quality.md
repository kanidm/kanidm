# Password Quality and Badlisting

Kanidm embeds a set of tools to help your users use and create strong passwords. This is important
as not all user types will require multi-factor authentication (MFA) for their roles, but
compromised accounts still pose a risk. There may also be deployment or other barriers to a site
rolling out sitewide MFA.

## Quality Checking

Kanidm enforces that all passwords are checked by the library
"[zxcvbn](https://github.com/dropbox/zxcvbn)". This has a large number of checks for password
quality. It also provides constructive feedback to users on how to improve their passwords if they
are rejected.

Some things that zxcvbn looks for is use of the account name or email in the password, common
passwords, low entropy passwords, dates, reverse words and more.

This library can not be disabled - all passwords in Kanidm must pass this check.

## Password Badlisting

This is the process of configuring a list of passwords to exclude from being able to be used. This
is especially useful if a specific business has been notified of compromised accounts, allowing you
to maintain a list of customised excluded passwords.

The other value to this feature is being able to badlist common passwords that zxcvbn does not
detect, or from other large scale password compromises.

By default we ship with a preconfigured badlist that is updated over time as new password breach
lists are made available.

The password badlist by default is append only, meaning it can only grow, but will never remove
passwords previously considered breached.

### Updating your own Badlist

You can display the current badlist with:

```bash
kanidm system pw-badlist show
```

You can update your own badlist with:

```bash
kanidm system pw-badlist upload "path/to/badlist" [...]
```

Multiple bad lists can be listed and uploaded at once. These are preprocessed to identify and remove
passwords that zxcvbn and our password rules would already have eliminated. That helps to make the
bad list more efficient to operate over at run time.

## Password Rotation

Kanidm will never support this "anti-feature". Password rotation encourages poor password hygiene
and is not shown to prevent any attacks.
