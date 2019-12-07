# Password Quality and Badlisting

Kanidm embeds a set of tools to help your users use and create strong passwords. This is important
as not all user types will require MFA for their roles, but compromised accounts still pose a risk.
There may also be deployment or other barriers to a site rolling out site wide MFA.

## Quality Checking

Kanidm enforces that all passwords are checked by the library "zxcvbn". This has a large number of
checks for password quality. It also provides constructive feedback to users on how to improve their
passwords if it was rejected.

Some things that zxcvbn looks for is use of the account name or email in the password, common passwords,
low entropy passwords, dates, reverse words and more.

This library can not be disabled - all passwords in Kanidm must pass this check.

## Password Badlisting

This is the process of configuring a list of passwords to exclude from being able to be used. This
is especially useful if a specific business has been notified of a compromised account, allowing
you to maintain a list of customised excluded passwords.

The other value to this feature is being able to badlist common passwords that zxcvbn does not
detect, or from other large scale password compromises.

By default we ship with a preconfigured badlist that is updated overtime as new password breach
lists are made available.

## Updating your own badlist.

You can update your own badlist by using the proided `kanidm_badlist_preprocess` tool which helps
to automate this process.

Given a list of passwords in a text file, it will generate a modification set which can be
applied. The tool also provides the command you need to run to apply this.

    kanidm_badlist_preprocess -m -o /tmp/modlist.json <password file> [<password file> <password file> ...]


