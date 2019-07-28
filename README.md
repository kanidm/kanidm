
<p align="center">
  <img src="https://raw.githubusercontent.com/Firstyear/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

# Kanidm

Kanidm is an identity management platform written in rust. Our goals are:

* Modern identity management platform
* Simple to deploy and integrate with
* extensible
* correct

## Code of Conduct

See CODE_OF_CONDUCT.md

## Examples

## MVP features

* Pam/nsswitch clients (with offline auth, and local totp)
* CLI for admin
* OIDC/Oauth
* SSH key distribution
* MFA (TOTP)
* In memory read cache (cow)
* backup/restore

## Planned features

* Replicated database backend (389-ds, couchdb, or custom repl proto)
* SAML
* Read Only Replicas
* Certificate distribution?
* Web UI for admin
* Account impersonation
* Webauthn
* Sudo rule distribution via nsswitch?

## Features we want to avoid

* Audit: This is better solved by ...
* Fully synchronous behaviour: ...
* Generic database: ... (max db size etc)
* Being LDAP: ...
* GSSAPI/Kerberos

## More?

## Get involved

To get started, you'll need to fork or branch, and we'll merge based on PR's.

If you are a contributor to the project, simply clone:

```
git clone git@github.com:Firstyear/kanidm.git
```

If you are forking, then Fork in github and clone with:

```
git clone https://github.com/Firstyear/kanidm.git
cd kanidm
git remote add myfork git@github.com:<YOUR USERNAME>/kanidm.git
```

Select and issue (and always feel free to reach out to us for advice!), and create a branch to
start working:

```
git branch <feature-branch-name>
git checkout <feature-branche-name>
```

When you are ready for review (even if the feature isn't complete and you just want some advice)

```
git commit -m 'Commit message' change_file.rs ...
git push <myfork/origin> <feature-branch-name>
```

If you get advice or make changes, just keep commiting to the branch, and pushing to your branch.
When we are happy with the code, we'll merge in github, meaning you can now cleanup your branch.

```
git checkout master
git pull
git branch -D <feature-branch-name>
```

Rebasing:

If you are asked to rebase your change, follow these steps:

```
git checkout master
git pull
git checkout <feature-branche-name>
git rebase master
```

Then be sure to fix any merge issues or other comments as they arise. If you have issues, you can
always stop and reset with:

```
git rebase --abort
```



## Designs

See the designs folder

## Why do I see rsidm references?

The original project name was rsidm while it was a thought experiment. Now that it's growing
and developing, we gave it a better project name. Kani is Japanese for "crab". Rust's mascot
is a crab. It all works out in the end.



