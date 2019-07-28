
<p align="center">
  <img src="https://raw.githubusercontent.com/Firstyear/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

# Kanidm

Kanidm is an identity management platform written in rust. Our goals are:

* Modern identity management platform
* Simple to deploy and integrate with
* Extensible for various needs
* Correct and secure behaviour by default

Today the project is still under heavy development to achieve these goals - we don't expect a fully
functional release before early 2020.

## Code of Conduct

See [CODE_OF_CONDUCT.md]

[CODE_OF_CONDUCT.md]: https://github.com/Firstyear/kanidm/blob/master/CODE_OF_CONDUCT.md

## Some key ideas

* All people should be respected and able to be respresented securely.
* Devices represent users and their identities - they are part of the authentication.
* Human error occurs - we should be designed to minimise human mistakes and empower people.
* The system should be easy to understand and reason about for users and admins.

## Quick start

Details to come ...

## Implemented/Planned features

* RBAC design
* SSH key distribution for servers
* Pam/nsswitch clients (with limited offline auth)
* Sudo rule distribution via nsswitch
* CLI and WebUI for administration
* OIDC/Oauth
* Claims (limited by time and credential scope)
* MFA (Webauthn, TOTP)
* Highly concurrent desgin (MVCC, COW)
* Replication (async multiple active write servers, read only servers)
* Account impersonation
* RADIUS integration
* Self service UI with wifi enrollment, claim management and more.
* Synchronisation to other IDM services

## Features we want to avoid

* Auditing: This is better solved by SIEM software, so we should generate data they can consume.
* Fully synchronous behaviour: This is slow.
* Generic database: We don't want to be another NoSQL database, we want to be an IDM solution.
* Being LDAP/GSSAPI/Kerberos: These are all legacy protocols that are hard to use and confine our thinking - we should avoid "being like them".

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



