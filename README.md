
<p align="center">
  <img src="https://raw.githubusercontent.com/kanidm/kanidm/master/artwork/logo-small.png" width="20%" height="auto" />
</p>

# Kanidm

Kanidm is an identity management platform written in rust. Our goals are:

* Modern identity management platform
* Simple to deploy and integrate with
* Extensible for various needs
* Correct and secure behaviour by default

Today the project is still under heavy development to achieve these goals - we don't expect a fully
functional release before early 2020. It is important to note that not all needed security features
of the system have been completed yet!

## Code of Conduct

See our [code of conduct]

[code of conduct]: https://github.com/kanidm/kanidm/blob/master/CODE_OF_CONDUCT.md

## Ethics / Rights

See our documentation on [rights and ethics]

[rights and ethics]: https://github.com/kanidm/kanidm/blob/master/ethics/README.md

## Some key ideas

* All people should be respected and able to be respresented securely.
* Devices represent users and their identities - they are part of the authentication.
* Human error occurs - we should be designed to minimise human mistakes and empower people.
* The system should be easy to understand and reason about for users and admins.

## Documentation

If you want to deploy kanidm, or to see what it can do, you should read the [kanidm book]

[kanidm book]: https://github.com/kanidm/kanidm/blob/master/kanidm_book/src/SUMMARY.md

## Implemented/Planned features

* SSH key distribution for servers (done)
* Pam/nsswitch clients (with limited offline auth) (done)
* Sudo rule distribution via nsswitch
* CLI and WebUI for administration
* OIDC/Oauth
* RBAC/Claims (limited by time and credential scope)
* MFA (Webauthn, TOTP) (TOTP done)
* Highly concurrent desgin (MVCC, COW) (done)
* Replication (async multiple active write servers, read only servers)
* Account impersonation
* RADIUS integration (done)
* Self service UI with wifi enrollment, claim management and more.
* Synchronisation to other IDM services

## Features we want to avoid

* Auditing: This is better solved by SIEM software, so we should generate data they can consume.
* Fully synchronous behaviour: This is slow.
* Generic database: We don't want to be another NoSQL database, we want to be an IDM solution.
* Being LDAP/GSSAPI/Kerberos: These are all legacy protocols that are hard to use and confine our thinking - we should avoid "being like them".

## Development and Testing

### Designs

See the [designs] folder, and compile the private documentation locally:

```
cargo doc --document-private-items --open --no-deps
```

[designs]: https://github.com/kanidm/kanidm/tree/master/designs

### Get involved

To get started, you'll need to fork or branch, and we'll merge based on PR's.

If you are a contributor to the project, simply clone:

```
git clone git@github.com:kanidm/kanidm.git
```

If you are forking, then Fork in github and clone with:

```
git clone https://github.com/kanidm/kanidm.git
cd kanidm
git remote add myfork git@github.com:<YOUR USERNAME>/kanidm.git
```

Select and issue (and always feel free to reach out to us for advice!), and create a branch to
start working:

```
git branch <feature-branch-name>
git checkout <feature-branche-name>
cargo test
```

When you are ready for review (even if the feature isn't complete and you just want some advice)

```
cargo test
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

### Development Server Quickstart for Interactive Testing

Today the server is still in a state of heavy development, and hasn't been packaged or setup for
production usage.

However, we are able to run test or demo servers that are suitable for previews and testing.

After getting the code, you will need a rust environment. Please investigate rustup for your platform
to establish this.

Once you have the source code, you need certificates to use with the server. I recommend using
let's encrypt, but if this is not possible, please use our insecure cert tool:

    mkdir insecure
    cd insecure
    ../insecure_generate_tls.sh

You can now build and run the server with:

    cd kanidmd
    cargo run -- recover_account -D /tmp/kanidm.db -n admin
    cargo run -- server -D /tmp/kanidm.db -C ../insecure/ca.pem -c ../insecure/cert.pem -k ../insecure/key.pem --bindaddr 127.0.0.1:8080

In a new terminal, you can now build and run the client tools with:

    cd kanidm_tools
    cargo run -- --help
    cargo run -- self whoami -H https://localhost:8080 -D anonymous -C ../insecure/ca.pem
    cargo run -- self whoami -H https://localhost:8080 -D admin -C ../insecure/ca.pem


### Using curl with anonymous:

Sometimes you may want to check the json of an endpoint. Before you can do this, you need
a valid session and cookie jar established. To do this with curl and anonymous:

    curl -b /tmp/cookie.jar -c /tmp/cookie.jar --cacert ../insecure/ca.pem  -X POST -d "{\"step\":{\"Init\":[\"anonymous\",null]}}"  https://localhost:8080/v1/auth
    curl -b /tmp/cookie.jar  -c /tmp/cookie.jar --cacert ../insecure/ca.pem  -X POST -d "{\"step\":{\"Creds\":[\"Anonymous\"]}}"  https://localhost:8080/v1/auth


## Why do I see rsidm references?

The original project name was rsidm while it was a thought experiment. Now that it's growing
and developing, we gave it a better project name. Kani is Japanese for "crab". Rust's mascot is a crab.
Idm is the common industry term for identity management services.



