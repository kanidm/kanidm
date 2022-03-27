## Getting Started (for Developers)

### Designs

See the [designs] folder, and compile the private documentation locally:

```
cargo doc --document-private-items --open --no-deps
```

[designs]: https://github.com/kanidm/kanidm/tree/master/designs

### Rust Documentation

The library documentation is [here](https://kanidm.github.io/kanidm/rustdoc/master/kanidm/).

### Minimum Supported Rust Version

The MSRV is specified [here](https://github.com/kanidm/kanidm/blob/master/profiles/RUST_MSRV).

### Dependencies

#### MacOS

You will need [rustup] to install a rust toolchain.

[rustup]: https://rustup.rs/

If you plan to work on the web-ui, you may also need npm for setting up some parts.

    brew install npm

#### SUSE

You will need [rustup] to install a rust toolchain.

[rustup]: https://rustup.rs/

You will also need some system libraries to build this:

    libudev-devel sqlite3-devel libopenssl-devel npm-default


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

Select an issue (always feel free to reach out to us for advice!), and create a branch to start working:

```
git branch <feature-branch-name>
git checkout <feature-branch-name>
cargo test
```

When you are ready for review (even if the feature isn't complete and you just want some advice)

```
cargo test
git commit -m 'Commit message' change_file.rs ...
git push <myfork/origin> <feature-branch-name>
```

If you get advice or make changes, just keep commiting to the branch, and pushing to your branch.
When we are happy with the code, we'll merge in github, meaning you can now clean up your branch.

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
git checkout <feature-branch-name>
git rebase master
```

Then be sure to fix any merge issues or other comments as they arise. If you have issues, you can always stop and reset with:

```
git rebase --abort
```

### Development Server Quickstart for Interactive Testing

After getting the code, you will need a rust environment. Please investigate [rustup](https://rustup.rs) for your platform to establish this.

Once you have the source code, you need certificates to use with the server, because without certificates, authentication will fail. 

We recommend using [Let's Encrypt](https://letsencrypt.org), but if this is not possible, please use our insecure cert tool (`insecure_generate_tls.sh`). The insecure cert tool creates `/tmp/kanidm` and puts some self-signed certificates there.

You can now build and run the server with the commands below. It will use a database in `/tmp/kanidm.db`.

Create the initial database and generate an `admin` username:

    cargo run --bin kanidmd recover_account -c ./examples/insecure_server.toml -n admin
    <snip>
    Success - password reset to -> Et8QRJgQkMJu3v1AQxcbxRWW44qRUZPpr6BJ9fCGapAB9cT4

Record the password above, then run the server start command:

    cd kanidmd/daemon
    cargo run --bin kanidmd server -c ../../examples/insecure_server.toml

In a new terminal, you can now build and run the client tools with:

    cargo run --bin kanidm -- --help
    cargo run --bin kanidm -- login -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
    cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
    
    cargo run --bin kanidm -- login -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
    cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem

### Building the Web UI

__NOTE:__ There is a pre-packaged version of the Web UI at `/kanidmd_web_ui/pkg/`, which can be used directly. This means you don't need to build the Web UI yourself

The web UI uses rust wasm rather than javascript. To build this you need to set up the environment.

    cargo install wasm-pack
    npm install --global rollup

Then you are able to build the UI.

    cd kanidmd_web_ui/
    ./build_wasm.sh

The "developer" profile for kanidmd will automatically use the pkg output in this folder.

Setting different developer profiles while building is done by setting the environment variable KANIDM_BUILD_PROFILE to one of the bare filename of the TOML files in `/profiles`. 

For example: `KANIDM_BUILD_PROFILE=release_suse_generic cargo build --release --bin kanidmd`
