## Getting Started (for Developers)

### Designs

See the [designs] folder, and compile the private documentation locally:

```
cargo doc --document-private-items --open --no-deps
```

[designs]: https://github.com/kanidm/kanidm/tree/master/designs

### Rust Documentation

A list of links to the library documentation is at 
[kanidm.com/documentation](https://kanidm.com/documentation/).

### Minimum Supported Rust Version

The MSRV is specified in the package `Cargo.toml` files.

### Dependencies

#### MacOS

You will need [rustup](https://rustup.rs/) to install a Rust toolchain.
    
#### SUSE

You will need [rustup](https://rustup.rs/) to install a Rust toolchain. If 
you're 
using the Tumbleweed release, it's packaged in `zypper`.

You will also need some system libraries to build this:

    libudev-devel sqlite3-devel libopenssl-devel npm-default

#### Fedora

You need to install the Rust toolchain packages:

    rust cargo

You will also need some system libraries to build this:

    systemd-devel sqlite-devel openssl-devel pam-devel

Building the Web UI requires additional packages:

    perl-FindBin perl-File-Compare rust-std-static-wasm32-unknown-unknown

#### Ubuntu

You need [rustup](https://rustup.rs/) to install a Rust toolchain.

You will also need some system libraries to build this, which can be installed by running:

```shell
sudo apt-get install libsqlite3-dev libudev-dev libssl-dev
```

Tested with Ubuntu 20.04.

### Get Involved

To get started, you'll need to fork or branch, and we'll merge based on pull
requests.

If you are a contributor to the project, simply clone:

```shell
git clone git@github.com:kanidm/kanidm.git
```

If you are forking, then fork in GitHub and clone with:

```shell
git clone https://github.com/kanidm/kanidm.git
cd kanidm
git remote add myfork git@github.com:<YOUR USERNAME>/kanidm.git
```

Select an issue (always feel free to reach out to us for advice!), and create a 
branch to start working:

```shell
git branch <feature-branch-name>
git checkout <feature-branch-name>
cargo test
```

When you are ready for review (even if the feature isn't complete and you just 
want some advice):

1. Run the test suite: `cargo test --workspace`
2. Ensure rust formatting standards are followed: `cargo fmt --check`
3. Try following the suggestions from clippy, after running `cargo clippy`. 
    This is not a blocker on us accepting your code!
4. Then commit your changes:

```shell
git commit -m 'Commit message' change_file.rs ...
git push <myfork/origin> <feature-branch-name>
```

If you receive advice or make further changes, just keep commiting to the branch, 
and pushing to your branch. When we are happy with the code, we'll merge in GitHub, 
meaning you can now clean up your branch.

```
git checkout master
git pull
git branch -D <feature-branch-name>
```

#### Rebasing

If you are asked to rebase your change, follow these steps:

```
git checkout master
git pull
git checkout <feature-branch-name>
git rebase master
```

Then be sure to fix any merge issues or other comments as they arise. If you 
have issues, you can always stop and reset with:

```
git rebase --abort
```

### Development Server Quickstart for Interactive Testing

After getting the code, you will need a rust environment. Please investigate 
[rustup](https://rustup.rs) for your platform to establish this.

Once you have the source code, you need encryption certificates to use with the server, 
because without certificates, authentication will fail. 

We recommend using [Let's Encrypt](https://letsencrypt.org), but if this is not 
possible, please use our insecure certificate tool (`insecure_generate_tls.sh`). The 
insecure certificate tool creates `/tmp/kanidm` and puts some self-signed certificates there.

You can now build and run the server with the commands below. It will use a database 
in `/tmp/kanidm.db`.

Create the initial database and generate an `admin` username:

    cargo run --bin kanidmd recover_account -c ./examples/insecure_server.toml -n admin
    <snip>
    Success - password reset to -> Et8QRJgQkMJu3v1AQxcbxRWW44qRUZPpr6BJ9fCGapAB9cT4

Record the password above, then run the server start command:

    cd kanidmd/daemon
    cargo run --bin kanidmd server -c ../../examples/insecure_server.toml

(The server start command is also a script in `kanidmd/daemon/run_insecure_dev_server.sh`)

In a new terminal, you can now build and run the client tools with:

    cargo run --bin kanidm -- --help
    cargo run --bin kanidm -- login -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
    cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
    
    cargo run --bin kanidm -- login -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
    cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem

### Building the Web UI

__NOTE:__ There is a pre-packaged version of the Web UI at `/kanidmd_web_ui/pkg/`, 
which can be used directly. This means you don't need to build the Web UI yourself.

The Web UI uses Rust WebAssembly rather than Javascript. To build this you need 
to set up the environment:

    cargo install wasm-pack
    npm install --global rollup

Then you are able to build the UI:

    cd kanidmd_web_ui/
    ./build_wasm.sh

The "developer" profile for kanidmd will automatically use the pkg output in this folder.

Setting different developer profiles while building is done by setting the 
environment 
variable KANIDM_BUILD_PROFILE to one of the bare filename of the TOML files in 
`/profiles`. 

For example: `KANIDM_BUILD_PROFILE=release_suse_generic cargo build --release --bin kanidmd`

### Build a Kanidm Container

Build a container with the current branch using:

    make <TARGET>

Check `make help` for a list of valid targets.

The following environment variables control the build:

|ENV variable|Definition|Default|
|-|-|-|
|`IMAGE_BASE`|Base location of the container image.|`kanidm`|
|`IMAGE_VERSION`|Determines the container's tag.|None|
|`CONTAINER_TOOL_ARGS`|Specify extra options for the container build tool.|None|
|`IMAGE_ARCH`|Passed to `--platforms` when the container is built.|`linux/amd64,linux/arm64`|
|`CONTAINER_BUILD_ARGS`|Override default ARG settings during the container build.|None|
|`CONTAINER_TOOL`|Use an alternative container build tool.|`docker`|
|`BOOK_VERSION`|Sets version used when building the documentation book.|`master`|

#### Container Build Examples

Build a `kanidm` container using `podman`:

    CONTAINER_TOOL=podman make build/kanidmd

Build a `kanidm` container and use a redis build cache:

    CONTAINER_BUILD_ARGS='--build-arg "SCCACHE_REDIS=redis://redis.dev.blackhats.net.au:6379"' make build/kanidmd

#### Automatically Built Containers

To speed up testing across platforms, we're leveraging GitHub actions to build 
containers for test use.

Whenever code is merged with the `master` branch of Kanidm, containers are automatically 
built for `kanidmd` and `radius`. Sometimes they fail to build, but we'll try to 
keep them avilable.

To find information on the packages, 
[visit the Kanidm packages page](https://github.com/orgs/kanidm/packages?repo_name=kanidm).

An example command for pulling and running the radius container is below. You'll 
need to 
[authenticate with the GitHub container registry first](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry).

```shell
docker pull ghcr.io/kanidm/radius:devel
docker run --rm -it \
    -v $(pwd)/config.ini:/data/config.ini \
    ghcr.io/kanidm/radius:devel
```

This assumes you have a `config.ini` file in the current working directory.
