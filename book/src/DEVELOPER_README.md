## Getting Started (for Developers)

### Setup the Server

It's important before you start trying to write code and contribute that you understand
what Kanidm does and it's goals.

An important first step is to [install the server](installing_the_server.md) so if you have
not done that yet, go and try that now! 😄

### Setting up your Machine

Each operating system has different steps required to configure and build Kanidm.

#### MacOS

A prerequisite is [Apple Xcode](https://apps.apple.com/au/app/xcode/id497799835?mt=12) for
access to git and compiler tools. You should install this first.

You will need [rustup](https://rustup.rs/) to install a Rust toolchain.

#### SUSE / OpenSUSE

You will need to install rustup and our build dependencies with:

```bash
zypper in rustup git libudev-devel sqlite3-devel libopenssl-3-devel
```

You can then use rustup to complete the setup of the toolchain.

#### Fedora

You will need [rustup](https://rustup.rs/) to install a Rust toolchain.

You will also need some system libraries to build this:

```text
systemd-devel sqlite-devel openssl-devel pam-devel
```

Building the Web UI requires additional packages:

```text
perl-FindBin perl-File-Compare
```

#### Ubuntu

You need [rustup](https://rustup.rs/) to install a Rust toolchain.

You will also need some system libraries to build this, which can be installed by running:

```bash
sudo apt-get install libsqlite3-dev libudev-dev libssl-dev pkg-config libpam0g-dev
```

Tested with Ubuntu 20.04 and 22.04.

#### Windows

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=NOTICE
text=Our support for Windows is still in development, so you may encounter some compilation or build issues.
}}

<!-- deno-fmt-ignore-end -->

You need [rustup](https://rustup.rs/) to install a Rust toolchain.

An easy way to grab the dependencies is to install
[vcpkg](https://vcpkg.io/en/getting-started.html).

This is how it works in the automated build:

1. Enable use of installed packages for the user system-wide:

```bash
vcpkg integrate install
```

2. Install the openssl dependency, which compiles it from source. This downloads all sorts of
   dependencies, including perl for the build.

```bash
vcpkg install openssl:x64-windows-static-md
```

There's a powershell script in the root directory of the repository which, in concert with `openssl`
will generate a config file and certs for testing.

### Getting the Source Code

### Get Involved

To get started, you'll need to fork or branch, and we'll merge based on pull requests.

Kanidm is (largely) a monorepo. This can be checked out with:

```bash
git clone https://github.com/kanidm/kanidm.git
cd kanidm
```

Other supporting projects can be found on the [project github](https://github.com/kanidm)

If you are forking, then fork in GitHub and then add your remote.

```bash
git remote add myfork git@github.com:<YOUR USERNAME>/kanidm.git
```

Select an issue (always feel free to reach out to us for advice!), and create a branch to start
working:

```bash
git branch <feature-branch-name>
git checkout <feature-branch-name>
cargo test
```

When you are ready for review (even if the feature isn't complete and you just want some advice):

1. Run the test suite: `cargo test`
2. Ensure rust formatting standards are followed: `cargo fmt --check`
3. Try following the suggestions from clippy, after running `cargo clippy`. This is not a blocker on
   us accepting your code!
4. Then commit your changes:

```bash
git commit -m 'Commit message' change_file.rs ...
git push <myfork> <feature-branch-name>
```

If you receive advice or make further changes, just keep committing to the branch, and pushing to
your branch. When we are happy with the code, we'll merge in GitHub, meaning you can now clean up
your branch.

```bash
git checkout master
git pull
git branch -D <feature-branch-name>
```

#### Rebasing

If you are asked to rebase your change, follow these steps:

```bash
git checkout master
git pull
git checkout <feature-branch-name>
git rebase master
```

Then be sure to fix any merge issues or other comments as they arise. If you have issues, you can
always stop and reset with:

```bash
git rebase --abort
```

### Building the Book

You'll need `mdbook` to build the book:

```bash
cargo install mdbook
```

To build it:

```bash
make book
```

Or to run a local webserver:

```bash
cd book
mdbook serve
```

### Designs

See the "Design Documents" section of this book.

### Rust Documentation

A list of links to the library documentation is at
[kanidm.com/documentation](https://kanidm.com/documentation/).

### Advanced

#### Minimum Supported Rust Version

The MSRV is specified in the package `Cargo.toml` files.

We tend to be quite proactive in updating this to recent rust versions so we are open to increasing
this value if required!

#### Build Profiles

Build profiles allow us to change the operation of Kanidm during it's compilation for development
or release on various platforms. By default the "developer" profile is used that assumes the correct
relative paths within the monorepo.

Setting different developer profiles while building is done by setting the environment variable
`KANIDM_BUILD_PROFILE` to one of the bare filename of the TOML files in `/profiles`.

For example, this will set the CPU flags to "none" and the location for the Web UI files to
`/usr/share/kanidm/ui/pkg`:


```bash
KANIDM_BUILD_PROFILE=release_suse_generic cargo build --release --bin kanidmd
```

#### Building the Web UI

**NOTE:** There is a pre-packaged version of the Web UI at `/server/web_ui/pkg/`, which can be used
directly. This means you don't need to build the Web UI yourself.

The Web UI uses Rust WebAssembly rather than Javascript. To build this you need to set up the
environment:

```bash
cargo install wasm-pack
```

Then you are able to build the UI:

```bash
cd server/web_ui/
./build_wasm_dev.sh
```

To build for release, run `build_wasm_release.sh`.

The "developer" profile for kanidmd will automatically use the pkg output in this folder.

#### Development Server for Interactive Testing

Especially if you wish to develop the WebUI then the ability to run the server from the source
tree is critical.

Once you have the source code, you need encryption certificates to use with the server, because
without certificates, authentication will fail.

We recommend using [Let's Encrypt](https://letsencrypt.org), but if this is not possible, please use
our insecure certificate tool (`scripts/insecure_generate_tls.sh`). The insecure certificate tool
creates `/tmp/kanidm` and puts some self-signed certificates there.

**NOTE:** Windows developers can use `scripts/insecure_generate_tls.ps1`, which puts everything (including a
templated confi gfile) in `$TEMP\kanidm`. Please adjust paths below to suit.

You can now build and run the server with the commands below. It will use a database in
`/tmp/kanidm.db`.

Create the initial database and generate an `admin` password:

```bash
cd server/daemon
./run_insecure_dev_server.sh recover-account admin
```

Record the password above, then run the server start command:

```bash
./run_insecure_dev_server.sh
```

In a new terminal, you can now build and run the client tools with:

```bash
cargo run --bin kanidm -- --help
cargo run --bin kanidm -- login -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem

cargo run --bin kanidm -- login -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
```

You may find it easier to modify `~/.config/kanidm` per the [book client tools section](client_tools.md)
for extended administration locally.

#### Raw actions

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=NOTICE
text=It's not recommended to use these tools outside of extremely complex or advanced development requirements. These are a last resort!
}}

<!-- deno-fmt-ignore-end -->


The server has a low-level stateful API you can use for more complex or advanced tasks on large
numbers of entries at once. Some examples are below, but generally we advise you to use the APIs or
CLI tools. These are very handy to "unbreak" something if you make a mistake however!

```bash
# Create from json (group or account)
kanidm raw create -H https://localhost:8443 -C ../insecure/ca.pem -D admin example.create.account.json
kanidm raw create  -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin example.create.group.json

# Apply a json stateful modification to all entries matching a filter
kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"or": [ {"eq": ["name", "idm_person_account_create_priv"]}, {"eq": ["name", "idm_service_account_create_priv"]}, {"eq": ["name", "idm_account_write_priv"]}, {"eq": ["name", "idm_group_write_priv"]}, {"eq": ["name", "idm_people_write_priv"]}, {"eq": ["name", "idm_group_create_priv"]} ]}' example.modify.idm_admin.json
kanidm raw modify -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"eq": ["name", "idm_admins"]}' example.modify.idm_admin.json

# Search and show the database representations
kanidm raw search -H https://localhost:8443 -C ../insecure/ca.pem -D admin '{"eq": ["name", "idm_admin"]}'

# Delete all entries matching a filter
kanidm raw delete -H https://localhost:8443 -C ../insecure/ca.pem -D idm_admin '{"eq": ["name", "test_account_delete_me"]}'
```

#### Build a Kanidm Container

Build a container with the current branch using:

```bash
make <TARGET>
```

Check `make help` for a list of valid targets.

The following environment variables control the build:

| ENV variable           | Definition                                                | Default                   |
| ---------------------- | --------------------------------------------------------- | ------------------------- |
| `IMAGE_BASE`           | Base location of the container image.                     | `kanidm`                  |
| `IMAGE_VERSION`        | Determines the container's tag.                           | None                      |
| `CONTAINER_TOOL_ARGS`  | Specify extra options for the container build tool.       | None                      |
| `IMAGE_ARCH`           | Passed to `--platforms` when the container is built.      | `linux/amd64,linux/arm64` |
| `CONTAINER_BUILD_ARGS` | Override default ARG settings during the container build. | None                      |
| `CONTAINER_TOOL`       | Use an alternative container build tool.                  | `docker`                  |
| `BOOK_VERSION`         | Sets version used when building the documentation book.   | `master`                  |

##### Container Build Examples

Build a `kanidm` container using `podman`:

```bash
CONTAINER_TOOL=podman make build/kanidmd
```

Build a `kanidm` container and use a redis build cache:

```bash
CONTAINER_BUILD_ARGS='--build-arg "SCCACHE_REDIS=redis://redis.dev.blackhats.net.au:6379"' make build/kanidmd
```

##### Automatically Built Containers

To speed up testing across platforms, we're leveraging GitHub actions to build containers for test
use.

Whenever code is merged with the `master` branch of Kanidm, containers are automatically built for
`kanidmd` and `radius`. Sometimes they fail to build, but we'll try to keep them available.

To find information on the packages,
[visit the Kanidm packages page](https://github.com/orgs/kanidm/packages?repo_name=kanidm).

An example command for pulling and running the radius container is below. You'll need to
[authenticate with the GitHub container registry first](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry).

```bash
docker pull ghcr.io/kanidm/radius:devel
docker run --rm -it \
    -v $(pwd)/kanidm:/data/kanidm \
    ghcr.io/kanidm/radius:devel
```

This assumes you have a `kanidm` client configuration file in the current working directory.

