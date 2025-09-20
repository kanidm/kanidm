# Getting Started (for Developers)

## Development Principles

As a piece of software that stores the identities of people, the project becomes bound to social and political matters.
The decisions we make have consequences on many people - many who never have the chance to choose what software is used
to store their identities (think employees in a business, or the users of a website).

This means we have a responsibility to not only be aware of our impact on our direct users (developers, system
administrators, dev ops, security and more) but also the impact on indirect consumers - many of who are unlikely to be
in a position to contact us to ask for changes and help.

### Ethics / Rights

If you have not already, please see our documentation on [rights and ethics](developer_ethics.md)

### Humans First

We must at all times make decisions that put humans first. We must respect all cultures, languages and identities and
how they are represented.

We will never put a burden on the user to correct for poor designs on our part.

This may mean we make technical choices that are difficult or more complex, or different to "how things have always been
done". But we do this to ensure that all people can have their identities stored how they choose.

For example, any user may change their name, display name and legal name at any time. Many applications will break as
they primary key from name when this occurs. But this is the fault of the application. Name changes must be allowed. Our
job as technical experts is to allow that to happen.

### Correct and Simple

As a piece of security sensitive software we must always put correctness first. All code must have tests. All developers
must be able to run all tests on their machine and environment of choice.

This means that the following must always work:

```bash
git clone ...
cargo test
```

If a test or change would require extra requirements or preconfiguration (such as setting up an external database or
service), then we can no longer provide the above. Testing must be easy and accessible - otherwise people will not run
the tests, leading to poor quality.

The project must be simple. Any one should be able to understand how it works and why those decisions were made.

### Hierarchy of Controls

When a possible risk arises we should always consider the [hierarchy of controls]. In descedending order of priority

- Elimination - eliminate the risk from existing
- Substitution - replace the risk with something less dangerous
- Engineering Controls - isolate the risk from causing harm
- Administrative Controls - educate about the risk, add warnings
- Personal Protection - document the risk

[hierarchy of controls]: https://en.wikipedia.org/wiki/Hierarchy_of_hazard_controls

### Languages

The core server will (for now) always be written in Rust. This is due to the strong type guarantees it gives, and how
that can help raise the quality of our project.

### Over-Configuration

Configuration will be allowed, but only if it does not impact the statements above. Having configuration is good, but
allowing too much (i.e. a scripting engine for security rules) can give deployments the ability to violate human first
principles, which reflects badly on us.

In addition every extra configuration item expands our testing matrix exponentially. We should optimally only offer one
path that is correct for all users unless no other options are possible.

All configuration items, must be constrained to fit within our principles so that every Kanidm deployment, will aim to
provide a positive experience to all people.

## Setup the Server

It's important before you start trying to write code and contribute that you understand what Kanidm does and its goals.

An important first step is to [install the server](../installing_the_server.md) so if you have not done that yet, go and
try that now! 😄

## Setting up your Machine

Each operating system has different steps required to configure and build Kanidm.

### MacOS

A prerequisite is [Apple Xcode](https://apps.apple.com/au/app/xcode/id497799835?mt=12) for access to git and compiler
tools. You should install this first.

You will need [rustup](https://rustup.rs/) to install a Rust toolchain.

### SUSE / OpenSUSE

> NOTE: clang and lld are required to build Kanidm due to performance issues with GCC/ld

You will need to install rustup and our build dependencies with:

```bash
zypper in rustup git libudev-devel sqlite3-devel libopenssl-3-devel libselinux-devel \
    pam-devel systemd-devel tpm2-0-tss-devel clang lld make sccache
```

You can then use rustup to complete the setup of the toolchain.

You should also adjust your environment with:

```bash
export RUSTC_WRAPPER=sccache
export CC="sccache /usr/bin/clang"
export CXX="sccache /usr/bin/clang++"
```

### Fedora

> NOTE: clang and lld are required to build Kanidm due to performance issues with GCC/ld

You will need [rustup](https://rustup.rs/) to install a Rust toolchain.

You will also need some system libraries to build this:

```text
systemd-devel sqlite-devel openssl-devel pam-devel clang lld
```

Building the Web UI requires additional packages:

```text
perl-FindBin perl-File-Compare
```

### Ubuntu

> NOTE: clang and lld are required to build Kanidm due to performance issues with GCC/ld

You need [rustup](https://rustup.rs/) to install a Rust toolchain.

You will also need some system libraries to build this, which can be installed by running:

```bash
sudo apt-get install libudev-dev libssl-dev libsystemd-dev pkg-config libpam0g-dev clang lld
```

Tested with Ubuntu 20.04 and 22.04.

### Windows

> [!CAUTION]
>
> Our support for Windows is still in development, so you may encounter some compilation or build issues.

You need [rustup](https://rustup.rs/) to install a Rust toolchain.

An easy way to grab the dependencies is to install [vcpkg](https://vcpkg.io/en/getting-started.html).

This is how it works in the automated build:

1. Enable use of installed packages for the user system-wide:

   ```bash
   vcpkg integrate install
   ```

2. Install the openssl dependency, which compiles it from source. This downloads all sorts of dependencies, including
   perl for the build.

   ```bash
   vcpkg install openssl:x64-windows-static-md
   ```

There's a powershell script in the root directory of the repository which, in concert with `openssl` will generate a
config file and certs for testing.

## Getting the Source Code

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

Select an issue (always feel free to reach out to us for advice!), and create a branch to start working:

```bash
git branch <feature-branch-name>
git checkout <feature-branch-name>
cargo test
```

> [!IMPORTANT]
>
> Kanidm is unable to accept code that is generated by an AI for legal reasons. copilot and other tools that generate
> code in this way can not be used in Kanidm.

When you are ready for review (even if the feature isn't complete and you just want some advice):

1. Run the test suite: `cargo test`
2. Ensure rust formatting standards are followed: `cargo fmt --check`
3. Try following the suggestions from clippy, after running `cargo clippy`. This is not a blocker on us accepting your
   code!
4. Then commit your changes:

```bash
git commit -m 'Commit message' change_file.rs ...
git push <myfork> <feature-branch-name>
```

If you receive advice or make further changes, just keep committing to the branch, and pushing to your branch. When we
are happy with the code, we'll merge in GitHub, meaning you can now clean up your branch.

```bash
git checkout master
git pull
git branch -D <feature-branch-name>
```

### Rebasing

If you are asked to rebase your change, follow these steps:

```bash
git checkout master
git pull
git checkout <feature-branch-name>
git rebase master
```

Then be sure to fix any merge issues or other comments as they arise. If you have issues, you can always stop and reset
with:

```bash
git rebase --abort
```

### Building the Book

You'll need `mdbook` and the extensions to build the book:

```shell
cargo install mdbook mdbook-mermaid mdbook-alerts
```

To build it:

```shell
make book
```

Or to run a local webserver:

```shell
cd book
mdbook serve
```

## Designs

See the "Design Documents" section of this book.

## Rust Documentation

A list of links to the library documentation is at [kanidm.com/documentation](https://kanidm.com/documentation/).

## Advanced

### Minimum Supported Rust Version

The MSRV is specified in the package `Cargo.toml` files.

We tend to be quite proactive in updating this to recent rust versions so we are open to increasing this value if
required!

### Build Profiles

Build profiles allow us to change the operation of Kanidm during it's compilation for development or release on various
platforms. By default the "developer" profile is used that assumes the correct relative paths within the monorepo.

Setting different developer profiles while building is done by setting the environment variable `KANIDM_BUILD_PROFILE`
to one of the bare filename of the TOML files in `/profiles`.

For example, this will set the CPU flags to "none" and the location for the Web UI files to `/usr/share/kanidm/ui/pkg`:

```bash
KANIDM_BUILD_PROFILE=release_linux cargo build --release --bin kanidmd
```

### Development Server for Interactive Testing

Especially if you wish to develop the WebUI then the ability to run the server from the source tree is critical.

Once you have the source code, you need encryption certificates to use with the server, because without certificates,
authentication will fail.

We recommend using [Let's Encrypt](https://letsencrypt.org), but if this is not possible kanidmd will create self-signed
certificates in `/tmp/kanidm`.

You can now build and run the server with the commands below. It will use a database in `/tmp/kanidm/kanidm.db`.

Start the server

```bash
cd server/daemon
./run_insecure_dev_server.sh
```

While the server is running, you can use the admin socket to generate an `admin` password:

```bash
./run_insecure_dev_server.sh recover-account admin
```

Record the password above.

In a new terminal, you can now build and run the client tools with:

```bash
cargo run --bin kanidm -- --help
cargo run --bin kanidm -- login -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem
cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D anonymous -C /tmp/kanidm/ca.pem

cargo run --bin kanidm -- login -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
cargo run --bin kanidm -- self whoami -H https://localhost:8443 -D admin -C /tmp/kanidm/ca.pem
```

You may find it easier to modify `~/.config/kanidm` per the [book client tools section](../client_tools.md) for extended
administration locally.

### Raw actions

> [!NOTICE]
>
> It's not recommended to use these tools outside of extremely complex or advanced development requirements. These are a
> last resort!

The server has a low-level stateful API you can use for more complex or advanced tasks on large numbers of entries at
once. Some examples are below, but generally we advise you to use the APIs or CLI tools. These are very handy to
"unbreak" something if you make a mistake however!

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

### Build a Kanidm Container

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

#### Container Build Examples

Build a `kanidm` container using `podman`:

```bash
CONTAINER_TOOL=podman make build/kanidmd
```

Build a `kanidm` container and use a redis build cache:

```bash
CONTAINER_BUILD_ARGS='--build-arg "SCCACHE_REDIS=redis://redis.dev.blackhats.net.au:6379"' make build/kanidmd
```

#### Automatically Built Containers

To speed up testing across platforms, we're leveraging GitHub actions to build containers for test use.

Whenever code is merged with the `master` branch of Kanidm, containers are automatically built for `kanidmd` and
`radius`. Sometimes they fail to build, but we'll try to keep them available.

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

### Testing the OpenAPI generator things

There's a script in `scripts/openapi_tests` which runs a few docker containers - you need to be running a local instance
on port 8443 to be able to pull the JSON file for testing.
