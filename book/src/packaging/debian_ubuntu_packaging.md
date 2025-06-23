# Debian / Ubuntu Packaging

## Building packages

- Debian packaging is complex enough that it lives in a separate repository:
  [kanidm/kanidm_ppa_automation](https://github.com/kanidm/kanidm_ppa_automation).
- While community-maintained packages are available at <https://kanidm.github.io/kanidm_ppa/> these instructions will
  guide you through replicating the same process locally, using Docker to isolate the build process from your normal
  computer.
- Due to the complexity of crosscompilation, we no longer support it and recommend building natively, i.e. on the
  platform you're targeting.
- While the examples below will use `aarch64-unknown-linux-gnu` aka `arm64`, the same process works for
  `x86_64-unknown-linux-gnu` aka `amd64` as well.

1. Start in the root directory of the main [kanidm/kanidm](https://github.com/kanidm/kanidm) repository.
2. Pull in the separate deb packaging submodule:

```shell
git submodule update platform/debian/kanidm_ppa_automation
```

3. Create a sacrificial deb builder container to avoid changing your own system:

```shell
docker run --rm -it -e VERBOSE=true -e CI=true \
  --mount "type=bind,src=$PWD,target=/src" \
  --workdir /src \
  rust:bookworm
```

4. In the container install dependencies with:

```shell
platform/debian/kanidm_ppa_automation/scripts/install_ci_build_dependencies.sh
```

5. Launch your desired target build:

```shell
platform/debian/kanidm_ppa_automation/scripts/build_native.sh aarch64-unknown-linux-gnu
```

6. Go get a drink of your choice while the build completes.
7. Launch the deb build:

```shell
platform/debian/kanidm_ppa_automation/scripts/build_debs.sh aarch64-unknown-linux-gnu
```

8. You can now exit the container, the package paths displayed at the end under `target` will persist.

## Adding or amending a deb package

The rough overview of steps is as follows, see further down for details.

1. Add cargo-deb specific metadata to the rust package and any static assets. Submit your changes as a PR.
2. Add build steps to the separate packaging repo. Submit your changes as a PR.
3. Go back to the main repo to update the packaging submodule reference to aid running manual dev builds of the new
   package.

In theory steps 1 & 3 could be done in one PR, but this way is simpler.

### Configuration in the main repo

- The repo is: [kanidm/kanidm](https://github.com/kanidm/kanidm)
- Packages are primarily based on their package specific `Cargo.toml` definition read by `cargo-deb`. For an example,
  see `unix_integration/resolver/Cargo.toml`
- A package specific `debian` folder is used for static assets. See: `unix_integration/resolver/debian` for an example.
- The debian folder may house needed `postinst`, `prerm` etc hook definitions. They must include the `#DEBHELPER#`
  comment after any custom actions.
- The package debian folder is also used for any systemd unit files. The file naming pattern is very specific, refer to
  `cargo-deb` documentation for details.

### Configuration in the kanidm_ppa_automation repo

- The repo is: [kanidm/kanidm_ppa_automation](https://github.com/kanidm/kanidm_ppa_automation)
- Changes are needed if a new binary and/or package is added, or if build time dependencies change.
- Amend `scripts/build_native.sh` build rules to include new binaries or packages with shared libraries.
- Add any new build time system dependencies to `scripts/install_ci_build_dependencies.sh`, be aware of any difference
  in package names between Debian & Ubuntu.
- Add any new packages to `scripts/build_debs.sh`, search for the line starting with `for package in`.
- Finally, once your changes have been approved go back to the main `kanidm/kanidm` repo and update the submodule
  reference and PR the reference update. This is not needed for official builds but helps anyone doing dev builds
  themselves:

  ```shell
  cd platform/debian/kanidm_ppa_automation
  git pull
  cd -
  git add platform/debian/kanidm_ppa_automation
  git commit -m "Update kanidm_ppa_automation reference to latest"
  ```
