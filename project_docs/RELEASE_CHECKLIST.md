# Release checklist

## Pre-Reqs

```bash
cargo install cargo-audit
cargo install cargo-outdated
cargo install cargo-udeps
cargo install wasm-bindgen-cli
```

## Pre Release Check List

### Start a release

- [ ] git checkout -b YYYYMMDD-pre-release

### Cargo Tasks

- [ ] Update MSRV if applicable
- [ ] RUSTC\_BOOTSTRAP=1 cargo udeps
- [ ] cargo outdated -R
- [ ] cargo audit
- [ ] cargo test

### Code Changes

- [ ] upgrade crypto policy values if required
- [ ] bump index version in constants
- [ ] check for breaking db entry changes.

### Administration

- [ ] cargo test
- [ ] build wasm components with release profile
- [ ] Update `RELEASE_NOTES.md`
- [ ] Update `README.md`
- [ ] git commit
- [ ] git push origin YYYYMMDD-pre-release
- [ ] Merge PR

### Git Management

- [ ] git checkout master
- [ ] git pull
- [ ] git checkout -b 1.1.x (Note no v to prevent ref conflict)
- [ ] update version to set pre tag in ./Cargo.toml
- [ ] update version to set pre tag in ./Makefile
- [ ] git commit
- [ ] git tag v1.1.x-pre

- [ ] Final inspect of the branch

- [ ] git push origin 1.1.x
- [ ] git push origin 1.1.x --tags

- [ ] github -> Ensure release branch is protected

### Follow up

- [ ] git checkout master
- [ ] git pull
- [ ] git checkout -b YYYYMMDD-dev-version
- [ ] update version to +1 and add dev tag in ./Cargo.toml
- [ ] update version to +1 and add dev tag in ./Makefile

## Final Release Check List

### Git Management

- [ ] git checkout 1.1.x
- [ ] git pull origin 1.1.x

- [ ] update version to remove pre tag in ./Cargo.toml
- [ ] update version to remove pre tag in ./Makefile
- [ ] git tag v1.1.x
- [ ] git push origin 1.1.x --tags

- [ ] github -> create new release based on tag (not branch) - use tag because then tools will get
      the tag + patches we apply.

### Community

- [ ] Publish release announcement

### Cargo publish

- [ ] publish `kanidm_proto`
- [ ] publish `sketching`
- [ ] publish `kanidm_utils_users`
- [ ] publish `kanidm_lib_file_permissions`
- [ ] publish `kanidm_lib_crypto`
- [ ] publish `kanidm_build_profiles`
- [ ] publish `kanidm_client`
- [ ] publish `kanidm_tools`

### Docker

- [ ] docker buildx use cluster
- [ ] `make buildx/kanidmd/x86_64_v3 buildx/kanidmd buildx/kanidm_tools buildx/radiusd`
- [ ] `IMAGE_VERSION=latest make buildx`
- [ ] Update the readme on docker <https://hub.docker.com/repository/docker/kanidm/server>

### Distro

- [ ] vendor and release to build.opensuse.org
