## Pre-Reqs

```bash
cargo install cargo-audit
cargo install cargo-outdated
```

## Check List

### Start a release

- [ ] git checkout -b YYYYMMDD-release

### Cargo Tasks

- [ ] cargo outdated -R
- [ ] cargo audit
- [ ] cargo test

### Code Changes

- [ ] upgrade crypto policy values if requires
- [ ] bump index version in constants
- [ ] check for breaking db entry changes.

### Administration

- [ ] update version in ./kanidmd\_web\_ui/Cargo.toml
- [ ] update version in ./Cargo.toml
- [ ] cargo test
- [ ] build wasm components with release profile
- [ ] Update `RELEASE_NOTES.md`
- [ ] git commit
- [ ] git rebase -i HEAD~X
- [ ] git push origin YYYYMMDD-release
- [ ] Merge PR

### Git Management

- [ ] git checkout master
- [ ] git branch 1.1.0-alpha.x (Note no v to prevent ref conflict)
- [ ] git checkout v1.1.0-alpha.x
- [ ] git tag v1.1.0-alpha.x

- [ ] Final inspect of the branch

- [ ] git push origin 1.1.0-alpha.x
- [ ] git push origin 1.1.0-alpha.x --tags

### Cargo publish

- [ ] publish `kanidm_proto`
- [ ] publish `kanidmd/kanidm`
- [ ] publish `kanidm_client`
- [ ] publish `kanidm_tools`

### Docker

- [ ] docker buildx use cluster
- [ ] `make buildx/kanidmd/x86_64_v3 buildx/kanidmd buildx/kanidm_tools buildx/radiusd`
- [ ] `IMAGE_VERSION=latest make buildx/kanidmd/x86_64_v3 buildx/kanidmd buildx/kanidm_tools buildx/radiusd`
- [ ] Update the readme on docker https://hub.docker.com/repository/docker/kanidm/server

### Distro

- [ ] vendor and release to build.opensuse.org

### Follow up

- [ ] git checkout master
- [ ] git pull
- [ ] git branch YYYYMMDD-dev-version
- [ ] update version in ./kanidmd\_web\_ui/Cargo.toml
- [ ] update version in ./Cargo.toml
