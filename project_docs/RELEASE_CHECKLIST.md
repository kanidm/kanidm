
## Pre-Reqs

    cargo install cargo-audit
    cargo install cargo-outdated
    cargo install cargo-release

## Check List

### Code Changes

[ ] upgrade crypto policy values if requires
[ ] bump index version in constants
[ ] check for breaking db entry changes.
[ ] build wasm components with release

### Cargo Tasks

[ ] cargo outdated -R
[ ] cargo audit
[ ] cargo test

### Administration

[ ] Update `RELEASE_NOTES.md`
[ ] git commit
[ ] Update the readme on docker https://hub.docker.com/repository/docker/kanidm/server

### Git Management

[ ] cargo release --no-dev-version --no-push --no-publish --no-tag  1.1.0-alpha.X
[ ] git rebase -i HEAD~X
[ ] git tag v1.1.0-alpha.x
[ ] git branch 1.1.0-alpha.x   (Note no v to prevent ref conflict)
[ ] git checkout v1.1.0-alpha.x

[ ] Inspect the branch

[ ] git push origin 1.1.0-alpha.x
[ ] git push origin 1.1.0-alpha.x --tags
[ ] git push origin master
[ ] git push origin master --tags

### Cargo publish

[ ] publish `kanidm_proto`
[ ] publish `kanidmd/kanidm`
[ ] publish `kanidm_client`
[ ] publish `kanidm_tools`

### Docker

[ ]  docker buildx use cluster
[ ] `make buildx/kanidmd/x86_64_v3 buildx/kanidmd buildx/radiusd`

### Distro

[ ] vendor and release to build.opensuse.org

