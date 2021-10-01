
// cargo install cargo-audit
// cargo install cargo-outdated
// cargo install cargo-release

* upgrade crypto policy values if requires
* bump index version in constants
* check for breaking db entry changes.

* cargo outdated -R
* cargo audit

* cargo test

* Update RELEASE_NOTES.md

* cargo release --no-dev-version --skip-push --skip-publish --skip-tag  1.1.0-alpha.X
* git rebase -i HEAD~X
* git tag v1.1.0-alpha.x

* release kanidm_proto
* release kanidmd/kanidm
* release kanidm_client
* release kanidm_tools

* build kanidmd docker
* build kanidm_radisud docker

* vendor and release to build.opensuse.org
    osc service ra; osc ci


