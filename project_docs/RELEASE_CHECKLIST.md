
// cargo install cargo-audit
// cargo install cargo-outdated
// cargo install cargo-release

* cargo audit
* cargo outdated

* upgrade crypto policy values if requires
* bump index version in constants
* check for breaking db entry changes.

* Update RELEASE_NOTES.md

* git tag v1.1.x-alpha

* bump all cargo.toml versions
    find kani* -name Cargo.toml -exec cat '{}' \; | grep -e '^version ='

* release kanidm_proto
* release kanidmd/kanidm
* release kanidm_client
* release kanidm_tools

* build kanidmd docker
* build kanidm_radisud docker

* vendor and release to build.opensuse.org
    osc service ra; osc ci


