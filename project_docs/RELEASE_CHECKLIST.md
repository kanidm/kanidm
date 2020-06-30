
// cargo install cargo-audit
// cargo install carga-outdated

* cargo audit
* cargo outdated

* bump all cargo.toml versions
    find kani* -name Cargo.toml -exec cat '{}' \; | grep -e '^version ='

* bump index version in constants
* check for breaking db entry changes.

* Update RELEASE_NOTES.md

* release kanidm_proto
* release kanidmd/kanidm
* release kanidm_client
* release kanidm_tools

* build kanidmd docker
* build kanidm_radisud docker

* vendor and release to build.opensuse.org
    osc service ra; osc ci


