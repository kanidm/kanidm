
// cargo install cargo-audit
// cargo install cargo-outdated
// cargo install cargo-release

* cargo audit
* cargo outdated -R

* upgrade crypto policy values if requires
* bump index version in constants
* check for breaking db entry changes.

* Update RELEASE_NOTES.md

* cargo release --no-dev-version --skip-publish --skip-tag  1.1.0-alpha.4
* git tag v1.1.0-alpha.x

* release kanidm_proto
* release kanidmd/kanidm
* release kanidm_client
* release kanidm_tools

* build kanidmd docker
* build kanidm_radisud docker

* vendor and release to build.opensuse.org
    osc service ra; osc ci


