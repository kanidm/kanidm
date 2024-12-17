# Kanidm PPA automation

This dir holds packaging automation that builds debs from the `kanidm/kanidm` repo and
publishes them into the `kanidm/kanidm_ppa` repo. The PPA repo is just a snapshot with no history.

You can also use these pieces outside of the PPA to build deb's locally, see the book at:
https://kanidm.github.io/kanidm/stable/packaging/debian_ubuntu_packaging.html

## PPA dev reference guide

As the book chapter mentioned above is quite verbose, here's the 101 primer for developing this
thing.

All of the various puzzle pieces live directly in this repository:
- The GitHub Actions workflow that orchestrates the automated builds is at `.github/workflows/create-apt-repo.yml`
- Packages and what the depend on are defined by the per package `Cargo.toml`, e.g. `tools/cli/Cargo.toml`
- Build-time dependencies are are configured in the `platform/debian/scripts/` folder.
- Dev instructions live in the book at `book/src/packaging/debian_ubuntu_packaging.md`.
- User facing repo instructions are similarly in `book/src/packaging/ppa_packages.md`.
- Signing keys are defined as repo secrets and also drive the published public key file.
