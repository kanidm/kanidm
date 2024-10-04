# PPA Packages

- This builds packages from the [main Kanidm repository](https://github.com/kanidm/kanidm) and makes a package archive for “nightly” packages.
Stable packages are intended to be introduced soon which will require repeating updated instructions
here.
- Packages are distributed for the latest LTS versions, Ubuntu 22.04 & Debian 12.

- Please note that while the commands below should also work on other Ubuntu-based distributions, we
cannot ensure their compatibility. Pop OS, for example, would require an altered setup in
line with their [instructions](https://support.system76.com/articles/ppa-third-party/).

## Adding it to your system

Set pipefail so that failures are caught.

```bash
set -o pipefail
```

Make sure you have a “trusted GPG” directory.

```bash
sudo mkdir -p /etc/apt/trusted.gpg.d/
```

Download the Kanidm PPA GPG public key.

```bash
curl -s --compressed "https://kanidm.github.io/kanidm_ppa/KEY.gpg" \
    | gpg --dearmor \
    | sudo tee /etc/apt/trusted.gpg.d/kanidm_ppa.gpg >/dev/null
```

Add the Kanidm PPA to your local APT configuration, with autodetection of Ubuntu vs. Debian.

```bash
sudo curl -s --compressed "https://kanidm.github.io/kanidm_ppa/kanidm_ppa.list" \
    | grep $( ( . /etc/os-release && echo $ID) ) \
    | sudo tee /etc/apt/sources.list.d/kanidm_ppa.list
```

Update your local package cache.

```bash
sudo apt update
```

## Listing Packages

Use `apt search` to list the packages available:

```bash
apt search kanidm
```
