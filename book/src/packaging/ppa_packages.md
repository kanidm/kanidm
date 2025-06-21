# Kanidm PPA Packages

> [!NOTE]
> These are not supported in the main repo, please raise issues in the
> [kanidm/kanidm_ppa_automation](https://github.com/kanidm/kanidm_ppa_automation) repository, and understand that it is
> a community-supported effort, rather than by the core Kanidm project.

- The Kanidm PPA repository contains Debian & Ubuntu packages built from the
  [main Kanidm repository](https://github.com/kanidm/kanidm).
- Two separate components are available, `stable` for released versions and `nightly` which only provides the latest
  bleeding edge, refreshed once a day.
- Packages are distributed for current LTS versions of Debian & Ubuntu that natively package the required dependencies;
  - Ubuntu: 22.04 aka `jammy` & 24.04 aka `noble`.
  - Debian 12 aka `bookworm`.

- Please note that while the spirit of the commands below should also work on other Debian-based distributions, the
  codename detection will not work and you will need to manually choose which distribution is the closest to yours. The
  methods for adding repositories may also vary, for example Pop OS, requires an altered setup in line with their
  [instructions](https://support.system76.com/articles/ppa-third-party/).

## Adding it to your system

Make sure you have a “trusted GPG” directory for storing signing keys.

```bash
sudo mkdir -p /etc/apt/trusted.gpg.d/
```

Download the Kanidm PPA GPG public key.

```bash
curl -s "https://kanidm.github.io/kanidm_ppa/kanidm_ppa.asc" \
    | sudo tee /etc/apt/trusted.gpg.d/kanidm_ppa.asc >/dev/null
```

Add the Kanidm PPA to your local APT configuration, with autodetection of Ubuntu vs. Debian. Please adjust accordingly
if you want the `nightly` component instead of the default `stable`.

```bash
curl -s "https://kanidm.github.io/kanidm_ppa/kanidm_ppa.list" \
    | grep $( ( . /etc/os-release && echo $VERSION_CODENAME) ) | grep stable \
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

## Installing stable on top of nightly

If you previously had the alpha version kanidm nightly packages installed or are switching from nightly down to stable,
it may be difficult to remove the previous versions safely without losing for example Kanidm backed sudo in the middle.
This snippet is intended to help with that:

```bash
sudo bash <<EOT
dpkg --remove kanidm kanidm-unixd libnss-kanidm libpam-kanidm
apt install -y kanidm kanidm-unixd
EOT
```

If anything goes wrong during the snippet, you may need to fall back to other methods of gaining root to complete the
transition!
