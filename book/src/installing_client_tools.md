# Installing Client Tools

> **NOTE** Running different release versions will likely present incompatibilities. Ensure you're
> running matching release versions of client and server binaries. If you have any issues, check
> that you are running the latest version of Kanidm.

## From packages

Kanidm currently is packaged for the following systems:

- OpenSUSE Tumbleweed
- OpenSUSE Leap 15.4/15.5/15.6
- MacOS
- Arch Linux
- NixOS
- Fedora 38
- CentOS Stream 9

The `kanidm` client has been built and tested from Windows, but is not (yet) packaged routinely.

### OpenSUSE Tumbleweed / Leap 15.6

Kanidm is available in Tumbleweed and Leap 15.6. You can install the clients with:

```bash
zypper ref
zypper in kanidm-clients
```

### OpenSUSE Leap 15.4/15.5

Using zypper you can add the Kanidm leap repository with:

```bash
zypper ar -f obs://network:idm network_idm
```

Then you need to refresh your metadata and install the clients.

```bash
zypper ref
zypper in kanidm-clients
```

### MacOS - Brew

[Homebrew](https://brew.sh/) allows addition of third party repositories for installing tools. On
MacOS you can use this to install the Kanidm tools.

```bash
brew tap kanidm/kanidm
brew install kanidm
```

### Arch Linux

[Kanidm on AUR](https://aur.archlinux.org/packages?O=0&K=kanidm)

### NixOS

[Kanidm in NixOS](https://search.nixos.org/packages?sort=relevance&type=packages&query=kanidm)

### Fedora / Centos Stream

<!-- deno-fmt-ignore-start -->

{{#template templates/kani-warning.md
imagepath=images
title=Take Note!
text=Kanidm frequently uses new Rust versions and features, however Fedora and Centos frequently are behind in Rust releases. As a result, they may not always have the latest Kanidm versions available.
}}

<!-- deno-fmt-ignore-end -->

Fedora has limited support through the development repository. You need to add the repository
metadata into the correct directory:

```bash
# Fedora
wget https://download.opensuse.org/repositories/network:/idm/Fedora_38/network:idm.repo
# Centos Stream 9
wget https://download.opensuse.org/repositories/network:/idm/CentOS_9_Stream/network:idm.repo
```

You can then install with:

```bash
dnf install kanidm-clients
```

## Tools Container

In some cases if your distribution does not have native kanidm-client support, and you can't access
cargo for the install for some reason, you can use the cli tools from a docker container instead.

This is a "last resort" and we don't really recommend this for day to day usage.

```bash
echo '{}' > ~/.cache/kanidm_tokens
chmod 666 ~/.cache/kanidm_tokens
docker pull kanidm/tools:latest
docker run --rm -i -t \
    --network host \
    -v /etc/kanidm/config:/etc/kanidm/config:ro \
    -v ~/.config/kanidm:/home/kanidm/.config/kanidm:ro \
    -v ~/.cache/kanidm_tokens:/home/kanidm/.cache/kanidm_tokens \
    kanidm/tools:latest \
    /sbin/kanidm --help
```

If you have a ca.pem you may need to bind mount this in as required as well.

> **TIP** You can alias the docker run command to make the tools easier to access such as:

```bash
alias kanidm="docker run ..."
```

## Cargo

The tools are available as a cargo download if you have a rust tool chain available. To install rust
you should follow the documentation for [rustup](https://rustup.rs/). These will be installed into
your home directory. To update these, re-run the install command. You will likely need to install
additional development libraries, specified in the [Developer Guide](developers/readme.md).

```bash
cargo install kanidm_tools
```
