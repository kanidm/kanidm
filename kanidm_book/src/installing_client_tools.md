# Installing Client Tools

## From packages

Kanidm currently supports:

 * OpenSUSE Tumbleweed
 * OpenSUSE Leap 15.3
 * Fedora 33/34

### OpenSUSE Tumbleweed

Kanidm is part of OpenSUSE Tumbleweed since October 2020. This means you can install
the clients with:

    zypper ref
    zypper in kanidm-clients

### OpenSUSE Leap 15.3

Leap 15.3 is still not fully supported with Kanidm. For an experimental client, you can
try the development repository. Using zypper you can add the repository with:

    zypper ar -f obs://network:idm network_idm

Then you need to refresh your metadata and install the clients.

    zypper ref
    zypper in kanidm-clients

### Fedora

Fedora is still experimentally supported through the development repository. You need to add the repository metadata into the correct directory.

    cd /etc/yum.repos.d
    # 33
    wget https://download.opensuse.org/repositories/network:/idm/Fedora_33/network:idm.repo
    # 34
    wget https://download.opensuse.org/repositories/network:/idm/Fedora_34/network:idm.repo

You can then install with:

    dnf install kanidm-clients

## From source (CLI only, not recommended)

After you check out the source (see [GitHub](https://github.com/kanidm/kanidm)), navigate to:

    cd kanidm_tools
    cargo install --path .

## Checking that the tools work

Now you can check your instance is working. You may need to provide a CA certificate for verification
with the -C parameter:

    kanidm login --name anonymous
    kanidm self whoami -C ../path/to/ca.pem -H https://localhost:8443 --name anonymous
    kanidm self whoami -H https://localhost:8443 --name anonymous

Now you can take some time to look at what commands are available - please [ask for help at any time](https://github.com/kanidm/kanidm#getting-in-contact--questions).