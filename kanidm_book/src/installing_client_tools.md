# Installing Client Tools

> **NOTE** As this project is in a rapid development phase, running different release versions will likely present incompatibilities. Ensure you're running matching release versions of client and server binaries.

## From packages

Kanidm currently supports:

 * OpenSUSE Tumbleweed
 * OpenSUSE Leap 15.3/15.4
 * Fedora 34/35
 * Centos Stream 9

### OpenSUSE Tumbleweed

Kanidm is part of OpenSUSE Tumbleweed since October 2020. This means you can install
the clients with:

    zypper ref
    zypper in kanidm-clients

### OpenSUSE Leap 15.3/15.4

Leap 15.3/15.4 is still not fully supported with Kanidm. For an experimental client, you can
try the development repository. Using zypper you can add the repository with:

    zypper ar -f obs://network:idm network_idm

Then you need to refresh your metadata and install the clients.

    zypper ref
    zypper in kanidm-clients

### Fedora / Centos Stream

Fedora has limited supported through the development repository. You need to add the repository metadata into the correct directory.

    cd /etc/yum.repos.d
    # Fedora 34
    sudo wget https://download.opensuse.org/repositories/network:/idm/Fedora_34/network:idm.repo
    # Fedora 35
    sudo wget https://download.opensuse.org/repositories/network:/idm/Fedora_35/network:idm.repo
    # Centos Stream 9
    sudo wget https://download.opensuse.org/repositories/network:/idm/CentOS_9_Stream/network:idm.repo

You can then install with:

    sudo dnf install kanidm-clients

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
