# Installing Client Tools

> **NOTE** As this project is in a rapid development phase, running different 
release versions will likely present incompatibilities. Ensure you're running 
matching release versions of client and server binaries. If you have any issues, 
check that you are running the latest software.

## From packages

Kanidm currently supports the following Linux distributions:

 * OpenSUSE Tumbleweed
 * OpenSUSE Leap 15.3/15.4
 * Fedora 36
 * CentOS Stream 9

The `kanidm` client has been built and tested from Windows, but is not (yet) packaged routinely.

### OpenSUSE Tumbleweed

Kanidm has been part of OpenSUSE Tumbleweed since October 2020. You can install
the clients with:

    zypper ref
    zypper in kanidm-clients

### OpenSUSE Leap 15.3/15.4

Using zypper you can add the Kanidm leap repository with:

    zypper ar -f obs://network:idm network_idm

Then you need to refresh your metadata and install the clients.

    zypper ref
    zypper in kanidm-clients

### Fedora / Centos Stream

Fedora has limited support through the development repository. You need to add the repository
metadata into the correct directory:

    # Fedora
    wget https://download.opensuse.org/repositories/network:/idm/Fedora_36/network:idm.repo
    # Centos Stream 9
    wget https://download.opensuse.org/repositories/network:/idm/CentOS_9_Stream/network:idm.repo

You can then install with:

    dnf install kanidm-clients

{{#template
    templates/kani-warning.md
    imagepath=images
    title=Take Note!
    text=Kanidm frequently uses new Rust versions and features, however Fedora and Centos frequently are behind in Rust releases. As a result, they may not always have the latest Kanidm versions available.
}}

## Tools Container

In some cases if your distribution does not have native kanidm-client support, you can use the cli
tools from a docker container instead.

    docker pull kanidm/tools:latest
    docker run --rm -i -t \
        -v /etc/kanidm/config:/etc/kanidm/config:ro \
        -v ~/.config/kanidm:/home/kanidm/.config/kanidm:ro \
        -v ~/.cache/kanidm_tokens:/home/kanidm/.cache/kanidm_tokens \
        kanidm/tools:latest \
        /sbin/kanidm --help

If you have a ca.pem you may need to bind mount this in as required.

> **TIP** You can alias the docker run command to make the tools easier to access such as:

    alias kanidm="docker run ..."

## From source (CLI only, not recommended)

After you check out the source (see [GitHub](https://github.com/kanidm/kanidm)), navigate to:

    cd kanidm_tools
    cargo install --path .

## Checking that the tools work

Now you can check your instance is working. You may need to provide a CA certificate for verification
with the -C parameter:

    kanidm login --name anonymous
    kanidm self whoami -H https://localhost:8443 --name anonymous
    kanidm self whoami -C ../path/to/ca.pem -H https://localhost:8443 --name anonymous

Now you can take some time to look at what commands are available - please
[ask for help at any time](https://github.com/kanidm/kanidm#getting-in-contact--questions).
