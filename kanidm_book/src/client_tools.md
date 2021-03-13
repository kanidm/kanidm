# Interacting with the Server

To interact with Kanidm as an administration, you'll need to use our command line tools

## From (experimental) packages

Kanidm currently supports:
 * Fedora 33
 * OpenSUSE leap 15.2
 * Tumbleweed

### OpenSUSE Tumbleweed

Kanidm is part of OpenSUSE Tumbleweed since October 2020. This means you can install
the clients with:

    zypper ref
    zypper in kanidm-clients

### OpenSUSE Leap 15.2

Leap 15.2 is still not fully supported with Kanidm. For an experimental client, you can
try the development repository. Using zypper you can add the repository with:

    zypper ar https://download.opensuse.org/repositories/home:/firstyear:/kanidm/openSUSE_Leap_15.2/ home_firstyear_kanidm
    zypper mr -f home_firstyear_kanidm

Then you need to referesh your metadata and install the clients.

    zypper ref
    zypper in kanidm-clients

### Fedora

Fedora is still experimentally supported through the development repository. You need to add the repository metadata into the correct directory.

    cd /etc/yum.repos.d
    wget https://download.opensuse.org/repositories/home:/firstyear:/kanidm/Fedora_33/home:firstyear:kanidm.repo

You can then install with:

    dnf install kanidm-clients

## From source

After you check out the source (see github), navigate to:

    cd kanidm_tools
    cargo install --path .

## Check the tools work

Now you can check your instance is working. You may need to provide a CA certificate for verification
with the -C parameter:

    kanidm login --name anonymous
    kanidm self whoami -C ../path/to/ca.pem -H https://localhost:8443 --name anonymous
    kanidm self whoami -H https://localhost:8443 --name anonymous

Now you can take some time to look at what commands are available - please ask for help at anytime.

## Authenticating a user with the command line

To authenticate as a user for use with the command line, you need to use the `login` command
to establish a session token.

    kanidm login --name USERNAME
    kanidm login --name admin

Once complete, you can use kanidm without reauthenticating for a period of time for administration.

## Kandim configuration

You can configure kanidm to help make commands simpler by modifying ~/.config/kanidm OR /etc/kanidm/config

    uri = "https://idm.example.com"
    verify_ca = true|false
    verify_hostnames = true|false
    ca_path = "/path/to/ca.pem"

Once configured, you can test this with:

    kanidm self whoami --name anonymous

