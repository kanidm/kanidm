# Interacting with the Server

To interact with Kanidm as an administrator, you'll need to use our command line tools.

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

## Kanidm configuration

You can configure kanidm to help make commands simpler by modifying ~/.config/kanidm OR /etc/kanidm/config

    uri = "https://idm.example.com"
    verify_ca = true|false
    verify_hostnames = true|false
    ca_path = "/path/to/ca.pem"
    prompt_user_token = true|false

Once configured, you can test this with:

    kanidm self whoami --name anonymous

## Session Management

To authenticate as a user for use with the command line, you need to use the `login` command
to establish a session token.

    kanidm login --name USERNAME
    kanidm login --name admin

Once complete, you can use kanidm without reauthenticating for a period of time for administration.

You can list active sessions with:

    kanidm session list

Sessions will expire after a period of time (by default 1 hour). To remove these expired sessions
locally you can use:

    kanidm session cleanup

To logout of a session:

    kanidm logout --name USERNAME
    kanidm logout --name admin

