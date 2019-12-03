# Interacting with the Server

To interact with Kanidm as an administration, you'll need to use our command line tools

## From (experimental) packages

Today we support Fedora 30/31 and OpenSUSE leap 15.1 and Tumbleweed.

### SUSE

Using zypper you can add the repository with:

    zypper ar obs://home:firstyear:kanidm home_firstyear_kanidm

Then you need to referesh your metadata and install the clients.

    zypper ref
    zypper in kanidm-clients

### Fedora

On fedora you need to add the repos into the correct directory

    cd /etc/yum.repos.d
    30:
    wget https://download.opensuse.org/repositories/home:/firstyear:/kanidm/Fedora_30/home:firstyear:kanidm.repo
    31:
    wget https://download.opensuse.org/repositories/home:/firstyear:/kanidm/Fedora_31/home:firstyear:kanidm.repo

Now you can add the packages:

    dnf install kanidm-clients

## From source

After you check out the source (see github), navigate to:

    cd kanidm_tools
    cargo build
    cargo install --path ./

## Check the tools work.

Now you can check your instance is working. You may need to provide a CA certificate for verification
with the -C parameter:

    kanidm self whoami -C ../path/to/ca.pem -H https://localhost:8443 --name anonymous
    kanidm self whoami -H https://localhost:8443 --name anonymous

Now you can take some time to look at what commands are available - things may still be rough so
please ask for help at anytime.

## Kandim configuration

You can configure kanidm to help make commands simpler by modifying ~/.config/kanidm OR /etc/kanidm/config

    uri = "https://idm.example.com"
    verify_ca = true|false
    verify_hostnames = true|false
    ca_path = "/path/to/ca.pem"

Once configured, you can test this with:

    kanidm self whoami --name anonymous
