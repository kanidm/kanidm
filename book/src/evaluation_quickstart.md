# Evaluation Quickstart

This section will guide you through a quick setup of Kanidm for evaluation. It's recommended that
for a production deployment you follow the steps in the
[installation chapter](installing_the_server.html) instead as there are a number of security
considerations you should be aware of for production deployments.

## Requirements

The only thing you'll need for this is Docker, Podman, or a compatible containerd environment
installed and running.

## Get the software

```bash
docker pull docker.io/kanidm/server:latest
```

## Create your configuration

Create `server.toml`. The important parts are the `domain` and `origin`. For this example, if you
use `localhost` and `https://localhost:8443` this will match later commands.

```toml
{{#rustdoc_include ../../examples/server_container.toml}}
```

## Start the container

First we create a docker volume to store the data, then we start the container.

```bash
docker volume create kanidmd
docker create --name kanidmd \
  -p 443:8443 \
  -p 636:3636 \
  -v kanidmd:/data \
  docker.io/kanidm/kanidm/server:latest
```

## Copy the configuration to the container

```bash
docker cp server.toml kanidmd:/data/server.toml
```

## Generate evaluation certificates

```bash
docker run --rm -i -t -v kanidmd:/data \
  docker.io/kanidm/server:latest \
  kanidmd cert-generate
```

## Start Kanidmd Container

```bash
docker start kanidmd
```

## Recover the Admin Role Passwords

The `admin` account is used to configure Kanidm itself.

```bash
docker exec -i -t kanidmd \
  kanidmd recover-account admin
```

The `idm_admin` account is used to manage persons and groups.

```shell
docker exec -i -t kanidmd \
  kanidmd recover-account idm_admin
```

## Setup the client configuration

This happens on your computer, not in the container.

```toml
# ~/.config/kanidm

uri = "https://localhost:8443"
verify_ca = false
```

## Check you can login

```bash
kanidm login --name idm_admin
```

## Create an account for yourself

```shell
kanidm person create <your username> <Your Displayname>
```

## Set up your account credentials

```shell
kanidm person credential create-reset-token <your username>
```

Then follow the presented steps.

## What next?

You'll probably want to set it up properly, so that other computers can access it, so
[choose a domain name](choosing_a_domain_name.md) and complete the full server installation.

Alternatively you might like to try configurig one of these:

- [OAuth2](./integrations/oauth2.md) for web services
- [PAM and nsswitch](./integrations/pam_and_nsswitch.md) for authentication to Linux systems
- [Replication](repl/), if one Kanidm instance isn't enough
