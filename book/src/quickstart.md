# Evaluation Quickstart

This section will guide you through a quick setup of Kanidm for evaluation. It's recommended that
for a production deployment you follow the steps in the
[installation chapter](installing_the_server.html) instead as there are a number of security
considerations you should be aware of for production deployments.

### Requirements

- docker or podman
- `x86_64` cpu supporting `x86_64_v2` OR `aarch64` cpu supporting `neon`

### Get the software

```bash
docker pull kanidm/server:latest
```

### Configure the container

```bash
docker volume create kanidmd
docker create --name kanidmd \
  -p 443:8443 \
  -p 636:3636 \
  -v kanidmd:/data \
  kanidm/server:latest
```

### Configure the server

Create server.toml

```toml
{{#rustdoc_include ../../examples/server_container.toml}}
```

### Add configuration to container

```bash
docker cp server.toml kanidmd:/data/server.toml
```

### Generate evaluation certificates

```bash
docker run --rm -i -t -v kanidmd:/data \
  kanidm/server:latest \
  kanidmd cert-generate
```

### Start Kanidmd Container

```bash
docker start kanidmd
```

### Recover the admin roles

The `admin` account is used to configure Kanidm itself.

```bash
docker exec -i -t kanidmd \
  kanidmd recover-account admin
```

The `idm_admin` account is used to manage persons and groups.

```
docker exec -i -t kanidmd \
  kanidmd recover-account idm_admin
```

### Setup the client configuration

```toml
# ~/.config/kanidm

uri = "https://localhost:443"
verify_ca = false
```

### Check you can login

```bash
kanidm login --name idm_admin
```

### Create an account for yourself

```
kanidm person create <your username> <Your Displayname>
```

### Setup your account credentials

```
kanidm person credential create-reset-token <your username>
```

Then follow the presented steps.

### What next?

You can now follow the steps in the [administration section](administrivia.md)
