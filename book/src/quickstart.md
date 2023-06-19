# Evaluation Quickstart

This section will guide you through a quick setup of Kanidm for evaluation. It's recommended that
for a production deployment you follow the steps in the
[installation chapter](installing_the_server.html) instead as there are a number of security
considerations you should understand.

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
  kanidmd cert-generate -c /data/server.toml
```

### Recover the admin password

```bash
docker run --rm -i -t -v kanidmd:/data \
  kanidm/server:latest \
  kanidmd recover-account admin -c /data/server.toml
```

### Start Kanidmd

```bash
docker start kanidmd
```

### Setup the client configuration

```toml
# ~/.config/kanidm

uri = "https://localhost:443"
verify_ca = false
```

### Check you can login

```bash
kanidm login
```

### What next?

You can now follow the steps in the [administration section](administrivia.md)
