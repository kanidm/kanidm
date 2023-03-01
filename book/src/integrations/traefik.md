# Traefik

Traefik is a flexible HTTP reverse proxy webserver that can be integrated with Docker to allow
dynamic configuration and to automatically use LetsEncrypt to provide valid TLS certificates. We can
leverage this in the setup of Kanidm by specifying the configuration of Kanidm and Traefik in the
same [Docker Compose configuration](https://docs.docker.com/compose/).

## Example setup

Create a new directory and copy the following YAML file into it as `docker-compose.yml`. Edit the
YAML to update the LetsEncrypt account email for your domain and the FQDN where Kanidm will be made
available. Ensure you adjust this file or Kanidm's configuration to have a matching HTTPS port; the
line `traefik.http.services.kanidm.loadbalancer.server.port=8443` sets this on the Traefik side.

> **NOTE** You will need to generate self-signed certificates for Kanidm, and copy the configuration
> into the `kanidm_data` volume. Some instructions are available in the "Installing the Server"
> section of this book.

`docker-compose.yml`

```yaml
version: "3.4"

services:
  traefik:
    image: traefik:v2.6
    container_name: traefik
    command:
      - "--certificatesresolvers.http.acme.email=admin@example.com"
      - "--certificatesresolvers.http.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.http.acme.tlschallenge=true"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.http.tls=true"
      - "--entrypoints.websecure.http.tls.certResolver=http"
      - "--log.level=INFO"
      - "--providers.docker=true"
      - "--providers.docker.exposedByDefault=false"
      - "--serverstransport.insecureskipverify=true"
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "443:443"
  kanidm:
    container_name: kanidm
    image: kanidm/server:devel
    restart: unless-stopped
    volumes:
      - kanidm_data:/data
    labels:
      - traefik.enable=true
      - traefik.http.routers.kanidm.entrypoints=websecure
      - traefik.http.routers.kanidm.rule=Host(`idm.example.com`)
      - traefik.http.routers.kanidm.service=kanidm
      - traefik.http.serversTransports.kanidm.insecureSkipVerify=true
      - traefik.http.services.kanidm.loadbalancer.server.port=8443
      - traefik.http.services.kanidm.loadbalancer.server.scheme=https
volumes:
  kanidm_data: {}
```

Finally you may run `docker-compose up` to start up both Kanidm and Traefik.
