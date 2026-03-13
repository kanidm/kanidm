# Traefik

Traefik is a flexible HTTP reverse proxy webserver that can be integrated with Docker to allow dynamic configuration and to automatically use LetsEncrypt to provide valid TLS certificates. 

To leverage this with Kanidm, Traefik must be configured with a custom [ServersTransport](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport/) and routed to Kanidm's `HTTPS` scheme and port.

## Example setup

This example assumes that you have a working Traefik configuration with automatic TLS certificates.

> [!NOTE]
>
> Kanidm still requires its own certificates. Generate them according to the [documented quickstart steps](evaluation_quickstart.html#generate-evaluation-certificates)

Because Kanidm uses another set of certificates in its container, Traefik must be configured to skip verification of the certificate chain using a custom serversTransport. This cannot be declared in labels or tags, and must be declared in the [routing configuration](https://doc.traefik.io/traefik/getting-started/configuration-overview/#the-routing-configuration) (formerly known as dynamic configuration).

If your Traefik deployment does not use a routing configuration, mount the routing configuration file to the container and define the rightmost path as a provider in Traefik's [install configuration](https://doc.traefik.io/traefik/getting-started/configuration-overview/#the-install-configuration) (formerly known as static configuration). Because the install configuration can be defined in three different, mutually exclusive ways, this will depend on your current deployment. 

For more information, see the examples below or read Traefik's official documentation for [providing routing configuration to Traefik](https://doc.traefik.io/traefik/reference/routing-configuration/dynamic-configuration-methods/#using-the-file-provider) and their [CLI reference](https://doc.traefik.io/traefik/reference/install-configuration/configuration-options/#opt-providers-file-directory).

```yaml
# Mount the routing configuration file to Traefik via compose
volumes:
  - /path/to/dynamic/conf:/config/dynamic
# Then declare the provider in one of two ways
# Configuration file
providers:
  file:
    directory: /config/dynamic
# Command-line arguments via compose:
command:
  - --providers.file.directory=/config/dynamic
```

Once you've declared a routing configuration, add the following custom serversTransport to it.

```yaml
http:
  serversTransports:
    insecureTransport:
      insecureSkipVerify: true
```

Then, set the scheme to `HTTPS`, the port to `8443`, and the custom serversTransport to `insecureTransport@file`, as seen below.

```yaml
services:
  kanidm:
    image: kanidm/server:devel
    container_name: kanidm
    restart: unless-stopped
    networks:
      - traefik-network
    volumes:
      - kanidm_data:/data
    labels:
      - traefik.enable=true
      - traefik.docker.network=traefik-network
      - traefik.http.routers.kanidm.service=kanidm
      - traefik.http.routers.kanidm.entrypoints=websecure
      - traefik.http.routers.kanidm.rule=Host(`idm.example.com`)
      # IMPORTANT!
      - traefik.http.services.kanidm.loadBalancer.server.scheme=https
      - traefik.http.services.kanidm.loadBalancer.server.port=8443
      - traefik.http.services.kanidm.loadBalancer.serversTransport=insecureTransport@file
networks:
  traefik-network:
volumes:
  kanidm_data:
```
