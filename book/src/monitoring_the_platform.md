# Monitoring the platform

The monitoring design of Kanidm is still very much in its infancy -
[take part in the discussion at github.com/kanidm/kanidm/issues/216](https://github.com/kanidm/kanidm/issues/216).

## kanidmd status endpoint

kanidmd currently responds to HTTP GET requests at the `/status` endpoint with a JSON object of
either "true" or "false". `true` indicates that the platform is responding to requests.

| URL                | `<hostname>/status`                              |
| ------------------ | ------------------------------------------------ |
| Example URL        | `https://example.com/status`                     |
| Expected response  | One of either `true` or `false` (without quotes) |
| Additional Headers | x-kanidm-opid                                    |
| Content Type       | application/json                                 |
| Cookies            | kanidm-session                                   |

## OpenTelemetry Tracing

Configure OTLP trace exports by setting a `otel_grpc_url` in the server configuration. This'll
enable [OpenTelemetry traces](https://opentelemetry.io) to be sent for observability use cases.

Example:

```toml
otel_grpc_url = "http://my-otel-host:4317"
```

### Troubleshooting

#### Max Span Size Exceeded

On startup, we run some big processes that might hit a "max trace size" in certain configurations.
Grafana Tempo defaults to 5MB, which is sensible for most things, but ... 😁

Grafana Tempo
[config to allow larger spans](https://grafana.com/docs/tempo/latest/troubleshooting/response-too-large/):

```yaml
distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          max_recv_msg_size_mib: 20
```
