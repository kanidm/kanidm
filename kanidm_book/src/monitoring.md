# Monitoring the platform

The monitoring design of Kanidm is still very much in its infancy - [take part in the dicussion here!](https://github.com/kanidm/kanidm/issues/216).

## kanidmd

### Health Checks

kanidmd currently responds to HTTP GET requests at the `/status` endpoint with a JSON object of either "true" or "false". `true` indicates that the platform is responding to requests.

| URL | `<hostname>/status` |
| --- | --- |
| Example URL | `https://example.com/status` |
| Expected response | One of either `true` or `false` (without quotes) |
| Additional Headers | x-kanidm-opid
| Content Type | application/json |
| Cookies | kanidm-session |

### Metrics

Enable the metrics listener by setting `metrics_listener` in the server configuration.

To listen on localhost, port 31292:

```
metrics_listener = "127.0.0.1:31292"
```

Or to open it up globally, if you want to configure remote monitoring:

```
metrics_listener = "0.0.0.0:31292"
```

This exposes an OpenMetrics port with (currently) basic counters for the number of requests which have reached the `kanidmd` web server.

The endpoint is at `/metrics`, so if you set `127.0.0.1:31292` above, you can check it's working by running:

```
curl http://localhost:31292/metrics
```

If you don't see results and you've just started `kanidmd`, access the web server then re-run the query. The statistics aren't enabled until a connection is made.
