# OpenTelemetry for Kanidm

First, start the containers:

```shell
docker-compose up
```

Once that's stopped scrolling for a bit, run the Kanidm server:

```shell
OTLP_ENDPOINT="http://localhost:4317" <run kanidm>
```

Then access the Jaeger UI on <http://localhost:16686/search>
