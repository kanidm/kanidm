# REST Interface

> [!NOTE]
>
> This is a work in progress and not all endpoints have perfect schema definitions, but they're all covered!

We're generating an OpenAPI specification file and Swagger interface using [utoipa](https://crates.io/crates/utoipa).

The Swagger UI is available at `/docs/swagger-ui` on your server (ie, if your origin is `https://example.com:8443`,
visit `https://example.com:8443/docs/swagger-ui`).

The OpenAPI schema is similarly available at `/docs/v1/openapi.json`.

You can download the schema file using `kanidm api download-schema <filename>` - it defaults to `./kanidm-openapi.json`.
