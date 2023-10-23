# REST Interface

<!-- deno-fmt-ignore-start -->

{{#template ../../templates/kani-warning.md
imagepath=../../images/
title=Note!
text=This is a work in progress and not all endpoints have perfect schema definitions, but they're all covered!
}}

<!-- deno-fmt-ignore-end -->

We're generating an OpenAPI specification file and Swagger interface using
[utoipa](https://crates.io/crates/utoipa).

The Swagger UI is available at `/docs/swagger-ui` on your server (ie, if your origin is
`https://example.com:8443`, visit `https://example.com:8443/docs/swagger-ui`).

The OpenAPI schema is similarly available at `/docs/v1/openapi.json`.
