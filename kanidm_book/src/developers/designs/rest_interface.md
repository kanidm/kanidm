# REST Interface

<!-- deno-fmt-ignore-start -->

{{#template ../../templates/kani-warning.md
imagepath=../../images/
title=Note!
text=Here begins some early notes on the REST interface - much better ones are in the repository's designs directory.
}}

<!-- deno-fmt-ignore-end -->

There's an endpoint at `/<api_version>/routemap` (for example, `https://localhost/v1/routemap`)
which is based on the API routes as they get instantiated.

It's _very, very, very_ early work, and should not be considered stable at all.

An example of some elements of the output is below:

```json
{
  "routelist": [
    {
      "path": "/",
      "method": "GET"
    },
    {
      "path": "/robots.txt",
      "method": "GET"
    },
    {
      "path": "/ui/",
      "method": "GET"
    },
    {
      "path": "/v1/account/:id/_unix/_token",
      "method": "GET"
    },
    {
      "path": "/v1/schema/attributetype/:id",
      "method": "GET"
    },
    {
      "path": "/v1/schema/attributetype/:id",
      "method": "PUT"
    },
    {
      "path": "/v1/schema/attributetype/:id",
      "method": "PATCH"
    }
  ]
}
```
