# Kanidm Python Module

So far it includes:

- asyncio methods for all calls, leveraging [aiohttp](https://pypi.org/project/aiohttp/)
- every class and function is fully python typed
- test coverage for 95% of code, and most of the missing bit is just when you break things
- loading configuration files into nice models using [pydantic](https://pypi.org/project/pydantic/)
- basic password authentication
- pulling RADIUS tokens

TODO: a lot of things.

## Building the documentation

To build a static copy of the docs, run:

```shell
docs/pykanidm/build
```

You can also run a local live server by running:

```shell
docs/pykanidm/serve
```

This'll expose a web server at [http://localhost:8000](http://localhost:8000).
