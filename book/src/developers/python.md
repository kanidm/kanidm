# Kanidm Python Module

So far it includes:

- asyncio methods for all calls, leveraging [aiohttp](https://pypi.org/project/aiohttp/)
- every class and function is fully python typed (test by running `make test/pykanidm/mypy`)
- test coverage for 95% of code, and most of the missing bit is just when you break things
- loading configuration files into nice models using [pydantic](https://pypi.org/project/pydantic/)
- basic password authentication
- pulling RADIUS tokens

TODO: a lot of things.

## Setting up your dev environment.

Setting up a dev environment can be a little complex because of the mono-repo.

1. Install poetry: `python -m pip install poetry`. This is what we use to manage the packages, and
   allows you to set up virtual python environments easier.
2. Build the base environment. From within the `pykanidm` directory, run: `poetry install` This'll
   set up a virtual environment and install all the required packages (and development-related ones)
3. Start editing!

Most IDEs will be happier if you open the kanidm_rlm_python or pykanidm directories as the base you
are working from, rather than the kanidm repository root, so they can auto-load integrations etc.

## Building the documentation

To build a static copy of the docs, run:

```shell
make docs/pykanidm/build
```

You can also run a local live server by running:

```shell
make docs/pykanidm/serve
```

This'll expose a web server at [http://localhost:8000](http://localhost:8000).
