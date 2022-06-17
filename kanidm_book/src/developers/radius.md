# RADIUS Module Development

Setting up your dev environment is a little complex because of the mono-repo.

1. Install poetry: `python -m pip install poetry`. This is what we use to manage the packages, and allows you to set up virtual python environments easier.
2. Build the base environment. From within the kanidm_rlm_python directory, run: `poetry install`
3. Install the `kanidm` python library: `poetry run python -m pip install ../pykanidm`

Then follow: __[instructions for running a test container](../integrations/radius.html#deploying-a-radius-container)__