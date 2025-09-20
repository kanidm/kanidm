#!/bin/bash

uv run coverage run -m pytest -vvx && \
	uv run coverage html

