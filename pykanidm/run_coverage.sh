#!/bin/bash

poetry run coverage run -m pytest -vvx && \
	poetry run coverage html

