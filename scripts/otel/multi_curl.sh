#!/bin/bash

# This allows testing a bunch of endpoints in a really dumb way

COMMAND="curl -ks"

# 404
$COMMAND https://localhost:8443/asdfasfasfsadf > /dev/null 2>&1
# auth fail
$COMMAND --json '{"hello" : "world" }' https://localhost:8443/v1/auth > /dev/null 2>&1
# good
$COMMAND  https://localhost:8443/status