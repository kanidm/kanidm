#!/bin/bash

# checks that all the cargo files are found in the dependabot config
# doesn't check that extras are there, dependabot will tell you
# typically here - https://github.com/kanidm/kanidm/network/updates

DIRNAMES="$(find . -type f -name Cargo.toml | sed -E 's/^\.//' | xargs -n1 dirname)"

for dirname in $DIRNAMES; do
    echo "Checking for ${dirname}"
    if [ "$(grep -c "\"${dirname}\"" .github/dependabot.yml)" -ne 1 ]; then
        echo "Need to find this!"
    else
        echo "OK!"
    fi
done