#!/bin/bash

# This script will find all duplicated names in the Kanidm database, handy for upgrading from 1.1.0 RC15 to RC16

if [ -z "${KANIDM_NAME}" ]; then
    echo "Setting the KANIDM_NAME env var will save you selecting a user multiple times!" >&2
fi

RES="$(
	kanidm group list | grep -E '^name' | awk '{print $2}' || exit 1
	kanidm person list | grep -E '^name' | awk '{print $2}' || exit 1
	kanidm service-account list | grep -E '^name' | awk '{print $2}' || exit 1
	kanidm system oauth2 list | grep -E '^oauth2_rs_name' | awk '{print $2}' || exit 1
)"

DUPES="$(echo "${RES}" | sort | uniq -c | grep -vE '^\s+1' | awk '{print $2}')"

if [ -z "${DUPES}" ]; then
    echo "No duplicates found" >&2
    exit 0
else
    echo "Duplicates found, here's a list" >&2
    echo "${DUPES}"
    exit 1
fi