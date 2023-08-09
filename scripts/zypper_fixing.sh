#!/bin/bash

# makes sure the repos are configured because the containers are derpy sometimes

#disable the openh264 repo
if [ "$(zypper lr | grep -ci 'repo-openh264')" -eq 1 ]; then
    zypper mr -d -f -n 'repo-openh264'
fi

# add the non-oss repo if it doesn't exist
if [ "$(zypper lr | grep -c 'repo-non-oss')" -eq 0 ]; then
    zypper ar -f -n 'Non-OSS' http://download.opensuse.org/tumbleweed/repo/non-oss/ repo-non-oss
fi

# update the repos and make sure the ones we want are enabled
zypper mr -k repo-oss
zypper mr -k repo-non-oss
zypper mr -k repo-update
zypper ref --force
zypper -v dup -y
