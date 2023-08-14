#!/bin/bash

# makes sure the repos are configured because the containers are derpy sometimes

set -e

#disable the openh264 repo
if [ "$(zypper lr | grep -ci 'repo-openh264')" -eq 1 ]; then
    echo "Disabling openh264 repo"
    zypper mr -d -f repo-openh264
fi

# add the non-oss repo if it doesn't exist
echo "Adding the non-oss repo"
if [ "$(zypper lr | grep -c 'repo-non-oss')" -eq 0 ]; then
    zypper ar -f -n 'Non-OSS' http://download.opensuse.org/tumbleweed/repo/non-oss/ repo-non-oss
fi

# update the repos and make sure the ones we want are enabled
zypper mr -k repo-oss
zypper mr -k repo-non-oss
zypper mr -k repo-update
# force the refresh because zypper is too silly to work out it needs to do it itself
zypper ref --force
# show which mirror is failing if an error occurs (otherwise zypper shows the wrong mirror url)
zypper -v dup -y
