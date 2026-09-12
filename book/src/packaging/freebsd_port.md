# FreeBSD Port Update Process

## Setup

* Ensure you have a machine with plenty of CPU/RAM - at least 3G per CPU.
* Setup a jail with the ports git repo within
* Inside the jail go to `security/kanidm` and type `make` to ensure all the dependencies are setup
* Consider installing `ports-mgmt/portmaster` so you can run `portmaster -af` to update if needed


## Port Update

```
cd /usr/ports
git checkout -b kanidm-update
cd security/kanidm

# Change the port file as needed.

make makesum
make extract
make cargo-crates > Makefile.crates
rm -rf ./work-client ./work
make makesum
make

```

