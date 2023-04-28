CURDIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))

export KANIDM_BUILD_PROFILE ?= release_suse_generic
export RUST_TOOLCHAIN ?= stable
export CACHE_DIR ?= $(CURDIR)/cache


kanidm-builder-el9:
	BASE_IMAGE=almalinux:9 IMAGE_NAME=$@ ./build-image.sh

kanidm-builder-el8:
	BASE_IMAGE=almalinux:8 IMAGE_NAME=$@ ./build-image.sh

build-images: kanidm-builder-el9 kanidm-builder-el8


el9: export IMAGE_NAME=kanidm-builder-el9:latest
el9: export TARGET_DIR=$(CURDIR)/cache/target-el9
el9:
	./run-image.sh $(CMD)

prep-el9:
	$(MAKE) el9 CMD="bash -lc 'cargo install wasm-pack mdbook'"

run-el9:
	$(MAKE) el9 CMD="bash -l"

build-el9:
	$(MAKE) el9 CMD='bash -lc "make release"'

rpms-el9:
	$(MAKE) el9 CMD='bash -lc "platform/el/build-rpms.sh"'


el8: export IMAGE_NAME=kanidm-builder-el8:latest
el8: export TARGET_DIR=$(CURDIR)/cache/target-el8
el8:
	./run-image.sh $(CMD)

prep-el8:
	$(MAKE) el8 CMD="bash -lc 'cargo install wasm-pack mdbook'"

run-el8:
	$(MAKE) el8 CMD="bash -l"

build-el8:
	$(MAKE) el8 CMD='bash -lc "make release"'

rpms-el8:
	$(MAKE) el8 CMD='bash -lc "platform/el/build-rpms.sh"'

build-rpms: rpms-el9 rpms-el8
