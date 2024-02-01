ARCH ?= $(shell dpkg --print-architecture)


.DEFAULT: help

.PHONY: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/\n\t/'

.PHONY: debs/kanidm
debs/kanidm: ## Build the Kanidm CLI package - make sure you set the environment variable KANIDM_BUILD_PROFILE
debs/kanidm:
	ARCH=$(ARCH) bash ./platform/debian/build_kanidm.sh kanidm

.PHONY: debs/kanidmd
debs/kanidmd: ## Build the Kanidmd package - make sure you set the environment variable KANIDM_BUILD_PROFILE
debs/kanidmd:
	ARCH=$(ARCH) bash ./platform/debian/build_kanidm.sh kanidmd

.PHONY: debs/kanidm-unixd
debs/kanidm-unixd: ## Build the Kanidm UNIX tools package (PAM/NSS, unixd and related tools) - make sure you set the environment variable KANIDM_BUILD_PROFILE
debs/kanidm-unixd:
	ARCH=$(ARCH) bash ./platform/debian/build_kanidm.sh kanidm-unixd

.PHONY: debs/all
debs/all: ## Build all the .deb packages - make sure you set the environment variable KANIDM_BUILD_PROFILE
debs/all: debs/kanidmd debs/kanidm debs/kanidm-unixd
