
########################################################################

.PHONY: debs/kanidm
debs/kanidm: ## build a .deb for the Kanidm CLI
debs/kanidm:
	./platform/debian/build_kanidm.sh kanidm

.PHONY: debs/kanidmd
debs/kanidmd: ## build a .deb for the Kanidm daemon
debs/kanidmd:
	./platform/debian/build_kanidm.sh kanidmd

.PHONY: debs/kanidm-ssh
debs/kanidm-ssh: ## build a .deb for the Kanidm SSH tools
debs/kanidm-ssh:
	./platform/debian/build_kanidm.sh kanidm-ssh

.PHONY: debs/kanidm-unixd
debs/kanidm-unixd: ## build a .deb for the Kanidm UNIX tools (PAM/NSS, unixd and related tools)
debs/kanidm-unixd:
	./platform/debian/build_kanidm.sh kanidm-unixd

.PHONY: debs/all
debs/all: ## build all the debs
debs/all: debs/kanidmd debs/kanidm debs/kanidm-ssh debs/kanidm-unixd
