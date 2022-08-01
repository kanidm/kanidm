# set the following environment variables
# OAUTH_HOSTNAME       - the hostname you'll be exposing this as
# OAUTH_PORT           - the external port this'll be running on (sets it in --publish)
#                        this is 8553, but ... things get weird if the stack doesn't end up being accessed
#                        through 443, eg via a tunneled proxy
# KANIDM_HOSTNAME      - the hostname of the Kanidm instance
# KANIDM_PORT          - if you're running it on a different port
# KANIDM_CLIENT_SECRET - the client secret for the RP in Kanidm's OAuth config
KANIDM_PORT ?= 443
OAUTH_PORT ?= 8553

.DEFAULT: build_and_run

.PHONY: build_and_run
build_and_run: build run

.PHONY: build
build:
	docker build -t kanidm_oauth_test:latest .

.PHONY: run
run:
	docker rm -f kanidm_oauth_test
	docker run --rm -it \
		--env OAUTH_HOSTNAME=$(OAUTH_HOSTNAME) \
		--env KANIDM_HOSTNAME=$(KANIDM_HOSTNAME) \
		--env KANIDM_PORT=$(KANIDM_PORT) \
		--env KANIDM_CLIENT_SECRET=$(KANIDM_CLIENT_SECRET) \
		--volume /tmp/kanidm/:/certs/ \
		--publish "$(OAUTH_PORT):443" \
		--name kanidm_oauth_test \
		kanidm_oauth_test:latest
