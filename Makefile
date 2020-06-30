.PHONY: help build/kanidmd build/radiusd test/kanidmd push/kanidmd push/radiusd vendor-prep doc install-tools prep

IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= alpha

.DEFAULT: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/\n\t/'

build/kanidmd:	## build kanidmd images
build/kanidmd:
	@docker build -f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) .

build/radiusd:	## build radiusd image
build/radiusd:
	@docker build -f kanidm_rlm_python/Dockerfile -t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) \
		kanidm_rlm_python

build: build/kanidmd build/radiusd

tag/kanidmd:
	@docker tag $(IMAGE_BASE)/server:$(IMAGE_VERSION) $(IMAGE_BASE)/server:latest

tag/radiusd:
	@docker tag $(IMAGE_BASE)/radius:$(IMAGE_VERSION) $(IMAGE_BASE)/radius:latest

tag: tag/kanidmd tag/radiusd

push/kanidmd:	## push kanidmd images
push/kanidmd:
	@docker push $(IMAGE_BASE)/server:$(IMAGE_VERSION)

push/radiusd:	## push radiusd image
push/radiusd:
	@docker push $(IMAGE_BASE)/radius:$(IMAGE_VERSION)

push: build push/kanidmd push/radiusd

pushlatest: build tag push
	@docker push $(IMAGE_BASE)/server:latest
	@docker push $(IMAGE_BASE)/radius:latest

test/kanidmd:	## test kanidmd
test/kanidmd:
	@docker build -f kanidmd/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		.
	@docker run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

test/radiusd:	build/radiusd	## test radiusd

vendor-prep:
	cargo vendor
	tar -czf vendor.tar.gz vendor

doc: ## build doc local
doc:
	cargo doc --document-private-items

install-tools: ## install tools in local environment
install-tools:
	cd kanidm_tools && cargo install --path . --force

prep:
	cargo outdated -R
	cargo audit

update-version: ## update version form VERSION file in all Cargo.toml manifests
update-version: */Cargo.toml
	@VERSION=`cat VERSION`; sed -i "0,/^version\ \= .*$$/{s//version = \"$$VERSION\"/}" */Cargo.toml
	@echo updated to version "`cat VERSION`" cargo files

publish:
	cd kanidm_proto; cargo package
	cd kanidm_proto; cargo publish
	cd kanidmd; cargo package
	cd kanidmd; cargo publish
	cd kanidm_client; cargo package
	cd kanidm_client; cargo publish
	cd kanidm_tools; cargo package
	cd kanidm_tools; cargo publish
