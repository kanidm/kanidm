.PHONY: help build/kanidmd build/radiusd test/kanidmd push/kanidmd push/radiusd vendor-prep doc install-tools prep

IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= latest

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

test/kanidmd:	## test kanidmd
test/kanidmd:
	@docker build -f kanidmd/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		.
	@docker run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

test/radiusd:	build/radiusd	## test radiusd

push/kanidmd:	## push kanidmd images
push/kanidmd:
	@docker push $(IMAGE_BASE)/server:$(IMAGE_VERSION)

push/radiusd:	## push radiusd image
push/radiusd:
	@docker push $(IMAGE_BASE)/radius:$(IMAGE_VERSION)

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
