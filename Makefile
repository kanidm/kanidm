.PHONY: help build/kanidmd build/radiusd test/kanidmd push/kanidmd push/radiusd vendor-prep doc install-tools prep vendor book clean_book

IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= devel
EXT_OPTS ?=
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
ARGS ?= --build-arg "SCCACHE_REDIS=redis://172.24.20.4:6379"

BOOK_VERSION ?= master

.DEFAULT: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/\n\t/'

buildx/kanidmd/x86_64_v3: ## build multiarch server images
buildx/kanidmd/x86_64_v3:
	@docker buildx build $(EXT_OPTS) --pull --push --platform "linux/amd64" \
		-f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:x86_64_$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_x86_64_v3" \
		--build-arg "KANIDM_FEATURES=" \
		$(ARGS) .
	@docker buildx imagetools $(EXT_OPTS) inspect $(IMAGE_BASE)/server:$(IMAGE_VERSION)

buildx/kanidmd: ## build multiarch server images
buildx/kanidmd:
	@docker buildx build $(EXT_OPTS) --pull --push --platform $(IMAGE_ARCH) \
		-f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(ARGS) .
	@docker buildx imagetools $(EXT_OPTS) inspect $(IMAGE_BASE)/server:$(IMAGE_VERSION)

buildx/radiusd: ## build multiarch radius images
buildx/radiusd:
	@docker buildx build $(EXT_OPTS) --pull --push --platform $(IMAGE_ARCH) \
		-f kanidm_rlm_python/Dockerfile -t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) kanidm_rlm_python
	@docker buildx imagetools $(EXT_OPTS) inspect $(IMAGE_BASE)/radius:$(IMAGE_VERSION)

buildx: buildx/kanidmd buildx/radiusd

build/kanidmd:	## build kanidmd images
build/kanidmd:
	@docker build $(EXT_OPTS) -f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=developer" \
		--build-arg "KANIDM_FEATURES=" \
		$(ARGS) .

build/radiusd:	## build radiusd image
build/radiusd:
	@docker build $(EXT_OPTS) -f kanidm_rlm_python/Dockerfile -t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) kanidm_rlm_python

build: build/kanidmd build/radiusd

test/kanidmd:	## test kanidmd
test/kanidmd:
	@docker build \
		$(EXT_OPTS) -f kanidmd/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		$(ARGS) .
	@docker run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

# test/radiusd:	build/radiusd	## test radiusd

vendor:
	cargo vendor

vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

doc: ## build doc local
doc:
	cargo doc --document-private-items

book:
	cargo doc --no-deps
	mdbook build kanidm_book
	mv ./kanidm_book/book/ ./docs/
	mkdir -p ./docs/rustdoc/${BOOK_VERSION}
	mv ./target/doc/* ./docs/rustdoc/${BOOK_VERSION}/

clean_book:
	rm -rf ./docs


install-tools: ## install tools in local environment
install-tools:
	cd kanidm_tools && cargo install --path . --force

prep:
	cargo outdated -R
	cargo audit

