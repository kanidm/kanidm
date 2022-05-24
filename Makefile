.PHONY: help build/kanidmd build/radiusd test/kanidmd push/kanidmd push/radiusd vendor-prep doc install-tools prep vendor book clean_book

IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= devel
CONTAINER_TOOL_ARGS ?=
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
CONTAINER_BUILD_ARGS ?= 
CONTAINER_TOOL ?= docker

BOOK_VERSION ?= master

.DEFAULT: help
help:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##/\n\t/'

buildx/kanidmd/x86_64_v3: ## build multiarch server images
buildx/kanidmd/x86_64_v3:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) --pull --push --platform "linux/amd64" \
		-f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:x86_64_$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_x86_64_v3" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/server:$(IMAGE_VERSION)

buildx/kanidmd: ## build multiarch server images
buildx/kanidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) --pull --push --platform $(IMAGE_ARCH) \
		-f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/server:$(IMAGE_VERSION)

buildx/radiusd: ## build multiarch radius images
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) --pull --push --platform $(IMAGE_ARCH) \
		-f kanidm_rlm_python/Dockerfile -t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) kanidm_rlm_python
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/radius:$(IMAGE_VERSION)

buildx: buildx/kanidmd buildx/radiusd

build/kanidmd:	## build kanidmd images
build/kanidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=developer" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .

build/radiusd:	## build radiusd image
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f kanidm_rlm_python/Dockerfile -t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) kanidm_rlm_python

build: build/kanidmd build/radiusd

test/kanidmd:	## test kanidmd
test/kanidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f kanidmd/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

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

book_versioned:
	echo "Book version: ${BOOK_VERSION}"
	rm -rf ./target/doc
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build kanidm_book
	mkdir -p ./docs
	mv ./kanidm_book/book/ ./docs/${BOOK_VERSION}/
	mkdir -p ./docs/${BOOK_VERSION}/rustdoc/
	mv ./target/doc/* ./docs/${BOOK_VERSION}/rustdoc/
	git switch master

clean_book:
	rm -rf ./docs


install-tools: ## install tools in local environment
install-tools:
	cd kanidm_tools && cargo install --path . --force

prep:
	cargo outdated -R
	cargo audit

