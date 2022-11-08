.PHONY: help build/kanidmd build/radiusd test/kanidmd push/kanidmd push/radiusd vendor-prep doc install-tools prep vendor book clean_book test/pykanidm/pytest test/pykanidm/mypy test/pykanidm/pylint docs/pykanidm/build  docs/pykanidm/serve release/kanidm release/kanidmd release/kanidm-unixd debs/all debs/kanidm debs/kanidmd debs/kandim-ssh debs/kandim-unixd

IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= devel
CONTAINER_TOOL_ARGS ?=
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
CONTAINER_BUILD_ARGS ?=
# Example of using redis with sccache
# --build-arg "SCCACHE_REDIS=redis://redis.dev.blackhats.net.au:6379"
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

buildx/kanidmd: ## Build multiarch kanidm server images and push to docker hub
buildx/kanidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f kanidmd/Dockerfile \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/server:$(IMAGE_VERSION)

buildx/kanidm_tools: ## Build multiarch kanidm tool images and push to docker hub
buildx/kanidm_tools:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f kanidm_tools/Dockerfile \
		-t $(IMAGE_BASE)/tools:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/tools:$(IMAGE_VERSION)

buildx/radiusd: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f kanidm_rlm_python/Dockerfile \
		-t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) .
	@$(CONTAINER_TOOL) buildx imagetools $(CONTAINER_TOOL_ARGS) inspect $(IMAGE_BASE)/radius:$(IMAGE_VERSION)

buildx: buildx/kanidmd/x86_64_v3 buildx/kanidmd buildx/kanidm_tools buildx/radiusd

build/kanidmd:	## Build the kanidmd docker image locally
build/kanidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f kanidmd/Dockerfile -t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .

build/radiusd:	## Build the radiusd docker image locally
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f kanidm_rlm_python/Dockerfile \
		-t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) .

build: build/kanidmd build/radiusd

test/kanidmd: ## Run cargo test in docker
test/kanidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f kanidmd/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

test/radiusd: ## Run a test radius server
test/radiusd: build/radiusd
	cd kanidm_rlm_python && \
	./run_radius_container.sh

test:
	cargo test

vendor:
	cargo vendor

vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

install-tools: ## install tools in local environment
install-tools:
	cd kanidm_tools && cargo install --path . --force

prep:
	cargo outdated -R
	cargo audit

test/pykanidm/pytest:
	cd pykanidm && \
	poetry install && \
	poetry run pytest -vv

test/pykanidm/pylint:
	cd pykanidm && \
	poetry install && \
	poetry run pylint tests kanidm

test/pykanidm/mypy:
	cd pykanidm && \
	poetry install && \
	echo "Running mypy" && \
	poetry run mypy --strict tests kanidm

test/pykanidm: ## run the test suite (mypy/pylint/pytest) for the kanidm python module
test/pykanidm: test/pykanidm/pytest test/pykanidm/mypy test/pykanidm/pylint

########################################################################

doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

book: ## Build the Kanidm book
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

docs/pykanidm/build: ## Build the mkdocs
docs/pykanidm/build:
	cd pykanidm && \
	poetry install && \
	poetry run mkdocs build

docs/pykanidm/serve: ## Run the local mkdocs server
docs/pykanidm/serve:
	cd pykanidm && \
	poetry install && \
	poetry run mkdocs serve

########################################################################

release/kanidm: ## Build the Kanidm CLI - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p kanidm_tools --bin kanidm --release

release/kanidmd: ## Build the Kanidm daemon - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p daemon --bin kanidmd --release

release/kanidm-ssh: ## Build the Kanidm SSH tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build --release \
		--bin kanidm_ssh_authorizedkeys \
		--bin kanidm_ssh_authorizedkeys_direct

release/kanidm-unixd: ## Build the Kanidm UNIX tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
release/kanidm-unixd:
	cargo build -p pam_kanidm --release
	cargo build -p nss_kanidm --release
	cargo build --release \
		--bin kanidm_unixd  \
		--bin kanidm_unixd_status \
		--bin kanidm_unixd_tasks \
		--bin kanidm_cache_clear \
		--bin kanidm_cache_invalidate
